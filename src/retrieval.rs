//! Opt-in CRL discovery and injected artifact retrieval. No fetched artifact is a trust anchor.
mod http;
use crate::{
    TrustStore,
    domain::*,
    verify::{VerifyOptions, budget::Budget, verify_inner_budget},
};
use ::der::Decode;
pub use http::HttpCrlSource;
use std::collections::BTreeSet;
use x509_cert::{
    Certificate,
    ext::pkix::{
        CrlDistributionPoints,
        name::{DistributionPointName, GeneralName},
    },
};

pub const MAX_CRL_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_TOTAL_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_REQUESTS: usize = 16;

/// Providers return untrusted bytes, never a trust/revocation verdict. Implementations
/// must bound their own I/O/allocation by `max_bytes` and enforce a finite deadline.
/// The engine independently checks response length and authenticates every artifact.
pub trait CrlSource {
    fn fetch(&mut self, url: &str, max_bytes: usize) -> Result<FetchedCrl, VerificationError>;
}
pub struct FetchedCrl {
    pub bytes: Vec<u8>,
    pub final_url: String,
}

pub(crate) fn error(code: ErrorCode, message: impl Into<String>) -> VerificationError {
    VerificationError::new(code, Stage::Revocation, message)
}
pub(crate) fn limit(
    resource: &str,
    cap: usize,
    used: usize,
    requested: usize,
) -> VerificationError {
    error(
        ErrorCode::ResourceLimitExceeded,
        "CRL retrieval budget exhausted",
    )
    .detail("resource", resource)
    .detail("limit", cap)
    .detail("used", used)
    .detail("requested", requested)
}

/// Decode direct, complete CRL distribution-point URIs. Relative names, reason
/// partitions, and indirect CRL issuers are unsupported and fail closed.
pub fn crl_distribution_points(cert: &Certificate) -> Result<Vec<String>, VerificationError> {
    let value = cert
        .tbs_certificate
        .get::<CrlDistributionPoints>()
        .map_err(|e| error(ErrorCode::InvalidCertificate, e.to_string()))?;
    let Some((_, points)) = value else {
        return Ok(Vec::new());
    };
    let mut urls = Vec::new();
    for point in points.0 {
        if point.reasons.is_some() || point.crl_issuer.is_some() {
            return Err(error(
                ErrorCode::CrlFetchDenied,
                "partitioned or indirect CRL distribution points are unsupported",
            ));
        }
        let Some(DistributionPointName::FullName(names)) = point.distribution_point else {
            return Err(error(
                ErrorCode::CrlFetchDenied,
                "CRL distribution point requires a full URI name",
            ));
        };
        for name in names {
            if let GeneralName::UniformResourceIdentifier(uri) = name {
                if urls.len() >= MAX_REQUESTS {
                    return Err(limit("crl_urls", MAX_REQUESTS, urls.len(), 1));
                }
                if uri.as_str().len() > 2048 {
                    return Err(limit("crl_url_bytes", 2048, 0, uri.as_str().len()));
                }
                urls.push(uri.as_str().into());
            } else {
                return Err(error(
                    ErrorCode::CrlFetchDenied,
                    "non-URI CRL distribution point is unsupported",
                ));
            }
        }
    }
    Ok(urls)
}

/// Selected-path certificates below the anchor.
fn collect<'a>(bundle: &'a VerificationBundle, output: &mut Vec<&'a CertificateReport>) {
    let mut path = |trust: &'a TrustReport| {
        output.extend(trust.chain.iter().take(trust.chain.len().saturating_sub(1)));
    };
    for signature in &bundle.signatures {
        if let Some(trust) = &signature.trust {
            path(trust);
        }
        if let Some(timestamp) = &signature.timestamp_verification
            && let Some(trust) = &timestamp.trust
        {
            path(trust);
        }
    }
    if let Some(appx) = &bundle.appx
        && let Some(packages) = &appx.bundle_packages
    {
        for package in packages {
            collect(&package.verification, output);
        }
    }
}

/// Verify signatures and configured-root paths without revocation, then with
/// required revocation against the supplied CRLs. Only when that result is
/// `revocation_unknown` are the selected certificates' listed distribution
/// points fetched and verification repeated; any other result is returned as
/// it is. Retrieval is driven by the verifier's own outcome, so no CRL
/// applicability rule is restated here. The passes share one SEC-02 work
/// budget. The input store is never modified.
pub fn verify_with_crl_source(
    bytes: &[u8],
    filename: Option<&str>,
    options: &VerifyOptions<'_>,
    source: &mut dyn CrlSource,
) -> Result<VerificationBundle, VerificationError> {
    retrieve(bytes, filename, options, source, &Budget::default())
}

impl crate::verify::Verifier<'_> {
    /// [`verify_with_crl_source`] with this verifier's logger, which also
    /// receives each CRL request and response size.
    pub fn verify_with_crl_source(
        &self,
        bytes: &[u8],
        filename: Option<&str>,
        source: &mut dyn CrlSource,
    ) -> Result<VerificationBundle, VerificationError> {
        let (options, logger) = self.parts();
        let budget = Budget::with_logger(logger);
        crate::verify::logged(&budget, options, || {
            Ok(retrieve(bytes, filename, options, source, &budget)?)
        })
    }
}

/// Retrieval state for one verification: the store that grows with fetched
/// CRLs and the provenance report.
struct Retrieval<'s, 'b, 'l> {
    base: &'s TrustStore,
    store: TrustStore,
    report: CrlRetrievalReport,
    downloaded: usize,
    fetched_urls: BTreeSet<String>,
    budget: &'b Budget<'l>,
}

fn crl_internal(e: anyhow::Error) -> VerificationError {
    VerificationError::from_internal(e, ErrorCode::InvalidCrl, Stage::Revocation)
}

impl Retrieval<'_, '_, '_> {
    /// Request every listed point of `cert`. A point that cannot be
    /// discovered, is denied by transport policy, or whose request fails
    /// yields no evidence and is recorded in `skipped`: whether that matters
    /// is decided by the next verification, which still requires evidence for
    /// every certificate. Work and size limits, and undecodable responses, are
    /// final. Returns whether anything was added.
    fn fetch(
        &mut self,
        cert: &Certificate,
        source: &mut dyn CrlSource,
        skipped: &mut Option<VerificationError>,
    ) -> Result<bool, VerificationError> {
        let log = &self.budget.log;
        let mut added = false;
        let urls = match crl_distribution_points(cert) {
            Ok(urls) => urls,
            Err(e) => {
                skipped.get_or_insert(e);
                return Ok(false);
            }
        };
        for raw in urls {
            let url = match http::checked_url(&raw) {
                Ok(url) => url.to_string(),
                Err(e) => {
                    skipped.get_or_insert(e);
                    continue;
                }
            };
            if !self.fetched_urls.insert(url.clone()) {
                continue;
            }
            if self.report.artifacts.len() >= MAX_REQUESTS {
                return Err(limit(
                    "crl_requests",
                    MAX_REQUESTS,
                    self.report.artifacts.len(),
                    1,
                ));
            }
            if self.store.retrieval_crl_count() >= 64 {
                return Err(limit(
                    "retrieval_crl_artifacts",
                    64,
                    self.store.retrieval_crl_count(),
                    1,
                ));
            }
            let used = self.base.retrieval_bytes() + self.downloaded;
            let cap = MAX_CRL_BYTES.min(MAX_TOTAL_BYTES.saturating_sub(used));
            if cap == 0 {
                return Err(limit("retrieval_trust_bytes", MAX_TOTAL_BYTES, used, 1));
            }
            log.info(
                Stage::Revocation,
                format_args!("requesting CRL {url:?} (at most {cap} bytes)"),
            );
            let fetched = match source.fetch(&url, cap) {
                Ok(fetched) => fetched,
                Err(e) => {
                    skipped.get_or_insert(e.detail("url", &url));
                    continue;
                }
            };
            log.debug(
                Stage::Revocation,
                format_args!(
                    "CRL source returned {} bytes from {:?}; not yet authenticated",
                    fetched.bytes.len(),
                    fetched.final_url
                ),
            );
            if fetched.bytes.len() > cap {
                return Err(limit("crl_response_bytes", cap, 0, fetched.bytes.len()));
            }
            if let Err(e) = http::checked_url(&fetched.final_url) {
                skipped.get_or_insert(e.detail("url", &url));
                continue;
            }
            for _ in 0..8 {
                self.budget
                    .decoded_bytes
                    .charge(fetched.bytes.len())
                    .map_err(crl_internal)?;
            }
            self.budget
                .hash_bytes
                .charge(fetched.bytes.len())
                .map_err(crl_internal)?;
            self.downloaded += fetched.bytes.len();
            self.report.artifacts.push(CrlRetrievalArtifact {
                url,
                final_url: fetched.final_url,
                sha256: hex(&crate::crypto::Hash::Sha256.digest(&fetched.bytes)),
                bytes: fetched.bytes.len(),
            });
            let prior = self.store.retrieval_crl_count();
            self.store.add_crl(&fetched.bytes).map_err(|e| {
                error(
                    ErrorCode::InvalidCrl,
                    format!("decoding retrieved CRL: {e:#}"),
                )
            })?;
            // A PEM response may contain multiple distinct CRLs. Bound the
            // retained store after deduplication, before verification.
            let loaded = self.store.retrieval_crl_count();
            if loaded > 64 {
                return Err(limit("retrieval_crl_artifacts", 64, prior, loaded - prior));
            }
            added = true;
        }
        Ok(added)
    }
}

fn retrieve(
    bytes: &[u8],
    filename: Option<&str>,
    options: &VerifyOptions<'_>,
    source: &mut dyn CrlSource,
    budget: &Budget,
) -> Result<VerificationBundle, VerificationError> {
    let base = options.trust.ok_or_else(|| {
        error(
            ErrorCode::Configuration,
            "CRL retrieval requires configured trust",
        )
    })?;
    if !options.check_revocation {
        return Err(error(
            ErrorCode::Configuration,
            "CRL retrieval requires revocation checking",
        ));
    }
    let format = crate::format::detect(bytes, filename)?;
    let log = &budget.log;
    let internal =
        |e| VerificationError::from_internal(e, ErrorCode::InvalidCertificate, Stage::Certificate);
    let mut state = Retrieval {
        base,
        store: base.clone(),
        report: CrlRetrievalReport::default(),
        downloaded: 0,
        fetched_urls: BTreeSet::new(),
        budget,
    };
    let result = (|| {
        if base.retrieval_bytes() > MAX_TOTAL_BYTES {
            return Err(limit(
                "retrieval_trust_bytes",
                MAX_TOTAL_BYTES,
                0,
                base.retrieval_bytes(),
            ));
        }
        log.debug(
            Stage::Revocation,
            format_args!(
                "CRL retrieval: verifying without revocation to discover distribution points"
            ),
        );
        let preliminary = VerifyOptions {
            check_revocation: false,
            ..*options
        };
        let pending = verify_inner_budget(bytes, &preliminary, format, budget).map_err(internal)?;
        let mut selected = Vec::new();
        collect(&pending, &mut selected);
        // A certificate whose issuer no supplied CRL even names certainly
        // lacks evidence, so its points are requested first. The others are
        // requested only if verification then still reports unknown status:
        // the verifier does not say which certificate lacked evidence, and a
        // name-matching CRL may or may not be authoritative for it.
        let named = base.crl_issuers(budget).map_err(crl_internal)?;
        let mut seen = BTreeSet::new();
        let mut stages = [Vec::new(), Vec::new()];
        for cert in selected {
            if !seen.insert(&cert.sha256) {
                continue;
            }
            budget
                .decoded_bytes
                .charge(cert.der_hex.len())
                .map_err(internal)?;
            let der = cert
                .der_hex
                .as_bytes()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| {
                    u8::from_str_radix(std::str::from_utf8(pair).expect("generated DER hex"), 16)
                        .expect("generated DER hex")
                })
                .collect::<Vec<_>>();
            let cert = Certificate::from_der(&der)
                .map_err(|e| error(ErrorCode::InvalidCertificate, e.to_string()))?;
            let named_issuer = named.contains(&cert.tbs_certificate.issuer);
            stages[usize::from(named_issuer)].push(cert);
        }
        let mut skipped = None;
        let mut verdict = None;
        let [uncovered, named_only] = stages;
        let mut added = false;
        for cert in &uncovered {
            added |= state.fetch(cert, source, &mut skipped)?;
        }
        // Verify with revocation required: after the first step's fetches,
        // or with the supplied CRLs alone. A good result or any failure but
        // unknown status is final. With no CRL at all the status is unknown.
        if added || state.store.retrieval_crl_count() > 0 {
            match verify_with(bytes, options, &state.store, format, budget) {
                Err(e) if e.code == ErrorCode::RevocationUnknown => verdict = Some(e),
                result => return result,
            }
        }
        let mut added = false;
        for cert in &named_only {
            added |= state.fetch(cert, source, &mut skipped)?;
        }
        if added {
            match verify_with(bytes, options, &state.store, format, budget) {
                Err(e) if e.code == ErrorCode::RevocationUnknown => verdict = Some(e),
                result => return result,
            }
        }
        // Still unknown. A skipped point says why more specifically.
        Err(skipped.or(verdict).unwrap_or_else(|| {
            error(
                ErrorCode::RevocationUnknown,
                "no CRL was supplied and no selected certificate lists a CRL distribution point",
            )
        }))
    })();
    match result {
        Ok(mut verified) => {
            verified.crl_retrieval = Some(state.report);
            Ok(verified)
        }
        Err(e) => Err(e.detail("crl_retrieval", state.report)),
    }
}

/// One verification with revocation required against `store`.
fn verify_with(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
    store: &TrustStore,
    format: crate::format::Format,
    budget: &Budget,
) -> Result<VerificationBundle, VerificationError> {
    budget.log.debug(
        Stage::Revocation,
        format_args!(
            "CRL retrieval: verifying with required revocation and {} loaded CRL(s)",
            store.retrieval_crl_count()
        ),
    );
    let options = VerifyOptions {
        trust: Some(store),
        ..*options
    };
    verify_inner_budget(bytes, &options, format, budget).map_err(|e| {
        VerificationError::from_internal(e, ErrorCode::InvalidCertificate, Stage::Certificate)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TrustStore, verify::RevocationPolicy};
    struct Never;
    impl CrlSource for Never {
        fn fetch(&mut self, _: &str, _: usize) -> Result<FetchedCrl, VerificationError> {
            panic!("unexpected provider call")
        }
    }
    fn store() -> TrustStore {
        let mut store = TrustStore::default();
        store
            .add_roots(include_bytes!("../tests/fixtures/root.der"))
            .unwrap();
        store
    }
    #[test]
    fn retrieval_cannot_bypass_integrity_trust_or_explicit_revocation() {
        let store = store();
        let options = VerifyOptions::trusted(&store, 1800000000);
        for (bytes, code) in [
            (
                include_bytes!("../tests/fixtures/bad-crl-discovery-image.exe").as_slice(),
                ErrorCode::ImageDigestMismatch,
            ),
            (
                include_bytes!("../tests/fixtures/bad-crl-private-url.exe").as_slice(),
                ErrorCode::CrlFetchDenied,
            ),
            (
                include_bytes!("../tests/fixtures/good-pe64.exe").as_slice(),
                ErrorCode::RevocationUnknown,
            ),
        ] {
            assert_eq!(
                verify_with_crl_source(bytes, None, &options, &mut Never)
                    .unwrap_err()
                    .code,
                code
            );
        }
        let bytes = include_bytes!("../tests/fixtures/good-crl-discovery.exe");
        let empty = TrustStore::default();
        assert_eq!(
            verify_with_crl_source(
                bytes,
                None,
                &VerifyOptions::trusted(&empty, 1800000000),
                &mut Never
            )
            .unwrap_err()
            .code,
            ErrorCode::UntrustedRoot
        );
        assert_eq!(
            verify_with_crl_source(
                bytes,
                None,
                &VerifyOptions::integrity_only(1800000000),
                &mut Never
            )
            .unwrap_err()
            .code,
            ErrorCode::Configuration
        );
        let options =
            VerifyOptions::trusted_with_revocation(&store, 1800000000, RevocationPolicy::Disabled);
        assert_eq!(
            verify_with_crl_source(bytes, None, &options, &mut Never)
                .unwrap_err()
                .code,
            ErrorCode::Configuration
        );
    }
    #[test]
    fn selected_paths_include_intermediates_timestamps_and_bundle_children() {
        let mut store = store();
        store
            .add_crl(include_bytes!("../tests/fixtures/good.crl"))
            .unwrap();
        store
            .add_crl(include_bytes!("../tests/fixtures/good-intermediate.crl"))
            .unwrap();
        for bytes in [
            include_bytes!("../tests/fixtures/good-intermediate.exe").as_slice(),
            include_bytes!("../tests/fixtures/good-rfc3161.exe").as_slice(),
            include_bytes!("../tests/fixtures/good.msixbundle").as_slice(),
        ] {
            let options = VerifyOptions::trusted(&store, 1800000000);
            let result = verify_with_crl_source(bytes, None, &options, &mut Never).unwrap();
            assert!(result.crl_retrieval.as_ref().unwrap().artifacts.is_empty());
            let mut selected = Vec::new();
            collect(&result, &mut selected);
            assert!(selected.len() >= 2);
            assert!(
                selected
                    .iter()
                    .all(|c| c.subject.common_names != ["rssig test root"])
            );
        }
    }
    #[test]
    fn provider_overflow_is_rejected_without_loading_or_trusting_the_artifact() {
        struct Huge;
        impl CrlSource for Huge {
            fn fetch(&mut self, url: &str, cap: usize) -> Result<FetchedCrl, VerificationError> {
                Ok(FetchedCrl {
                    bytes: vec![0; cap + 1],
                    final_url: url.into(),
                })
            }
        }
        let store = store();
        let result = verify_with_crl_source(
            include_bytes!("../tests/fixtures/good-crl-discovery.exe"),
            None,
            &VerifyOptions::trusted(&store, 1800000000),
            &mut Huge,
        )
        .unwrap_err();
        assert_eq!(result.code, ErrorCode::ResourceLimitExceeded);
        assert_eq!(result.details["resource"], "crl_response_bytes");
        assert_eq!(result.details["requested"], MAX_CRL_BYTES + 1);
    }
    #[test]
    fn discovery_preserves_uri_and_rejects_malformed_extensions() {
        let pe =
            crate::parse::Pe::parse(include_bytes!("../tests/fixtures/good-crl-discovery.exe"))
                .unwrap();
        let cms = pe.signatures().unwrap();
        let sd = crate::parse::SignedData::parse(cms[0]).unwrap();
        let mut cert = sd.certificate_choices()[0].x509().unwrap().clone();
        assert_eq!(
            crl_distribution_points(&cert).unwrap(),
            ["http://crl.example.invalid/test.crl"]
        );
        let ext = cert
            .tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e.extn_id.to_string() == "2.5.29.31")
            .unwrap();
        ext.extn_value = ::der::asn1::OctetString::new([0x30, 0x7f]).unwrap();
        assert_eq!(
            crl_distribution_points(&cert).unwrap_err().code,
            ErrorCode::InvalidCertificate
        );
    }
}
