//! Opt-in CRL discovery and injected artifact retrieval. No fetched artifact is a trust anchor.
mod http;
use crate::{
    TrustStore,
    domain::*,
    verify::{VerifyOptions, budget::Budget, verify_inner_budget},
};
use ::der::Decode;
pub use http::HttpCrlSource;
use std::collections::{BTreeMap, BTreeSet};
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
    listed_points(cert, true)?.into_iter().collect()
}

/// Each listed name of `cert`'s cRLDistributionPoints: a URI, or
/// `crl_fetch_denied` for a point with reasons, a cRLIssuer, a relative name or
/// a non-URI name. A malformed extension and the URL count and length limits
/// are errors for the whole certificate. With `strict`, the first unsupported
/// point is that error, before any later limit, as [`crl_distribution_points`]
/// has always reported it.
fn listed_points(
    cert: &Certificate,
    strict: bool,
) -> Result<Vec<Result<String, VerificationError>>, VerificationError> {
    let value = cert
        .tbs_certificate
        .get::<CrlDistributionPoints>()
        .map_err(|e| error(ErrorCode::InvalidCertificate, e.to_string()))?;
    let Some((_, points)) = value else {
        return Ok(Vec::new());
    };
    let mut listed = Vec::new();
    let deny = |listed: &mut Vec<_>, message: &'static str| {
        let e = error(ErrorCode::CrlFetchDenied, message);
        if strict {
            return Err(e);
        }
        listed.push(Err(e));
        Ok(())
    };
    let mut urls = 0;
    for point in points.0 {
        if point.reasons.is_some() || point.crl_issuer.is_some() {
            deny(
                &mut listed,
                "partitioned or indirect CRL distribution points are unsupported",
            )?;
            continue;
        }
        let Some(DistributionPointName::FullName(names)) = point.distribution_point else {
            deny(
                &mut listed,
                "CRL distribution point requires a full URI name",
            )?;
            continue;
        };
        for name in names {
            let GeneralName::UniformResourceIdentifier(uri) = name else {
                deny(&mut listed, "non-URI CRL distribution point is unsupported")?;
                continue;
            };
            if urls >= MAX_REQUESTS {
                return Err(limit("crl_urls", MAX_REQUESTS, urls, 1));
            }
            if uri.as_str().len() > 2048 {
                return Err(limit("crl_url_bytes", 2048, 0, uri.as_str().len()));
            }
            urls += 1;
            listed.push(Ok(uri.as_str().into()));
        }
    }
    Ok(listed)
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

/// Verify signatures and configured-root paths without revocation to find the
/// selected certificates, then retrieve CRLs in two steps and verify with
/// required revocation after each: first for certificates whose issuer no
/// supplied CRL names (with no such certificate, the first verification uses
/// the supplied CRLs alone, before any request), then, only if the status is
/// still `revocation_unknown`, for the rest. A good result or any other failure
/// is final. Whether a CRL applies is decided only by verification; retrieval
/// compares issuer names to order requests. See `docs/crl-retrieval.md`. The
/// passes share one SEC-02 work budget. The input store is never modified.
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
    /// Requested URLs, with the failure of those that yielded no evidence.
    requested: BTreeMap<String, Option<VerificationError>>,
    /// Requests made, answered or not; bounded by `MAX_REQUESTS`.
    requests: usize,
    budget: &'b Budget<'l>,
}

fn crl_internal(e: anyhow::Error) -> VerificationError {
    VerificationError::from_internal(e, ErrorCode::InvalidCrl, Stage::Revocation)
}

impl<'s, 'b, 'l> Retrieval<'s, 'b, 'l> {
    fn new(base: &'s TrustStore, budget: &'b Budget<'l>) -> Self {
        Self {
            base,
            store: base.clone(),
            report: CrlRetrievalReport::default(),
            downloaded: 0,
            requested: BTreeMap::new(),
            requests: 0,
            budget,
        }
    }

    /// Record a point that yielded no evidence. Every error about one
    /// listed point ends here, whatever its code, including any error the
    /// source returns: the source is the caller's, so its errors mean only
    /// that this URL produced nothing. The next verification still requires
    /// evidence for every certificate, so this never accepts anything. Only
    /// the engine's own limits end the run; they never reach here.
    fn skip(&mut self, certificate: &str, url: Option<&str>, e: VerificationError) {
        let e = match url {
            Some(url) => e.detail("url", url),
            None => e,
        };
        self.budget.log.info(
            Stage::Revocation,
            format_args!("CRL point yielded no evidence: {:?}", e.message),
        );
        self.record(certificate, url, &e);
        if let Some(entry) = url.and_then(|url| self.requested.get_mut(url)) {
            *entry = Some(e);
        }
    }

    /// One failure entry per certificate and URL; without a URL, per
    /// certificate and message.
    fn record(&mut self, certificate: &str, url: Option<&str>, e: &VerificationError) {
        if self.report.failures.iter().any(|f| {
            f.certificate_sha256 == certificate
                && f.url.as_deref() == url
                && (url.is_some() || f.message == e.message)
        }) {
            return;
        }
        self.report.failures.push(CrlRetrievalFailure {
            certificate_sha256: certificate.into(),
            url: url.map(Into::into),
            code: e.code,
            stage: e.stage,
            message: e.message.clone(),
            details: e.details.clone(),
            causes: e.causes.clone(),
        });
    }

    /// Request every listed point of `cert`. A point that yields no evidence
    /// is recorded in the report's failures (see [`Self::skip`]); whether that
    /// matters is decided by the next verification. The engine's own limits
    /// (requests, retained CRLs, combined bytes, response size, URLs per
    /// certificate) end the run. A URL already requested is not
    /// requested again; if it failed, the failure is recorded for this
    /// certificate too. Returns whether anything was added.
    fn fetch(
        &mut self,
        sha256: &str,
        cert: &Certificate,
        source: &mut dyn CrlSource,
    ) -> Result<bool, VerificationError> {
        let log = self.budget.log;
        let mut added = false;
        let listed = match listed_points(cert, false) {
            Ok(listed) => listed,
            // The engine's own per-certificate URL limits end the run.
            Err(e) if e.code == ErrorCode::ResourceLimitExceeded => return Err(e),
            // A malformed extension: webpki skips it offline, so it is no
            // evidence here, not a rejection.
            Err(e) => {
                self.skip(sha256, None, e);
                return Ok(false);
            }
        };
        for listed in listed {
            let raw = match listed {
                Ok(raw) => raw,
                Err(e) => {
                    self.skip(sha256, None, e);
                    continue;
                }
            };
            let url = match http::checked_url(&raw) {
                Ok(url) => url.to_string(),
                Err(e) => {
                    self.skip(sha256, Some(&raw), e);
                    continue;
                }
            };
            if let Some(previous) = self.requested.get(&url) {
                if let Some(e) = previous.clone() {
                    self.record(sha256, Some(&url), &e);
                }
                continue;
            }
            if self.requests >= MAX_REQUESTS {
                return Err(limit("crl_requests", MAX_REQUESTS, self.requests, 1));
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
            self.requests += 1;
            self.requested.insert(url.clone(), None);
            log.info(
                Stage::Revocation,
                format_args!("requesting CRL {url:?} (at most {cap} bytes)"),
            );
            let fetched = match source.fetch(&url, cap) {
                Ok(fetched) => fetched,
                Err(e) => {
                    self.skip(sha256, Some(&url), e);
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
            // A source that returns more than it was allowed is not trusted
            // with that response; the bytes are not loaded.
            if fetched.bytes.len() > cap {
                let e = limit("crl_response_bytes", cap, 0, fetched.bytes.len());
                self.skip(sha256, Some(&url), e);
                continue;
            }
            if let Err(e) = http::checked_url(&fetched.final_url) {
                self.skip(sha256, Some(&url), e);
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
                url: url.clone(),
                final_url: fetched.final_url,
                sha256: hex(&crate::crypto::Hash::Sha256.digest(&fetched.bytes)),
                bytes: fetched.bytes.len(),
            });
            let prior = self.store.retrieval_crl_count();
            if let Err(e) = self.store.add_crl(&fetched.bytes) {
                let e = error(
                    ErrorCode::InvalidCrl,
                    format!("decoding retrieved CRL: {e:#}"),
                );
                self.skip(sha256, Some(&url), e);
                continue;
            }
            // A PEM response may contain multiple distinct CRLs. Bound the
            // retained store after deduplication, before verification.
            let loaded = self.store.retrieval_crl_count();
            if loaded > 64 {
                return Err(limit("retrieval_crl_artifacts", 64, prior, loaded - prior));
            }
            // A response identical to a loaded CRL adds nothing to verify.
            added |= loaded > prior;
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
    let mut state = Retrieval::new(base, budget);
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
        for cert_report in selected {
            if !seen.insert(&cert_report.sha256) {
                continue;
            }
            budget
                .decoded_bytes
                .charge(cert_report.der_hex.len())
                .map_err(internal)?;
            let der = cert_report
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
            let named_issuer = crate::der::tbs_issuer(&der, 0xa0, 2)
                .is_some_and(|issuer| named.iter().any(|n| n == issuer));
            let cert = Certificate::from_der(&der)
                .map_err(|e| error(ErrorCode::InvalidCertificate, e.to_string()))?;
            stages[usize::from(named_issuer)].push((&cert_report.sha256, cert));
        }
        // Step 1 fetches for certificates no supplied CRL names, step 2 for
        // the rest. Verification follows each step that has any CRL to use
        // (after step 1 that includes the supplied CRLs alone); a good result
        // or any failure but unknown status is final.
        let mut verdict = None;
        for (step, certificates) in stages.iter().enumerate() {
            let mut added = false;
            for (sha256, cert) in certificates {
                added |= state.fetch(sha256, cert, source)?;
            }
            let verify = if step == 0 {
                state.store.retrieval_crl_count() > 0
            } else {
                added
            };
            if verify {
                match verify_with(bytes, options, &state.store, format, budget) {
                    Err(e) if e.code == ErrorCode::RevocationUnknown => verdict = Some(e),
                    result => return result,
                }
            }
        }
        // Still unknown. The result is always the verifier's own: if no
        // verification ran yet (no CRL at all), it runs now. Points that
        // yielded no evidence, and why, are in the report's failures.
        match verdict {
            Some(e) => Err(e),
            None => verify_with(bytes, options, &state.store, format, budget),
        }
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
                ErrorCode::RevocationUnknown,
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
        // An over-cap response is no evidence: not loaded, not reported as an
        // artifact, and the status stays unknown with the reason recorded.
        assert_eq!(result.code, ErrorCode::RevocationUnknown);
        let report = &result.details["crl_retrieval"];
        assert_eq!(report["artifacts"], serde_json::json!([]));
        let failure = &report["failures"][0];
        assert_eq!(failure["code"], "resource_limit_exceeded");
        assert_eq!(failure["details"]["resource"], "crl_response_bytes");
        assert_eq!(failure["details"]["requested"], MAX_CRL_BYTES + 1);
    }
    /// The good-crl-discovery signer with `count` distinct listed URIs.
    fn signer_with_points(tag: &str, count: usize) -> Certificate {
        fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            match body.len() {
                n @ 0..128 => out.push(n as u8),
                n @ 128..256 => out.extend([0x81, n as u8]),
                n => out.extend([0x82, (n >> 8) as u8, n as u8]),
            }
            out.extend_from_slice(body);
            out
        }
        let pe =
            crate::parse::Pe::parse(include_bytes!("../tests/fixtures/good-crl-discovery.exe"))
                .unwrap();
        let cms = pe.signatures().unwrap();
        let sd = crate::parse::SignedData::parse(cms[0]).unwrap();
        let mut cert = sd.certificate_choices()[0].x509().unwrap().clone();
        let mut points = Vec::new();
        for i in 0..count {
            let uri = format!("http://crl.example.invalid/{tag}-{i}.crl");
            points.extend(tlv(
                0x30,
                &tlv(0xa0, &tlv(0xa0, &tlv(0x86, uri.as_bytes()))),
            ));
        }
        cert.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e.extn_id.to_string() == "2.5.29.31")
            .unwrap()
            .extn_value = ::der::asn1::OctetString::new(tlv(0x30, &points)).unwrap();
        cert
    }
    #[test]
    fn failed_requests_count_toward_the_request_cap() {
        struct Failing(usize);
        impl CrlSource for Failing {
            fn fetch(&mut self, _: &str, _: usize) -> Result<FetchedCrl, VerificationError> {
                self.0 += 1;
                Err(error(ErrorCode::CrlFetchFailed, "unreachable"))
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let mut source = Failing(0);
        assert!(
            !state
                .fetch("a", &signer_with_points("a", 10), &mut source)
                .unwrap()
        );
        assert_eq!(state.report.failures.len(), 10);
        let error = state
            .fetch("b", &signer_with_points("b", 10), &mut source)
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::ResourceLimitExceeded);
        assert_eq!(error.details["resource"], "crl_requests");
        assert_eq!(source.0, MAX_REQUESTS);
    }
    #[test]
    fn every_point_error_is_recorded_once_per_certificate_and_url() {
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let url = Some("http://x.invalid/a");
        state.skip("a", None, error(ErrorCode::InvalidCertificate, "malformed"));
        state.skip("a", url, limit("crl_network_bytes", 1, 1, 1));
        state.skip("a", url, error(ErrorCode::CrlFetchFailed, "again"));
        state.skip("b", url, error(ErrorCode::CrlFetchFailed, "unreachable"));
        let entries: Vec<_> = state
            .report
            .failures
            .iter()
            .map(|f| (f.certificate_sha256.as_str(), f.url.as_deref(), f.code))
            .collect();
        assert_eq!(
            entries,
            [
                ("a", None, ErrorCode::InvalidCertificate),
                ("a", url, ErrorCode::ResourceLimitExceeded),
                ("b", url, ErrorCode::CrlFetchFailed),
            ]
        );
        // A URL that was never requested is not tracked as one.
        assert!(state.requested.is_empty());
    }
    #[test]
    fn a_source_error_is_no_evidence_even_when_it_is_a_limit() {
        struct Limited;
        impl CrlSource for Limited {
            fn fetch(&mut self, _: &str, _: usize) -> Result<FetchedCrl, VerificationError> {
                Err(limit("crl_network_bytes", 1, 1, 1))
            }
        }
        let store = store();
        let error = verify_with_crl_source(
            include_bytes!("../tests/fixtures/good-crl-discovery.exe"),
            None,
            &VerifyOptions::trusted(&store, 1800000000),
            &mut Limited,
        )
        .unwrap_err();
        // The source is the caller's: its limit means this URL produced
        // nothing, so the status is unknown and the reason is recorded.
        assert_eq!(error.code, ErrorCode::RevocationUnknown);
        let failure = &error.details["crl_retrieval"]["failures"][0];
        assert_eq!(failure["code"], "resource_limit_exceeded");
        assert_eq!(failure["details"]["resource"], "crl_network_bytes");
        assert_eq!(failure["url"], "http://crl.example.invalid/test.crl");
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
        // The public API stops at the first unsupported point, before limits.
        let pe = crate::parse::Pe::parse(include_bytes!(
            "../tests/fixtures/sec10-leaf-crl-dp-mixed.exe"
        ))
        .unwrap();
        let cms = pe.signatures().unwrap();
        let sd = crate::parse::SignedData::parse(cms[0]).unwrap();
        let mixed = sd
            .certificate_choices()
            .iter()
            .map(|c| c.x509().unwrap())
            .find(|c| c.tbs_certificate.serial_number.as_bytes() == [127])
            .unwrap();
        assert_eq!(
            crl_distribution_points(mixed).unwrap_err().code,
            ErrorCode::CrlFetchDenied
        );
        assert_eq!(
            listed_points(mixed, false)
                .unwrap()
                .iter()
                .filter(|p| p.is_ok())
                .count(),
            1
        );
        assert_eq!(
            crl_distribution_points(&cert).unwrap_err().code,
            ErrorCode::InvalidCertificate
        );
    }
}
