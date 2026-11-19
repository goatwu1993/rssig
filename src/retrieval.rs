//! Opt-in CRL discovery and injected artifact retrieval. No fetched artifact is a trust anchor.
mod http;
pub use crate::domain::CrlSourceErrorKind;
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
/// Requests to a [`CrlSource`] per verification, one per certificate.
pub const MAX_SOURCE_REQUESTS: usize = 64;
/// CRL bodies and failures one [`CrlResponse`] may carry together.
pub const MAX_RESPONSE_ENTRIES: usize = 64;

/// The single interface through which the engine obtains CRLs, asked once per
/// certificate, like OpenSSL's `get_crl` (by certificate) or `lookup_crls` (by
/// issuer name). A source returns untrusted bytes, never a trust or revocation
/// verdict: the engine authenticates every CRL and applies no transport rule
/// of its own. Where CRLs come from, and how (HTTP, HTTPS, LDAP, a proxy, a
/// cache, a local directory keyed by issuer), is the source's decision;
/// [`HttpCrlSource`] is the built-in one, and [`fetch_each`] adapts any
/// per-URL fetch. A source must bound its own I/O and allocation by
/// [`CrlRequest::max_bytes`] and finish in finite time; the engine still
/// checks every size.
///
/// A source reports what produced no CRL with a [`CrlSourceError`] of one of
/// four kinds ([`CrlSourceErrorKind`]): per URL inside a [`CrlResponse`], or
/// for the whole request as `Err`. `Denied`, `Failed` and `Unknown` mean only
/// that nothing came from there: the engine records it and goes on. `Abort`,
/// anywhere, means the source can do no more work; the engine asks nothing
/// further and verifies with what it has. See `docs/crl-retrieval.md`.
pub trait CrlSource {
    fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError>;
}

/// What the engine needs CRLs for: one selected certificate.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct CrlRequest<'a> {
    /// The certificate, DER.
    pub certificate: &'a [u8],
    /// Its issuer Name, DER as encoded in the certificate: the key a store of
    /// CRLs by issuer looks up.
    pub issuer: &'a [u8],
    /// Its supported cRLDistributionPoints URIs, in listed order, without
    /// those already asked about in this verification. A hint: a source may
    /// use them, ignore them, or find CRLs elsewhere.
    pub distribution_points: &'a [String],
    /// The most bytes the whole response may have.
    pub max_bytes: usize,
}
impl<'a> CrlRequest<'a> {
    /// For sources that delegate to another source.
    pub fn new(
        certificate: &'a [u8],
        issuer: &'a [u8],
        distribution_points: &'a [String],
        max_bytes: usize,
    ) -> Self {
        Self {
            certificate,
            issuer,
            distribution_points,
            max_bytes,
        }
    }
}

/// CRLs a source found for a request, and what produced nothing.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct CrlResponse {
    pub crls: Vec<SourcedCrl>,
    /// Per-URL problems; the engine records each. An `Abort` here stops
    /// retrieval like an `Err` of that kind.
    pub failures: Vec<CrlSourceError>,
}
impl CrlResponse {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_crl(mut self, crl: SourcedCrl) -> Self {
        self.crls.push(crl);
        self
    }
    pub fn with_failure(mut self, failure: CrlSourceError) -> Self {
        self.failures.push(failure);
        self
    }
}

/// One response body: DER or PEM, possibly several CRLs.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct SourcedCrl {
    pub bytes: Vec<u8>,
    /// Where it was obtained, if from a URL. Provenance only.
    pub url: Option<String>,
    /// Where it actually came from, when a redirect changed `url`.
    pub final_url: Option<String>,
}
impl SourcedCrl {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            url: None,
            final_url: None,
        }
    }
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }
    pub fn with_final_url(mut self, final_url: impl Into<String>) -> Self {
        self.final_url = Some(final_url.into());
        self
    }
}

/// Why something a [`CrlSource`] tried produced no CRL: one of the
/// restricted [`CrlSourceErrorKind`]s, a message, the URL when there is one,
/// and optional details, all reported in the failure entry.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct CrlSourceError {
    pub kind: CrlSourceErrorKind,
    pub message: String,
    pub url: Option<String>,
    /// Optional structured context, reported with the failure.
    pub details: std::collections::BTreeMap<String, serde_json::Value>,
}
impl CrlSourceError {
    pub fn new(kind: CrlSourceErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            url: None,
            details: Default::default(),
        }
    }
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = Some(url.into());
        self
    }
    pub fn detail(mut self, key: impl Into<String>, value: impl serde::Serialize) -> Self {
        self.details.insert(
            key.into(),
            serde_json::to_value(value).unwrap_or(serde_json::Value::Null),
        );
        self
    }
    /// The verification error this failure is reported as.
    fn into_error(self) -> VerificationError {
        let mut error = error(self.kind.code(), self.message);
        error.details.extend(self.details);
        error
    }
}

/// Builds a [`CrlResponse`] for a source that works URL by URL: calls `fetch`
/// for each of the request's distribution points in order, with the bytes
/// still allowed (at most [`MAX_CRL_BYTES`] each), and stops at the first
/// `Abort`. Each answer becomes a [`SourcedCrl`] or a failure with its URL.
pub fn fetch_each(
    request: &CrlRequest<'_>,
    mut fetch: impl FnMut(&str, usize) -> Result<SourcedCrl, CrlSourceError>,
) -> CrlResponse {
    let mut response = CrlResponse::new();
    let mut remaining = request.max_bytes;
    for url in request.distribution_points {
        if remaining == 0 {
            response.failures.push(
                CrlSourceError::new(
                    CrlSourceErrorKind::Failed,
                    "the byte allowance for this request is spent",
                )
                .with_url(url.clone()),
            );
            continue;
        }
        match fetch(url, remaining.min(MAX_CRL_BYTES)) {
            Ok(mut crl) => {
                remaining = remaining.saturating_sub(crl.bytes.len());
                crl.url.get_or_insert_with(|| url.clone());
                response.crls.push(crl);
            }
            Err(mut e) => {
                e.url.get_or_insert_with(|| url.clone());
                let abort = e.kind == CrlSourceErrorKind::Abort;
                response.failures.push(e);
                if abort {
                    break;
                }
            }
        }
    }
    response
}

/// A dedup key for a URI: its parsed, normalized form when it parses.
fn url_key(raw: &str) -> String {
    url::Url::parse(raw).map_or_else(|_| raw.to_owned(), |u| u.to_string())
}

/// Whether a URI is fit to pass to a source and record: no control
/// characters or whitespace, and no user name or password. This is input
/// hygiene, not transport policy.
fn hygienic_url(raw: &str) -> bool {
    !raw.chars().any(|c| c.is_control() || c.is_whitespace())
        && url::Url::parse(raw).map_or(true, |u| u.username().is_empty() && u.password().is_none())
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

/// Verify with required revocation against the supplied CRLs; while the
/// result is `revocation_unknown`, ask the source about exactly the
/// certificates the verifier reports without a usable CRL, and verify again.
/// A good result or any other failure is final. Whether a CRL applies is
/// decided only by verification. See `docs/crl-retrieval.md`. The passes share
/// one SEC-02 work budget. The input store is never modified.
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
    /// URIs already passed to the source in this verification (by
    /// normalized key), with the failure reported for each, if any.
    asked: BTreeMap<String, Option<(VerificationError, Option<CrlSourceErrorKind>)>>,
    /// Requests made to the source, one per certificate; bounded by
    /// `MAX_SOURCE_REQUESTS`.
    requests: usize,
    /// The source reported `Abort`: nothing further is asked.
    aborted: bool,
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
            asked: BTreeMap::new(),
            requests: 0,
            aborted: false,
            budget,
        }
    }

    /// Record something that yielded no evidence. This never accepts
    /// anything: the next verification still requires evidence for every
    /// certificate. Only the engine's own limits end the run.
    fn skip(
        &mut self,
        certificate: &str,
        url: Option<&str>,
        e: VerificationError,
        kind: Option<CrlSourceErrorKind>,
    ) {
        let url = url.filter(|u| hygienic_url(u));
        let e = match url {
            Some(url) => e.detail("url", url),
            None => e,
        };
        self.budget.log.info(
            Stage::Revocation,
            format_args!("CRL evidence missing: {:?}", e.message),
        );
        self.record(certificate, url, &e, kind);
        if let Some(entry) = url.and_then(|url| self.asked.get_mut(&url_key(url))) {
            *entry = Some((e, kind));
        }
    }

    /// One failure entry per certificate and URL. A failure without a URL is
    /// reached once per certificate (certificates are deduplicated), so each
    /// is listed.
    fn record(
        &mut self,
        certificate: &str,
        url: Option<&str>,
        e: &VerificationError,
        source_error: Option<CrlSourceErrorKind>,
    ) {
        if url.is_some()
            && self.report.failures.iter().any(|f| {
                f.certificate_sha256 == certificate
                    && f.url.as_deref().map(url_key) == url.map(url_key)
            })
        {
            return;
        }
        self.report.failures.push(CrlRetrievalFailure {
            problem: e.problem.clone(),
            certificate_sha256: certificate.into(),
            url: url.map(Into::into),
            code: e.code,
            stage: e.stage,
            message: e.message.clone(),
            details: e.details.clone(),
            causes: e.causes.clone(),
            source_error,
        });
    }

    fn source_failure(&mut self, certificate: &str, e: CrlSourceError) {
        let kind = e.kind;
        let url = e.url.clone();
        self.skip(certificate, url.as_deref(), e.into_error(), Some(kind));
        if kind == CrlSourceErrorKind::Abort && !self.aborted {
            self.aborted = true;
            self.budget.log.info(
                Stage::Revocation,
                format_args!("CRL source aborted retrieval"),
            );
        }
    }

    /// Ask the source for CRLs for one certificate. Its listed URIs are read
    /// here, never fetched: unsupported points and malformed URIs are
    /// recorded, URIs already asked about in this verification are left out
    /// (a failure reported for one is recorded for this certificate too), and
    /// the rest go to the source as a hint. Returns whether a new CRL was
    /// added. The engine's own limits end the run.
    fn request(
        &mut self,
        sha256: &str,
        der: &[u8],
        cert: &Certificate,
        source: &mut dyn CrlSource,
    ) -> Result<bool, VerificationError> {
        if self.aborted {
            return Ok(false);
        }
        // The issuer name is the key for a source that stores CRLs by
        // issuer; a certificate without a readable one is not asked about.
        let decoded_issuer;
        let issuer = match crate::der::tbs_issuer(der, 0xa0, 2) {
            Some(issuer) => issuer,
            None => match ::der::Encode::to_der(&cert.tbs_certificate.issuer) {
                Ok(encoded) => {
                    decoded_issuer = encoded;
                    &decoded_issuer
                }
                Err(_) => {
                    let e = error(
                        ErrorCode::InvalidCertificate,
                        "certificate issuer name cannot be read for a CRL request",
                    );
                    self.skip(sha256, None, e, None);
                    return Ok(false);
                }
            },
        };
        let listed = match listed_points(cert, false) {
            Ok(listed) => listed,
            // The engine's own per-certificate URL limits end the run.
            Err(e) if e.code == ErrorCode::ResourceLimitExceeded => return Err(e),
            // A malformed extension: webpki skips it offline, so it is no
            // evidence here, not a rejection.
            Err(e) => {
                self.skip(sha256, None, e, None);
                Vec::new()
            }
        };
        let mut points = Vec::new();
        for listed in listed {
            let raw = match listed {
                Ok(raw) => raw,
                Err(e) => {
                    self.skip(sha256, None, e, None);
                    continue;
                }
            };
            if !hygienic_url(&raw) {
                let e = error(
                    ErrorCode::CrlFetchDenied,
                    "distribution point URI has control characters, whitespace or credentials",
                );
                self.skip(sha256, None, e, None);
                continue;
            }
            match self.asked.get(&url_key(&raw)) {
                Some(Some((e, kind))) => {
                    let (e, kind) = (e.clone(), *kind);
                    self.record(sha256, Some(&raw), &e, kind);
                }
                Some(None) => {}
                None => {
                    // The engine bounds the URIs it passes to sources in one
                    // verification, whatever each source does with them.
                    if self.asked.len() >= MAX_SOURCE_REQUESTS {
                        return Err(limit("crl_urls", MAX_SOURCE_REQUESTS, self.asked.len(), 1));
                    }
                    self.asked.insert(url_key(&raw), None);
                    points.push(raw);
                }
            }
        }
        if self.requests >= MAX_SOURCE_REQUESTS {
            return Err(limit("crl_requests", MAX_SOURCE_REQUESTS, self.requests, 1));
        }
        // The retained-CRL limit is enforced as CRLs are loaded, so a request
        // that adds nothing new does not hit it.
        let used = self.base.retrieval_bytes() + self.downloaded;
        let max_bytes = MAX_TOTAL_BYTES.saturating_sub(used);
        if max_bytes == 0 {
            return Err(limit("retrieval_trust_bytes", MAX_TOTAL_BYTES, used, 1));
        }
        let request = CrlRequest::new(der, issuer, &points, max_bytes);
        self.requests += 1;
        self.budget.log.info(
            Stage::Revocation,
            format_args!(
                "asking the CRL source for certificate {sha256}, listed points {points:?}"
            ),
        );
        let response = match source.crls(&request) {
            Ok(response) => response,
            Err(e) => {
                // The whole request failed: every point it carried yielded
                // nothing, for this certificate and any later one listing it.
                // The URL the source named keeps its own entry; every other
                // point of the request is recorded with the same error.
                let named = e.url.as_deref().map(url_key);
                for point in points.iter().filter(|p| named != Some(url_key(p))) {
                    self.source_failure(sha256, e.clone().with_url(point.clone()));
                }
                if points.is_empty() || e.url.is_some() {
                    self.source_failure(sha256, e);
                }
                return Ok(false);
            }
        };
        // Every body and failure becomes a report entry: the engine bounds
        // how many one response may carry.
        let entries = response.crls.len().saturating_add(response.failures.len());
        if entries > MAX_RESPONSE_ENTRIES {
            return Err(limit(
                "crl_response_entries",
                MAX_RESPONSE_ENTRIES,
                0,
                entries,
            ));
        }
        // A point is answered by a CRL or failure naming it, compared as
        // URLs (a source may report the normalized form).
        let answers = |url: &Option<String>, point: &str| {
            url.as_deref().is_some_and(|u| url_key(u) == url_key(point))
        };
        let unanswered: Vec<String> = points
            .iter()
            .filter(|point| {
                !response.crls.iter().any(|c| answers(&c.url, point))
                    && !response.failures.iter().any(|f| answers(&f.url, point))
            })
            .cloned()
            .collect();
        for failure in response.failures {
            self.source_failure(sha256, failure);
        }
        // A point the source neither answered nor reported is recorded, so
        // that no listed point disappears from the report; after an abort the
        // rest were never tried, and the abort explains them. A source that
        // also answered by issuer still passed over these points.
        if !self.aborted {
            for point in &unanswered {
                let e = error(
                    ErrorCode::CrlFetchFailed,
                    "the CRL source returned nothing for this point",
                );
                self.skip(sha256, Some(point), e, None);
            }
        }
        let mut added = false;
        let mut total = 0usize;
        for crl in response.crls {
            added |= self.load(sha256, crl, &mut total, max_bytes)?;
        }
        Ok(added)
    }

    /// Check, account for and load one returned body. A body over its size
    /// caps, or that is not a CRL, is no evidence and is not loaded.
    fn load(
        &mut self,
        sha256: &str,
        crl: SourcedCrl,
        total: &mut usize,
        max_bytes: usize,
    ) -> Result<bool, VerificationError> {
        let url = crl.url.filter(|u| hygienic_url(u));
        let final_url = crl.final_url.filter(|u| hygienic_url(u));
        let len = crl.bytes.len();
        self.budget.log.debug(
            Stage::Revocation,
            format_args!("CRL source returned {len} bytes from {url:?}; not yet authenticated"),
        );
        // A body over its caps is not counted against the bodies after it.
        if len > MAX_CRL_BYTES || total.saturating_add(len) > max_bytes {
            let cap = MAX_CRL_BYTES.min(max_bytes);
            let e = limit("crl_response_bytes", cap, 0, len);
            self.skip(sha256, url.as_deref(), e, None);
            return Ok(false);
        }
        *total += len;
        for _ in 0..8 {
            self.budget
                .decoded_bytes
                .charge(len)
                .map_err(crl_internal)?;
        }
        self.budget.hash_bytes.charge(len).map_err(crl_internal)?;
        self.downloaded += len;
        self.report.artifacts.push(CrlRetrievalArtifact {
            certificate_sha256: Some(sha256.into()),
            final_url: final_url.or_else(|| url.clone()),
            url: url.clone(),
            sha256: hex(&crate::crypto::Hash::Sha256.digest(&crl.bytes)),
            bytes: len,
        });
        let prior = self.store.retrieval_crl_count();
        if let Err(e) = self.store.add_crl(&crl.bytes) {
            let e = error(
                ErrorCode::InvalidCrl,
                format!("decoding retrieved CRL: {e:#}"),
            );
            self.skip(sha256, url.as_deref(), e, None);
            return Ok(false);
        }
        // A PEM response may contain multiple distinct CRLs. Bound the
        // retained store after deduplication, before verification.
        let loaded = self.store.retrieval_crl_count();
        if loaded > 64 {
            return Err(limit("retrieval_crl_artifacts", 64, prior, loaded - prior));
        }
        // A body identical to a loaded CRL adds nothing to verify.
        Ok(loaded > prior)
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
        // The verifier decides first, with the supplied CRLs: a good result
        // or any failure but unknown status is final, and an unknown status
        // names the certificates that lacked a usable CRL.
        let mut result = verify_with(bytes, options, &state.store, format, budget);
        let mut selected: Option<Vec<(String, Vec<u8>, Certificate)>> = None;
        let mut asked = BTreeSet::new();
        loop {
            let unknown = match &result {
                Err(e) if e.code == ErrorCode::RevocationUnknown => e,
                _ => break,
            };
            if state.aborted {
                break;
            }
            // Ask about exactly the certificates the verifier reports without
            // a usable CRL, as OpenSSL and Bouncy Castle look up CRLs for the
            // certificate being checked. The report carries each certificate,
            // whichever candidate path it was on. Without that list (an
            // unknown status from webpki itself, not from rssig's per-
            // certificate evaluation), the selected certificates are found
            // once by verifying without revocation, where integrity and
            // trust failures end the run.
            let targets = match uncovered(unknown) {
                // webpki rejected the path rssig's own evaluation accepted:
                // every certificate on it had a usable CRL, so no source can
                // help, and asking about covered certificates is refused.
                Uncovered::Final => break,
                Uncovered::Listed(reports) => {
                    let mut targets = Vec::new();
                    for report in &reports {
                        budget
                            .decoded_bytes
                            .charge(report.der_hex.len())
                            .map_err(|e| {
                                VerificationError::from_internal(
                                    e,
                                    ErrorCode::InvalidCertificate,
                                    Stage::Certificate,
                                )
                            })?;
                        targets.push(decode_report(report)?);
                    }
                    targets
                }
                Uncovered::Unlisted => match &selected {
                    Some(selected) => selected.clone(),
                    None => selected
                        .insert(selected_certificates(bytes, options, format, budget)?)
                        .clone(),
                },
            };
            let mut added = false;
            let mut any = false;
            for (sha256, der, cert) in &targets {
                if !asked.insert(sha256.clone()) {
                    continue;
                }
                any = true;
                added |= state.request(sha256, der, cert, source)?;
                if state.aborted {
                    break;
                }
            }
            if !any || !added {
                break;
            }
            result = verify_with(bytes, options, &state.store, format, budget);
        }
        // Evidence is still missing because the source stopped: say so, so
        // that "the source gave up" is distinct from "no CRL was available".
        match result {
            Err(e) if state.aborted && e.code == ErrorCode::RevocationUnknown => {
                let mut aborted = error(
                    ErrorCode::CrlFetchAborted,
                    "the CRL source stopped retrieval before revocation status was known",
                );
                // Keep the verifier's structured details, such as the
                // certificates still without a CRL.
                aborted.details.extend(e.details);
                Err(aborted.detail("revocation_unknown", e.message))
            }
            result => result,
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

/// What an unknown revocation status tells retrieval to ask about.
enum Uncovered {
    /// The certificates the verifier reports without a usable CRL.
    Listed(Vec<CertificateReport>),
    /// No source can help: the status is final.
    Final,
    /// Not named: the selected certificates, found by verifying without
    /// revocation.
    Unlisted,
}

fn uncovered(unknown: &VerificationError) -> Uncovered {
    if unknown.details.get("reason").and_then(|r| r.as_str()) == Some("confirmation") {
        return Uncovered::Final;
    }
    match unknown
        .details
        .get("certificates_without_crl")
        .and_then(|v| serde_json::from_value::<Vec<CertificateReport>>(v.clone()).ok())
    {
        // An empty list names nothing to ask about.
        Some(reports) if !reports.is_empty() => Uncovered::Listed(reports),
        _ => Uncovered::Unlisted,
    }
}

/// A reported certificate's SHA-256, DER and decoded form.
fn decode_report(
    report: &CertificateReport,
) -> Result<(String, Vec<u8>, Certificate), VerificationError> {
    if !report.der_hex.len().is_multiple_of(2) {
        return Err(error(
            ErrorCode::InvalidCertificate,
            "malformed certificate report",
        ));
    }
    let der = report
        .der_hex
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        })
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(|| {
            error(
                ErrorCode::InvalidCertificate,
                "malformed certificate report",
            )
        })?;
    let cert = Certificate::from_der(&der)
        .map_err(|e| error(ErrorCode::InvalidCertificate, e.to_string()))?;
    Ok((report.sha256.clone(), der, cert))
}

/// The selected non-anchor certificates of every signature, timestamp and
/// bundle child, each once, from a verification without revocation.
fn selected_certificates(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
    format: crate::format::Format,
    budget: &Budget,
) -> Result<Vec<(String, Vec<u8>, Certificate)>, VerificationError> {
    let internal =
        |e| VerificationError::from_internal(e, ErrorCode::InvalidCertificate, Stage::Certificate);
    budget.log.debug(
        Stage::Revocation,
        format_args!("CRL retrieval: verifying without revocation to find the certificates"),
    );
    let preliminary = VerifyOptions {
        check_revocation: false,
        ..*options
    };
    let pending = verify_inner_budget(bytes, &preliminary, format, budget).map_err(internal)?;
    let mut reports = Vec::new();
    collect(&pending, &mut reports);
    let mut seen = BTreeSet::new();
    let mut selected = Vec::new();
    for report in reports {
        if !seen.insert(report.sha256.clone()) {
            continue;
        }
        budget
            .decoded_bytes
            .charge(report.der_hex.len())
            .map_err(internal)?;
        selected.push(decode_report(report)?);
    }
    Ok(selected)
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
        fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
            Ok(fetch_each(request, |_url, _max_bytes| {
                panic!("unexpected provider call")
            }))
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
        // Transport policy is the source's: the engine asks, and the built-in
        // source refuses a private destination before any network access.
        let error = verify_with_crl_source(
            include_bytes!("../tests/fixtures/bad-crl-private-url.exe"),
            None,
            &options,
            &mut HttpCrlSource::new(),
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::RevocationUnknown);
        let failure = &error.details["crl_retrieval"]["failures"][0];
        assert_eq!(failure["code"], "crl_fetch_denied");
        assert_eq!(failure["source_error"], "denied");
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
            fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(fetch_each(request, |_url, cap| {
                    Ok(SourcedCrl::new(vec![0; cap + 1]))
                }))
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
        let uris: Vec<_> = (0..count)
            .map(|i| format!("http://crl.example.invalid/{tag}-{i}.crl"))
            .collect();
        signer_with_uris(&uris)
    }
    /// The good-crl-discovery signer listing exactly `uris`, one per point.
    fn signer_with_uris(uris: &[String]) -> Certificate {
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
        for uri in uris {
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
    /// Ask the source about `cert` through the engine's per-certificate path.
    fn ask(
        state: &mut Retrieval<'_, '_, '_>,
        sha256: &str,
        cert: &Certificate,
        source: &mut dyn CrlSource,
    ) -> Result<bool, VerificationError> {
        use ::der::Encode;
        let der = cert.to_der().unwrap();
        state.request(sha256, &der, cert, source)
    }
    /// Records what the source was asked, and answers every listed URI with
    /// the next kind in turn.
    struct Kinds {
        kinds: Vec<CrlSourceErrorKind>,
        calls: usize,
        urls: Vec<String>,
        issuers: Vec<Vec<u8>>,
    }
    impl Kinds {
        fn new(kinds: Vec<CrlSourceErrorKind>) -> Self {
            Self {
                kinds,
                calls: 0,
                urls: Vec::new(),
                issuers: Vec::new(),
            }
        }
    }
    impl CrlSource for Kinds {
        fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
            self.calls += 1;
            self.issuers.push(request.issuer.to_vec());
            Ok(fetch_each(request, |url, _| {
                self.urls.push(url.into());
                let kind = self.kinds[(self.urls.len() - 1) % self.kinds.len()];
                Err(CrlSourceError::new(kind, "no CRL").detail("hint", "test"))
            }))
        }
    }
    #[test]
    fn the_source_is_asked_once_per_certificate_up_to_the_cap() {
        use CrlSourceErrorKind::*;
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let mut source = Kinds::new(vec![Failed]);
        // Every certificate lists the same URL: one URI, many requests.
        let shared = || signer_with_points("shared", 1);
        for i in 0..MAX_SOURCE_REQUESTS {
            assert!(!ask(&mut state, &format!("c{i}"), &shared(), &mut source).unwrap());
        }
        let error = ask(&mut state, "last", &shared(), &mut source).unwrap_err();
        assert_eq!(error.code, ErrorCode::ResourceLimitExceeded);
        assert_eq!(error.details["resource"], "crl_requests");
        assert_eq!(source.calls, MAX_SOURCE_REQUESTS);
        // Distinct URIs passed to sources are capped too.
        let mut state = Retrieval::new(&store, &budget);
        let mut source = Kinds::new(vec![Failed]);
        let error = (0..)
            .map(|i| {
                ask(
                    &mut state,
                    &format!("u{i}"),
                    &signer_with_points(&format!("u{i}"), 16),
                    &mut source,
                )
            })
            .find_map(Result::err)
            .unwrap();
        assert_eq!(error.details["resource"], "crl_urls");
        assert_eq!(source.urls.len(), MAX_SOURCE_REQUESTS);
    }
    #[test]
    fn the_request_carries_the_certificate_issuer_and_every_listed_uri() {
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let uris = [
            "https://crl.example.invalid/a.crl".to_string(),
            "ldap://crl.example.invalid/cn=a".to_string(),
            "http://127.0.0.1/a.crl".to_string(),
        ];
        let cert = signer_with_uris(&uris);
        let mut source = Kinds::new(vec![CrlSourceErrorKind::Denied]);
        ask(&mut state, "s", &cert, &mut source).unwrap();
        // No transport rule in the engine: every listed URI, of any scheme,
        // reaches the source, which alone decides what it may request.
        assert_eq!(source.urls, uris);
        use ::der::Encode;
        assert_eq!(
            source.issuers,
            [cert.tbs_certificate.issuer.to_der().unwrap()]
        );
        // A refusal costs the engine one request for the certificate, not
        // one per URI.
        assert_eq!(state.requests, 1);
    }
    #[test]
    fn uris_are_deduplicated_per_verification_and_screened_for_hygiene() {
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let mut source = Kinds::new(vec![CrlSourceErrorKind::Failed]);
        let spellings = [
            "HTTP://CRL.Example.invalid/a.crl".to_string(),
            "http://crl.example.invalid:80/a.crl".to_string(),
            "http://user:secret@crl.example.invalid/b.crl".to_string(),
            "http://crl.example.invalid/c\u{7}.crl".to_string(),
        ];
        ask(&mut state, "a", &signer_with_uris(&spellings), &mut source).unwrap();
        // Two spellings of one URL are asked once; credentials and control
        // characters never reach the source or the report.
        assert_eq!(source.urls, ["HTTP://CRL.Example.invalid/a.crl"]);
        // A second certificate listing the same URL is not asked again, and
        // the earlier failure is recorded for it too.
        ask(
            &mut state,
            "b",
            &signer_with_uris(&["http://crl.example.invalid/a.crl".into()]),
            &mut source,
        )
        .unwrap();
        assert_eq!(source.urls.len(), 1);
        let entries: Vec<_> = state
            .report
            .failures
            .iter()
            .map(|f| (f.certificate_sha256.as_str(), f.url.is_some(), f.code))
            .collect();
        assert_eq!(
            entries,
            [
                ("a", false, ErrorCode::CrlFetchDenied),
                ("a", false, ErrorCode::CrlFetchDenied),
                ("a", true, ErrorCode::CrlFetchFailed),
                ("b", true, ErrorCode::CrlFetchFailed),
            ]
        );
        assert!(
            serde_json::to_string(&state.report)
                .unwrap()
                .find("secret")
                .is_none()
        );
    }
    #[test]
    fn an_oversized_body_does_not_count_against_the_bodies_after_it() {
        struct Two;
        impl CrlSource for Two {
            fn crls(&mut self, _: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(CrlResponse::new()
                    .with_crl(SourcedCrl::new(vec![0; MAX_CRL_BYTES + 1]))
                    .with_crl(SourcedCrl::new(
                        include_bytes!("../tests/fixtures/good.crl").to_vec(),
                    )))
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        assert!(ask(&mut state, "a", &signer_with_points("a", 1), &mut Two).unwrap());
        // Only the oversized body is rejected; the listed point it passed
        // over is reported separately.
        let resources: Vec<_> = state
            .report
            .failures
            .iter()
            .filter_map(|f| f.details.get("resource"))
            .collect();
        assert_eq!(resources, ["crl_response_bytes"]);
    }
    #[test]
    fn no_listed_point_disappears_from_the_report() {
        // A source that ignores the points, and one whose whole-request
        // error names only one of them: every point is still recorded.
        struct Ignores;
        impl CrlSource for Ignores {
            fn crls(&mut self, _: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(CrlResponse::new())
            }
        }
        struct NamesOne;
        impl CrlSource for NamesOne {
            fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Err(CrlSourceError::new(CrlSourceErrorKind::Failed, "down")
                    .with_url(request.distribution_points[0].clone()))
            }
        }
        let store = store();
        let budget = Budget::default();
        for source in [&mut Ignores as &mut dyn CrlSource, &mut NamesOne] {
            let mut state = Retrieval::new(&store, &budget);
            ask(&mut state, "a", &signer_with_points("a", 2), source).unwrap();
            let urls: Vec<_> = state
                .report
                .failures
                .iter()
                .filter_map(|f| f.url.clone())
                .collect();
            assert_eq!(urls.len(), 2, "{urls:?}");
        }
    }
    #[test]
    fn a_point_answered_under_its_normalized_url_is_answered() {
        struct Normalizes;
        impl CrlSource for Normalizes {
            fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                let mut response = CrlResponse::new();
                for point in request.distribution_points {
                    let url = point.replace("crl.example.invalid", "CRL.Example.Invalid");
                    response = response.with_failure(
                        CrlSourceError::new(CrlSourceErrorKind::Failed, "down").with_url(url),
                    );
                }
                Ok(response)
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        ask(
            &mut state,
            "a",
            &signer_with_points("a", 2),
            &mut Normalizes,
        )
        .unwrap();
        // One entry per point: the source's own, not also "returned nothing".
        assert_eq!(
            state.report.failures.len(),
            2,
            "{:?}",
            state.report.failures
        );
        assert!(state.report.failures.iter().all(|f| f.message == "down"));
    }
    #[test]
    fn points_passed_over_by_an_issuer_answer_are_recorded_once() {
        struct ByIssuer(Vec<usize>);
        impl CrlSource for ByIssuer {
            fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                self.0.push(request.distribution_points.len());
                Ok(CrlResponse::new().with_crl(SourcedCrl::new(b"not a CRL".to_vec())))
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let mut source = ByIssuer(Vec::new());
        let cert = signer_with_points("a", 2);
        ask(&mut state, "a", &cert, &mut source).unwrap();
        ask(&mut state, "b", &cert, &mut source).unwrap();
        // Each URI goes to the source once per verification; both
        // certificates report the points the answer passed over.
        assert_eq!(source.0, [2, 0]);
        for certificate in ["a", "b"] {
            let urls = state
                .report
                .failures
                .iter()
                .filter(|f| f.certificate_sha256 == certificate && f.url.is_some())
                .count();
            assert_eq!(urls, 2, "{certificate}: {:?}", state.report.failures);
        }
    }
    #[test]
    fn a_response_with_too_many_entries_ends_the_run() {
        // Each body and failure becomes a report entry: the engine bounds how
        // many one response may carry, whatever the source does.
        struct Floods(usize, usize);
        impl CrlSource for Floods {
            fn crls(&mut self, _: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                let mut response = CrlResponse::new();
                for _ in 0..self.0 {
                    response = response.with_crl(SourcedCrl::new(Vec::new()));
                }
                for _ in 0..self.1 {
                    response = response
                        .with_failure(CrlSourceError::new(CrlSourceErrorKind::Failed, "down"));
                }
                Ok(response)
            }
        }
        let store = store();
        for (bodies, failures) in [
            (MAX_RESPONSE_ENTRIES + 1, 0),
            (0, MAX_RESPONSE_ENTRIES + 1),
            (MAX_RESPONSE_ENTRIES, 1),
        ] {
            let budget = Budget::default();
            let mut state = Retrieval::new(&store, &budget);
            let e = ask(
                &mut state,
                "a",
                &signer_with_points("a", 1),
                &mut Floods(bodies, failures),
            )
            .unwrap_err();
            assert_eq!(e.code, ErrorCode::ResourceLimitExceeded);
            assert_eq!(e.details["resource"], "crl_response_entries");
            assert!(state.report.artifacts.is_empty());
        }
        // At the limit, every entry is taken.
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        ask(
            &mut state,
            "a",
            &signer_with_points("a", 1),
            &mut Floods(MAX_RESPONSE_ENTRIES, 0),
        )
        .unwrap();
        assert_eq!(state.report.artifacts.len(), MAX_RESPONSE_ENTRIES);
    }
    #[test]
    fn a_confirmation_disagreement_is_final_for_retrieval() {
        let unknown = || error(ErrorCode::RevocationUnknown, "unknown");
        // webpki rejected the path every certificate of which had a CRL.
        assert!(matches!(
            uncovered(&unknown().detail("reason", "confirmation")),
            Uncovered::Final
        ));
        assert!(matches!(uncovered(&unknown()), Uncovered::Unlisted));
        assert!(matches!(
            uncovered(
                &unknown().detail("certificates_without_crl", Vec::<CertificateReport>::new())
            ),
            Uncovered::Unlisted
        ));
    }
    #[test]
    fn denied_failed_and_unknown_are_recorded_and_retrieval_goes_on() {
        use CrlSourceErrorKind::*;
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let mut source = Kinds::new(vec![Denied, Failed, Unknown]);
        assert!(!ask(&mut state, "k", &signer_with_points("k", 3), &mut source).unwrap());
        assert_eq!(source.urls.len(), 3);
        assert!(!state.aborted);
        let seen: Vec<_> = state
            .report
            .failures
            .iter()
            .map(|f| (f.code, f.source_error, f.details["hint"].clone()))
            .collect();
        assert_eq!(
            seen,
            [
                (ErrorCode::CrlFetchDenied, Some(Denied), "test".into()),
                (ErrorCode::CrlFetchFailed, Some(Failed), "test".into()),
                (ErrorCode::CrlFetchFailed, Some(Unknown), "test".into()),
            ]
        );
    }
    #[test]
    fn abort_stops_every_further_request() {
        use CrlSourceErrorKind::*;
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let mut source = Kinds::new(vec![Failed, Abort]);
        assert!(!ask(&mut state, "a", &signer_with_points("a", 4), &mut source).unwrap());
        assert!(!ask(&mut state, "b", &signer_with_points("b", 4), &mut source).unwrap());
        assert_eq!(source.urls.len(), 2, "nothing is fetched after Abort");
        assert_eq!(source.calls, 1, "nothing is asked after Abort");
        assert!(state.aborted);
        assert_eq!(state.report.failures.len(), 2);
        assert_eq!(state.report.failures[1].code, ErrorCode::CrlFetchAborted);
    }
    #[test]
    fn the_result_tells_an_aborted_source_from_missing_evidence() {
        use CrlSourceErrorKind::*;
        let store = store();
        let options = VerifyOptions::trusted(&store, 1800000000);
        let input = include_bytes!("../tests/fixtures/good-crl-discovery.exe");
        for (kind, code) in [
            (Denied, ErrorCode::RevocationUnknown),
            (Failed, ErrorCode::RevocationUnknown),
            (Unknown, ErrorCode::RevocationUnknown),
            (Abort, ErrorCode::CrlFetchAborted),
        ] {
            let error = verify_with_crl_source(input, None, &options, &mut Kinds::new(vec![kind]))
                .unwrap_err();
            assert_eq!(error.code, code, "{kind:?}");
            let failure = &error.details["crl_retrieval"]["failures"][0];
            assert_eq!(failure["source_error"], serde_json::to_value(kind).unwrap());
            assert_eq!(failure["url"], "http://crl.example.invalid/test.crl");
        }
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
