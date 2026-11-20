//! Opt-in CRL discovery and injected artifact retrieval. No fetched artifact is a trust anchor.
mod http;
pub use crate::domain::CrlSourceErrorKind;
use crate::{
    TrustStore,
    domain::*,
    verify::{VerifyOptions, budget::Budget, verify_inner_budget},
};
use ::der::Decode;
pub use http::{HttpCrlSource, check_public_http_url};
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
/// certificate (except one with no new point whose issuer name, authority key
/// and CA role were already asked about: CRLs are per issuer key and role), like OpenSSL's `get_crl` (by certificate) or `lookup_crls` (by
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
    /// Called once at the start of each verification that may ask this
    /// source, before any request. A source that keeps allowances for one
    /// verification (requests, bytes, a deadline) starts them afresh here, so
    /// that reusing it across files or calls never charges one to the next.
    /// [`HttpCrlSource`] does; the default does nothing. A source that
    /// delegates to another (a cache in front of [`HttpCrlSource`], say) must
    /// forward this call, or the inner source's allowances are never renewed.
    fn begin_verification(&mut self) {}
    fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError>;
}

/// What the engine needs CRLs for: one selected certificate.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct CrlRequest<'a> {
    /// The certificate, DER as rssig re-encodes it after decoding. That is
    /// the original encoding for DER-conformant input; a name whose SET OF is
    /// out of DER order is sorted (SEC-22).
    pub certificate: &'a [u8],
    /// Its issuer Name, DER, read from `certificate`: the key a store of CRLs
    /// by issuer looks up.
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
    /// The verification error this failure is reported as. `details.url` is
    /// the engine's to set, from [`Self::with_url`] and only when that URL
    /// passes its screening, so a `url` detail of the source's is dropped.
    /// The message and the other details are reported as given: a source
    /// must not put a URL in them.
    fn into_error(self) -> VerificationError {
        let mut error = error(self.kind.code(), self.message);
        error.details.extend(self.details);
        error.details.remove("url");
        error
    }
}

/// Builds a [`CrlResponse`] for a source that works URL by URL: calls `fetch`
/// for each of the request's distribution points in order, with the bytes
/// still allowed (at most [`MAX_CRL_BYTES`] each), and stops at the first
/// `Abort` or once the request's byte allowance is spent; the points left are
/// not answered, and the engine records them as not tried. Each answer
/// becomes a [`SourcedCrl`] or a failure with its URL.
pub fn fetch_each(
    request: &CrlRequest<'_>,
    mut fetch: impl FnMut(&str, usize) -> Result<SourcedCrl, CrlSourceError>,
) -> CrlResponse {
    let mut response = CrlResponse::new();
    let mut remaining = request.max_bytes;
    let mut oversized = false;
    for url in request.distribution_points {
        // The allowance is spent: the rest are not tried, and the engine
        // records them as such.
        if remaining == 0 {
            break;
        }
        let allowed = remaining.min(MAX_CRL_BYTES);
        match fetch(url, allowed) {
            // A body over what was allowed is passed on for the engine to
            // reject and report, but does not spend the allowance: the next
            // point is still tried.
            // Only the first such body is kept; later ones are reported
            // without their bytes, so a response cannot pile them up.
            Ok(mut crl) if crl.bytes.len() > allowed => {
                if oversized {
                    response.failures.push(
                        CrlSourceError::new(
                            CrlSourceErrorKind::Failed,
                            "the response is larger than allowed",
                        )
                        .with_url(url.clone())
                        .detail("resource", "crl_response_bytes")
                        .detail("limit", allowed)
                        .detail("requested", crl.bytes.len()),
                    );
                } else {
                    oversized = true;
                    crl.url.get_or_insert_with(|| url.clone());
                    response.crls.push(crl);
                }
            }
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
        // A URL that does not parse cannot be screened for credentials, so it
        // is withheld too: never passed on, logged or reported.
        && url::Url::parse(raw).is_ok_and(|u| u.username().is_empty() && u.password().is_none())
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
/// a non-URI name. A malformed extension is an error for the whole
/// certificate. With `strict`, the first unsupported point and the URL count
/// and length limits are errors too, as [`crl_distribution_points`] has always
/// reported them. Otherwise, as OpenSSL and Bouncy Castle never fail a chain
/// over one certificate's points, an over-long URI is one skipped point and
/// the URIs past the count limit are one recorded failure: the first ones
/// still go to the source.
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
    // Diagnostics kept for one certificate are bounded like its URIs: past
    // the bound they are counted, and one entry reports how many were left
    // out, so many unusable names cannot grow the report.
    let mut diagnostics = 0usize;
    let mut omitted = 0usize;
    let mut note = |listed: &mut Vec<_>, e: VerificationError| {
        if diagnostics < MAX_REQUESTS {
            diagnostics += 1;
            listed.push(Err(e));
        } else {
            omitted += 1;
        }
    };
    let mut urls = 0;
    let mut over_limit = false;
    'points: for point in points.0 {
        if point.reasons.is_some() || point.crl_issuer.is_some() {
            let e = error(
                ErrorCode::CrlFetchDenied,
                "partitioned or indirect CRL distribution points are unsupported",
            );
            if strict {
                return Err(e);
            }
            note(&mut listed, e);
            continue;
        }
        let Some(DistributionPointName::FullName(names)) = point.distribution_point else {
            let e = error(
                ErrorCode::CrlFetchDenied,
                "CRL distribution point requires a full URI name",
            );
            if strict {
                return Err(e);
            }
            note(&mut listed, e);
            continue;
        };
        for name in names {
            let GeneralName::UniformResourceIdentifier(uri) = name else {
                let e = error(
                    ErrorCode::CrlFetchDenied,
                    "non-URI CRL distribution point is unsupported",
                );
                if strict {
                    return Err(e);
                }
                note(&mut listed, e);
                continue;
            };
            if urls >= MAX_REQUESTS {
                let e = limit("crl_urls", MAX_REQUESTS, urls, 1);
                if strict {
                    return Err(e);
                }
                over_limit = true;
                break 'points;
            }
            if uri.as_str().len() > 2048 {
                let e = limit("crl_url_bytes", 2048, 0, uri.as_str().len());
                if strict {
                    return Err(e);
                }
                note(&mut listed, e);
                continue;
            }
            urls += 1;
            listed.push(Ok(uri.as_str().into()));
        }
    }
    // Always reported, whatever the diagnostics bound.
    if over_limit {
        listed.push(Err(limit("crl_urls", MAX_REQUESTS, urls, 1)));
    }
    if omitted > 0 {
        listed.push(Err(error(
            ErrorCode::CrlFetchDenied,
            "further unusable CRL distribution point names are not listed",
        )
        .detail("omitted", omitted)));
    }
    Ok(listed)
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
    /// What was already asked about in this verification, by issuer name
    /// (DER), authority key identifier and whether the certificate is a CA:
    /// an issuer's CRLs can differ by key and be split between CA and
    /// end-entity certificates.
    asked_issuers: BTreeSet<IssuerKey>,
    /// A source just answered by certificate with a new full CRL of the
    /// issuer: verification runs again before any further request, since
    /// only it can tell which certificates that CRL covers.
    reverify: bool,
    /// The source reported `Abort`: nothing further is asked.
    aborted: bool,
    /// The certificate whose request the source aborted.
    aborted_for: Option<String>,
    /// How many distinct normalized URIs were passed to sources in this
    /// verification; one passed again after an answer by certificate left it
    /// unused counts once. Bounded by `MAX_SOURCE_REQUESTS`.
    urls_passed: usize,
    /// The normalized URIs already counted in `urls_passed`: one offered
    /// again after an answer by certificate left it unused costs nothing.
    urls_counted: BTreeSet<String>,
    /// The normalized points the current request carries: only their
    /// recorded outcome may change while it is answered.
    in_flight: BTreeSet<String>,
    /// Per certificate, in request order, the listed points its source left
    /// unused when it answered by certificate: recorded only for a
    /// certificate the failed result still names (its status unsettled).
    unused_points: Vec<(String, Vec<String>)>,
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
            asked_issuers: BTreeSet::new(),
            reverify: false,
            aborted: false,
            aborted_for: None,
            urls_passed: 0,
            urls_counted: BTreeSet::new(),
            in_flight: BTreeSet::new(),
            unused_points: Vec::new(),
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
        // The point's outcome is kept under its normalized key even when the
        // URL as given is not recorded, so a later certificate listing the
        // point still reports it.
        let key = url.map(url_key);
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
        // Only a point of the current request takes this outcome: a source
        // naming another URL does not change what that URL yielded.
        if let Some(entry) = key
            .filter(|key| self.in_flight.contains(key))
            .and_then(|key| self.asked.get_mut(&key))
        {
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
            self.aborted_for = Some(certificate.into());
            self.budget.log.info(
                Stage::Revocation,
                format_args!("CRL source aborted retrieval"),
            );
        }
    }

    /// Records, for each certificate the final result still names (its
    /// source's answer by certificate did not settle its status), the listed
    /// points that answer left unused: with the failure a request for another
    /// certificate reported for the point, nothing if such a request was
    /// answered, and otherwise as not used. A certificate whose status
    /// was settled leaves no per-point failure.
    fn report_unused_points(&mut self, named: &[String]) {
        let held = core::mem::take(&mut self.unused_points);
        for (certificate, points) in held {
            if !named.contains(&certificate) {
                continue;
            }
            for point in points {
                match self.asked.get(&url_key(&point)).cloned() {
                    Some(Some((e, kind))) => self.record(&certificate, Some(&point), &e, kind),
                    Some(None) => {}
                    None => {
                        let e = error(
                            ErrorCode::CrlFetchFailed,
                            "not used: the CRL source answered for the certificate \
                             without using this point, and its answer did not settle the status",
                        );
                        self.record(&certificate, Some(&point), &e, None);
                    }
                }
            }
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
        self.in_flight.clear();
        let listed = match listed_points(cert, false) {
            Ok(listed) => listed,
            // A malformed extension: webpki skips it offline, so it is no
            // evidence here, not a rejection.
            Err(e) => {
                self.skip(sha256, None, e, None);
                Vec::new()
            }
        };
        let mut points = Vec::new();
        // URIs first counted by this request: given back if it is not made.
        let mut newly_counted = Vec::new();
        for listed in listed {
            let raw = match listed {
                Ok(raw) => raw,
                Err(e) => {
                    self.skip(sha256, None, e, None);
                    continue;
                }
            };
            if !hygienic_url(&raw) {
                // The URI itself is never recorded; the message says which
                // screening withheld it.
                let clean = !raw.chars().any(|c| c.is_control() || c.is_whitespace());
                let e = error(
                    ErrorCode::CrlFetchDenied,
                    if clean && url::Url::parse(&raw).is_err() {
                        "distribution point URI is not an absolute URL"
                    } else {
                        "distribution point URI has control characters, whitespace or credentials"
                    },
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
                    let key = url_key(&raw);
                    if !self.urls_counted.contains(&key) {
                        if self.urls_passed >= MAX_SOURCE_REQUESTS {
                            return Err(limit(
                                "crl_source_urls",
                                MAX_SOURCE_REQUESTS,
                                self.urls_passed,
                                1,
                            ));
                        }
                        self.urls_passed += 1;
                        self.urls_counted.insert(key.clone());
                        newly_counted.push(key.clone());
                    }
                    // Listed twice by this certificate: offered once.
                    if !points.iter().any(|point: &String| url_key(point) == key) {
                        points.push(raw);
                    }
                }
            }
        }
        self.in_flight = points.iter().map(|p| url_key(p)).collect();
        // The issuer name is the key for a source that stores CRLs by
        // issuer; a certificate without a readable one is not asked about,
        // and each of its listed points is recorded with that reason. The
        // certificate here is itself a re-encoding (SEC-22), so its issuer
        // bytes are sorted like the chain's names. No committed input
        // reaches the failure branch: a decoded name re-encodes
        // (docs/testing.md).
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
                    // Reported for this certificate only: no source was given
                    // the points, so they stay open for other certificates.
                    if points.is_empty() {
                        self.record(sha256, None, &e, None);
                    }
                    for point in &points {
                        self.record(sha256, Some(point), &e, None);
                    }
                    // No source was given them: they cost no URI allowance.
                    for key in &newly_counted {
                        self.urls_counted.remove(key);
                    }
                    self.urls_passed -= newly_counted.len();
                    return Ok(false);
                }
            },
        };
        // CRLs are per issuer key and role: a certificate with no new point,
        // whose issuer, authority key and role (CA or end entity) were
        // already asked about, needs no request of its own (its points'
        // outcomes were recorded above) and does not spend the cap.
        // The authorityKeyIdentifier extension's raw bytes (none: empty), so
        // that one that cannot be read, or names its issuer by name and
        // serial, is told apart from other keys of the same name and still
        // asked about only once.
        let key = issuer_key(issuer, cert);
        let new_issuer = self.asked_issuers.insert(key.clone());
        if points.is_empty() && !new_issuer {
            return Ok(false);
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
        // Only now, with every engine limit passed, are the points offered:
        // a limit that ends the run leaves them as they were.
        for point in &points {
            self.asked.insert(url_key(point), None);
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
                // A URL that is none of this request's points is not this
                // certificate's: it is dropped, and the error stands for the
                // whole request.
                let mut e = e;
                let named = e
                    .url
                    .as_deref()
                    .map(url_key)
                    .filter(|named| points.iter().any(|p| url_key(p) == *named));
                if named.is_none() {
                    e.url = None;
                }
                for point in points.iter().filter(|p| named != Some(url_key(p))) {
                    self.source_failure(sha256, e.clone().with_url(point.clone()));
                }
                if points.is_empty() || named.is_some() {
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
        // A failure without a URL is about the whole request, as an `Err`
        // is: it answers every point no CRL or failure named, so each is
        // recorded with it and none as "returned nothing".
        // The first such failure answers the points; every other one is
        // still recorded as it is, and an `Abort` among them stops retrieval.
        // An abort about the whole request (no URL): the points left were
        // not tried, whatever other URL-less failure came with it.
        let whole_abort = response
            .failures
            .iter()
            .any(|f| f.url.is_none() && f.kind == CrlSourceErrorKind::Abort);
        let mut whole_request = None;
        for failure in response.failures {
            if failure.url.is_none() && !unanswered.is_empty() && whole_request.is_none() {
                whole_request = Some(failure);
            } else {
                self.source_failure(sha256, failure);
            }
        }
        // The bodies are loaded first: what they turn out to be decides how
        // the points the source did not answer are recorded.
        let loaded = self.load_all(sha256, issuer, response.crls, max_bytes)?;
        let returned = loaded.accepted_bytes;
        if let Some(failure) = whole_request {
            // Beside an answer by certificate, such a failure is recorded as
            // it is: the points were not used, so it is not about them. So
            // is one beside a URL-less abort in this response: the points
            // left were not tried, as recorded below.
            let aborted_elsewhere = whole_abort && failure.kind != CrlSourceErrorKind::Abort;
            // An answer by certificate counts only without an abort (see
            // `by_certificate` below), so with one it does not change this.
            if loaded.by_certificate && !self.aborted && failure.kind != CrlSourceErrorKind::Abort
                || aborted_elsewhere
            {
                self.source_failure(sha256, failure);
            } else {
                for point in &unanswered {
                    self.source_failure(sha256, failure.clone().with_url(point.clone()));
                }
                return Ok(loaded.added);
            }
        }
        // A point the source neither answered nor reported is recorded, so
        // that no listed point disappears from the report; after an abort, or
        // once the accepted bodies used the request's whole byte allowance,
        // the points never tried are recorded as such.
        // A source that answered with a CRL naming no URL looked the CRL up
        // by certificate or issuer, as OpenSSL's `lookup_crls` does: the
        // points it did not use are not failures. Only a body that
        // loaded as a CRL of this certificate's issuer counts as such an
        // answer, as OpenSSL and Bouncy Castle look CRLs up by issuer name.
        let by_certificate = !self.aborted && loaded.by_certificate;
        if by_certificate {
            // A new full CRL may cover the issuer's other certificates, but
            // its name and syntax do not establish authority or freshness:
            // verification decides, before anything else is asked.
            self.reverify = loaded.full_added;
            // No source used these points: a later certificate listing one
            // still offers it. A distinct URI counts once toward
            // `crl_source_urls`; every offer costs a source request, which
            // `crl_requests` bounds (64 per verification).
            for point in &unanswered {
                self.asked.remove(&url_key(point));
            }
            if !unanswered.is_empty() {
                self.unused_points.retain(|(held, _)| held != sha256);
                self.unused_points
                    .push((sha256.to_owned(), unanswered.clone()));
            }
        }
        for point in unanswered.iter().filter(|_| !by_certificate) {
            let e = if self.aborted {
                error(
                    ErrorCode::CrlFetchAborted,
                    "not tried: the CRL source aborted retrieval",
                )
            } else if returned >= max_bytes {
                error(
                    ErrorCode::ResourceLimitExceeded,
                    "not tried: the byte allowance for this request is spent",
                )
                .detail("resource", "crl_response_bytes")
                .detail("limit", max_bytes)
                .detail("used", returned)
            } else {
                error(
                    ErrorCode::CrlFetchFailed,
                    "the CRL source returned nothing for this point",
                )
            };
            self.skip(sha256, Some(point), e, None);
        }
        Ok(loaded.added)
    }

    /// Load every returned body.
    fn load_all(
        &mut self,
        sha256: &str,
        issuer: &[u8],
        crls: Vec<SourcedCrl>,
        max_bytes: usize,
    ) -> Result<Loaded, VerificationError> {
        let mut loaded = Loaded::default();
        for crl in crls {
            let (by_certificate, added) =
                self.load(sha256, issuer, crl, &mut loaded.accepted_bytes, max_bytes)?;
            loaded.added |= added;
            loaded.by_certificate |= by_certificate.is_some();
            loaded.full_added |= by_certificate == Some(true);
        }
        Ok(loaded)
    }

    /// Check, account for and load one returned body. A body over its size
    /// caps, or that is not a CRL, is no evidence and is not loaded. Returns
    /// whether it is an answer by certificate (it names no URL and loaded a
    /// CRL, DER or PEM, of `issuer`), and whether it added a CRL not already
    /// loaded. The body is decoded only after its size is checked and
    /// charged.
    fn load(
        &mut self,
        sha256: &str,
        issuer: &[u8],
        crl: SourcedCrl,
        total: &mut usize,
        max_bytes: usize,
    ) -> Result<(Option<bool>, bool), VerificationError> {
        // Whether the source named a URL at all is decided before the URL is
        // screened: one withheld from the report is still not an answer by
        // certificate.
        let without_url = crl.url.is_none();
        // The URL as the source gave it keys the point's recorded outcome,
        // even when it is not fit to be reported.
        let raw_url = crl.url.clone();
        let url = crl.url.filter(|u| hygienic_url(u));
        // A redirect target the source reported but that is not recorded is
        // withheld, never replaced by the requested URL.
        let final_url = match crl.final_url {
            Some(target) => hygienic_url(&target).then_some(target),
            None => url.clone(),
        };
        let len = crl.bytes.len();
        self.budget.log.debug(
            Stage::Revocation,
            format_args!("CRL source returned {len} bytes from {url:?}; not yet authenticated"),
        );
        // A body over its caps is not counted against the bodies after it.
        if let Some(e) = body_over_allowance(len, *total, max_bytes) {
            self.skip(sha256, raw_url.as_deref(), e, None);
            return Ok((None, false));
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
            final_url,
            url: url.clone(),
            sha256: hex(&crate::crypto::Hash::Sha256.digest(&crl.bytes)),
            bytes: len,
        });
        // Before loading: whether this body brings a full CRL of the issuer
        // that is not already loaded (one PEM may hold several CRLs).
        let of_issuer: Vec<bool> = if without_url {
            crate::trust::crl_issuers(&crl.bytes)
                .into_iter()
                .filter(|(name, _, _)| name == issuer)
                .map(|(_, full, der)| full && !self.store.has_crl(&der))
                .collect()
        } else {
            Vec::new()
        };
        let prior = self.store.retrieval_crl_count();
        if let Err(e) = self.store.add_crl(&crl.bytes) {
            let e = error(
                ErrorCode::InvalidCrl,
                format!("decoding retrieved CRL: {e:#}"),
            );
            self.skip(sha256, raw_url.as_deref(), e, None);
            return Ok((None, false));
        }
        // A PEM response may contain multiple distinct CRLs. Bound the
        // retained store after deduplication, before verification.
        let loaded = self.store.retrieval_crl_count();
        if loaded > 64 {
            return Err(limit("retrieval_crl_artifacts", 64, prior, loaded - prior));
        }
        // An answer by certificate, and whether it brought a new full CRL,
        // which serves every certificate of that issuer and role.
        let answer = (!of_issuer.is_empty()).then(|| of_issuer.contains(&true));
        // A body identical to a loaded CRL adds nothing to verify.
        Ok((answer, loaded > prior))
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
    source.begin_verification();
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
        // names the certificates that lacked a usable CRL. A revocation on
        // one candidate path is final too, unless it names certificates of
        // another path that could still verify with a CRL: then those are
        // asked about, and the revocation stands if none is found.
        let mut result = verify_with(bytes, options, &state.store, format, budget);
        let mut asked = BTreeSet::new();
        let mut authenticated = false;
        loop {
            let unknown = match &result {
                Err(e) if e.code == ErrorCode::RevocationUnknown => e,
                // A revocation naming another path's gap, or an expired CRL
                // naming the certificates a source could refresh.
                Err(e)
                    if e.code == ErrorCode::CertificateRevoked
                        && (e.details.contains_key("certificates_without_crl")
                            || e.details.contains_key("certificates_with_expired_crl"))
                        || e.code == ErrorCode::CrlExpired
                            && e.details.contains_key("certificates_with_expired_crl") =>
                {
                    e
                }
                _ => break,
            };
            if state.aborted {
                break;
            }
            // Ask about exactly the certificates the verifier reports without
            // a usable CRL, as OpenSSL and Bouncy Castle look up CRLs for the
            // certificate being checked. The report carries each certificate,
            // whichever candidate path it was on. A result that names none
            // is final: asking about every selected certificate would ask
            // about covered ones.
            let targets = match uncovered(unknown) {
                // webpki rejected the path rssig's own evaluation accepted:
                // every certificate on it had a usable CRL, so no source can
                // help, and asking about covered certificates is refused.
                // Unit-tested only: no fixture makes the two disagree.
                // An unknown status that names nothing also arises when no
                // path passes path policy: no CRL can help and the status is
                // no evidence, so the input is checked without revocation and
                // that failure is the result. A definite CRL failure or
                // revocation keeps its code, as without `--fetch-crls`.
                Uncovered::Final => {
                    if unknown.code == ErrorCode::RevocationUnknown && !authenticated {
                        authenticate(bytes, options, &state.store, format, budget)?;
                    }
                    break;
                }
                Uncovered::Listed(reports) => {
                    let mut targets = Vec::new();
                    // A certificate already asked about is neither decoded
                    // nor charged again.
                    for report in reports.iter().filter(|r| !asked.contains(&r.sha256)) {
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
            };
            let mut added = false;
            let mut any = false;
            for (sha256, der, cert) in &targets {
                if asked.contains(sha256) {
                    continue;
                }
                // Verification with required revocation stops at the first
                // signer without a CRL: later signers, nested signatures and
                // bundle members are not yet checked. Before the first
                // request, the whole input must pass integrity and trust
                // checks, so that no source is asked about a file that
                // fails them and that failure is the result.
                if !authenticated {
                    authenticate(bytes, options, &state.store, format, budget)?;
                    authenticated = true;
                }
                asked.insert(sha256.clone());
                any = true;
                added |= state.request(sha256, der, cert, source)?;
                if state.aborted || core::mem::take(&mut state.reverify) {
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
        // Only when the abort cut retrieval short: a certificate still
        // without a CRL was never asked about, or was being asked about.
        let cut_short = |e: &VerificationError| {
            state.aborted
                && match uncovered(e) {
                    Uncovered::Listed(reports) => reports.iter().any(|report| {
                        !asked.contains(&report.sha256)
                            || state.aborted_for.as_deref() == Some(report.sha256.as_str())
                    }),
                    Uncovered::Final => false,
                }
        };
        match result {
            // A revocation is definite evidence and keeps its code; that
            // another path might have verified is marked.
            Err(e)
                if matches!(
                    e.code,
                    ErrorCode::CertificateRevoked | ErrorCode::CrlExpired
                ) && cut_short(&e) =>
            {
                Err(e.detail("retrieval_aborted", true))
            }
            Err(e) if e.code == ErrorCode::RevocationUnknown && cut_short(&e) => {
                let mut aborted = error(
                    ErrorCode::CrlFetchAborted,
                    "the CRL source stopped retrieval before revocation status was known",
                );
                // Keep the verifier's structured details, such as the
                // certificates still without a CRL, and its result.
                aborted.details.extend(e.details);
                Err(aborted.detail("revocation_unknown", e.message))
            }
            result => result,
        }
    })();
    // A certificate the failed result still names, whose source answered by
    // certificate, reports the points that answer left unused. A run ended
    // by an engine limit or a failed check reports what was recorded until
    // then: that error is the result.
    if let Err(e) = &result
        && let Uncovered::Listed(reports) = uncovered(e)
    {
        let named: Vec<String> = reports.iter().map(|r| r.sha256.clone()).collect();
        state.report_unused_points(&named);
    }
    match result {
        Ok(mut verified) => {
            verified.crl_retrieval = Some(state.report);
            Ok(verified)
        }
        Err(e) => Err(e.detail("crl_retrieval", state.report)),
    }
}

/// The limit a body of `len` bytes exceeds, reported with the cap it hit:
/// the per-CRL size, or the request's allowance with the bytes already taken
/// from earlier bodies of the same response.
fn body_over_allowance(len: usize, total: usize, max_bytes: usize) -> Option<VerificationError> {
    if len > MAX_CRL_BYTES {
        Some(limit("crl_response_bytes", MAX_CRL_BYTES, 0, len))
    } else if total.saturating_add(len) > max_bytes {
        Some(limit("crl_response_bytes", max_bytes, total, len))
    } else {
        None
    }
}

/// An issuer as retrieval tells them apart: its name (DER), the
/// certificate's authorityKeyIdentifier extension as raw bytes (none: empty,
/// so that one that cannot be read, or names its issuer by name and serial,
/// is its own key), and whether the certificate is a CA, as an issuer's CRLs
/// can differ by key and be split between CA and end-entity certificates.
type IssuerKey = (Vec<u8>, Vec<u8>, bool);

fn issuer_key(issuer: &[u8], cert: &Certificate) -> IssuerKey {
    let authority_key = cert
        .tbs_certificate
        .extensions
        .iter()
        .flatten()
        .find(|e| e.extn_id.to_string() == "2.5.29.35")
        .map(|e| e.extn_value.as_bytes().to_vec())
        .unwrap_or_default();
    let is_ca = cert
        .tbs_certificate
        .get::<x509_cert::ext::pkix::BasicConstraints>()
        .ok()
        .flatten()
        .is_some_and(|(_, constraints)| constraints.ca);
    (issuer.to_vec(), authority_key, is_ca)
}

/// What one response's bodies turned out to be.
#[derive(Default)]
struct Loaded {
    /// A CRL not already loaded was added.
    added: bool,
    /// The bytes of the bodies accepted within the size caps.
    accepted_bytes: usize,
    /// A body naming no URL loaded as a CRL of the certificate's issuer: the
    /// source answered by certificate or issuer.
    by_certificate: bool,
    /// Such a body brought a full CRL (no issuingDistributionPoint, not a
    /// delta) that was not already loaded: it serves every certificate of
    /// that issuer and role, so verification runs again first.
    full_added: bool,
}

/// What an unknown revocation status tells retrieval to ask about.
enum Uncovered {
    /// The certificates the verifier reports without a usable CRL.
    Listed(Vec<CertificateReport>),
    /// No source can help, or nothing is named: the status is final.
    Final,
}

fn uncovered(unknown: &VerificationError) -> Uncovered {
    if unknown.details.get("reason").and_then(|r| r.as_str()) == Some("confirmation") {
        return Uncovered::Final;
    }
    let listed = |key: &str| {
        unknown
            .details
            .get(key)
            .and_then(|v| serde_json::from_value::<Vec<CertificateReport>>(v.clone()).ok())
    };
    // Certificates whose only CRLs have expired can be refreshed.
    let expired = listed("certificates_with_expired_crl").unwrap_or_default();
    match listed("certificates_without_crl") {
        Some(mut reports) => {
            // Once each: a certificate can lack a CRL on one path and have
            // only an expired one on another.
            for report in expired {
                if !reports.iter().any(|r| r.sha256 == report.sha256) {
                    reports.push(report);
                }
            }
            if reports.is_empty() {
                // The verifier's own list, but empty: the certificate
                // without a CRL could not be named. Asking about every
                // selected certificate would ask about covered ones, so
                // nothing is asked.
                Uncovered::Final
            } else {
                Uncovered::Listed(reports)
            }
        }
        None if !expired.is_empty() => Uncovered::Listed(expired),
        // Any other result is definite evidence: only the certificates it
        // names are worth asking about, never every selected one.
        None => Uncovered::Final,
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

/// Verify the whole input without revocation: every signature, nested
/// signature, timestamp and bundle member must pass integrity and trust
/// checks before a CRL source is asked about any of it.
fn authenticate(
    bytes: &[u8],
    options: &VerifyOptions<'_>,
    store: &TrustStore,
    format: crate::format::Format,
    budget: &Budget,
) -> Result<(), VerificationError> {
    budget.log.debug(
        Stage::Revocation,
        format_args!(
            "CRL retrieval: verifying without revocation (integrity and trust of the whole input)"
        ),
    );
    let options = VerifyOptions {
        trust: Some(store),
        check_revocation: false,
        ..*options
    };
    verify_inner_budget(bytes, &options, format, budget)
        .map(|_| ())
        .map_err(|e| {
            VerificationError::from_internal(e, ErrorCode::InvalidCertificate, Stage::Certificate)
        })
}

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
        // Every certificate lists the same URL, under its own issuer name:
        // one URI, many requests.
        let shared = |i: usize| {
            use core::str::FromStr;
            let mut cert = signer_with_points("shared", 1);
            cert.tbs_certificate.issuer =
                x509_cert::name::Name::from_str(&format!("CN=issuer {i}")).unwrap();
            cert
        };
        for i in 0..MAX_SOURCE_REQUESTS {
            assert!(!ask(&mut state, &format!("c{i}"), &shared(i), &mut source).unwrap());
        }
        let error = ask(
            &mut state,
            "last",
            &shared(MAX_SOURCE_REQUESTS),
            &mut source,
        )
        .unwrap_err();
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
        assert_eq!(error.details["resource"], "crl_source_urls");
        assert_eq!(source.urls.len(), MAX_SOURCE_REQUESTS);
    }
    #[test]
    fn a_request_with_nothing_new_for_an_asked_issuer_is_not_made() {
        use CrlSourceErrorKind::*;
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let mut source = Kinds::new(vec![Failed]);
        // Many certificates of one issuer listing one URL: CRLs are per
        // issuer, so one request answers all, and none spends the cap.
        for i in 0..=MAX_SOURCE_REQUESTS {
            assert!(
                !ask(
                    &mut state,
                    &format!("c{i}"),
                    &signer_with_points("shared", 1),
                    &mut source
                )
                .unwrap()
            );
        }
        assert_eq!(source.calls, 1);
        // Each certificate still reports the shared point's failure.
        for i in 0..=MAX_SOURCE_REQUESTS {
            let certificate = format!("c{i}");
            assert!(
                state
                    .report
                    .failures
                    .iter()
                    .any(|f| f.certificate_sha256 == certificate && f.url.is_some()),
                "{certificate}"
            );
        }
    }
    #[test]
    fn a_point_answered_under_an_unhygienic_spelling_stays_in_later_reports() {
        // The source names the point with a trailing space: the URL is not
        // recorded as given, but the point's outcome is, for every
        // certificate listing it.
        struct Spaced;
        impl CrlSource for Spaced {
            fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                let mut response = CrlResponse::new();
                for point in request.distribution_points {
                    response = response.with_failure(
                        CrlSourceError::new(CrlSourceErrorKind::Failed, "down")
                            .with_url(format!("{point} ")),
                    );
                }
                Ok(response)
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let cert = signer_with_points("a", 1);
        ask(&mut state, "a", &cert, &mut Spaced).unwrap();
        ask(&mut state, "b", &cert, &mut Spaced).unwrap();
        assert!(
            state
                .report
                .failures
                .iter()
                .any(|f| f.certificate_sha256 == "b" && f.message == "down"),
            "{:?}",
            state.report.failures
        );
    }
    #[test]
    fn a_ca_and_an_end_entity_of_one_issuer_are_each_asked() {
        // CRLs of one issuer can be split between CA and end-entity
        // certificates (an ARL and a user CRL), so each role is asked about.
        use ::der::{Decode, Encode};
        use x509_cert::ext::{Extension, pkix::BasicConstraints};
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let mut source = Kinds::new(vec![CrlSourceErrorKind::Failed]);
        let leaf = signer_with_uris(&[]);
        let mut ca = leaf.clone();
        let constraints = BasicConstraints {
            ca: true,
            path_len_constraint: None,
        };
        let extension = Extension {
            extn_id: ::der::oid::ObjectIdentifier::new_unwrap("2.5.29.19"),
            critical: true,
            extn_value: ::der::asn1::OctetString::new(constraints.to_der().unwrap()).unwrap(),
        };
        let extensions = ca.tbs_certificate.extensions.get_or_insert_with(Vec::new);
        extensions.retain(|e| e.extn_id != extension.extn_id);
        extensions.push(extension);
        let _ = Certificate::from_der(&ca.to_der().unwrap()).unwrap();
        ask(&mut state, "leaf", &leaf, &mut source).unwrap();
        ask(&mut state, "ca", &ca, &mut source).unwrap();
        assert_eq!(source.calls, 2);
        // Another end entity of the same issuer, with nothing new, is not.
        ask(&mut state, "leaf2", &leaf, &mut source).unwrap();
        assert_eq!(source.calls, 2);
    }
    #[test]
    fn a_failure_without_a_url_in_a_response_answers_every_point() {
        struct DeniesAll;
        impl CrlSource for DeniesAll {
            fn crls(&mut self, _: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(CrlResponse::new()
                    .with_failure(CrlSourceError::new(CrlSourceErrorKind::Denied, "policy")))
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        ask(&mut state, "a", &signer_with_points("a", 2), &mut DeniesAll).unwrap();
        // One entry per point, each the source's own denial: no
        // contradictory "returned nothing".
        let entries: Vec<_> = state
            .report
            .failures
            .iter()
            .map(|f| (f.url.is_some(), f.code))
            .collect();
        assert_eq!(
            entries,
            [
                (true, ErrorCode::CrlFetchDenied),
                (true, ErrorCode::CrlFetchDenied)
            ]
        );
    }
    #[test]
    fn every_failure_without_a_url_counts_and_an_abort_among_them_stops() {
        struct FailsThenAborts;
        impl CrlSource for FailsThenAborts {
            fn crls(&mut self, _: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(CrlResponse::new()
                    .with_failure(CrlSourceError::new(CrlSourceErrorKind::Failed, "down"))
                    .with_failure(CrlSourceError::new(CrlSourceErrorKind::Abort, "deadline")))
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        ask(
            &mut state,
            "a",
            &signer_with_points("a", 2),
            &mut FailsThenAborts,
        )
        .unwrap();
        assert!(state.aborted);
        assert!(
            state
                .report
                .failures
                .iter()
                .any(|f| f.source_error == Some(CrlSourceErrorKind::Abort))
        );
    }
    #[test]
    fn a_withheld_redirect_target_is_not_replaced_by_the_requested_url() {
        struct Redirected;
        impl CrlSource for Redirected {
            fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(CrlResponse::new().with_crl(
                    SourcedCrl::new(include_bytes!("../tests/fixtures/good.crl").to_vec())
                        .with_url(request.distribution_points[0].clone())
                        .with_final_url("http://user:pw@crl.example.invalid/b.crl"),
                ))
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        ask(
            &mut state,
            "a",
            &signer_with_points("a", 1),
            &mut Redirected,
        )
        .unwrap();
        let artifact = &state.report.artifacts[0];
        assert!(artifact.url.is_some());
        assert_eq!(artifact.final_url, None);
    }
    #[test]
    fn a_failure_naming_a_url_outside_the_request_does_not_change_its_outcome() {
        // A's request is answered with a CRL for its point; B's request then
        // fails naming A's point, which B did not carry. C, listing A's
        // point, must not inherit that unrelated failure.
        struct Source(usize);
        impl CrlSource for Source {
            fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                self.0 += 1;
                match self.0 {
                    1 => Ok(CrlResponse::new().with_crl(
                        SourcedCrl::new(include_bytes!("../tests/fixtures/good.crl").to_vec())
                            .with_url(request.distribution_points[0].clone()),
                    )),
                    _ => Err(CrlSourceError::new(CrlSourceErrorKind::Failed, "down")
                        .with_url("http://crl.example.invalid/a-0.crl")),
                }
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let mut source = Source(0);
        ask(&mut state, "a", &signer_with_points("a", 1), &mut source).unwrap();
        ask(&mut state, "b", &signer_with_points("b", 1), &mut source).unwrap();
        let mut c = signer_with_points("a", 1);
        c.tbs_certificate.serial_number = x509_cert::serial_number::SerialNumber::from(77u32);
        ask(&mut state, "c", &c, &mut source).unwrap();
        assert!(
            !state
                .report
                .failures
                .iter()
                .any(|f| f.certificate_sha256 == "c"),
            "{:?}",
            state.report.failures
        );
    }
    #[test]
    fn points_not_tried_after_an_abort_stay_in_the_report() {
        use CrlSourceErrorKind::*;
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        // The first point aborts; fetch_each tries no other.
        let mut source = Kinds::new(vec![Abort]);
        ask(&mut state, "a", &signer_with_points("a", 3), &mut source).unwrap();
        assert_eq!(source.urls.len(), 1);
        let urls: Vec<_> = state
            .report
            .failures
            .iter()
            .filter(|f| f.certificate_sha256 == "a")
            .filter_map(|f| f.url.clone())
            .collect();
        assert_eq!(urls.len(), 3, "{:?}", state.report.failures);
        assert!(
            state
                .report
                .failures
                .iter()
                .all(|f| f.code == ErrorCode::CrlFetchAborted)
        );
    }
    #[test]
    fn a_certificate_over_the_url_limits_is_skipped_point_by_point() {
        // As OpenSSL and Bouncy Castle: one certificate's points never end
        // the run. An over-long URI is skipped and recorded; past 16, the
        // rest are recorded as not passed, and the first 16 still go out.
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let mut source = Kinds::new(vec![CrlSourceErrorKind::Failed]);
        let long = format!("http://crl.example.invalid/{}.crl", "x".repeat(2100));
        let mut uris: Vec<String> = (0..17)
            .map(|i| format!("http://crl.example.invalid/many-{i}.crl"))
            .collect();
        uris.insert(0, long);
        ask(&mut state, "a", &signer_with_uris(&uris), &mut source).unwrap();
        assert_eq!(source.urls.len(), MAX_REQUESTS);
        let resources: Vec<_> = state
            .report
            .failures
            .iter()
            .filter_map(|f| f.details.get("resource").and_then(|r| r.as_str()))
            .collect();
        assert_eq!(resources, ["crl_url_bytes", "crl_urls"]);
        // The strict public discovery still reports the limit as an error.
        assert!(crl_distribution_points(&signer_with_uris(&uris)).is_err());
    }
    #[test]
    fn points_left_when_the_byte_allowance_is_spent_are_not_tried() {
        // The first body fills the request's whole allowance: the other
        // points are never fetched, and say so, not "failed".
        struct Fills(usize);
        impl CrlSource for Fills {
            fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(fetch_each(request, |_, max_bytes| {
                    self.0 += 1;
                    Ok(SourcedCrl::new(vec![0; max_bytes]))
                }))
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let mut source = Fills(0);
        let request_points = signer_with_points("a", 3);
        // A request allowance equal to one CRL's cap.
        let der = ::der::Encode::to_der(&request_points).unwrap();
        let points: Vec<String> = (0..3)
            .map(|i| format!("http://crl.example.invalid/a-{i}.crl"))
            .collect();
        let issuer = crate::der::tbs_issuer(&der, 0xa0, 2).unwrap().to_vec();
        let response = source
            .crls(&CrlRequest::new(&der, &issuer, &points, 10))
            .unwrap();
        assert_eq!(source.0, 1);
        // fetch_each reports no failure for the points it never tried.
        assert!(response.failures.is_empty());
        // Through the engine, with a 10-byte allowance left for the request:
        // those points are recorded as not tried.
        state.downloaded = MAX_TOTAL_BYTES - state.base.retrieval_bytes() - 10;
        ask(&mut state, "a", &request_points, &mut Fills(0)).unwrap();
        let not_tried = state
            .report
            .failures
            .iter()
            .filter(|f| f.message.starts_with("not tried"))
            .count();
        assert_eq!(not_tried, 2, "{:?}", state.report.failures);
    }
    #[test]
    fn an_unreadable_authority_key_is_its_own_issuer_key() {
        // It cannot be told from another key of the same name, so a request
        // for a readable key does not stand in for it; a second certificate
        // with the same unreadable bytes needs no request of its own.
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let mut source = Kinds::new(vec![CrlSourceErrorKind::Failed]);
        let plain = signer_with_uris(&[]);
        let mut broken = plain.clone();
        let extensions = broken.tbs_certificate.extensions.as_mut().unwrap();
        let aki = extensions
            .iter_mut()
            .find(|e| e.extn_id.to_string() == "2.5.29.35")
            .expect("the signer has an authorityKeyIdentifier");
        aki.extn_value = ::der::asn1::OctetString::new(vec![0x04, 0x00]).unwrap();
        ask(&mut state, "plain", &plain, &mut source).unwrap();
        ask(&mut state, "broken", &broken, &mut source).unwrap();
        assert_eq!(source.calls, 2);
        ask(&mut state, "broken2", &broken, &mut source).unwrap();
        assert_eq!(source.calls, 2);
    }
    #[test]
    fn fetch_each_tries_the_next_point_after_an_over_allowance_body() {
        let points: Vec<String> = (0..2)
            .map(|i| format!("http://crl.example.invalid/a-{i}.crl"))
            .collect();
        let mut calls = 0;
        let response = fetch_each(&CrlRequest::new(b"", b"", &points, 10), |_, max_bytes| {
            calls += 1;
            // The first answer ignores its allowance; the second fits.
            let len = if calls == 1 { max_bytes + 1 } else { 4 };
            Ok(SourcedCrl::new(vec![0; len]))
        });
        // Both points are tried: the oversized body is left for the engine
        // to reject, and the second still has the whole allowance.
        assert_eq!(calls, 2);
        assert_eq!(response.crls.len(), 2);
        assert!(response.failures.is_empty());
        assert_eq!(response.crls[1].bytes.len(), 4);
        // Only the first oversized body is kept: later ones are reported
        // without their bytes.
        let points: Vec<String> = (0..3)
            .map(|i| format!("http://crl.example.invalid/b-{i}.crl"))
            .collect();
        let response = fetch_each(&CrlRequest::new(b"", b"", &points, 10), |_, max_bytes| {
            Ok(SourcedCrl::new(vec![0; max_bytes + 1]))
        });
        assert_eq!(response.crls.len(), 1);
        assert_eq!(response.failures.len(), 2);
        assert_eq!(response.failures[0].details["requested"], 11);
    }
    #[test]
    fn points_unused_by_an_answer_by_certificate_are_offered_again() {
        // Certificate A is answered by its issuer's CRL, naming no URL; B, of
        // another issuer, lists the same points and still carries them.
        struct Source(Vec<usize>);
        impl CrlSource for Source {
            fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                self.0.push(request.distribution_points.len());
                Ok(match self.0.len() {
                    1 => CrlResponse::new().with_crl(SourcedCrl::new(
                        include_bytes!("../tests/fixtures/good.crl").to_vec(),
                    )),
                    _ => fetch_each(request, |_, _| {
                        Err(CrlSourceError::new(CrlSourceErrorKind::Failed, "down"))
                    }),
                })
            }
        }
        use core::str::FromStr;
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let mut source = Source(Vec::new());
        let a = signer_with_points("shared", 2);
        let mut b = a.clone();
        b.tbs_certificate.issuer = x509_cert::name::Name::from_str("CN=another issuer").unwrap();
        ask(&mut state, "a", &a, &mut source).unwrap();
        ask(&mut state, "b", &b, &mut source).unwrap();
        assert_eq!(source.0, [2, 2]);
        // A URI offered again costs nothing more: each distinct one counts once.
        assert_eq!(state.urls_passed, 2);
    }
    #[test]
    fn a_source_is_told_when_a_verification_begins() {
        struct Source {
            begun: usize,
            asked: usize,
        }
        impl CrlSource for Source {
            fn begin_verification(&mut self) {
                self.begun += 1;
            }
            fn crls(&mut self, _: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                self.asked += 1;
                Ok(CrlResponse::new())
            }
        }
        let trust = store();
        let options = VerifyOptions::trusted(&trust, 1_800_000_000);
        let mut source = Source { begun: 0, asked: 0 };
        let input = include_bytes!("../tests/fixtures/good-crl-discovery.exe");
        for round in 1..=2 {
            let _ = crate::verify::Verifier::new(&options).verify_with_crl_source(
                input,
                Some("a.exe"),
                &mut source,
            );
            assert_eq!(source.begun, round);
        }
    }
    #[test]
    fn points_left_after_an_abort_among_url_less_failures_are_not_tried() {
        struct Source;
        impl CrlSource for Source {
            fn crls(&mut self, _: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(CrlResponse::new()
                    .with_failure(CrlSourceError::new(CrlSourceErrorKind::Denied, "no"))
                    .with_failure(CrlSourceError::new(CrlSourceErrorKind::Abort, "stop")))
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        ask(&mut state, "a", &signer_with_points("p", 2), &mut Source).unwrap();
        assert!(state.aborted);
        let points: Vec<_> = state
            .report
            .failures
            .iter()
            .filter(|f| f.url.is_some())
            .map(|f| f.code)
            .collect();
        assert_eq!(
            points,
            [ErrorCode::CrlFetchAborted, ErrorCode::CrlFetchAborted]
        );
    }
    #[test]
    fn an_abort_naming_one_point_does_not_relabel_the_others() {
        struct Source;
        impl CrlSource for Source {
            fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(CrlResponse::new()
                    .with_failure(CrlSourceError::new(CrlSourceErrorKind::Denied, "policy"))
                    .with_failure(
                        CrlSourceError::new(CrlSourceErrorKind::Abort, "stop")
                            .with_url(request.distribution_points[0].clone()),
                    ))
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        ask(&mut state, "a", &signer_with_points("p", 2), &mut Source).unwrap();
        let second = state
            .report
            .failures
            .iter()
            .find(|f| f.url.as_deref() == Some("http://crl.example.invalid/p-1.crl"))
            .unwrap();
        assert_eq!(second.code, ErrorCode::CrlFetchDenied);
        // The same with a body answering by certificate beside them: the
        // result does not depend on that body.
        struct WithBody;
        impl CrlSource for WithBody {
            fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(CrlResponse::new()
                    .with_crl(SourcedCrl::new(
                        include_bytes!("../tests/fixtures/good.crl").to_vec(),
                    ))
                    .with_failure(CrlSourceError::new(CrlSourceErrorKind::Denied, "policy"))
                    .with_failure(
                        CrlSourceError::new(CrlSourceErrorKind::Abort, "stop")
                            .with_url(request.distribution_points[0].clone()),
                    ))
            }
        }
        let mut state = Retrieval::new(&store, &budget);
        ask(&mut state, "a", &signer_with_points("p", 2), &mut WithBody).unwrap();
        let second = state
            .report
            .failures
            .iter()
            .find(|f| f.url.as_deref() == Some("http://crl.example.invalid/p-1.crl"))
            .unwrap();
        assert_eq!(second.code, ErrorCode::CrlFetchDenied);
    }
    #[test]
    fn a_certificate_named_twice_is_one_target() {
        use ::der::Decode;
        let cert =
            Certificate::from_der(include_bytes!("../tests/fixtures/sec06-issuer.der")).unwrap();
        let report = serde_json::to_value(CertificateReport::parse(&cert).unwrap()).unwrap();
        let error = error(ErrorCode::RevocationUnknown, "x")
            .detail("certificates_without_crl", vec![report.clone()])
            .detail("certificates_with_expired_crl", vec![report]);
        let Uncovered::Listed(reports) = uncovered(&error) else {
            panic!("listed");
        };
        assert_eq!(reports.len(), 1);
    }
    #[test]
    fn a_point_requested_later_is_reported_with_its_outcome() {
        // Certificate A is answered by its issuer's CRL without a URL and
        // leaves its point unused; certificate B, of another issuer, lists
        // the same point, which is then requested.
        struct Source(usize);
        impl CrlSource for Source {
            fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                self.0 += 1;
                Ok(match self.0 {
                    1 => CrlResponse::new().with_crl(SourcedCrl::new(
                        include_bytes!("../tests/fixtures/good.crl").to_vec(),
                    )),
                    _ => fetch_each(request, |_, _| {
                        Err(CrlSourceError::new(CrlSourceErrorKind::Failed, "down"))
                    }),
                })
            }
        }
        use core::str::FromStr;
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let a = signer_with_points("shared", 1);
        let mut b = a.clone();
        b.tbs_certificate.issuer = x509_cert::name::Name::from_str("CN=another issuer").unwrap();
        ask(&mut state, "a", &a, &mut Source(0)).unwrap();
        assert!(state.unused_points.iter().any(|(held, _)| held == "a"));
        let mut source = Source(1);
        ask(&mut state, "b", &b, &mut source).unwrap();
        // A's point is reported with the failure it got for B.
        state.report_unused_points(&["a".to_string()]);
        let a_entries: Vec<_> = state
            .report
            .failures
            .iter()
            .filter(|f| f.certificate_sha256 == "a")
            .map(|f| (f.url.clone().unwrap(), f.message.clone()))
            .collect();
        assert_eq!(
            a_entries,
            [(
                "http://crl.example.invalid/shared-0.crl".to_string(),
                "down".to_string()
            )]
        );
        // Never requested: reported as such, for a named certificate only.
        let mut state = Retrieval::new(&store, &budget);
        ask(&mut state, "a", &a, &mut Source(0)).unwrap();
        state.report_unused_points(&["a".to_string()]);
        assert_eq!(state.report.failures.len(), 1);
        assert!(state.report.failures[0].message.starts_with("not used"));
        // A certificate whose status was settled (not named) leaves none.
        let mut state = Retrieval::new(&store, &budget);
        ask(&mut state, "a", &a, &mut Source(0)).unwrap();
        state.report_unused_points(&["other".to_string()]);
        assert!(state.report.failures.is_empty());
        // A point answered for another certificate leaves none either.
        let mut state = Retrieval::new(&store, &budget);
        ask(&mut state, "a", &a, &mut Source(0)).unwrap();
        state
            .asked
            .insert(url_key("http://crl.example.invalid/shared-0.crl"), None);
        state.report_unused_points(&["a".to_string()]);
        assert!(state.report.failures.is_empty());
    }
    #[test]
    fn re_offered_points_are_bounded_by_the_request_limit() {
        struct Source;
        impl CrlSource for Source {
            fn crls(&mut self, _: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(CrlResponse::new().with_crl(SourcedCrl::new(
                    include_bytes!("../tests/fixtures/good.crl").to_vec(),
                )))
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let cert = signer_with_points("shared", 2);
        for index in 0..MAX_SOURCE_REQUESTS {
            ask(&mut state, &format!("c{index}"), &cert, &mut Source).unwrap();
        }
        // The points were offered every time but cost no URI allowance; the
        // source requests are what stop the run.
        assert_eq!(state.urls_passed, 2);
        let e = ask(&mut state, "last", &cert, &mut Source).unwrap_err();
        assert_eq!(e.code, ErrorCode::ResourceLimitExceeded);
        assert_eq!(e.details["resource"], "crl_requests");
        // The limit leaves the points as they were: not marked as offered,
        // so a certificate that left them unused still reports them.
        assert!(
            !state
                .asked
                .contains_key(&url_key("http://crl.example.invalid/shared-0.crl"))
        );
    }
    #[test]
    fn a_source_answering_by_certificate_never_exhausts_the_uri_limit() {
        // Five certificates, each listing the same 16 points, all answered
        // by the issuer's CRL without a URL: the points are offered every
        // time but are 16 distinct URIs, far below the 64 limit.
        struct Source;
        impl CrlSource for Source {
            fn crls(&mut self, _: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(CrlResponse::new().with_crl(SourcedCrl::new(
                    include_bytes!("../tests/fixtures/good.crl").to_vec(),
                )))
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let cert = signer_with_points("shared", 16);
        for index in 0..5 {
            ask(&mut state, &format!("c{index}"), &cert, &mut Source).unwrap();
        }
        assert_eq!(state.urls_passed, 16);
    }
    #[test]
    fn a_whole_request_error_naming_a_foreign_url_is_not_attributed_to_the_certificate() {
        struct Source;
        impl CrlSource for Source {
            fn crls(&mut self, _: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Err(CrlSourceError::new(CrlSourceErrorKind::Failed, "down")
                    .with_url("http://other.example.invalid/x.crl"))
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let cert = signer_with_points("own", 2);
        ask(&mut state, "a", &cert, &mut Source).unwrap();
        let urls: Vec<_> = state
            .report
            .failures
            .iter()
            .map(|f| f.url.clone().unwrap_or_default())
            .collect();
        assert_eq!(
            urls,
            [
                "http://crl.example.invalid/own-0.crl",
                "http://crl.example.invalid/own-1.crl"
            ]
        );
    }
    #[test]
    fn a_duplicate_full_crl_by_certificate_beside_a_new_url_body_does_not_ask_for_verification() {
        struct Source(usize);
        impl CrlSource for Source {
            fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                self.0 += 1;
                let mut response = CrlResponse::new().with_crl(SourcedCrl::new(
                    include_bytes!("../tests/fixtures/good.crl").to_vec(),
                ));
                if self.0 == 2 {
                    response = response.with_crl(
                        SourcedCrl::new(
                            include_bytes!("../tests/fixtures/sec10-root-idp-named-point.crl")
                                .to_vec(),
                        )
                        .with_url(request.distribution_points[0].clone()),
                    );
                }
                Ok(response)
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let mut source = Source(0);
        // The full CRL is new for the first certificate.
        ask(
            &mut state,
            "c0",
            &signer_with_points("first", 2),
            &mut source,
        )
        .unwrap();
        assert!(state.reverify);
        state.reverify = false;
        // For the second it is a duplicate, beside a new body from a URL.
        ask(
            &mut state,
            "c1",
            &signer_with_points("second", 2),
            &mut source,
        )
        .unwrap();
        assert!(!state.reverify);
    }
    #[test]
    fn a_new_full_crl_by_certificate_asks_for_verification_first() {
        // Whether a full CRL returned by certificate covers the issuer's
        // other certificates is for verification to decide: retrieval
        // verifies again before asking about anything else.
        struct Source(&'static [u8]);
        impl CrlSource for Source {
            fn crls(&mut self, _: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(CrlResponse::new().with_crl(SourcedCrl::new(self.0.to_vec())))
            }
        }
        let store = store();
        let budget = Budget::default();
        let cert = signer_with_points("shared", 2);
        let mut state = Retrieval::new(&store, &budget);
        let mut full = Source(include_bytes!("../tests/fixtures/good.crl"));
        ask(&mut state, "c0", &cert, &mut full).unwrap();
        assert!(state.reverify);
        // The same body again adds nothing: no reason to verify again.
        state.reverify = false;
        ask(&mut state, "c1", &cert, &mut full).unwrap();
        assert!(!state.reverify);
        // A partition answers only the certificate it was returned for.
        let mut state = Retrieval::new(&store, &budget);
        let mut partition = Source(include_bytes!(
            "../tests/fixtures/sec10-root-idp-named-point.crl"
        ));
        ask(&mut state, "p0", &cert, &mut partition).unwrap();
        assert!(!state.reverify);
        // One PEM body holding the loaded full CRL and a new partition: the
        // full CRL is not new, so no reason to verify again.
        let pem = |der: &[u8]| {
            ::der::pem::encode_string("X509 CRL", ::der::pem::LineEnding::LF, der).unwrap()
        };
        let both = pem(include_bytes!("../tests/fixtures/good.crl"))
            + &pem(include_bytes!(
                "../tests/fixtures/sec10-root-idp-named-point.crl"
            ));
        let mut state = Retrieval::new(&store, &budget);
        let mut full = Source(include_bytes!("../tests/fixtures/good.crl"));
        ask(&mut state, "b0", &cert, &mut full).unwrap();
        state.reverify = false;
        let both: &'static [u8] = Box::leak(both.into_bytes().into_boxed_slice());
        ask(
            &mut state,
            "b1",
            &signer_with_points("other", 2),
            &mut Source(both),
        )
        .unwrap();
        assert!(!state.reverify);
        // A delta CRL is not a full CRL: webpki cannot use it.
        let mut state = Retrieval::new(&store, &budget);
        let mut delta = Source(include_bytes!("../tests/fixtures/sec10-root-delta.crl"));
        ask(&mut state, "d0", &cert, &mut delta).unwrap();
        assert!(!state.reverify);
        // A body whose URL is withheld from the report is not an answer by
        // certificate: its certificate's points are still recorded.
        struct Credentialed;
        impl CrlSource for Credentialed {
            fn crls(&mut self, _: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(CrlResponse::new().with_crl(
                    SourcedCrl::new(include_bytes!("../tests/fixtures/good.crl").to_vec())
                        .with_url("http://user:pw@crl.example.invalid/other.crl"),
                ))
            }
        }
        let mut state = Retrieval::new(&store, &budget);
        ask(&mut state, "u0", &cert, &mut Credentialed).unwrap();
        assert!(!state.reverify);
        assert_eq!(
            state
                .report
                .failures
                .iter()
                .filter(|f| f.url.is_some())
                .count(),
            2,
            "{:?}",
            state.report.failures
        );
    }
    #[test]
    fn a_url_that_cannot_be_screened_is_withheld() {
        assert!(hygienic_url("http://crl.example.invalid/a.crl"));
        assert!(hygienic_url("ldap://crl.example.invalid/cn=a"));
        // Credentials, even where the URL does not parse (an invalid port).
        assert!(!hygienic_url("http://user:pw@crl.example.invalid/a.crl"));
        assert!(!hygienic_url(
            "http://user:pw@crl.example.invalid:port/a.crl"
        ));
        assert!(!hygienic_url("not a url"));
    }
    #[test]
    fn diagnostics_for_unusable_names_are_bounded_per_certificate() {
        // 200 dNSName names in one point: none is a URI. The report keeps a
        // bounded number of entries and one that counts the rest.
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
        let names: Vec<u8> = (0..200).flat_map(|_| tlv(0x82, b"crl.invalid")).collect();
        let point = tlv(0x30, &tlv(0xa0, &tlv(0xa0, &names)));
        let mut cert = signer_with_points("d", 1);
        cert.tbs_certificate
            .extensions
            .as_mut()
            .unwrap()
            .iter_mut()
            .find(|e| e.extn_id.to_string() == "2.5.29.31")
            .unwrap()
            .extn_value = ::der::asn1::OctetString::new(tlv(0x30, &point)).unwrap();
        let listed = listed_points(&cert, false).unwrap();
        assert_eq!(listed.len(), MAX_REQUESTS + 1);
        let last = listed.last().unwrap().as_ref().unwrap_err();
        assert_eq!(last.details["omitted"], 200 - MAX_REQUESTS);
        // The strict public discovery still fails at the first such name.
        assert!(crl_distribution_points(&cert).is_err());
    }
    #[test]
    fn a_rejected_body_under_an_unhygienic_spelling_keeps_its_point() {
        // The body for the point is not a CRL and its URL has a trailing
        // space: the point's outcome is still kept for later certificates.
        struct Spaced;
        impl CrlSource for Spaced {
            fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                let mut response = CrlResponse::new();
                for point in request.distribution_points {
                    response = response.with_crl(
                        SourcedCrl::new(b"not a CRL".to_vec()).with_url(format!("{point} ")),
                    );
                }
                Ok(response)
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let cert = signer_with_points("a", 1);
        let mut other = cert.clone();
        other.tbs_certificate.serial_number = x509_cert::serial_number::SerialNumber::from(78u32);
        ask(&mut state, "a", &cert, &mut Spaced).unwrap();
        ask(&mut state, "b", &other, &mut Spaced).unwrap();
        assert!(
            state
                .report
                .failures
                .iter()
                .any(|f| f.certificate_sha256 == "b" && f.code == ErrorCode::InvalidCrl),
            "{:?}",
            state.report.failures
        );
    }
    #[test]
    fn a_failure_beside_an_answer_by_certificate_is_not_about_the_points() {
        // The issuer's full CRL, naming no URL, plus a failure naming none:
        // the points were not used, so they are not failures, they stay
        // open, and verification runs before anything else is asked.
        struct Source;
        impl CrlSource for Source {
            fn crls(&mut self, _: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(CrlResponse::new()
                    .with_crl(SourcedCrl::new(
                        include_bytes!("../tests/fixtures/good.crl").to_vec(),
                    ))
                    .with_failure(CrlSourceError::new(
                        CrlSourceErrorKind::Failed,
                        "mirror down",
                    )))
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        ask(&mut state, "a", &signer_with_points("a", 2), &mut Source).unwrap();
        assert!(state.reverify);
        assert_eq!(
            state.report.failures.len(),
            1,
            "{:?}",
            state.report.failures
        );
        assert!(state.report.failures[0].url.is_none());
        assert!(state.asked.is_empty());
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
    fn a_uri_that_is_not_an_absolute_url_is_withheld_with_its_own_reason() {
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let mut source = Kinds::new(vec![CrlSourceErrorKind::Failed]);
        let uris = ["crl.example.invalid/ca.crl".to_string()];
        ask(&mut state, "a", &signer_with_uris(&uris), &mut source).unwrap();
        // As in OpenSSL (http:// prefix only) and Bouncy Castle (toURL fails
        // on a relative URI), it is never offered to a source.
        assert!(source.urls.is_empty());
        let failure = &state.report.failures[0];
        assert_eq!(failure.code, ErrorCode::CrlFetchDenied);
        assert!(failure.url.is_none());
        assert!(failure.problem.detail.contains("not an absolute URL"));
    }
    #[test]
    fn a_sources_own_url_detail_is_not_reported() {
        let error = CrlSourceError::new(CrlSourceErrorKind::Failed, "failed")
            .with_url("http://user:secret@crl.example.invalid/a.crl")
            .detail("url", "http://user:secret@crl.example.invalid/a.crl")
            .detail("status", 500)
            .into_error();
        assert!(!error.details.contains_key("url"));
        assert_eq!(error.details["status"], 500);
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
    fn only_a_real_crl_without_a_url_answers_by_certificate() {
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
        // The body is not a CRL, so it is no answer by certificate: both
        // certificates report the two points it passed over, and the second
        // certificate of the same issuer, with nothing new, is not asked.
        assert_eq!(source.0, [2]);
        for certificate in ["a", "b"] {
            let urls = state
                .report
                .failures
                .iter()
                .filter(|f| f.certificate_sha256 == certificate && f.url.is_some())
                .count();
            assert_eq!(urls, 2, "{certificate}: {:?}", state.report.failures);
        }
        // A real CRL naming no URL is such an answer: no point is a failure.
        struct Answers;
        impl CrlSource for Answers {
            fn crls(&mut self, _: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(CrlResponse::new().with_crl(SourcedCrl::new(
                    include_bytes!("../tests/fixtures/good.crl").to_vec(),
                )))
            }
        }
        let mut state = Retrieval::new(&store, &budget);
        ask(&mut state, "c", &signer_with_points("c", 2), &mut Answers).unwrap();
        // The same CRL as PEM is such an answer too.
        struct Pem;
        impl CrlSource for Pem {
            fn crls(&mut self, _: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                // CertificateList has no PEM label of its own: wrap the DER.
                let pem = ::der::pem::encode_string(
                    "X509 CRL",
                    ::der::pem::LineEnding::LF,
                    include_bytes!("../tests/fixtures/good.crl"),
                )
                .unwrap();
                Ok(CrlResponse::new().with_crl(SourcedCrl::new(pem.into_bytes())))
            }
        }
        let mut pem = Retrieval::new(&store, &budget);
        ask(&mut pem, "p", &signer_with_points("p", 2), &mut Pem).unwrap();
        assert!(pem.report.failures.is_empty(), "{:?}", pem.report.failures);
        // A CRL of another issuer is no answer for this certificate: its
        // points are still recorded.
        struct Unrelated;
        impl CrlSource for Unrelated {
            fn crls(&mut self, _: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(CrlResponse::new().with_crl(SourcedCrl::new(
                    include_bytes!("../tests/fixtures/sec06-root.crl").to_vec(),
                )))
            }
        }
        let mut other = Retrieval::new(&store, &budget);
        ask(&mut other, "d", &signer_with_points("d", 2), &mut Unrelated).unwrap();
        assert_eq!(
            other.report.failures.len(),
            2,
            "{:?}",
            other.report.failures
        );
        assert!(
            state.report.failures.is_empty(),
            "{:?}",
            state.report.failures
        );
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
        // The verifier rejected a path every certificate of which had a CRL.
        assert!(matches!(
            uncovered(&unknown().detail("reason", "confirmation")),
            Uncovered::Final
        ));
        assert!(matches!(uncovered(&unknown()), Uncovered::Final));
        // The verifier's own list, empty: a certificate it could not name.
        assert!(matches!(
            uncovered(
                &unknown().detail("certificates_without_crl", Vec::<CertificateReport>::new())
            ),
            Uncovered::Final
        ));
        // A revocation names what is worth asking about, or nothing is.
        let revoked = || error(ErrorCode::CertificateRevoked, "revoked");
        assert!(matches!(uncovered(&revoked()), Uncovered::Final));
        assert!(matches!(
            uncovered(
                &revoked().detail("certificates_without_crl", Vec::<CertificateReport>::new())
            ),
            Uncovered::Final
        ));
    }

    #[test]
    fn an_over_allowance_body_reports_the_cap_it_hit() {
        let numbers = |e: VerificationError| {
            (
                e.details["limit"].as_u64().unwrap(),
                e.details["used"].as_u64().unwrap(),
                e.details["requested"].as_u64().unwrap(),
            )
        };
        let mib = 1024 * 1024;
        // A second 5 MiB body beside a first one, with an 8 MiB allowance.
        let e = body_over_allowance(5 * mib, 5 * mib, 8 * mib).unwrap();
        assert_eq!(numbers(e), (8 * mib as u64, 5 * mib as u64, 5 * mib as u64));
        // A body over the per-CRL size.
        let e = body_over_allowance(MAX_CRL_BYTES + 1, 0, MAX_TOTAL_BYTES).unwrap();
        assert_eq!(
            numbers(e),
            (MAX_CRL_BYTES as u64, 0, MAX_CRL_BYTES as u64 + 1)
        );
        assert!(body_over_allowance(3 * mib, 5 * mib, 8 * mib).is_none());
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
        // a's four points: the failed one, the aborting one, and the two
        // never tried, recorded as such.
        assert_eq!(state.report.failures.len(), 4);
        assert!(
            state.report.failures[1..]
                .iter()
                .all(|f| f.code == ErrorCode::CrlFetchAborted)
        );
        assert_eq!(state.report.failures[1].source_error, Some(Abort));
        assert_eq!(state.report.failures[2].source_error, None);
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
