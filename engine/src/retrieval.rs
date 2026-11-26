//! Opt-in CRL discovery and retrieval through an injected [`CrlSource`]. No
//! fetched artifact is a trust anchor. The engine has no transport: the
//! application supplies the source (the `rssig` package's `HttpCrlSource` is
//! the default one).
pub use crate::domain::CrlSourceErrorKind;
use crate::{
    TrustStore,
    domain::*,
    verify::{VerifyOptions, budget::Budget, verify_inner_budget},
};
use ::der::Decode;
use std::collections::{BTreeMap, BTreeSet};
use x509_cert::{
    Certificate,
    ext::pkix::{
        CrlDistributionPoints,
        name::{DistributionPointName, GeneralName},
    },
};

/// The most bytes of one CRL body the engine accepts from a source.
pub const MAX_CRL_BYTES: usize = 8 * 1024 * 1024;
/// The most bytes of roots and CRLs, supplied and fetched together, that one
/// verification retains: what its store holds, so a body that does not load,
/// or repeats a CRL already held, adds nothing. A source's own wire-byte
/// total is its own.
pub const MAX_TOTAL_BYTES: usize = 32 * 1024 * 1024;
/// The listed distribution points of one certificate that the strict
/// [`crl_distribution_points`] accepts. The engine offers a source every point
/// (CRL-024); a source decides how many it tries. Not a request total: the
/// engine keeps none (CRL-039).
pub const MAX_LISTED_URLS: usize = 16;
/// Failure entries the report keeps for one certificate, for the entries about
/// a point and for those about none each; further ones are
/// counted in one entry (`details.omitted`), CRL-024. A bound on the report,
/// not on what is offered to a source.
const MAX_FAILURES_PER_CERTIFICATE: usize = 16;
/// Points the log line for one request names; it always gives the count.
const LOGGED_POINTS: usize = 16;
/// CRL bodies and failures one [`CrlResponse`] may carry together, besides one
/// for each point the request offered.
pub const MAX_RESPONSE_ENTRIES: usize = 64;

/// The single interface through which the engine obtains CRLs, asked once per
/// certificate that lacks a usable CRL, with every point it lists, like
/// OpenSSL's `get_crl` (by certificate) or `lookup_crls` (by issuer name).
/// The engine reuses no earlier answer: a source that wants to answer a
/// repeated point or issuer without new work keeps its own cache, as an
/// OpenSSL lookup callback does (CRL-033). A source returns untrusted bytes, never a trust or revocation
/// verdict: the engine authenticates every CRL and applies no transport rule
/// of its own. Where CRLs come from, and how (HTTP, HTTPS, LDAP, a proxy, a
/// cache, a local directory keyed by issuer), is the source's decision;
/// the `rssig` application's `HttpCrlSource` is the default one, and
/// [`fetch_each`] adapts any per-URL fetch. A source must bound its own I/O and allocation by
/// [`CrlRequest::max_bytes`], its own number of requests per verification
/// (the engine keeps no total, CRL-039; see the application's
/// `MAX_SOURCE_REQUESTS` for the default source's) and finish in finite time; the engine still checks
/// every size.
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
    /// `HttpCrlSource` does; the default does nothing. A source that
    /// delegates to another (a cache in front of `HttpCrlSource`, say) must
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
    /// out of DER order is sorted (CRL-T010).
    pub certificate: &'a [u8],
    /// Its issuer Name, DER, read from `certificate`: the key a store of CRLs
    /// by issuer looks up.
    pub issuer: &'a [u8],
    /// Its supported cRLDistributionPoints URIs, in listed order, each once
    /// (compared after normalization), including those offered for another
    /// certificate earlier in this verification. A hint: a source may use
    /// them, ignore them, answer a repeat from its own cache, or find CRLs
    /// elsewhere.
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
/// becomes a [`SourcedCrl`] or a failure with its URL. It tries every point
/// the request carries: the engine offers every URI a certificate lists
/// (CRL-024), so a source built on it bounds its own count of points per
/// request, as the application's `HttpCrlSource` does.
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

/// A fixed-size key for a certificate and a point, so that remembering one
/// costs sixteen bytes: the first half of the SHA-256 of both, with a
/// separator no URL or hash contains. A collision would take about 2^64
/// work, and would only make the report omit one entry; it never changes
/// what is accepted.
fn point_hash(certificate: &str, key: &str) -> [u8; 16] {
    let digest = crate::crypto::Hash::Sha256.digest(format!("{certificate}\n{key}").as_bytes());
    let mut out = [0; 16];
    out.copy_from_slice(&digest[..16]);
    out
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

fn error(code: ErrorCode, message: impl Into<String>) -> VerificationError {
    VerificationError::new(code, Stage::Revocation, message)
}
/// The error every CRL retrieval limit reports, the engine's and a source's
/// own (such as `HttpCrlSource`'s request and URL caps): `resource_limit_exceeded`
/// at `revocation`, with `details.resource`, `limit`, `used` and `requested`.
/// A source reports one it reaches as an `Abort` carrying these details.
pub fn limit(resource: &str, cap: usize, used: usize, requested: usize) -> VerificationError {
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
    listed_points(cert, true)?
        .into_iter()
        .map(|point| point.map_err(|e| *e))
        .collect()
}

/// Each listed name of `cert`'s cRLDistributionPoints: a URI, or
/// `crl_fetch_denied` for a point with reasons, a cRLIssuer, a relative name or
/// a non-URI name. A malformed extension is an error for the whole
/// certificate. With `strict`, the first unsupported point and the URL count
/// and length limits are errors too, as [`crl_distribution_points`] has always
/// reported them. Otherwise, as OpenSSL and Bouncy Castle never fail a chain
/// over one certificate's points, an over-long URI is one skipped point and
/// every listed URI is returned, however many (CRL-024): the source decides
/// how many it tries, and the report bounds its own entries.
fn listed_points(
    cert: &Certificate,
    strict: bool,
) -> Result<Vec<Result<String, Box<VerificationError>>>, VerificationError> {
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
        if diagnostics < MAX_FAILURES_PER_CERTIFICATE {
            diagnostics += 1;
            listed.push(Err(Box::new(e)));
        } else {
            omitted += 1;
        }
    };
    let mut urls = 0;
    for point in points.0 {
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
            if strict && urls >= MAX_LISTED_URLS {
                return Err(limit("crl_urls", MAX_LISTED_URLS, urls, 1));
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
    // Counted here; the report bounds its own entries again.
    if omitted > 0 {
        listed.push(Err(Box::new(
            error(
                ErrorCode::CrlFetchDenied,
                "further unusable CRL distribution point names are not listed",
            )
            .detail("omitted", omitted),
        )));
    }
    Ok(listed)
}

/// Verify with required revocation against the supplied CRLs; while the
/// result names certificates without a usable CRL (`revocation_unknown`, a
/// revocation naming another path's gap, or the failure of a CRL a source
/// could replace: `crl_expired`, `crl_not_yet_valid`, `invalid_crl`), ask
/// the source about exactly those certificates, and verify again. A good
/// result or any other failure is final. When the source aborts before one of
/// the named certificates was asked about, or while one was being asked about
/// (CRL-047), an unknown status becomes `crl_fetch_aborted` and the
/// other results keep their code with `details.retrieval_aborted`. Whether a CRL applies is
/// decided only by verification. See `docs/crl-retrieval.md`. The passes share
/// one LIMIT-T002 work budget. The input store is never modified.
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
struct Retrieval<'b, 'l> {
    store: TrustStore,
    report: CrlRetrievalReport,
    /// What decoding each body that named a URL showed, by SHA-256: nothing
    /// to report, or the rejection. Bounded by the bodies a verification may
    /// receive (each certificate's response is bounded).
    decoded: BTreeMap<Vec<u8>, Decoded>,
    /// The retained-byte cap, [`MAX_TOTAL_BYTES`] outside tests.
    max_total: usize,
    /// A source just answered by certificate with a new full CRL of the
    /// issuer: verification runs again before any further request, since
    /// only it can tell which certificates that CRL covers.
    reverify: bool,
    /// The source reported `Abort`: nothing further is asked.
    aborted: bool,
    /// The certificate whose request the source aborted.
    aborted_for: Option<String>,
    /// Per certificate, in request order, the listed points its source left
    /// unused when it answered by certificate: recorded only for a
    /// certificate the failed result still names (its status unsettled).
    unused_points: Vec<(String, Vec<String>)>,
    /// Per certificate and normalized URL, what the report already has an
    /// entry for (listed or counted as omitted). Report bookkeeping only: it
    /// keeps no outcome, and entries of one certificate are not contiguous
    /// (the unused points of an earlier certificate are recorded last).
    recorded: BTreeSet<[u8; 16]>,
    /// Per certificate, the failure entries kept, up to
    /// `MAX_FAILURES_PER_CERTIFICATE`.
    kept: BTreeMap<(String, bool), usize>,
    /// Per certificate and kind, where its entry counting the omitted ones is.
    omitted_at: BTreeMap<(String, bool), usize>,
    /// Certificates whose source abort the report already lists past the bound.
    abort_kept: BTreeSet<String>,
    budget: &'b Budget<'l>,
}

fn crl_internal(e: anyhow::Error) -> VerificationError {
    VerificationError::from_internal(e, ErrorCode::InvalidCrl, Stage::Revocation)
}

impl<'b, 'l> Retrieval<'b, 'l> {
    fn new(base: &TrustStore, budget: &'b Budget<'l>) -> Self {
        Self {
            store: base.clone(),
            report: CrlRetrievalReport::default(),
            decoded: BTreeMap::new(),
            max_total: MAX_TOTAL_BYTES,
            reverify: false,
            aborted: false,
            aborted_for: None,
            unused_points: Vec::new(),
            recorded: BTreeSet::new(),
            kept: BTreeMap::new(),
            omitted_at: BTreeMap::new(),
            abort_kept: BTreeSet::new(),
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
        // Logged while the report would still list it: past the bound a
        // certificate's entries are counted, not each logged.
        let about_points = url.is_some() || kind.is_some();
        let listed = self
            .kept
            .get(&(certificate.to_owned(), about_points))
            .copied()
            .unwrap_or(0);
        if listed < MAX_FAILURES_PER_CERTIFICATE {
            self.budget.log.info(
                Stage::Revocation,
                format_args!("CRL evidence missing: {:?}", e.message),
            );
        }
        self.record(certificate, url, &e, kind);
    }

    /// One failure entry per certificate and URL, except a source's first
    /// abort, which is also listed where its URL already has an entry. A
    /// failure without a URL is reached once per certificate (certificates
    /// are deduplicated), so each is listed. The report keeps at most
    /// `MAX_FAILURES_PER_CERTIFICATE` entries of each kind (about points, or
    /// about none) per certificate, and one entry per kind counts the rest.
    fn record(
        &mut self,
        certificate: &str,
        url: Option<&str>,
        e: &VerificationError,
        source_error: Option<CrlSourceErrorKind>,
    ) {
        // A source's first abort is always kept, even where its point already
        // has an entry: it is what ended retrieval.
        let first_abort = source_error == Some(CrlSourceErrorKind::Abort)
            && !self.abort_kept.contains(certificate);
        // One entry per certificate and URL: a repeat of a point, listed or
        // withheld by the bound below, is not counted twice.
        if let Some(url) = url
            && !self.recorded.insert(point_hash(certificate, &url_key(url)))
            && !first_abort
        {
            return;
        }
        // Only the engine's own entry about unusable names carries a count
        // (no source error, no URL); a source's details are never one.
        let more = match (source_error, url) {
            (None, None) => e.details.get("omitted").and_then(|n| n.as_u64()),
            _ => None,
        }
        .unwrap_or(1);
        // Entries about a point and entries about none (unusable names,
        // screening, whole-request failures) are bounded apart, so one kind
        // cannot hide the other.
        // A source's failure is a point's, even one for the whole request.
        let about_points = url.is_some() || source_error.is_some();
        let bucket = (certificate.to_owned(), about_points);
        let kept = self.kept.entry(bucket.clone()).or_default();
        if *kept < MAX_FAILURES_PER_CERTIFICATE || first_abort {
            if *kept < MAX_FAILURES_PER_CERTIFICATE {
                *kept += 1;
            }
            if first_abort {
                self.abort_kept.insert(certificate.to_owned());
            }
            self.push_failure(certificate, url, e, source_error);
            return;
        }
        // Past the bound: one entry per bucket counts the rest.
        if let Some(&at) = self.omitted_at.get(&bucket) {
            let last = &mut self.report.failures[at];
            let total = last.details.get("omitted").and_then(|n| n.as_u64());
            last.details.insert(
                "omitted".into(),
                total.unwrap_or(0).saturating_add(more).into(),
            );
            return;
        }
        let marker = error(
            ErrorCode::ResourceLimitExceeded,
            "further CRL retrieval failures for this certificate are not listed",
        )
        .detail("resource", "crl_failure_entries")
        .detail("limit", MAX_FAILURES_PER_CERTIFICATE)
        .detail("omitted", more)
        .detail("about", if about_points { "points" } else { "no point" });
        self.omitted_at.insert(bucket, self.report.failures.len());
        self.push_failure(certificate, None, &marker, None);
    }

    fn push_failure(
        &mut self,
        certificate: &str,
        url: Option<&str>,
        e: &VerificationError,
        source_error: Option<CrlSourceErrorKind>,
    ) {
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
    /// points that answer left unused, as not used. A certificate whose
    /// status was settled leaves no per-point failure.
    fn report_unused_points(&mut self, named: &[String]) {
        let held = core::mem::take(&mut self.unused_points);
        for (certificate, points) in held {
            if !named.contains(&certificate) {
                continue;
            }
            for point in points {
                let e = error(
                    ErrorCode::CrlFetchFailed,
                    "not used: the CRL source answered for the certificate \
                     without using this point, and its answer did not settle the status",
                );
                self.record(&certificate, Some(&point), &e, None);
            }
        }
    }

    /// Ask the source for CRLs for one certificate. Its listed URIs are read
    /// here, never fetched: unsupported points and malformed URIs are
    /// recorded, and the rest go to the source as a hint, each once, whether
    /// or not another certificate listed it (reusing an earlier answer is the
    /// source's, CRL-033). Returns whether a new CRL was added. The engine's
    /// own limits end the run.
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
        let mut offered = BTreeSet::new();
        for listed in listed {
            let raw = match listed {
                Ok(raw) => raw,
                Err(e) => {
                    self.skip(sha256, None, *e, None);
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
            // The engine keeps no total of the URIs it passes on: that is
            // the source's (CRL-039). Listed twice by this certificate:
            // offered once.
            if offered.insert(url_key(&raw)) {
                points.push(raw);
            }
        }
        // The issuer name is the key for a source that stores CRLs by
        // issuer; a certificate without a readable one is not asked about,
        // and each of its listed points is recorded with that reason. The
        // certificate here is itself a re-encoding (CRL-T010), so its issuer
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
                    // Reported for this certificate only: no source was
                    // given the points.
                    if points.is_empty() {
                        self.record(sha256, None, &e, None);
                    }
                    for point in &points {
                        self.record(sha256, Some(point), &e, None);
                    }
                    return Ok(false);
                }
            },
        };
        // Every certificate that lacks a CRL is asked about, even one whose
        // issuer or points another certificate's request already carried:
        // reusing that answer is the source's (CRL-033). The engine keeps no
        // total of requests: that is the source's to bound (CRL-039). Each
        // certificate is asked about at most once.
        // The retained bytes are what the store holds: a body that did not
        // load, or only repeated a CRL already held, retains nothing. A
        // request's bodies are bounded by what is left, so the store stays
        // within the cap (a CRL's DER is never longer than its body).
        let used = self.store.encoded_len();
        let max_bytes = self.max_total.saturating_sub(used);
        if max_bytes == 0 {
            return Err(limit("retrieval_trust_bytes", self.max_total, used, 1));
        }
        let request = CrlRequest::new(der, issuer, &points, max_bytes);
        self.budget.log.info(
            Stage::Revocation,
            format_args!(
                "asking the CRL source for certificate {sha256}, {} listed points, first {:?}",
                points.len(),
                &points[..points.len().min(LOGGED_POINTS)]
            ),
        );
        let response = match source.crls(&request) {
            Ok(response) => response,
            Err(e) => {
                // The whole request failed: every point it carried yielded
                // nothing for this certificate.
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
        // Bodies are loaded, so their count is fixed; a source may answer each
        // point it was offered (the input's, so as many as the certificate
        // lists) with a failure, and no more than the bound beside.
        if response.crls.len() > MAX_RESPONSE_ENTRIES {
            return Err(limit(
                "crl_response_entries",
                MAX_RESPONSE_ENTRIES,
                0,
                response.crls.len(),
            ));
        }
        let allowed = MAX_RESPONSE_ENTRIES.saturating_add(points.len());
        let entries = response.crls.len().saturating_add(response.failures.len());
        if entries > allowed {
            return Err(limit("crl_response_entries", allowed, 0, entries));
        }
        // A point is answered by a CRL or failure naming it, compared as
        // URLs (a source may report the normalized form).
        let answered: BTreeSet<String> = response
            .crls
            .iter()
            .map(|c| &c.url)
            .chain(response.failures.iter().map(|f| &f.url))
            .filter_map(|url| url.as_deref().map(url_key))
            .collect();
        let unanswered: Vec<String> = points
            .iter()
            .filter(|point| !answered.contains(&url_key(point)))
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
            // No source used these points; they are reported as not used
            // if the status stays unsettled.
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
        // The allowance bounds the response whatever it holds: a replay of a
        // body already held counts like any other, so the rule is one for
        // the engine and every source (a replay adds nothing to the store,
        // but a source cannot tell the engine's room from its own).
        if let Some(e) = body_over_allowance(len, *total, max_bytes) {
            self.skip(sha256, raw_url.as_deref(), e, None);
            return Ok((None, false));
        }
        *total += len;
        // Every body is hashed for the report.
        self.budget.hash_bytes.charge(len).map_err(crl_internal)?;
        let digest = crate::crypto::Hash::Sha256.digest(&crl.bytes);
        self.report.artifacts.push(CrlRetrievalArtifact {
            certificate_sha256: Some(sha256.into()),
            final_url,
            url: url.clone(),
            sha256: hex(&digest),
            bytes: len,
        });
        // Decoding is a pure function of the bytes, so a body that is byte
        // for byte one already decoded in this verification (a source
        // replaying a point several certificates list, or the same answer by
        // certificate for several certificates of one issuer, CRL-051) is not
        // decoded or charged again: what loading it did is reused, and a
        // rejection is reported for this certificate too. This remembers no
        // answer of a source. Every CRL of a body that loaded is in the store,
        // so a replay adds nothing; one naming no URL is still an answer by
        // certificate when a CRL in it names this certificate's issuer, which
        // the issuer names kept from the first decode tell.
        match self.decoded.get(&digest) {
            Some(Decoded::Rejected(e)) => {
                let e = e.clone();
                self.skip(sha256, raw_url.as_deref(), e, None);
                return Ok((None, false));
            }
            Some(Decoded::Loaded(_)) if !without_url => return Ok((None, false)),
            Some(Decoded::Loaded(Some(issuers))) => {
                let answer = issuers.iter().any(|name| name == issuer).then_some(false);
                return Ok((answer, false));
            }
            // Decoded first without the issuer names an answer by
            // certificate needs: decoded again, once.
            Some(Decoded::Loaded(None)) | None => {}
        }
        for _ in 0..8 {
            self.budget
                .decoded_bytes
                .charge(len)
                .map_err(crl_internal)?;
        }
        // Before loading: whether this body brings a full CRL of the issuer
        // that is not already loaded (one PEM may hold several CRLs).
        let issuers = without_url.then(|| crate::trust::crl_issuers(&crl.bytes));
        let of_issuer: Vec<bool> = issuers
            .iter()
            .flatten()
            // Exact bytes: a body whose issuer equals the certificate's only
            // under CRL-041 may be another CA's, which verification sets
            // aside, so it does not count as this issuer's answer.
            .filter(|(name, _, _)| name == issuer)
            .map(|(_, full, der)| *full && !self.store.has_crl(der))
            .collect();
        let prior = self.store.crl_count();
        if let Err(e) = self.store.add_crl(&crl.bytes) {
            let e = error(
                ErrorCode::InvalidCrl,
                format!("decoding retrieved CRL: {e:#}"),
            );
            self.decoded.insert(digest, Decoded::Rejected(e.clone()));
            self.skip(sha256, raw_url.as_deref(), e, None);
            return Ok((None, false));
        }
        self.decoded.insert(
            digest,
            Decoded::Loaded(issuers.map(|all| all.into_iter().map(|(name, _, _)| name).collect())),
        );
        // A PEM response may contain multiple distinct CRLs. Bound the
        // retained store after deduplication, before verification.
        let loaded = self.store.crl_count();
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
        if base.encoded_len() > MAX_TOTAL_BYTES {
            return Err(limit(
                "retrieval_trust_bytes",
                MAX_TOTAL_BYTES,
                0,
                base.encoded_len(),
            ));
        }
        // The verifier decides first, with the supplied CRLs: a good result
        // is final, and so is any failure that names no certificate to ask
        // about. An unknown status names the certificates that lacked a
        // usable CRL; a revocation on one candidate path may name those of
        // another path that could still verify with a CRL; and the failure
        // of a CRL a source could replace (expired, not yet valid, or
        // another replaceable `invalid_crl`) names its certificates. Those
        // are asked about, and the result stands if nothing usable is found.
        let mut result = verify_with(bytes, options, &state.store, format, budget);
        let mut asked = BTreeSet::new();
        let mut authenticated = false;
        loop {
            let unknown = match &result {
                Err(e) if e.code == ErrorCode::RevocationUnknown => e,
                // Any other result that names certificates to ask about (a
                // revocation naming another path's gap, or the failure of a
                // CRL a source could replace): `uncovered` alone decides,
                // so a new code cannot be handled here and not there.
                Err(e) if matches!(uncovered(e), Uncovered::Listed(_)) => e,
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
                // path passes the path checks: no CRL can help and the status is
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
            Err(e) if e.code != ErrorCode::RevocationUnknown && cut_short(&e) => {
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

/// What decoding one retrieved body showed.
enum Decoded {
    /// It did not load: the rejection, reported again for a replay.
    Rejected(VerificationError),
    /// It loaded, so every CRL in it is in the store; with the issuer names
    /// of its CRLs when it was decoded as an answer by certificate.
    Loaded(Option<Vec<Vec<u8>>>),
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
    if unknown.details.get("reason").and_then(|r| r.as_str()) == Some("ambiguous_issuer_keys") {
        return Uncovered::Final;
    }
    let listed = |key: &str| {
        unknown
            .details
            .get(key)
            .and_then(|v| serde_json::from_value::<Vec<CertificateReport>>(v.clone()).ok())
    };
    // Certificates whose only CRLs have expired, or are unusable for
    // another reason a source's CRL could replace, can be refreshed.
    let mut expired = listed("certificates_with_expired_crl").unwrap_or_default();
    // Once each: a certificate can be expired on one path and unusable on
    // another.
    for report in listed(crate::trust::WITH_REPLACEABLE_CRL).unwrap_or_default() {
        if !expired.iter().any(|r| r.sha256 == report.sha256) {
            expired.push(report);
        }
    }
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
            store.crl_count()
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
            .add_roots(include_bytes!("../../tests/fixtures/root.der"))
            .unwrap();
        store
    }
    #[test]
    fn retrieval_cannot_bypass_integrity_trust_or_explicit_revocation() {
        let store = store();
        let options = VerifyOptions::trusted(&store, 1800000000);
        for (bytes, code) in [
            (
                include_bytes!("../../tests/fixtures/bad-crl-discovery-image.exe").as_slice(),
                ErrorCode::ImageDigestMismatch,
            ),
            (
                include_bytes!("../../tests/fixtures/good-pe64.exe").as_slice(),
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
        // Transport policy is the source's (the application's
        // `HttpCrlSource` tests that it refuses a private destination).
        let bytes = include_bytes!("../../tests/fixtures/good-crl-discovery.exe");
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
            include_bytes!("../../tests/fixtures/good-crl-discovery.exe"),
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
                n @ 256..65536 => out.extend([0x82, (n >> 8) as u8, n as u8]),
                n => out.extend([0x83, (n >> 16) as u8, (n >> 8) as u8, n as u8]),
            }
            out.extend_from_slice(body);
            out
        }
        let pe = crate::parse::Pe::parse(include_bytes!(
            "../../tests/fixtures/good-crl-discovery.exe"
        ))
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
        state: &mut Retrieval<'_, '_>,
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
    fn a_source_with_no_cap_is_not_stopped_by_the_engine_on_request_or_url_count() {
        use CrlSourceErrorKind::*;
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let mut source = Kinds::new(vec![Failed]);
        // One URI, many issuers: many requests, one distinct URI. The engine
        // keeps no total of requests (CRL-039); only the source may.
        let shared = |i: usize| {
            use core::str::FromStr;
            let mut cert = signer_with_points("shared", 1);
            cert.tbs_certificate.issuer =
                x509_cert::name::Name::from_str(&format!("CN=issuer {i}")).unwrap();
            cert
        };
        let requests = 192;
        for i in 0..requests {
            assert!(!ask(&mut state, &format!("c{i}"), &shared(i), &mut source).unwrap());
        }
        assert_eq!(source.calls, requests);
        // Nor does it cap the distinct URIs it passes on: that is the
        // source's too. 12 certificates of 16 points each are 192 URIs.
        let mut state = Retrieval::new(&store, &budget);
        let mut source = Kinds::new(vec![Failed]);
        for i in 0..12 {
            ask(
                &mut state,
                &format!("u{i}"),
                &signer_with_points(&format!("u{i}"), 16),
                &mut source,
            )
            .unwrap();
        }
        assert_eq!(source.urls.len(), 192);
    }
    #[test]
    fn every_certificate_of_one_issuer_is_offered_to_the_source_with_its_points() {
        use CrlSourceErrorKind::*;
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let mut source = Kinds::new(vec![Failed]);
        // Many certificates of one issuer listing one URL: each is asked
        // about with the point (CRL-033); reusing the first answer is the
        // source's, which this one does not do.
        for i in 0..=64 {
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
        assert_eq!(source.calls, 65);
        assert_eq!(source.urls.len(), 65);
        // Each certificate reports the shared point's failure.
        for i in 0..=64 {
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
        // recorded as given, but the source's failure is, for every
        // certificate it was offered for.
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
    fn every_certificate_is_asked_whatever_its_issuer_role_or_authority_key() {
        // The engine keeps no issuer key: a CA and an end entity of one
        // issuer, a certificate whose authorityKeyIdentifier cannot be read,
        // and a second certificate of an issuer already asked about are all
        // asked, even with no point to pass on (CRL-033).
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
        let mut broken = leaf.clone();
        let extensions = broken.tbs_certificate.extensions.as_mut().unwrap();
        let aki = extensions
            .iter_mut()
            .find(|e| e.extn_id.to_string() == "2.5.29.35")
            .expect("the signer has an authorityKeyIdentifier");
        aki.extn_value = ::der::asn1::OctetString::new(vec![0x04, 0x00]).unwrap();
        ask(&mut state, "leaf", &leaf, &mut source).unwrap();
        ask(&mut state, "ca", &ca, &mut source).unwrap();
        ask(&mut state, "leaf2", &leaf, &mut source).unwrap();
        ask(&mut state, "broken", &broken, &mut source).unwrap();
        ask(&mut state, "broken2", &broken, &mut source).unwrap();
        assert_eq!(source.calls, 5);
        assert!(source.urls.is_empty());
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
    fn a_failure_without_a_url_is_recorded_as_it_is_when_every_point_was_named() {
        // With no point left unanswered, a failure naming no URL answers
        // none: it is recorded once, as it is.
        // Not held, it keeps its place in response order, before a body
        // rejected on load (CRL-049).
        struct NamesThenDenies;
        impl CrlSource for NamesThenDenies {
            fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(CrlResponse::new()
                    .with_failure(
                        CrlSourceError::new(CrlSourceErrorKind::Failed, "down")
                            .with_url(request.distribution_points[0].clone()),
                    )
                    .with_failure(CrlSourceError::new(CrlSourceErrorKind::Denied, "policy"))
                    .with_crl(SourcedCrl::new(
                        include_bytes!("../../tests/fixtures/root.der").to_vec(),
                    )))
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        ask(
            &mut state,
            "a",
            &signer_with_points("a", 1),
            &mut NamesThenDenies,
        )
        .unwrap();
        let entries: Vec<_> = state
            .report
            .failures
            .iter()
            .map(|f| (f.url.is_some(), f.code))
            .collect();
        assert_eq!(
            entries,
            [
                (true, ErrorCode::CrlFetchFailed),
                (false, ErrorCode::CrlFetchDenied),
                (false, ErrorCode::InvalidCrl)
            ]
        );
    }
    #[test]
    fn the_first_failure_without_a_url_comes_after_the_bodies_rejected_on_load() {
        // `CrlRetrievalReport::failures`: the held failure answers the point
        // after the body that is no CRL is recorded, though it came first.
        struct DeniesThenNotACrl;
        impl CrlSource for DeniesThenNotACrl {
            fn crls(&mut self, _: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(CrlResponse::new()
                    .with_failure(CrlSourceError::new(CrlSourceErrorKind::Denied, "policy"))
                    .with_crl(SourcedCrl::new(
                        include_bytes!("../../tests/fixtures/root.der").to_vec(),
                    )))
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        ask(
            &mut state,
            "a",
            &signer_with_points("a", 1),
            &mut DeniesThenNotACrl,
        )
        .unwrap();
        let entries: Vec<_> = state
            .report
            .failures
            .iter()
            .map(|f| (f.url.is_some(), f.code))
            .collect();
        assert_eq!(
            entries,
            [
                (false, ErrorCode::InvalidCrl),
                (true, ErrorCode::CrlFetchDenied)
            ]
        );
    }
    #[test]
    fn the_first_of_two_aborts_without_a_url_answers_the_points() {
        // Another URL-less abort stops the first answering the points only
        // when the first is no abort itself.
        struct AbortsTwice;
        impl CrlSource for AbortsTwice {
            fn crls(&mut self, _: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(CrlResponse::new()
                    .with_failure(CrlSourceError::new(CrlSourceErrorKind::Abort, "first"))
                    .with_failure(CrlSourceError::new(CrlSourceErrorKind::Abort, "second")))
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        ask(
            &mut state,
            "a",
            &signer_with_points("a", 2),
            &mut AbortsTwice,
        )
        .unwrap();
        let entries: Vec<_> = state
            .report
            .failures
            .iter()
            .map(|f| (f.url.is_some(), f.code, f.source_error))
            .collect();
        let abort = (ErrorCode::CrlFetchAborted, Some(CrlSourceErrorKind::Abort));
        assert_eq!(
            entries,
            [
                (false, abort.0, abort.1),
                (true, abort.0, abort.1),
                (true, abort.0, abort.1)
            ]
        );
    }
    #[test]
    fn a_whole_request_error_records_the_point_it_names_last() {
        // CRL-049: the points it does not name, in listed order, then the
        // one it names, even when that one is listed first.
        struct FailsNamingFirst;
        impl CrlSource for FailsNamingFirst {
            fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Err(CrlSourceError::new(CrlSourceErrorKind::Failed, "down")
                    .with_url(request.distribution_points[0].clone()))
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        ask(
            &mut state,
            "a",
            &signer_with_points("a", 3),
            &mut FailsNamingFirst,
        )
        .unwrap();
        let urls: Vec<_> = state
            .report
            .failures
            .iter()
            .map(|f| f.url.as_deref().unwrap())
            .collect();
        assert_eq!(
            urls,
            [
                "http://crl.example.invalid/a-1.crl",
                "http://crl.example.invalid/a-2.crl",
                "http://crl.example.invalid/a-0.crl"
            ]
        );
        // A request with no points records the error once, as it is. (One
        // naming a URL outside the request is recorded for each point in
        // listed order: `a_whole_request_error_naming_a_foreign_url_is_not_attributed_to_the_certificate`.)
        // A URL outside the request is dropped first, so the entry has none.
        struct Fails;
        impl CrlSource for Fails {
            fn crls(&mut self, _: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Err(CrlSourceError::new(CrlSourceErrorKind::Failed, "down")
                    .with_url("http://crl.example.invalid/foreign.crl"))
            }
        }
        let mut state = Retrieval::new(&store, &budget);
        ask(&mut state, "b", &signer_with_uris(&[]), &mut Fails).unwrap();
        let entries: Vec<_> = state
            .report
            .failures
            .iter()
            .map(|f| (f.url.clone(), f.code))
            .collect();
        assert_eq!(entries, [(None, ErrorCode::CrlFetchFailed)]);
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
                    SourcedCrl::new(include_bytes!("../../tests/fixtures/good.crl").to_vec())
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
        // the run. An over-long URI is skipped and recorded; every other
        // listed point reaches the source, however many (CRL-024).
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
        assert_eq!(source.urls.len(), 17);
        assert!(source.urls.len() > MAX_LISTED_URLS);
        let resources: Vec<_> = state
            .report
            .failures
            .iter()
            .filter_map(|f| f.details.get("resource").and_then(|r| r.as_str()))
            .collect();
        // The 17 points past the report bound are counted in one entry.
        assert_eq!(resources, ["crl_url_bytes", "crl_failure_entries"]);
        // The strict public discovery still reports the limit as an error.
        assert!(crl_distribution_points(&signer_with_uris(&uris)).is_err());
    }
    #[test]
    fn the_report_bounds_failure_entries_per_certificate_not_the_points_offered() {
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let mut source = Kinds::new(vec![CrlSourceErrorKind::Failed]);
        let uris: Vec<String> = (0..60)
            .map(|i| format!("http://crl.example.invalid/p-{i}.crl"))
            .collect();
        ask(&mut state, "a", &signer_with_uris(&uris), &mut source).unwrap();
        assert_eq!(source.urls.len(), 60);
        let failures = &state.report.failures;
        assert_eq!(failures.len(), MAX_FAILURES_PER_CERTIFICATE + 1);
        let last = failures.last().unwrap();
        assert_eq!(last.url, None);
        assert_eq!(last.details["omitted"], 60 - MAX_FAILURES_PER_CERTIFICATE);
    }
    #[test]
    fn a_certificate_listing_more_points_than_a_response_may_carry_does_not_end_the_run() {
        // CRL-024: 70 points are 70 failure entries from a source that
        // answers each; the response bound allows one entry per point offered.
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let mut source = Kinds::new(vec![CrlSourceErrorKind::Failed]);
        let uris: Vec<String> = (0..70)
            .map(|i| format!("http://crl.example.invalid/q-{i}.crl"))
            .collect();
        ask(&mut state, "a", &signer_with_uris(&uris), &mut source).unwrap();
        assert_eq!(source.urls.len(), 70);
        assert_eq!(
            state.report.failures.len(),
            MAX_FAILURES_PER_CERTIFICATE + 1
        );
    }
    #[test]
    fn omitted_counts_carry_over_and_a_source_never_sets_one() {
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let e = error(ErrorCode::CrlFetchFailed, "x");
        for i in 0..MAX_FAILURES_PER_CERTIFICATE {
            state.record("a", Some(&format!("http://h.invalid/{i}")), &e, None);
        }
        // Entries about no point are bounded apart: this one is kept, and
        // the engine's own count past that bound is carried.
        for _ in 0..MAX_FAILURES_PER_CERTIFICATE {
            state.record("a", None, &e, None);
        }
        let many = error(ErrorCode::CrlFetchDenied, "names").detail("omitted", 200);
        state.record("a", None, &many, None);
        // A source's failure for the whole request is not hidden by them.
        let failed = Some(CrlSourceErrorKind::Failed);
        state.record("c", None, &many, None);
        for _ in 0..MAX_FAILURES_PER_CERTIFICATE {
            state.record("c", None, &e, None);
        }
        state.record("c", None, &e, failed);
        assert!(
            state
                .report
                .failures
                .iter()
                .any(|f| f.certificate_sha256 == "c" && f.source_error == failed)
        );
        // Two points past the bound, one recorded twice; a source's detail is
        // not a count, and a huge one cannot overflow.
        let lying = error(ErrorCode::CrlFetchFailed, "x").detail("omitted", u64::MAX);
        let kind = Some(CrlSourceErrorKind::Failed);
        state.record("a", Some("http://h.invalid/x"), &lying, kind);
        state.record("a", Some("http://h.invalid/x"), &lying, kind);
        state.record("a", Some("http://h.invalid/y"), &lying, kind);
        let counts: Vec<_> = state
            .report
            .failures
            .iter()
            .filter(|f| f.certificate_sha256 == "a")
            .filter_map(|f| f.details.get("omitted").and_then(|n| n.as_u64()))
            .collect();
        assert_eq!(counts, [200, 2]);
        // A source's abort past the bound stays listed, once.
        let abort = CrlSourceErrorKind::Abort;
        state.record("a", Some("http://h.invalid/z"), &e, Some(abort));
        state.record("a", Some("http://h.invalid/w"), &e, Some(abort));
        let aborts = state
            .report
            .failures
            .iter()
            .filter(|f| f.source_error == Some(abort))
            .count();
        assert_eq!(aborts, 1);
        // An abort for a point that already has an entry is still listed.
        let mut state = Retrieval::new(&store, &budget);
        let u = "http://h.invalid/u";
        state.record("b", Some(u), &e, Some(CrlSourceErrorKind::Failed));
        state.record("b", Some(u), &e, Some(abort));
        assert!(
            state
                .report
                .failures
                .iter()
                .any(|f| f.source_error == Some(abort))
        );
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
        state.max_total = state.store.encoded_len() + 10;
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
    fn the_retained_bytes_count_what_the_store_holds_and_a_decoded_body_is_work() {
        // A source that answers a shared point from its cache returns the
        // same body for each certificate (CRL-051): each certificate gets an
        // artifact, but the store holds the CRL once, so repeats leave the
        // retained bytes, and every later request's allowance, unchanged,
        // and are not decoded again (so cannot exhaust the work budget).
        // A body that is not exactly held is decoded and charged.
        struct Cached;
        impl CrlSource for Cached {
            fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(fetch_each(request, |url, _| {
                    Ok(
                        SourcedCrl::new(include_bytes!("../../tests/fixtures/good.crl").to_vec())
                            .with_url(url),
                    )
                }))
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let cert = signer_with_points("shared", 1);
        assert!(ask(&mut state, "a", &cert, &mut Cached).unwrap());
        let retained = state.store.encoded_len();
        assert!(retained > store.encoded_len());
        let decoded = |budget: &Budget| budget.decoded_bytes.used();
        let after_first = decoded(&budget);
        for i in 0..64 {
            assert!(!ask(&mut state, &format!("c{i}"), &cert, &mut Cached).unwrap());
        }
        assert_eq!(state.store.encoded_len(), retained);
        // The store already holds the exact DER: nothing is decoded again.
        assert_eq!(decoded(&budget), after_first);
        assert_eq!(state.report.artifacts.len(), 65);
        assert!(
            state.report.failures.is_empty(),
            "{:?}",
            state.report.failures
        );
        // A body that does not load retains nothing either, and is rejected
        // for each certificate it is returned for.
        struct NotACrl;
        impl CrlSource for NotACrl {
            fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(fetch_each(request, |url, _| {
                    Ok(SourcedCrl::new(b"not a CRL".to_vec()).with_url(url))
                }))
            }
        }
        let mut state = Retrieval::new(&store, &budget);
        ask(&mut state, "a", &cert, &mut NotACrl).unwrap();
        ask(&mut state, "b", &cert, &mut NotACrl).unwrap();
        assert_eq!(state.store.encoded_len(), store.encoded_len());
        let rejected_for = |state: &Retrieval<'_, '_>| -> Vec<String> {
            state
                .report
                .failures
                .iter()
                .filter(|f| f.code == ErrorCode::InvalidCrl)
                .map(|f| f.certificate_sha256.clone())
                .collect()
        };
        assert_eq!(rejected_for(&state), ["a", "b"]);
        // Decoded once: the rejection of a repeat is reported for each
        // certificate without decoding or charging it again.
        let junk = budget.decoded_bytes.used();
        for i in 0..64 {
            ask(&mut state, &format!("d{i}"), &cert, &mut NotACrl).unwrap();
        }
        assert_eq!(budget.decoded_bytes.used(), junk);
        assert_eq!(rejected_for(&state).len(), 66);
        // A body naming no URL (an answer by certificate) is decoded once
        // too, and a replay is still an answer by certificate for its issuer.
        struct ByCertificate;
        impl CrlSource for ByCertificate {
            fn crls(&mut self, _: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(CrlResponse::new().with_crl(SourcedCrl::new(
                    include_bytes!("../../tests/fixtures/good.crl").to_vec(),
                )))
            }
        }
        let mut state = Retrieval::new(&store, &budget);
        let before = budget.decoded_bytes.used();
        ask(&mut state, "a", &cert, &mut ByCertificate).unwrap();
        let one = budget.decoded_bytes.used() - before;
        assert!(one > 0);
        assert!(state.reverify);
        state.reverify = false;
        ask(&mut state, "b", &cert, &mut ByCertificate).unwrap();
        assert_eq!(budget.decoded_bytes.used() - before, one);
        // Answered by certificate (its point left unused), with nothing new.
        assert!(!state.reverify);
        assert!(state.unused_points.iter().any(|(held, _)| held == "b"));
    }
    #[test]
    fn a_replayed_body_counts_against_the_requests_allowance() {
        // The allowance is the room the response may have, replay or not (one
        // rule for the engine and every source): near the cap, a replay of a
        // CRL the store already holds is refused like a new one, and the
        // report says so. This pins the rule: a partial exemption fails it.
        struct Cached;
        impl CrlSource for Cached {
            fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(fetch_each(request, |url, _| {
                    Ok(
                        SourcedCrl::new(include_bytes!("../../tests/fixtures/good.crl").to_vec())
                            .with_url(url),
                    )
                }))
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let cert = signer_with_points("shared", 1);
        ask(&mut state, "a", &cert, &mut Cached).unwrap();
        state.max_total = state.store.encoded_len() + 1;
        ask(&mut state, "b", &cert, &mut Cached).unwrap();
        assert_eq!(state.report.artifacts.len(), 1);
        assert_eq!(state.report.failures.len(), 1);
        assert_eq!(state.report.failures[0].certificate_sha256, "b");
        assert_eq!(
            state.report.failures[0].details["resource"],
            "crl_response_bytes"
        );
        // With room, the replay is accepted and reports its artifact.
        state.max_total = MAX_TOTAL_BYTES;
        ask(&mut state, "c", &cert, &mut Cached).unwrap();
        assert_eq!(state.report.artifacts.len(), 2);
    }
    #[test]
    fn a_certificates_report_entries_are_deduplicated_when_they_interleave() {
        // The unused points of an earlier certificate are recorded after a
        // later certificate's entries: its repeats are still one entry.
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let e = error(ErrorCode::CrlFetchFailed, "down");
        let (p, q) = (
            "http://crl.example.invalid/p",
            "http://crl.example.invalid/q",
        );
        state.record("a", Some(p), &e, None);
        state.record("b", Some(q), &e, None);
        state.record("a", Some(p), &e, None);
        state.record("b", Some(q), &e, None);
        assert_eq!(state.report.failures.len(), 2);
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
                        include_bytes!("../../tests/fixtures/good.crl").to_vec(),
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
    }
    #[test]
    fn a_source_is_asked_about_each_certificate_at_most_once_in_a_verification() {
        // The engine keeps no total of requests (CRL-039); what bounds them
        // is that each certificate is asked about once, however many rounds
        // verification runs.
        struct Source(Vec<Vec<u8>>);
        impl CrlSource for Source {
            fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                self.0.push(request.certificate.to_vec());
                Ok(CrlResponse::new().with_crl(SourcedCrl::new(
                    include_bytes!("../../tests/fixtures/good.crl").to_vec(),
                )))
            }
        }
        let trust = store();
        let options = VerifyOptions::trusted(&trust, 1_800_000_000);
        let mut source = Source(Vec::new());
        let _ = crate::verify::Verifier::new(&options).verify_with_crl_source(
            include_bytes!("../../tests/fixtures/good-crl-discovery.exe"),
            Some("a.exe"),
            &mut source,
        );
        let mut distinct = source.0.clone();
        distinct.sort();
        distinct.dedup();
        assert!(!source.0.is_empty());
        assert_eq!(source.0.len(), distinct.len());
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
        let input = include_bytes!("../../tests/fixtures/good-crl-discovery.exe");
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
                        include_bytes!("../../tests/fixtures/good.crl").to_vec(),
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
            Certificate::from_der(include_bytes!("../../tests/fixtures/path-issuer.der")).unwrap();
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
    fn a_point_one_certificates_answer_left_unused_is_reported_as_not_used() {
        // Certificate A is answered by its issuer's CRL without a URL and
        // leaves its point unused; certificate B, of another issuer, lists
        // the same point, which is then requested and fails. A's entry is its
        // own request's: the engine keeps no outcome of a point across
        // certificates.
        struct Source(usize);
        impl CrlSource for Source {
            fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                self.0 += 1;
                Ok(match self.0 {
                    1 => CrlResponse::new().with_crl(SourcedCrl::new(
                        include_bytes!("../../tests/fixtures/good.crl").to_vec(),
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
        state.report_unused_points(&["a".to_string()]);
        let a_entries: Vec<_> = state
            .report
            .failures
            .iter()
            .filter(|f| f.certificate_sha256 == "a")
            .map(|f| (f.url.clone().unwrap(), f.message.starts_with("not used")))
            .collect();
        assert_eq!(
            a_entries,
            [("http://crl.example.invalid/shared-0.crl".to_string(), true)]
        );
        // B's own request reports the source's failure.
        assert!(
            state
                .report
                .failures
                .iter()
                .any(|f| f.certificate_sha256 == "b" && f.message == "down")
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
    }
    #[test]
    fn a_source_that_aborts_a_whole_request_over_its_own_cap_stops_retrieval() {
        // What the built-in source reports past its request cap (CRL-039):
        // the engine records it as an abort, with the source's details.
        struct Spent;
        impl CrlSource for Spent {
            fn crls(&mut self, _: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Err(CrlSourceError::new(CrlSourceErrorKind::Abort, "spent")
                    .detail("resource", "crl_requests"))
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let cert = signer_with_points("spent", 1);
        assert!(!ask(&mut state, "c", &cert, &mut Spent).unwrap());
        assert!(state.aborted);
        let failure = &state.report.failures[0];
        assert_eq!(failure.code, ErrorCode::CrlFetchAborted);
        assert_eq!(failure.details["resource"], "crl_requests");
    }
    #[test]
    fn re_offered_points_are_not_stopped_by_the_engine_on_request_count() {
        struct Source(usize);
        impl CrlSource for Source {
            fn crls(&mut self, _: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                self.0 += 1;
                Ok(CrlResponse::new().with_crl(SourcedCrl::new(
                    include_bytes!("../../tests/fixtures/good.crl").to_vec(),
                )))
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        let mut source = Source(0);
        let cert = signer_with_points("shared", 2);
        let offers = 128;
        for index in 0..offers {
            ask(&mut state, &format!("c{index}"), &cert, &mut source).unwrap();
        }
        // The points were offered every time and cost no URI allowance; how
        // often a source may be asked is the source's to decide (CRL-039).
        assert_eq!(source.0, offers);
    }
    #[test]
    fn a_source_answering_by_certificate_never_exhausts_the_uri_limit() {
        // Five certificates, each listing the same 16 points, all answered
        // by the issuer's CRL without a URL: the points are offered every
        // time; each stays open for a later certificate.
        struct Source;
        impl CrlSource for Source {
            fn crls(&mut self, _: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(CrlResponse::new().with_crl(SourcedCrl::new(
                    include_bytes!("../../tests/fixtures/good.crl").to_vec(),
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
                    include_bytes!("../../tests/fixtures/good.crl").to_vec(),
                ));
                if self.0 == 2 {
                    response = response.with_crl(
                        SourcedCrl::new(
                            include_bytes!("../../tests/fixtures/crl-root-idp-named-point.crl")
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
        let mut full = Source(include_bytes!("../../tests/fixtures/good.crl"));
        ask(&mut state, "c0", &cert, &mut full).unwrap();
        assert!(state.reverify);
        // The same body again adds nothing: no reason to verify again.
        state.reverify = false;
        ask(&mut state, "c1", &cert, &mut full).unwrap();
        assert!(!state.reverify);
        // A partition answers only the certificate it was returned for.
        let mut state = Retrieval::new(&store, &budget);
        let mut partition = Source(include_bytes!(
            "../../tests/fixtures/crl-root-idp-named-point.crl"
        ));
        ask(&mut state, "p0", &cert, &mut partition).unwrap();
        assert!(!state.reverify);
        // One PEM body holding the loaded full CRL and a new partition: the
        // full CRL is not new, so no reason to verify again.
        let pem = |der: &[u8]| {
            ::der::pem::encode_string("X509 CRL", ::der::pem::LineEnding::LF, der).unwrap()
        };
        let both = pem(include_bytes!("../../tests/fixtures/good.crl"))
            + &pem(include_bytes!(
                "../../tests/fixtures/crl-root-idp-named-point.crl"
            ));
        let mut state = Retrieval::new(&store, &budget);
        let mut full = Source(include_bytes!("../../tests/fixtures/good.crl"));
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
        let mut delta = Source(include_bytes!("../../tests/fixtures/crl-root-delta.crl"));
        ask(&mut state, "d0", &cert, &mut delta).unwrap();
        assert!(!state.reverify);
        // A body whose URL is withheld from the report is not an answer by
        // certificate: its certificate's points are still recorded.
        struct Credentialed;
        impl CrlSource for Credentialed {
            fn crls(&mut self, _: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(CrlResponse::new().with_crl(
                    SourcedCrl::new(include_bytes!("../../tests/fixtures/good.crl").to_vec())
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
        assert_eq!(listed.len(), MAX_FAILURES_PER_CERTIFICATE + 1);
        let last = listed.last().unwrap().as_ref().unwrap_err();
        assert_eq!(last.details["omitted"], 200 - MAX_FAILURES_PER_CERTIFICATE);
        // The strict public discovery still fails at the first such name.
        assert!(crl_distribution_points(&cert).is_err());
    }
    #[test]
    fn a_rejected_body_under_an_unhygienic_spelling_keeps_its_point() {
        // The body for the point is not a CRL and its URL has a trailing
        // space: the rejection is recorded, without the URL, for each
        // certificate the point was offered for.
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
                        include_bytes!("../../tests/fixtures/good.crl").to_vec(),
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
        assert!(state.unused_points.iter().any(|(held, _)| held == "a"));
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
        // One request for the certificate, not one per URI.
        assert_eq!(source.calls, 1);
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
    fn uris_are_deduplicated_per_certificate_and_screened_for_hygiene() {
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
        // A second certificate listing the same URL offers it again: reusing
        // the earlier answer is the source's (CRL-033). Its own failure is
        // recorded for it.
        ask(
            &mut state,
            "b",
            &signer_with_uris(&["http://crl.example.invalid/a.crl".into()]),
            &mut source,
        )
        .unwrap();
        assert_eq!(source.urls.len(), 2);
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
                        include_bytes!("../../tests/fixtures/good.crl").to_vec(),
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
    fn an_oversized_body_naming_its_point_is_its_only_failure() {
        // CRL-046: a body naming the point answers it, so the point is not
        // also recorded as one the source left unanswered. Two rules keep
        // this: the body answers the point, and a point is recorded once.
        struct Named;
        impl CrlSource for Named {
            fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
                Ok(CrlResponse::new().with_crl(
                    SourcedCrl::new(vec![0; MAX_CRL_BYTES + 1])
                        .with_url(request.distribution_points[0].clone()),
                ))
            }
        }
        let store = store();
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        assert!(!ask(&mut state, "a", &signer_with_points("a", 1), &mut Named).unwrap());
        let seen: Vec<_> = state
            .report
            .failures
            .iter()
            .map(|f| (f.code, f.details.get("resource").cloned()))
            .collect();
        assert_eq!(
            seen,
            [(
                ErrorCode::ResourceLimitExceeded,
                Some("crl_response_bytes".into())
            )]
        );
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
        // certificate of the same issuer is asked with both points too.
        assert_eq!(source.0, [2, 2]);
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
                    include_bytes!("../../tests/fixtures/good.crl").to_vec(),
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
                    include_bytes!("../../tests/fixtures/good.crl"),
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
                    include_bytes!("../../tests/fixtures/path-root.crl").to_vec(),
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
        for (bodies, failures, bound) in [
            // Bodies are bound at 64; bodies and failures together at 64
            // plus the one point this request offered.
            (MAX_RESPONSE_ENTRIES + 1, 0, MAX_RESPONSE_ENTRIES),
            (0, MAX_RESPONSE_ENTRIES + 2, MAX_RESPONSE_ENTRIES + 1),
            (MAX_RESPONSE_ENTRIES, 2, MAX_RESPONSE_ENTRIES + 1),
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
            assert_eq!(e.details["limit"], bound);
            assert!(state.report.artifacts.is_empty());
        }
        // At the limit, every entry is taken.
        let budget = Budget::default();
        let mut state = Retrieval::new(&store, &budget);
        ask(
            &mut state,
            "a",
            &signer_with_points("a", 1),
            &mut Floods(MAX_RESPONSE_ENTRIES, 1),
        )
        .unwrap();
        assert_eq!(state.report.artifacts.len(), MAX_RESPONSE_ENTRIES);
    }
    #[test]
    fn a_confirmation_disagreement_is_final_for_retrieval() {
        let unknown = || error(ErrorCode::RevocationUnknown, "unknown");
        // The verifier rejected a path every certificate of which had a CRL.
        assert!(matches!(
            uncovered(&unknown().detail("reason", "ambiguous_issuer_keys")),
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
        let input = include_bytes!("../../tests/fixtures/good-crl-discovery.exe");
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
        let pe = crate::parse::Pe::parse(include_bytes!(
            "../../tests/fixtures/good-crl-discovery.exe"
        ))
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
            "../../tests/fixtures/crl-leaf-crl-dp-mixed.exe"
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
