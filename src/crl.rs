//! The default CRL source: bounded public HTTP. The engine has no transport
//! and applies no transport policy; this source owns what to fetch, how often
//! and how much (CRL-039, `docs/crl-retrieval.md`).
use rssig_engine::{
    domain::{CrlSourceErrorKind, ErrorCode, Stage, VerificationError},
    retrieval::{
        CrlRequest, CrlResponse, CrlSource, CrlSourceError, MAX_CRL_BYTES, MAX_RESPONSE_ENTRIES,
        SourcedCrl, fetch_each, limit,
    },
};
use std::{
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    sync::mpsc,
    time::{Duration, Instant},
};
use url::{Host, Url};
/// What a source closed by a DNS timeout reports, on every path.
const CLOSED_AFTER_DNS_TIMEOUT: &str = "CRL source is closed after a DNS timeout";
const DEADLINE: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const HEADER_LIMIT: usize = 16 * 1024;
/// Requests to this source per verification: calls to [`CrlSource::crls`]
/// (one per certificate) that fetch a point, counted at the first point
/// fetched, even one the policy then refuses. A call with no point, or whose
/// points are all answered from this verification's memory, is not counted.
/// Once the cap is reached, the first point a call would fetch is answered
/// with an `Abort` with `details.resource` `crl_requests`, which ends
/// retrieval; points answered from memory before it still are. The engine
/// keeps no such total (CRL-039): this source does.
pub const MAX_SOURCE_REQUESTS: usize = 64;
/// Distinct URLs (compared after normalization) per verification that this
/// source is asked to fetch. A URL answered earlier in the verification is
/// answered again without a slot. The engine keeps no such total (CRL-039):
/// this source does, and reports the first one past it as an `Abort` with
/// `details.resource` `crl_source_urls`.
pub const MAX_SOURCE_URLS: usize = 64;
/// Points of one certificate that this source fetches per request: the first
/// ones it reaches that are not answered from this verification's memory
/// (those are answered again, up to the 64 bodies a response may hold,
/// `MAX_RESPONSE_ENTRIES`; the points past those are denied with
/// `crl_response_entries`). The others are
/// reported as `Denied` with `details.resource` `crl_request_points` and
/// `requested` the call's distinct points it reached and would fetch, spend no
/// request and no distinct-URL slot, and so
/// cannot end the verification for the certificates after it (CRL-024: the
/// engine offers every point, and a source decides how many it tries).
pub const MAX_POINTS_PER_REQUEST: usize = 16;
/// HTTP requests per verification, redirects included. This source's own
/// fetch policy (CRL-039), reported past it as an `Abort` with
/// `details.resource` `crl_http_requests`.
pub const MAX_HTTP_REQUESTS: usize = 16;
/// Bytes read from the network per verification, headers included. This
/// source's own fetch policy (CRL-039), reported past it as an `Abort` with
/// `details.resource` `crl_network_bytes`. The engine bounds what it retains
/// separately.
pub const MAX_NETWORK_BYTES: usize = 32 * 1024 * 1024;

fn error(code: ErrorCode, message: impl Into<String>) -> VerificationError {
    VerificationError::new(code, Stage::Revocation, message)
}
/// Whether a URL's outcome is kept for the verification whatever a later
/// request's allowance: not an abort, and not a size failure under an
/// allowance smaller than the fixed per-body cap (`crl_response_bytes` with a
/// `limit` below [`MAX_CRL_BYTES`]), which `too_big` keeps with its allowance.
/// A body over the fixed cap itself is kept: it fails every time.
fn cacheable(outcome: &Result<SourcedCrl, CrlSourceError>) -> bool {
    match outcome {
        Ok(_) => true,
        Err(e) => {
            e.kind != CrlSourceErrorKind::Abort
                && !(e.details.get("resource") == Some(&"crl_response_bytes".into())
                    && e.details
                        .get("limit")
                        .and_then(|l| l.as_u64())
                        .is_none_or(|l| l < MAX_CRL_BYTES as u64))
        }
    }
}
/// The size a kept size failure saw: at least what was read plus what was
/// refused, so a request with no more room than that fails the same way.
fn seen_size(e: &CrlSourceError) -> usize {
    let seen = |field: &str| e.details.get(field).and_then(|v| v.as_u64()).unwrap_or(0);
    seen("used").saturating_add(seen("requested")) as usize
}
/// The key a URL's outcome is kept under in one verification: its parsed,
/// normalized form, as the engine compares points, for a URL the policy
/// allows; its own text for one the policy refuses.
fn url_key(raw: &str) -> String {
    // A spelling parsing would shorten or clean (whitespace, control
    // characters, backslashes, or over the length the policy allows) keeps
    // its own text: normalized, it could share a URL the policy allows. Any
    // other spelling, allowed or refused (its scheme, host or port), keeps
    // what makes it refused when normalized, so it is normalized, as the
    // engine compares points.
    if refused_before_parsing(raw) {
        return raw.to_owned();
    }
    Url::parse(raw).map_or_else(|_| raw.to_owned(), |u| u.to_string())
}
/// What `checked_url` refuses before parsing, because parsing would change
/// the string: over 2,048 bytes, whitespace (as the engine's own screening,
/// any Unicode whitespace; `Url::parse` would trim it), control characters
/// or backslashes. `url_key` keys such a spelling by its own text.
fn refused_before_parsing(raw: &str) -> bool {
    raw.len() > 2048
        || raw
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '\\')
}
fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || a >= 224
                || (a == 100 && (64..=127).contains(&b))
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192
                    && (b == 168 || (b == 0 && (c == 0 || c == 2)) || (b == 88 && c == 99)))
                || (a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                || (a == 203 && b == 0 && c == 113))
        }
        IpAddr::V6(ip) => {
            let s = ip.segments();
            (s[0] & 0xe000) == 0x2000
                && !(s[0] == 0x2001 && (s[1] < 0x200 || s[1] == 0xdb8))
                && s[0] != 0x2002
                && !(s[0] == 0x3fff && s[1] < 0x1000)
        }
    }
}
fn checked_url(raw: &str) -> Result<Url, VerificationError> {
    let denied = || {
        error(
            ErrorCode::CrlFetchDenied,
            "CRL URL must be public HTTP on port 80 without credentials or fragments",
        )
    };
    let not_public = || {
        error(
            ErrorCode::CrlFetchDenied,
            "CRL URL host is not public: a private, reserved or special-use name or address",
        )
    };
    // The string as given must be the URL that is checked.
    if refused_before_parsing(raw) {
        return Err(error(
            ErrorCode::CrlFetchDenied,
            "CRL URL is over 2,048 bytes or has whitespace, control characters or backslashes",
        ));
    }
    let url = Url::parse(raw)
        .map_err(|_| error(ErrorCode::CrlFetchDenied, "CRL URL is not an absolute URL"))?;
    if url.scheme() != "http"
        || url.port_or_known_default() != Some(80)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(denied());
    }
    match url.host().ok_or_else(denied)? {
        Host::Ipv4(ip) if !public_ip(IpAddr::V4(ip)) => return Err(not_public()),
        Host::Ipv6(ip) if !public_ip(IpAddr::V6(ip)) => return Err(not_public()),
        Host::Domain(name)
            if !name.trim_end_matches('.').contains('.')
                // Special-use names (RFC 6761, 6762, 7686, 8375, 9476) and the
                // private-use `internal`.
                || [
                    "localhost", "local", "internal", "home.arpa", "invalid", "test", "example",
                    "onion", "alt",
                ]
                    .iter()
                    .any(|reserved| {
                        // Whole labels: `foo.local` is reserved, `foolocal` is not.
                        let name = name.trim_end_matches('.');
                        name == *reserved
                            || name
                                .strip_suffix(reserved)
                                .is_some_and(|rest| rest.ends_with('.'))
                    }) =>
        {
            return Err(not_public());
        }
        _ => {}
    }
    Ok(url)
}

/// One call to [`CrlSource::crls`].
#[derive(Default)]
struct Call {
    /// Whether it is counted in `source_requests`: at its first point fetched.
    counted: bool,
    /// The points it fetched, at most [`MAX_POINTS_PER_REQUEST`].
    fetched: usize,
    /// The distinct points it reached and would fetch (not answered from
    /// memory), reported as `requested`.
    reaching: std::collections::BTreeSet<String>,
    /// The bodies it returned, at most [`MAX_RESPONSE_ENTRIES`].
    bodies: usize,
}

/// Bounded public HTTP transport. HTTPS/LDAP, proxies, cookies, compressed and
/// chunked responses are unsupported. DNS results are checked and pinned to the
/// connection; every redirect is revalidated. No persistent cache is used:
/// each URL's outcome is kept for one verification only, so a point that
/// several certificates list is fetched once and its body or failure is
/// returned for each (the engine reuses no answer itself, CRL-033).
#[derive(Default)]
pub struct HttpCrlSource {
    /// Calls to [`CrlSource::crls`] in this verification that carried a point
    /// not yet answered, bounded by [`MAX_SOURCE_REQUESTS`]; `requests`
    /// counts HTTP requests.
    source_requests: usize,
    /// The current call to [`CrlSource::crls`].
    call: Call,
    /// The distinct URLs (normalized) asked for in this verification,
    /// bounded by [`MAX_SOURCE_URLS`].
    urls: std::collections::BTreeSet<String>,
    /// What each URL (normalized) yielded in this verification: its body,
    /// or the failure it reported. An abort is not kept: after one, the
    /// engine asks nothing more.
    answered: std::collections::BTreeMap<String, Result<SourcedCrl, CrlSourceError>>,
    /// Per URL (normalized), a size failure under a request allowance below
    /// [`MAX_CRL_BYTES`], with that allowance: a request with no more room
    /// gets the same failure, one with more fetches again.
    too_big: std::collections::BTreeMap<String, (usize, CrlSourceError)>,
    requests: usize,
    bytes: usize,
    started: Option<Instant>,
    poisoned: bool,
}
impl HttpCrlSource {
    pub fn new() -> Self {
        Self::default()
    }
    /// Start a new verification's allowances: requests, bytes and lifetime
    /// are bounded per verification, as in OpenSSL and Bouncy Castle, where
    /// nothing one validation fetched is charged to the next. The engine
    /// calls this through [`CrlSource::begin_verification`]. A DNS timeout
    /// still closes the source for good, so that no more than one unfinished
    /// resolver worker can exist.
    fn renew(&mut self) {
        *self = Self {
            poisoned: self.poisoned,
            ..Self::default()
        };
    }
    fn remaining(&self) -> Result<Duration, VerificationError> {
        // Both mean this source can do no more work, and say so.
        if self.poisoned {
            return Err(error(ErrorCode::CrlFetchFailed, CLOSED_AFTER_DNS_TIMEOUT)
                .detail("source_spent", true));
        }
        DEADLINE
            .checked_sub(self.started.expect("fetch started").elapsed())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| {
                error(ErrorCode::CrlFetchFailed, "CRL retrieval deadline exceeded")
                    .detail("source_spent", true)
            })
    }
    fn resolve(&mut self, url: &Url) -> Result<SocketAddr, VerificationError> {
        let host = url
            .host_str()
            .expect("validated URL")
            .trim_matches(['[', ']'])
            .to_string();
        let remaining = self.remaining()?.min(IO_TIMEOUT);
        let (tx, rx) = mpsc::sync_channel(1);
        // OS DNS has no cancellable std API. At most one timed-out resolver can
        // survive this source: a timeout permanently closes it to further work.
        std::thread::Builder::new()
            .name("rssig-crl-dns".into())
            .spawn(move || {
                let addresses = (host.as_str(), 80)
                    .to_socket_addrs()
                    .map(|v| v.take(17).collect::<Vec<_>>());
                let _ = tx.send(addresses);
            })
            .map_err(|e| error(ErrorCode::CrlFetchFailed, e.to_string()))?;
        let addresses = match rx.recv_timeout(remaining) {
            Ok(value) => value.map_err(|e| {
                error(
                    ErrorCode::CrlFetchFailed,
                    format!("CRL DNS lookup failed: {e}"),
                )
            })?,
            Err(_) => {
                self.poisoned = true;
                return Err(dns_timeout());
            }
        };
        if addresses.is_empty()
            || addresses.len() > 16
            || addresses.iter().any(|a| !public_ip(a.ip()))
        {
            return Err(error(
                ErrorCode::CrlFetchDenied,
                "CRL DNS results are empty, excessive, or contain a nonpublic address",
            ));
        }
        Ok(addresses[0])
    }
    fn read(
        &mut self,
        stream: &mut TcpStream,
        bytes: &mut [u8],
    ) -> Result<usize, VerificationError> {
        // The budget is exactly spent: one probe, within the time left, tells
        // a body that ends here from one that goes past the cap; the byte
        // limit keeps its precedence over the deadline.
        if self.bytes >= MAX_NETWORK_BYTES {
            let spent = || limit("crl_network_bytes", MAX_NETWORK_BYTES, self.bytes, 1);
            let left = self.remaining().map_err(|_| spent())?;
            stream
                .set_read_timeout(Some(left.min(IO_TIMEOUT)))
                .map_err(io_error)?;
            let mut probe = [0u8; 1];
            return match stream.read(&mut probe).map_err(io_error)? {
                0 => Ok(0),
                _ => Err(spent()),
            };
        }
        stream
            .set_read_timeout(Some(self.remaining()?.min(IO_TIMEOUT)))
            .map_err(io_error)?;
        let cap = bytes.len().min(MAX_NETWORK_BYTES - self.bytes);
        let n = stream.read(&mut bytes[..cap]).map_err(io_error)?;
        self.bytes += n;
        Ok(n)
    }
}
fn io_error(e: std::io::Error) -> VerificationError {
    // The marker only classifies (a wait cut by the deadline) and is not
    // reported.
    error(
        ErrorCode::CrlFetchFailed,
        format!("CRL HTTP I/O failed: {e}"),
    )
    .detail("io_error", true)
}

struct Headers {
    status: u16,
    length: Option<usize>,
    location: Option<String>,
}
fn headers(bytes: &[u8]) -> Result<Headers, VerificationError> {
    let mut storage = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut storage);
    if !matches!(response.parse(bytes), Ok(httparse::Status::Complete(n)) if n == bytes.len()) {
        return Err(error(
            ErrorCode::CrlFetchFailed,
            "invalid CRL HTTP response headers",
        ));
    }
    let mut length = None;
    let mut location = None;
    for header in response.headers {
        if header.name.eq_ignore_ascii_case("transfer-encoding")
            || header.name.eq_ignore_ascii_case("content-encoding")
        {
            return Err(error(
                ErrorCode::CrlFetchDenied,
                "encoded or chunked CRL HTTP responses are unsupported",
            ));
        }
        if header.name.eq_ignore_ascii_case("content-length") {
            let text = std::str::from_utf8(header.value)
                .map_err(|_| error(ErrorCode::CrlFetchFailed, "invalid Content-Length"))?;
            if length.is_some() || text.is_empty() || !text.bytes().all(|c| c.is_ascii_digit()) {
                return Err(error(
                    ErrorCode::CrlFetchFailed,
                    "duplicate or invalid Content-Length",
                ));
            }
            length = Some(
                text.parse()
                    .map_err(|_| error(ErrorCode::CrlFetchFailed, "invalid Content-Length"))?,
            );
        }
        if header.name.eq_ignore_ascii_case("location") {
            if location.is_some() {
                return Err(error(
                    ErrorCode::CrlFetchFailed,
                    "duplicate redirect location",
                ));
            }
            location = Some(
                std::str::from_utf8(header.value)
                    .map_err(|_| error(ErrorCode::CrlFetchFailed, "invalid redirect location"))?
                    .to_string(),
            );
        }
    }
    Ok(Headers {
        status: response.code.expect("complete response"),
        length,
        location,
    })
}
/// The built-in source's URL policy, for a source of its own that fetches
/// distribution points: `Ok` for a public HTTP URL on port 80 without
/// credentials or fragments and at most 2,048 bytes, `Denied` for anything
/// else (another scheme such as `file:` or `https:`, a literal private,
/// loopback or link-local address, a single-label or local name).
///
/// The engine passes a source every listed URI that passes input hygiene
/// and applies no transport policy itself, so a source that fetches by URL
/// must screen them. This checks the URL only: the built-in source also
/// rejects DNS answers that contain nonpublic addresses and re-checks each
/// redirect target, which a source must do in its own client.
pub fn check_public_http_url(url: &str) -> Result<(), CrlSourceError> {
    checked_url(url).map(|_| ()).map_err(|e| {
        CrlSourceError::new(CrlSourceErrorKind::Denied, e.message).with_url(url.to_owned())
    })
}

/// The request whose DNS lookup timed out closes the source: it is itself
/// the abort, not only the requests after it.
fn dns_timeout() -> VerificationError {
    error(ErrorCode::CrlFetchFailed, "CRL DNS deadline exceeded").detail("source_spent", true)
}

/// The kind of a failed request. `Abort` only when the source was spent
/// before it, or this request ran out of the source's own requests, bytes or
/// time: a request that failed for its own reason keeps that reason, even if
/// it was the last the source could make (the next one then aborts).
fn source_error_kind(e: &VerificationError, spent_before: bool) -> CrlSourceErrorKind {
    let ran_out = matches!(
        e.details.get("resource").and_then(|r| r.as_str()),
        Some("crl_http_requests" | "crl_network_bytes")
    ) || e.details.get("source_spent") == Some(&serde_json::Value::Bool(true));
    match e.code {
        _ if spent_before || ran_out => CrlSourceErrorKind::Abort,
        ErrorCode::CrlFetchDenied => CrlSourceErrorKind::Denied,
        ErrorCode::CrlFetchFailed | ErrorCode::ResourceLimitExceeded => CrlSourceErrorKind::Failed,
        _ => CrlSourceErrorKind::Unknown,
    }
}

impl CrlSource for HttpCrlSource {
    fn begin_verification(&mut self) {
        self.renew();
    }

    /// Requests the certificate's listed distribution points in order (see
    /// [`fetch_each`]). Reports a URL its policy refuses as `Denied`, a
    /// request that did not work as `Failed`, and its own spent request or
    /// byte budget, deadline or DNS timeout as `Abort`: after those this
    /// source can do no more work. Past [`MAX_SOURCE_REQUESTS`], the first
    /// point a call would fetch is the same: an `Abort` with
    /// `details.resource` `crl_requests`. A call counts as one source request when it fetches a
    /// point, even one the policy then refuses before any network work (a
    /// private address); a call whose points were all answered earlier in
    /// the verification counts none, and its answers are the same body or
    /// failure. Separately, a URL refused before any network work costs no
    /// HTTP request; one refused after it (a nonpublic DNS answer, a redirect
    /// to a refused URL, an encoded response) does.
    fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
        // What each point costs is decided as it is reached (`fetch_keyed`
        // and `answer`):
        // a point answered from this verification's memory costs nothing,
        // and only a point that would be fetched counts toward the 16 of this
        // call and, at the first, the request cap. `requested` in a
        // `crl_request_points` failure counts the distinct points of the call
        // with no outcome kept before it. Each point's key is computed once.
        let keys: std::collections::BTreeMap<&str, String> = request
            .distribution_points
            .iter()
            .map(|url| (url.as_str(), url_key(url)))
            .collect();
        self.call = Call::default();
        let mut response = fetch_each(request, |url, max_bytes| {
            let key = keys.get(url).cloned().unwrap_or_else(|| url_key(url));
            self.fetch_keyed(url, key, max_bytes)
        });
        // Known only once every point it reaches was reached (`fetch_each`
        // stops at an abort or a spent allowance).
        let requested = self.call.reaching.len();
        for failure in &mut response.failures {
            if failure.details.get("resource") == Some(&"crl_request_points".into()) {
                failure.details.insert("requested".into(), requested.into());
            }
        }
        Ok(response)
    }
}

impl HttpCrlSource {
    /// [`Self::fetch_keyed`] for a URL whose key is not computed yet.
    #[cfg(test)]
    fn fetch_cached(&mut self, url: &str, max_bytes: usize) -> Result<SourcedCrl, CrlSourceError> {
        self.fetch_keyed(url, url_key(url), max_bytes)
    }
    /// [`Self::fetch_one_keyed`] with this verification's memory of each URL's
    /// outcome, by `key` ([`url_key`]): a repeat returns the same body or
    /// failure, under the spelling it was offered. Not kept: an abort (the
    /// engine asks nothing more after it); a failure about the byte allowance
    /// a request had is kept with that allowance, so a request with more room
    /// than that and than the size seen fetches again, and any other gets the
    /// same failure. A response holds at most `MAX_RESPONSE_ENTRIES` bodies.
    fn fetch_keyed(
        &mut self,
        url: &str,
        key: String,
        max_bytes: usize,
    ) -> Result<SourcedCrl, CrlSourceError> {
        // A response carries no more bodies than the engine accepts
        // (`MAX_RESPONSE_ENTRIES`), however many points are answered from
        // memory: the rest are not tried, so the engine keeps the response.
        // A point whose kept outcome is a failure adds no body. Checked in
        // the order `answer` follows, so the two agree. A point with no kept
        // outcome is one the call would fetch, counted in `requested` even
        // when the body cap stops it.
        let room = max_bytes.min(MAX_CRL_BYTES);
        let kept_failure = match self.answered.get(&key) {
            Some(Ok(crl)) => crl.bytes.len() > room,
            Some(Err(_)) => true,
            None => self
                .too_big
                .get(&key)
                .is_some_and(|(under, e)| room <= *under || room < seen_size(e)),
        };
        if !kept_failure && !self.answered.contains_key(&key) {
            self.call.reaching.insert(key.clone());
        }
        if self.call.bodies >= MAX_RESPONSE_ENTRIES && !kept_failure {
            return Err(CrlSourceError::new(
                CrlSourceErrorKind::Denied,
                "not tried: the response already holds the most CRL bodies the engine accepts",
            )
            .with_url(url.to_owned())
            .detail("resource", "crl_response_entries")
            .detail("limit", MAX_RESPONSE_ENTRIES));
        }
        let outcome = self.answer(url, key, max_bytes);
        if outcome.is_ok() {
            self.call.bodies += 1;
        }
        outcome
    }
    fn answer(
        &mut self,
        url: &str,
        key: String,
        max_bytes: usize,
    ) -> Result<SourcedCrl, CrlSourceError> {
        if let Some(known) = self.answered.get(&key) {
            // A body over this request's room is refused as a fresh fetch
            // refuses it, without copying it: a replay counts against the
            // allowance like any body (CRL-051).
            let cap = max_bytes.min(MAX_CRL_BYTES);
            if let Ok(crl) = known
                && crl.bytes.len() > cap
            {
                let len = crl.bytes.len();
                return Err(self
                    .classify(limit("crl_response_bytes", cap, 0, len), false)
                    .with_url(url.to_owned()));
            }
            return match known.clone() {
                Ok(mut crl) => {
                    crl.url = Some(url.to_owned());
                    Ok(crl)
                }
                Err(e) => Err(e.with_url(url.to_owned())),
            };
        }
        let allowance = max_bytes.min(MAX_CRL_BYTES);
        if let Some((failed_under, e)) = self.too_big.get(&key)
            && (allowance <= *failed_under || allowance < seen_size(e))
        {
            // As this request's room, not the earlier one's.
            let size = seen_size(e);
            let kind = e.kind;
            let rebuilt = limit("crl_response_bytes", allowance, 0, size);
            let mut e = CrlSourceError::new(kind, rebuilt.message).with_url(url.to_owned());
            e.details = rebuilt.details;
            return Err(e);
        }
        // Only a point that is fetched costs anything: one of the 16 of this
        // call, and at the first, one of the source's requests.
        self.call.reaching.insert(key.clone());
        if self.call.fetched >= MAX_POINTS_PER_REQUEST {
            return Err(CrlSourceError::new(
                CrlSourceErrorKind::Denied,
                "not tried: the built-in source fetches at most 16 points per request \
                 that it has not answered earlier in the verification",
            )
            .with_url(url.to_owned())
            .detail("resource", "crl_request_points")
            .detail("limit", MAX_POINTS_PER_REQUEST)
            .detail("requested", self.call.reaching.len()));
        }
        if !self.call.counted {
            if self.source_requests >= MAX_SOURCE_REQUESTS {
                let e = limit("crl_requests", MAX_SOURCE_REQUESTS, self.source_requests, 1);
                let mut source_error =
                    CrlSourceError::new(CrlSourceErrorKind::Abort, e.message).with_url(url);
                source_error.details = e.details;
                return Err(source_error);
            }
            self.call.counted = true;
            self.source_requests += 1;
        }
        self.call.fetched += 1;
        let outcome = self.fetch_one_keyed(url, &key, max_bytes);
        if cacheable(&outcome) {
            // A kept outcome replaces an earlier size failure for the URL.
            self.too_big.remove(&key);
            self.answered.insert(key, outcome.clone());
        } else if let Err(e) = &outcome
            && e.kind != CrlSourceErrorKind::Abort
        {
            self.too_big.insert(key, (allowance, e.clone()));
        }
        outcome
    }
    #[cfg(test)]
    fn fetch_one(&mut self, raw: &str, max_bytes: usize) -> Result<SourcedCrl, CrlSourceError> {
        self.fetch_one_keyed(raw, &url_key(raw), max_bytes)
    }
    fn fetch_one_keyed(
        &mut self,
        raw: &str,
        key: &str,
        max_bytes: usize,
    ) -> Result<SourcedCrl, CrlSourceError> {
        // A source closed by a DNS timeout does no work at all, whatever the
        // URL: no request is spent and nothing is called denied.
        if self.poisoned {
            return Err(CrlSourceError::new(
                CrlSourceErrorKind::Abort,
                CLOSED_AFTER_DNS_TIMEOUT,
            ));
        }
        // A URL beyond the distinct-URL cap does no work: the source can do
        // no more, like a spent request cap. One already seen costs nothing.
        if !self.urls.contains(key) {
            if self.urls.len() >= MAX_SOURCE_URLS {
                let e = limit("crl_source_urls", MAX_SOURCE_URLS, self.urls.len(), 1);
                let mut source_error = CrlSourceError::new(CrlSourceErrorKind::Abort, e.message);
                source_error.details = e.details;
                return Err(source_error);
            }
            self.urls.insert(key.to_owned());
        }
        // Whether the source was already spent before this request: then
        // nothing this request reports is about its own URL.
        let spent_before = self.requests >= MAX_HTTP_REQUESTS
            || self.bytes >= MAX_NETWORK_BYTES
            || self.started.is_some() && self.remaining().is_err();
        // A source already spent does no work for this request: no request,
        // DNS lookup or connection.
        if spent_before {
            let e = if self.requests >= MAX_HTTP_REQUESTS {
                limit("crl_http_requests", MAX_HTTP_REQUESTS, self.requests, 1)
            } else if self.bytes >= MAX_NETWORK_BYTES {
                limit("crl_network_bytes", MAX_NETWORK_BYTES, self.bytes, 1)
            } else {
                self.remaining()
                    .err()
                    .unwrap_or_else(|| error(ErrorCode::CrlFetchFailed, "CRL source is spent"))
            };
            let mut source_error = CrlSourceError::new(CrlSourceErrorKind::Abort, e.message);
            source_error.details = e.details;
            source_error.details.remove("source_spent");
            return Err(source_error);
        }
        self.fetch_http(raw, max_bytes)
            .map_err(|e| self.classify(e, spent_before))
    }
    /// The source error a failed request is reported as. An I/O failure
    /// once the deadline has run out is the deadline (each wait is cut to
    /// the time left), so the source is spent: `Abort`.
    fn classify(&self, e: VerificationError, spent_before: bool) -> CrlSourceError {
        let deadline_passed = self.started.is_some() && self.remaining().is_err();
        let io = e.details.get("io_error") == Some(&serde_json::Value::Bool(true));
        let kind = if deadline_passed && io {
            CrlSourceErrorKind::Abort
        } else {
            source_error_kind(&e, spent_before)
        };
        let mut source_error = CrlSourceError::new(kind, e.message);
        source_error.details = e.details;
        // The markers only classify; the kind says the same.
        source_error.details.remove("source_spent");
        source_error.details.remove("io_error");
        source_error
    }
    fn fetch_http(&mut self, raw: &str, max_bytes: usize) -> Result<SourcedCrl, VerificationError> {
        // Refused before any work, so this refusal costs no request; later
        // refusals (DNS answer, redirect, response) come after one is spent.
        let mut url = checked_url(raw)?;
        let requested = url.clone();
        self.started.get_or_insert_with(Instant::now);
        let cap = max_bytes.min(MAX_CRL_BYTES);
        if cap == 0 {
            return Err(limit("crl_response_bytes", cap, 0, 1));
        }
        for redirects in 0..=3 {
            if self.requests >= MAX_HTTP_REQUESTS {
                return Err(limit(
                    "crl_http_requests",
                    MAX_HTTP_REQUESTS,
                    self.requests,
                    1,
                ));
            }
            self.requests += 1;
            let address = self.resolve(&url)?;
            let mut stream =
                TcpStream::connect_timeout(&address, self.remaining()?.min(IO_TIMEOUT))
                    .map_err(io_error)?;
            stream
                .set_write_timeout(Some(self.remaining()?.min(IO_TIMEOUT)))
                .map_err(io_error)?;
            let target = format!(
                "{}{}",
                url.path(),
                url.query().map(|q| format!("?{q}")).unwrap_or_default()
            );
            let request = format!(
                "GET {target} HTTP/1.0\r\nHost: {}\r\nAccept: application/pkix-crl, application/octet-stream\r\nConnection: close\r\n\r\n",
                url.host_str().expect("validated host")
            );
            stream.write_all(request.as_bytes()).map_err(io_error)?;
            let body = match receive(cap, |bytes| self.read(&mut stream, bytes))? {
                Response::Body(body) => body,
                Response::Redirect(location) => {
                    if redirects == 3 {
                        return Err(limit("crl_redirects", 3, 3, 1));
                    }
                    let next = url
                        .join(&location)
                        .map_err(|_| error(ErrorCode::CrlFetchDenied, "invalid redirect URL"))?;
                    url = checked_url(next.as_str())?;
                    continue;
                }
            };
            let crl = SourcedCrl::new(body).with_url(raw);
            // Only a redirect changes where the bytes came from.
            return Ok(if url == requested {
                crl
            } else {
                crl.with_final_url(url.to_string())
            });
        }
        unreachable!("redirect bound returns an error")
    }
}

enum Response {
    Redirect(String),
    Body(Vec<u8>),
}
fn receive(
    cap: usize,
    mut read: impl FnMut(&mut [u8]) -> Result<usize, VerificationError>,
) -> Result<Response, VerificationError> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= HEADER_LIMIT {
            return Err(limit("crl_http_headers", HEADER_LIMIT, head.len(), 1));
        }
        let mut byte = [0];
        if read(&mut byte)? == 0 {
            return Err(error(
                ErrorCode::CrlFetchFailed,
                "truncated CRL HTTP headers",
            ));
        }
        head.push(byte[0]);
    }
    let headers = headers(&head)?;
    if [301, 302, 303, 307, 308].contains(&headers.status) {
        return Ok(Response::Redirect(headers.location.ok_or_else(|| {
            error(ErrorCode::CrlFetchFailed, "redirect lacks Location")
        })?));
    }
    if headers.status != 200 {
        return Err(error(
            ErrorCode::CrlFetchFailed,
            "CRL HTTP response was not successful",
        )
        .detail("http_status", headers.status));
    }
    if headers.length.is_some_and(|n| n > cap) {
        return Err(limit("crl_response_bytes", cap, 0, headers.length.unwrap()));
    }
    let mut body = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let remaining = cap - body.len();
        let n = read(&mut buffer[..remaining.min(8191) + 1])?;
        if n == 0 {
            break;
        }
        if n > remaining {
            return Err(limit("crl_response_bytes", cap, body.len(), n));
        }
        body.extend_from_slice(&buffer[..n]);
    }
    if headers.length.is_some_and(|n| n != body.len()) {
        return Err(error(
            ErrorCode::CrlFetchFailed,
            "CRL HTTP body length differs from Content-Length",
        ));
    }
    Ok(Response::Body(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn response(bytes: &[u8], cap: usize) -> Result<Response, VerificationError> {
        let mut reader = std::io::Cursor::new(bytes);
        receive(cap, |buf| reader.read(buf).map_err(io_error))
    }
    #[test]
    fn denies_nonpublic_ambiguous_or_unsupported_destinations() {
        for url in [
            "http://127.0.0.1/x",
            "http://2130706433/x",
            "http://0x7f000001/x",
            "http://10.0.0.1/",
            "http://169.254.169.254/",
            "http://[::1]/",
            "http://[::ffff:8.8.8.8]/",
            "http://[2002:0808:0808::]/",
            "http://192.0.2.1/",
            "http://198.18.0.1/",
            "http://224.0.0.1/",
            "https://example.com/",
            "file:///etc/passwd",
            "http://user@example.com/",
            "http://example.com:8080/",
            "http://example.com/#x",
            "http://localhost./",
            "http://foo.local/",
            "http://local/",
            // RFC 6761 special-use names never resolve publicly.
            "http://crl.invalid/x.crl",
            "http://crl.example.invalid/x.crl",
            "http://ca.test/x.crl",
            "http://crl.example/x.crl",
            "http://crl.foo.onion/x.crl",
            "http://crl.ca.alt/x.crl",
            "http://a.com/x\u{3000}.crl",
            // Surrounding spaces: the URL as given is not clean.
            " http://example.com/x.crl",
            "http://example.com/x.crl ",
            // A trailing dot is the same name: still one label.
            "http://intranet./x.crl",
            "http://printer./",
            "http://a.b.internal./",
            "http://x.home.arpa/",
            "http://example.com/\r\nx",
        ] {
            assert!(checked_url(url).is_err(), "{url}");
        }
        // Each reason has its own message.
        let message = |url: &str| checked_url(url).unwrap_err().message;
        assert!(message("http://ca.test/x.crl").contains("not public"));
        assert!(message("http://10.0.0.1/x.crl").contains("not public"));
        assert!(message(" http://example.com/x").contains("whitespace"));
        assert!(message("https://example.com/x").contains("port 80"));
        assert!(message("crl.example.com/x.crl").contains("absolute"));
        for url in [
            "http://example.com/test.crl",
            "http://8.8.8.8/x",
            "http://[2001:4860:4860::8888]/x",
            // A reserved name is matched as a whole label, not a suffix.
            "http://crl.foolocal/x",
            "http://pki.theinternal/x",
            "http://crl.notlocalhost/x",
        ] {
            assert!(checked_url(url).is_ok(), "{url}");
        }
    }
    #[test]
    fn bounded_response_framing_requires_exact_supported_body() {
        for bytes in [
            b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nabc".as_slice(),
            b"HTTP/1.0 200 OK\r\n\r\nabc",
        ] {
            assert!(matches!(response(bytes, 3).unwrap(), Response::Body(b) if b == b"abc"));
            assert_eq!(
                response(bytes, 2).err().unwrap().code,
                ErrorCode::ResourceLimitExceeded
            );
        }
        for bytes in [
            b"HTTP/1.0 200 OK\r\nContent-Length: 4\r\n\r\nabc".as_slice(),
            b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nabc",
            b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc",
            b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            b"HTTP/1.0 200 OK\r\nContent-Encoding: gzip\r\n\r\nabc",
            b"HTTP/1.0 404 Missing\r\n\r\nabc",
            b"HTTP/1.0 200 OK\r\n",
        ] {
            assert!(response(bytes, 10).is_err());
        }
    }
    #[test]
    fn redirects_are_exposed_for_revalidation_and_headers_are_bounded() {
        let Response::Redirect(location) = response(
            b"HTTP/1.0 302 Found\r\nLocation: http://127.0.0.1/x\r\n\r\n",
            10,
        )
        .unwrap() else {
            panic!("expected redirect")
        };
        assert_eq!(
            checked_url(&location).unwrap_err().code,
            ErrorCode::CrlFetchDenied
        );
        let huge = format!("HTTP/1.0 200 OK\r\nX-Test: {}", "a".repeat(HEADER_LIMIT));
        assert_eq!(
            response(huge.as_bytes(), 10).err().unwrap().details["resource"],
            "crl_http_headers"
        );
    }
    #[test]
    fn the_public_url_policy_is_available_to_other_sources() {
        assert!(check_public_http_url("http://crl.example.com/a.crl").is_ok());
        for url in [
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "https://crl.example.com/a.crl",
            "http://localhost/a.crl",
            "http://10.0.0.1/a.crl",
        ] {
            let denied = check_public_http_url(url).unwrap_err();
            assert_eq!(denied.kind, CrlSourceErrorKind::Denied, "{url}");
            assert_eq!(denied.url.as_deref(), Some(url));
        }
    }
    #[test]
    fn the_last_request_keeps_its_own_failure() {
        // The 16th request returns 404: the source is now spent, but that
        // URL failed for its own reason. Only the next request aborts.
        let not_found = error(ErrorCode::CrlFetchFailed, "HTTP 404");
        assert_eq!(
            source_error_kind(&not_found, false),
            CrlSourceErrorKind::Failed
        );
        let refused = error(ErrorCode::CrlFetchDenied, "redirect refused");
        assert_eq!(
            source_error_kind(&refused, false),
            CrlSourceErrorKind::Denied
        );
        // Spent before the request, or ran out during it: abort.
        assert_eq!(source_error_kind(&refused, true), CrlSourceErrorKind::Abort);
        let deadline = HttpCrlSource {
            started: Some(Instant::now() - DEADLINE),
            ..HttpCrlSource::new()
        }
        .remaining()
        .unwrap_err();
        assert_eq!(
            source_error_kind(&deadline, false),
            CrlSourceErrorKind::Abort
        );
        // The request whose DNS lookup times out is itself the abort.
        assert_eq!(
            source_error_kind(&dns_timeout(), false),
            CrlSourceErrorKind::Abort
        );
        let budget = limit("crl_http_requests", MAX_HTTP_REQUESTS, MAX_HTTP_REQUESTS, 1);
        assert_eq!(source_error_kind(&budget, false), CrlSourceErrorKind::Abort);
        // An I/O error once the deadline has run out is the deadline: the
        // wait was cut to the time left.
        let mut source = HttpCrlSource {
            started: Some(Instant::now() - DEADLINE),
            ..HttpCrlSource::new()
        };
        let timed_out = io_error(std::io::Error::from(std::io::ErrorKind::TimedOut));
        assert_eq!(
            source.classify(timed_out, false).kind,
            CrlSourceErrorKind::Abort
        );
        // A request that completed and failed for its own reason (an HTTP
        // status) keeps that reason, even past the deadline.
        source.started = Some(Instant::now() - DEADLINE);
        let status = error(ErrorCode::CrlFetchFailed, "CRL HTTP status 404");
        assert_eq!(
            source.classify(status, false).kind,
            CrlSourceErrorKind::Failed
        );
        // The I/O marker is not part of the reported failure.
        let timed_out = io_error(std::io::Error::from(std::io::ErrorKind::TimedOut));
        assert!(
            !source
                .classify(timed_out, false)
                .details
                .contains_key("io_error")
        );
        // With time left, an I/O failure is the request's own.
        source.started = Some(Instant::now());
        let timed_out = io_error(std::io::Error::from(std::io::ErrorKind::TimedOut));
        assert_eq!(
            source.classify(timed_out, false).kind,
            CrlSourceErrorKind::Failed
        );
    }
    #[test]
    fn the_built_in_source_aborts_after_its_request_cap_until_a_new_verification() {
        let mut source = HttpCrlSource::new();
        // URLs the policy refuses before any network work: no HTTP request
        // is spent, but every call carrying a new point counts as a source
        // request.
        let point = |i: usize| vec![format!("http://127.0.0.1/{i}.crl")];
        for i in 0..MAX_SOURCE_REQUESTS {
            let points = point(i);
            assert!(
                source
                    .crls(&CrlRequest::new(&[], &[], &points, 1024))
                    .is_ok()
            );
        }
        // The cap is reached when a point would be fetched: that point is
        // answered with the abort, so retrieval stops there.
        let points = point(MAX_SOURCE_REQUESTS);
        let request = CrlRequest::new(&[], &[], &points, 1024);
        let abort = |source: &mut HttpCrlSource| {
            let response = source.crls(&request).unwrap();
            assert_eq!(response.failures.len(), 1);
            response.failures[0].clone()
        };
        let e = abort(&mut source);
        assert_eq!(e.kind, CrlSourceErrorKind::Abort);
        assert_eq!(e.url.as_deref(), Some(points[0].as_str()));
        assert_eq!(e.details["resource"], "crl_requests");
        assert_eq!(e.details["limit"], MAX_SOURCE_REQUESTS);
        assert_eq!(e.details["used"], MAX_SOURCE_REQUESTS);
        assert_eq!(e.details["requested"], 1);
        // Still spent for every later request of the verification.
        assert_eq!(abort(&mut source).kind, CrlSourceErrorKind::Abort);
        // A point answered before is still answered, at no cost.
        let known = point(0);
        let response = source
            .crls(&CrlRequest::new(&[], &[], &known, 1024))
            .unwrap();
        assert_eq!(response.failures[0].kind, CrlSourceErrorKind::Denied);
        // The cap is per verification, as every allowance of this source.
        CrlSource::begin_verification(&mut source);
        let response = source.crls(&request).unwrap();
        assert_eq!(response.failures[0].kind, CrlSourceErrorKind::Denied);
    }
    #[test]
    fn a_call_with_nothing_new_to_fetch_is_not_charged_and_repeats_the_earlier_answer() {
        // CRL-T041: the engine asks about every certificate with every point,
        // so a call with no point, or with only points answered earlier in
        // the verification, does no network work and costs no request.
        let mut source = HttpCrlSource::new();
        let points = vec!["http://127.0.0.1/x.crl".to_string()];
        let first = source
            .crls(&CrlRequest::new(&[], &[], &points, 1024))
            .unwrap();
        assert_eq!(source.source_requests, 1);
        assert_eq!(first.failures.len(), 1);
        assert_eq!(first.failures[0].kind, CrlSourceErrorKind::Denied);
        // Many more certificates listing the same point, or listing none:
        // the cap is never reached. (A refused URL is kept under its own
        // spelling; normalization of an allowed one is tested with
        // `a_cached_body_is_returned_under_the_spelling_offered_and_a_duplicate_goes_with_its_first`.)
        let spelled = points.clone();
        for _ in 0..=MAX_SOURCE_REQUESTS {
            let again = source
                .crls(&CrlRequest::new(&[], &[], &spelled, 1024))
                .unwrap();
            assert_eq!(again.failures.len(), 1);
            assert_eq!(again.failures[0].kind, CrlSourceErrorKind::Denied);
            assert_eq!(again.failures[0].message, first.failures[0].message);
            // Reported under the spelling this request offered.
            assert_eq!(again.failures[0].url.as_deref(), Some(spelled[0].as_str()));
            let none = source.crls(&CrlRequest::new(&[], &[], &[], 1024)).unwrap();
            assert!(none.crls.is_empty() && none.failures.is_empty());
        }
        assert_eq!(source.source_requests, 1);
        assert_eq!(source.urls.len(), 1);
        assert_eq!(source.requests, 0);
        // A known point beside a new one: the call is charged once, and the
        // known one does not count toward the per-request limit.
        let mut mixed = vec!["http://127.0.0.1/x.crl".to_string()];
        mixed.extend((0..MAX_POINTS_PER_REQUEST).map(|i| format!("http://127.0.0.1/m-{i}.crl")));
        let response = source
            .crls(&CrlRequest::new(&[], &[], &mixed, 1024))
            .unwrap();
        assert_eq!(source.source_requests, 2);
        assert!(
            response
                .failures
                .iter()
                .all(|f| f.details.get("resource") != Some(&"crl_request_points".into()))
        );
        // A new verification forgets every answer.
        CrlSource::begin_verification(&mut source);
        assert!(source.answered.is_empty());
    }
    #[test]
    fn a_failure_about_the_request_allowance_is_not_kept_for_a_later_request() {
        // A point that failed for lack of allowance (`crl_response_bytes`) may
        // fit a later request with more, so it is fetched again; a failure of
        // its own (a refused URL) is kept. No network: an allowance of 0
        // fails before any request.
        let mut source = HttpCrlSource::new();
        let e = source
            .fetch_cached("http://crl.example.com/x.crl", 0)
            .unwrap_err();
        assert_eq!(e.details["resource"], "crl_response_bytes");
        assert!(source.answered.is_empty());
        assert_eq!(source.requests, 0);
        let denied = source
            .fetch_cached("http://127.0.0.1/x.crl", 1024)
            .unwrap_err();
        assert_eq!(denied.kind, CrlSourceErrorKind::Denied);
        assert_eq!(source.answered.len(), 1);
        // Over the fixed per-body cap it fails every time, so it is kept;
        // under a smaller allowance it is not.
        let size = |cap: usize| {
            let e = limit("crl_response_bytes", cap, 0, cap + 1);
            let mut error = CrlSourceError::new(CrlSourceErrorKind::Failed, e.message);
            error.details = e.details;
            Err(error)
        };
        assert!(cacheable(&size(MAX_CRL_BYTES)));
        assert!(!cacheable(&size(MAX_CRL_BYTES - 1)));
        assert!(!cacheable(&size(0)));
        // The allowance failure is kept with its allowance: a request with
        // no more room gets it again without a request.
        let mut source = HttpCrlSource::new();
        let url = "http://crl.example.com/y.crl";
        let first = source.fetch_cached(url, 0).unwrap_err();
        assert_eq!(source.too_big.len(), 1);
        let again = source.fetch_cached(url, 0).unwrap_err();
        assert_eq!(again.details, first.details);
        assert_eq!(source.requests, 0);
    }
    #[test]
    fn points_left_after_an_abort_are_left_for_the_engine_to_record_as_not_tried() {
        let mut source = HttpCrlSource {
            poisoned: true,
            ..HttpCrlSource::new()
        };
        let points: Vec<String> = (0..MAX_POINTS_PER_REQUEST + 4)
            .map(|i| format!("http://crl.example.com/p-{i}.crl"))
            .collect();
        let response = source
            .crls(&CrlRequest::new(&[], &[], &points, 1024))
            .unwrap();
        assert_eq!(response.failures.len(), 1);
        assert_eq!(response.failures[0].kind, CrlSourceErrorKind::Abort);
    }
    #[test]
    fn a_cached_body_is_returned_under_the_spelling_offered_and_a_duplicate_goes_with_its_first() {
        let mut source = HttpCrlSource::new();
        let url = "http://crl.example.com/x.crl";
        source
            .answered
            .insert(url_key(url), Ok(SourcedCrl::new(vec![0; 10]).with_url(url)));
        let spelled = "HTTP://CRL.Example.com/x.crl";
        let again = source.fetch_cached(spelled, 10).unwrap();
        assert_eq!(again.bytes.len(), 10);
        assert_eq!(again.url.as_deref(), Some(spelled));
        // Offered twice in one call, a URL counts once toward the point limit.
        let points = vec![url.to_string(); MAX_POINTS_PER_REQUEST + 1];
        let response = source
            .crls(&CrlRequest::new(&[], &[], &points, 1024))
            .unwrap();
        assert!(
            response
                .failures
                .iter()
                .all(|f| f.details.get("resource") != Some(&"crl_request_points".into()))
        );
        // A repeat of a point left by the limit is left with it, not fetched.
        let mut source = HttpCrlSource::new();
        let mut points: Vec<String> = (0..=MAX_POINTS_PER_REQUEST)
            .map(|i| format!("http://127.0.0.1/p-{i}.crl"))
            .collect();
        points.push(points[MAX_POINTS_PER_REQUEST].clone());
        let response = source
            .crls(&CrlRequest::new(&[], &[], &points, 1024))
            .unwrap();
        let left: Vec<_> = response
            .failures
            .iter()
            .filter(|f| f.details.get("resource") == Some(&"crl_request_points".into()))
            .collect();
        assert_eq!(left.len(), 2);
        assert_eq!(source.urls.len(), MAX_POINTS_PER_REQUEST);
    }
    #[test]
    fn a_kept_body_replaces_an_earlier_size_failure_for_the_body_cap() {
        // A URL that once failed for its size and later answered with a body:
        // the body cap treats it as a body, as `answer` returns one.
        let mut source = HttpCrlSource::new();
        let url = "http://crl.example.com/w.crl";
        let e = limit("crl_response_bytes", 100, 0, 150);
        let mut error = CrlSourceError::new(CrlSourceErrorKind::Failed, e.message);
        error.details = e.details;
        source.too_big.insert(url_key(url), (100, error));
        source
            .answered
            .insert(url_key(url), Ok(SourcedCrl::new(vec![0; 50]).with_url(url)));
        source.call.bodies = MAX_RESPONSE_ENTRIES;
        let e = source.fetch_cached(url, 80).unwrap_err();
        assert_eq!(e.details["resource"], "crl_response_entries");
        // A cached body over the room is a failure, reported as its size.
        let e = source.fetch_cached(url, 40).unwrap_err();
        assert_eq!(e.details["resource"], "crl_response_bytes");
    }
    #[test]
    fn a_response_carries_no_more_bodies_than_the_engine_accepts() {
        // Replayed points are outside the 16-point limit, so the source
        // bounds the bodies of one response itself: the engine refuses a
        // response with more than MAX_RESPONSE_ENTRIES of them.
        let mut source = HttpCrlSource::new();
        let points: Vec<String> = (0..MAX_RESPONSE_ENTRIES + 6)
            .map(|i| format!("http://crl.example.com/{i}.crl"))
            .collect();
        for url in &points {
            source
                .answered
                .insert(url_key(url), Ok(SourcedCrl::new(vec![0; 1]).with_url(url)));
        }
        let response = source
            .crls(&CrlRequest::new(&[], &[], &points, 1024))
            .unwrap();
        assert_eq!(response.crls.len(), MAX_RESPONSE_ENTRIES);
        assert_eq!(response.failures.len(), 6);
        // Points the call would fetch are counted in `requested` even when
        // the body cap stops them (none here: all were answered).
        assert!(source.call.reaching.is_empty());
        assert!(
            response
                .failures
                .iter()
                .all(|f| f.details["resource"] == "crl_response_entries")
        );
        // A point whose kept outcome is a failure still reports it.
        let refused = "http://127.0.0.1/x.crl".to_string();
        source.call = Call::default();
        source.fetch_cached(&refused, 1024).unwrap_err();
        let mut more = points[..MAX_RESPONSE_ENTRIES].to_vec();
        more.push(refused);
        let response = source
            .crls(&CrlRequest::new(&[], &[], &more, 1024))
            .unwrap();
        assert_eq!(response.failures.len(), 1);
        assert_eq!(response.failures[0].kind, CrlSourceErrorKind::Denied);
        assert_ne!(
            response.failures[0].details.get("resource"),
            Some(&"crl_response_entries".into())
        );
    }
    #[test]
    fn a_cached_body_over_a_later_requests_room_is_refused_as_a_fetch_is() {
        let mut source = HttpCrlSource::new();
        let url = "http://crl.example.com/x.crl";
        source
            .answered
            .insert(url_key(url), Ok(SourcedCrl::new(vec![0; 10]).with_url(url)));
        let e = source.fetch_cached(url, 5).unwrap_err();
        assert_eq!(e.kind, CrlSourceErrorKind::Failed);
        assert_eq!(e.details["resource"], "crl_response_bytes");
        assert_eq!(e.details["limit"], 5);
        assert_eq!(e.url.as_deref(), Some(url));
        assert!(source.fetch_cached(url, 10).is_ok());
    }
    #[test]
    fn every_spelling_refused_before_parsing_keeps_its_own_key() {
        // `url_key` and `checked_url` share `refused_before_parsing`: every
        // spelling it refuses is refused by the policy and keyed by its text.
        for raw in [
            format!("http://crl.example.com/{}", "a".repeat(2048)),
            " http://crl.example.com/x.crl".to_string(),
            "http://crl.example.com/x\u{7}.crl".to_string(),
            "http://crl.example.com\\x.crl".to_string(),
        ] {
            assert!(refused_before_parsing(&raw), "{raw:?}");
            assert!(checked_url(&raw).is_err(), "{raw:?}");
            assert_eq!(url_key(&raw), raw);
        }
    }
    #[test]
    fn a_refused_spelling_does_not_share_a_clean_urls_cache_entry() {
        assert_ne!(
            url_key(" http://crl.example.com/x.crl"),
            url_key("http://crl.example.com/x.crl")
        );
        assert_ne!(
            url_key("http://crl.example.com/x\t.crl"),
            url_key("http://crl.example.com/x.crl")
        );
        assert_eq!(
            url_key("HTTP://CRL.Example.com:80/x.crl"),
            url_key("http://crl.example.com/x.crl")
        );
        // Over 2,048 bytes, refused, though it normalizes to the short URL.
        let long = format!("http://crl.example.com/{}x.crl", "a/../".repeat(500));
        assert!(long.len() > 2048);
        assert_eq!(
            Url::parse(&long).unwrap().as_str(),
            "http://crl.example.com/x.crl"
        );
        assert_ne!(url_key(&long), url_key("http://crl.example.com/x.crl"));
        // A spelling refused for its host is normalized, as the engine
        // compares points: two spellings of one refused URL share an entry.
        assert_eq!(
            url_key("HTTP://127.0.0.1:80/x.crl"),
            url_key("http://127.0.0.1/x.crl")
        );
    }
    #[test]
    fn a_kept_allowance_failure_reports_the_room_of_the_request_it_answers() {
        let mut source = HttpCrlSource::new();
        let url = "http://crl.example.com/z.crl";
        let e = limit("crl_response_bytes", 4, 0, 7);
        let mut error = CrlSourceError::new(CrlSourceErrorKind::Failed, e.message);
        error.details = e.details;
        source.too_big.insert(url_key(url), (4, error));
        // More room than before, but less than the size seen: no fetch.
        let more = source.fetch_cached(url, 6).unwrap_err();
        assert_eq!(more.details["limit"], 6);
        assert_eq!(source.requests, 0);
        let again = source.fetch_cached(url, 2).unwrap_err();
        assert_eq!(again.details["limit"], 2);
        assert_eq!(again.details["used"], 0);
        assert_eq!(again.details["requested"], 7);
        assert_eq!(source.requests, 0);
        // A call whose point is answered from memory fetches nothing, so it
        // is not counted, even when the whole request's room is larger than
        // the failure's: an earlier body took what was left of it.
        let points = vec![url.to_string()];
        let response = source.crls(&CrlRequest::new(&[], &[], &points, 2)).unwrap();
        assert_eq!(response.failures.len(), 1);
        assert_eq!(source.source_requests, 0);
        let cached = "http://crl.example.com/c.crl";
        source.answered.insert(
            url_key(cached),
            Ok(SourcedCrl::new(vec![0; 7]).with_url(cached)),
        );
        let points = vec![cached.to_string(), url.to_string()];
        let response = source.crls(&CrlRequest::new(&[], &[], &points, 8)).unwrap();
        assert_eq!(response.crls.len(), 1);
        assert_eq!(response.failures.len(), 1);
        assert_eq!(source.source_requests, 0);
        // Past the cap the same call is not refused: nothing is fetched.
        source.source_requests = MAX_SOURCE_REQUESTS;
        let response = source.crls(&CrlRequest::new(&[], &[], &points, 8)).unwrap();
        assert_eq!(response.crls.len(), 1);
        assert_eq!(response.failures.len(), 1);
        assert_ne!(response.failures[0].kind, CrlSourceErrorKind::Abort);
    }
    #[test]
    fn the_built_in_source_aborts_past_its_distinct_url_cap_until_a_new_verification() {
        let mut source = HttpCrlSource::new();
        // URLs the policy refuses before any network work: none costs an
        // HTTP request, but each distinct one counts toward the cap.
        let url = |i: usize| format!("http://127.0.0.1/{i}.crl");
        for i in 0..MAX_SOURCE_URLS {
            let e = source.fetch_one(&url(i), 1024).expect_err("refused");
            assert_eq!(e.kind, CrlSourceErrorKind::Denied, "{i}");
        }
        // A URL already seen costs nothing more.
        assert_eq!(
            source.fetch_one(&url(0), 1024).unwrap_err().kind,
            CrlSourceErrorKind::Denied
        );
        let e = source.fetch_one(&url(MAX_SOURCE_URLS), 1024).unwrap_err();
        assert_eq!(e.kind, CrlSourceErrorKind::Abort);
        assert_eq!(e.details["resource"], "crl_source_urls");
        assert_eq!(e.details["limit"], MAX_SOURCE_URLS);
        assert_eq!(e.details["used"], MAX_SOURCE_URLS);
        assert_eq!(e.details["requested"], 1);
        CrlSource::begin_verification(&mut source);
        assert_eq!(
            source
                .fetch_one(&url(MAX_SOURCE_URLS), 1024)
                .unwrap_err()
                .kind,
            CrlSourceErrorKind::Denied
        );
    }
    #[test]
    fn a_source_closed_by_a_dns_timeout_aborts_every_request_even_after_a_new_verification() {
        let mut source = HttpCrlSource {
            poisoned: true,
            ..HttpCrlSource::new()
        };
        CrlSource::begin_verification(&mut source);
        // A URL the policy would refuse, and one it would allow: both abort
        // before any work, so no request is spent and none is called denied.
        for url in ["http://127.0.0.1/x.crl", "http://example.com/x.crl"] {
            let e = source.fetch_one(url, 10).expect_err("a closed source");
            assert_eq!(e.kind, CrlSourceErrorKind::Abort, "{url}");
        }
        assert_eq!(source.requests, 0);
        // Through the whole-request interface, an abort is terminal: the first
        // URL reports it, the rest are left for the engine to record as not
        // tried, and still no request is spent.
        let points = vec![
            "http://127.0.0.1/a.crl".to_string(),
            "http://example.com/b.crl".to_string(),
            "http://example.org/c.crl".to_string(),
        ];
        let request = CrlRequest::new(&[], &[], &points, 1024);
        let response = source.crls(&request).unwrap();
        assert!(response.crls.is_empty());
        assert_eq!(response.failures.len(), 1);
        assert_eq!(response.failures[0].kind, CrlSourceErrorKind::Abort);
        assert_eq!(response.failures[0].message, CLOSED_AFTER_DNS_TIMEOUT);
        assert_eq!(source.requests, 0);
    }
    #[test]
    fn points_past_the_per_request_limit_are_denied_without_spending_the_allowances() {
        // CRL-024: a certificate listing 20 points tries 16; the other 4 are
        // denied and cost no request and no distinct-URL slot, so the
        // verification goes on. Every point is refused by policy here, so
        // no network is used.
        let mut source = HttpCrlSource::default();
        let points: Vec<String> = (0..20)
            .map(|i| format!("http://127.0.0.1/p-{i}.crl"))
            .collect();
        let request = CrlRequest::new(&[], &[], &points, 1024);
        let response = source.crls(&request).unwrap();
        assert_eq!(response.failures.len(), 20);
        assert!(
            response
                .failures
                .iter()
                .all(|f| f.kind == CrlSourceErrorKind::Denied)
        );
        let skipped: Vec<_> = response
            .failures
            .iter()
            .filter(|f| f.details.get("resource") == Some(&"crl_request_points".into()))
            .filter_map(|f| f.url.as_deref())
            .collect();
        assert_eq!(skipped, &points[MAX_POINTS_PER_REQUEST..]);
        assert_eq!(source.urls.len(), MAX_POINTS_PER_REQUEST);
        assert_eq!(source.requests, 0);
        // `requested` counts the points that were not answered earlier: with
        // 4 of 24 answered, 20 fresh points were requested, not 24.
        let mut more = points.clone();
        more.extend((0..4).map(|i| format!("http://127.0.0.1/q-{i}.crl")));
        let known: Vec<String> = more[..4].to_vec();
        let mut source = HttpCrlSource::default();
        source
            .crls(&CrlRequest::new(&[], &[], &known, 1024))
            .unwrap();
        let response = source
            .crls(&CrlRequest::new(&[], &[], &more, 1024))
            .unwrap();
        let limited: Vec<_> = response
            .failures
            .iter()
            .filter(|f| f.details.get("resource") == Some(&"crl_request_points".into()))
            .collect();
        assert_eq!(limited.len(), more.len() - 4 - MAX_POINTS_PER_REQUEST);
        assert!(limited.iter().all(|f| f.details["requested"] == 20));
        // The next certificate is still asked.
        let next = CrlRequest::new(&[], &[], &points[..1], 1024);
        let response = source.crls(&next).unwrap();
        assert_eq!(response.failures[0].kind, CrlSourceErrorKind::Denied);
    }
    #[test]
    fn a_new_verification_restores_a_sources_allowances_but_a_dns_timeout_closes_it_for_good() {
        let mut source = HttpCrlSource {
            source_requests: MAX_SOURCE_REQUESTS,
            urls: Default::default(),
            answered: Default::default(),
            call: Call::default(),
            too_big: Default::default(),
            requests: MAX_HTTP_REQUESTS,
            bytes: MAX_NETWORK_BYTES,
            started: Some(Instant::now() - DEADLINE),
            poisoned: false,
        };
        // The engine does this at the start of each verification.
        CrlSource::begin_verification(&mut source);
        assert_eq!((source.requests, source.bytes), (0, 0));
        assert_eq!(source.source_requests, 0);
        assert!(source.started.is_none());
        // The unfinished resolver worker still exists: no second one.
        source.poisoned = true;
        CrlSource::begin_verification(&mut source);
        assert!(source.poisoned);
    }
    #[test]
    fn a_body_ending_exactly_at_the_byte_cap_still_reads_its_end() {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let writer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream.write_all(b"abcd").unwrap();
        });
        let mut stream = TcpStream::connect(address).unwrap();
        writer.join().unwrap();
        let mut source = HttpCrlSource {
            bytes: MAX_NETWORK_BYTES - 4,
            started: Some(Instant::now()),
            ..HttpCrlSource::new()
        };
        let mut buffer = [0u8; 16];
        let mut read = 0;
        while read < 4 {
            read += source.read(&mut stream, &mut buffer[read..]).unwrap();
        }
        assert_eq!(&buffer[..4], b"abcd");
        // The budget is exactly spent; the end of the body is still seen.
        assert_eq!(source.read(&mut stream, &mut buffer).unwrap(), 0);
    }
    #[test]
    fn deadlines_request_budgets_and_dns_poison_are_terminal_without_network() {
        let mut source = HttpCrlSource {
            requests: MAX_HTTP_REQUESTS,
            ..HttpCrlSource::new()
        };
        // A spent request budget, the deadline and a DNS timeout all mean
        // this source can do no more work: Abort.
        let kind = |source: &mut HttpCrlSource| {
            source
                .fetch_one("http://example.com/x", 10)
                .expect_err("no network is reached")
                .kind
        };
        assert_eq!(kind(&mut source), CrlSourceErrorKind::Abort);
        let mut source = HttpCrlSource {
            started: Some(Instant::now() - DEADLINE),
            ..HttpCrlSource::new()
        };
        assert_eq!(
            source.remaining().unwrap_err().code,
            ErrorCode::CrlFetchFailed
        );
        assert_eq!(kind(&mut source), CrlSourceErrorKind::Abort);
        let mut source = HttpCrlSource {
            poisoned: true,
            ..HttpCrlSource::new()
        };
        assert!(source.remaining().is_err());
        assert_eq!(kind(&mut source), CrlSourceErrorKind::Abort);
        // A spent byte budget aborts before any work: no request is spent,
        // and nothing is resolved or connected.
        let mut source = HttpCrlSource {
            bytes: MAX_NETWORK_BYTES,
            ..HttpCrlSource::new()
        };
        assert_eq!(kind(&mut source), CrlSourceErrorKind::Abort);
        assert_eq!(source.requests, 0);
        assert!(source.started.is_none());
        // The classifying marker is not part of the reported failure.
        let mut source = HttpCrlSource {
            started: Some(Instant::now() - DEADLINE),
            ..HttpCrlSource::new()
        };
        let reported = source
            .fetch_one("http://example.com/x", 10)
            .expect_err("deadline");
        assert!(!reported.details.contains_key("source_spent"));
        // A URL the policy refuses is Denied, before any work.
        let mut source = HttpCrlSource::new();
        assert_eq!(
            source
                .fetch_one("http://127.0.0.1/x", 10)
                .expect_err("denied")
                .kind,
            CrlSourceErrorKind::Denied
        );
        // ... unless the source has no requests left: a refusal then still
        // leaves it unable to do more work.
        let mut source = HttpCrlSource {
            requests: MAX_HTTP_REQUESTS,
            ..HttpCrlSource::new()
        };
        assert_eq!(
            source
                .fetch_one("http://127.0.0.1/x", 10)
                .expect_err("denied")
                .kind,
            CrlSourceErrorKind::Abort
        );
    }

    #[test]
    fn the_engine_asks_and_this_source_refuses_a_private_destination() {
        // Transport policy is the source's: the engine asks, and this source
        // refuses a private destination before any network access.
        use rssig_engine::{TrustStore, VerifyOptions, retrieval::verify_with_crl_source};
        let mut store = TrustStore::default();
        store
            .add_roots(include_bytes!("../tests/fixtures/root.der"))
            .unwrap();
        let error = verify_with_crl_source(
            include_bytes!("../tests/fixtures/bad-crl-private-url.exe"),
            None,
            &VerifyOptions::trusted(&store, 1800000000),
            &mut HttpCrlSource::new(),
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::RevocationUnknown);
        let failure = &error.details["crl_retrieval"]["failures"][0];
        assert_eq!(failure["code"], "crl_fetch_denied");
        assert_eq!(failure["source_error"], "denied");
    }
}
