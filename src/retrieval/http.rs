use super::*;
use std::{
    io::{Read, Write},
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    sync::mpsc,
    time::{Duration, Instant},
};
use url::{Host, Url};
const DEADLINE: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const HEADER_LIMIT: usize = 16 * 1024;

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
pub(super) fn checked_url(raw: &str) -> Result<Url, VerificationError> {
    let denied = || {
        error(
            ErrorCode::CrlFetchDenied,
            "CRL URL must be public HTTP on port 80 without credentials or fragments",
        )
    };
    if raw.len() > 2048 || raw.bytes().any(|b| b.is_ascii_control() || b == b'\\') {
        return Err(denied());
    }
    let url = Url::parse(raw).map_err(|_| denied())?;
    if url.scheme() != "http"
        || url.port_or_known_default() != Some(80)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(denied());
    }
    match url.host().ok_or_else(denied)? {
        Host::Ipv4(ip) if !public_ip(IpAddr::V4(ip)) => return Err(denied()),
        Host::Ipv6(ip) if !public_ip(IpAddr::V6(ip)) => return Err(denied()),
        Host::Domain(name)
            if !name.contains('.')
                || ["localhost", "local", "internal", "home.arpa"]
                    .iter()
                    .any(|suffix| name.trim_end_matches('.').ends_with(suffix)) =>
        {
            return Err(denied());
        }
        _ => {}
    }
    Ok(url)
}

/// Bounded public HTTP transport. HTTPS/LDAP, proxies, cookies, compressed and
/// chunked responses are unsupported. DNS results are checked and pinned to the
/// connection; every redirect is revalidated. No persistent cache is used.
#[derive(Default)]
pub struct HttpCrlSource {
    requests: usize,
    bytes: usize,
    started: Option<Instant>,
    poisoned: bool,
}
impl HttpCrlSource {
    pub fn new() -> Self {
        Self::default()
    }
    fn remaining(&self) -> Result<Duration, VerificationError> {
        if self.poisoned {
            return Err(error(
                ErrorCode::CrlFetchFailed,
                "CRL source is closed after a DNS timeout",
            ));
        }
        DEADLINE
            .checked_sub(self.started.expect("fetch started").elapsed())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| error(ErrorCode::CrlFetchFailed, "CRL retrieval deadline exceeded"))
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
                return Err(error(
                    ErrorCode::CrlFetchFailed,
                    "CRL DNS deadline exceeded",
                ));
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
        if self.bytes >= MAX_TOTAL_BYTES {
            return Err(limit("crl_network_bytes", MAX_TOTAL_BYTES, self.bytes, 1));
        }
        stream
            .set_read_timeout(Some(self.remaining()?.min(IO_TIMEOUT)))
            .map_err(io_error)?;
        let cap = bytes.len().min(MAX_TOTAL_BYTES - self.bytes);
        let n = stream.read(&mut bytes[..cap]).map_err(io_error)?;
        self.bytes += n;
        Ok(n)
    }
}
fn io_error(e: std::io::Error) -> VerificationError {
    error(
        ErrorCode::CrlFetchFailed,
        format!("CRL HTTP I/O failed: {e}"),
    )
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
impl CrlSource for HttpCrlSource {
    fn fetch(&mut self, raw: &str, max_bytes: usize) -> Result<FetchedCrl, VerificationError> {
        self.started.get_or_insert_with(Instant::now);
        let mut url = checked_url(raw)?;
        let cap = max_bytes.min(MAX_CRL_BYTES);
        if cap == 0 {
            return Err(limit("crl_response_bytes", cap, 0, 1));
        }
        for redirects in 0..=3 {
            if self.requests >= MAX_REQUESTS {
                return Err(limit("crl_http_requests", MAX_REQUESTS, self.requests, 1));
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
            return Ok(FetchedCrl {
                bytes: body,
                final_url: url.into(),
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
            "http://example.com/\r\nx",
        ] {
            assert!(checked_url(url).is_err(), "{url}");
        }
        for url in [
            "http://example.com/test.crl",
            "http://8.8.8.8/x",
            "http://[2001:4860:4860::8888]/x",
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
    fn deadlines_request_budgets_and_dns_poison_are_terminal_without_network() {
        let mut source = HttpCrlSource {
            requests: MAX_REQUESTS,
            ..HttpCrlSource::new()
        };
        assert_eq!(
            source.fetch("http://example.com/x", 10).err().unwrap().code,
            ErrorCode::ResourceLimitExceeded
        );
        let source = HttpCrlSource {
            started: Some(Instant::now() - DEADLINE),
            ..HttpCrlSource::new()
        };
        assert_eq!(
            source.remaining().unwrap_err().code,
            ErrorCode::CrlFetchFailed
        );
        let source = HttpCrlSource {
            poisoned: true,
            ..HttpCrlSource::new()
        };
        assert!(source.remaining().is_err());
    }
}
