//! CRL retrieval through an injected source, offline. An input that starts
//! like a PE (`MZ`) is the signed artifact, and the source answers with the
//! committed CRL; any other input is the source's answer to every request for
//! a fixed artifact whose signer and issuer both list a distribution point.
//! So `.exe` seeds fuzz the artifact and `.crl`/`.der` seeds the response. Reaches retrieval ordering, the DER issuer walker over
//! certificates and fetched CRLs, failure recording and the engine's limits.
//! Property: no input panics, and the source is the only I/O.
#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use rssig::TrustStore;
use rssig::retrieval::{
    CrlRequest, CrlResponse, CrlSource, CrlSourceError, CrlSourceErrorKind, SourcedCrl, fetch_each,
    verify_with_crl_source,
};
use rssig::verify::VerifyOptions;

/// Fixed validation time (2027-01-15T07:59:59Z), matching the pinned test clock.
const NOW: u64 = 1_799_999_999;

static TEST_ROOT: LazyLock<TrustStore> = LazyLock::new(|| {
    let mut trust = TrustStore::default();
    trust
        .add_roots(include_bytes!("../../tests/fixtures/root.der"))
        .expect("committed test root loads");
    trust
});

static SEC06: LazyLock<TrustStore> = LazyLock::new(|| {
    let mut trust = TrustStore::default();
    trust
        .add_roots(include_bytes!("../../tests/fixtures/path-root.der"))
        .expect("committed SEC-06 root loads");
    trust
        .add_crl(include_bytes!("../../tests/fixtures/path-issuer.crl"))
        .expect("committed SEC-06 issuer CRL loads");
    trust
});

/// Answers every request with the same bytes, at most `max_bytes` of them.
/// An empty answer is a fetch error whose kind follows the URL's length, so
/// every kind, `Abort` included, is reached.
struct Answer<'a>(&'a [u8]);
impl CrlSource for Answer<'_> {
    fn crls(&mut self, request: &CrlRequest<'_>) -> Result<CrlResponse, CrlSourceError> {
        Ok(fetch_each(request, |url, max_bytes| {
            if self.0.is_empty() {
                let kinds = [
                    CrlSourceErrorKind::Denied,
                    CrlSourceErrorKind::Failed,
                    CrlSourceErrorKind::Abort,
                    CrlSourceErrorKind::Unknown,
                ];
                return Err(CrlSourceError::new(kinds[url.len() % 4], "fuzz"));
            }
            Ok(SourcedCrl::new(
                self.0[..self.0.len().min(max_bytes)].to_vec(),
            ))
        }))
    }
}

fuzz_target!(|data: &[u8]| {
    if data.starts_with(b"MZ") {
        let options = VerifyOptions::trusted(&TEST_ROOT, NOW);
        let crl = include_bytes!("../../tests/fixtures/good.crl");
        let _ = verify_with_crl_source(data, None, &options, &mut Answer(crl));
    } else {
        let options = VerifyOptions::trusted(&SEC06, NOW);
        let input = include_bytes!("../../tests/fixtures/crl-chain-crl-dp.exe");
        let _ = verify_with_crl_source(input, None, &options, &mut Answer(data));
    }
});
