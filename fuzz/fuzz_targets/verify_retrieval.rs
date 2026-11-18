//! CRL retrieval through an injected source, offline. The first byte picks the
//! mode: either the signed artifact is fuzzed and the source answers with the
//! committed CRL, or a fixed artifact whose signer and issuer both list a
//! distribution point is verified and the source answers every request with
//! the fuzzed bytes. Reaches retrieval ordering, the DER issuer walker over
//! certificates and fetched CRLs, failure recording and the engine's limits.
//! Property: no input panics, and the source is the only I/O.
#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use rssig::TrustStore;
use rssig::domain::VerificationError;
use rssig::retrieval::{CrlSource, FetchedCrl, verify_with_crl_source};
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
        .add_roots(include_bytes!("../../tests/fixtures/sec06-root.der"))
        .expect("committed SEC-06 root loads");
    trust
        .add_crl(include_bytes!("../../tests/fixtures/sec06-issuer.crl"))
        .expect("committed SEC-06 issuer CRL loads");
    trust
});

/// Answers every request with the same bytes, at most `max_bytes` of them.
struct Answer<'a>(&'a [u8]);
impl CrlSource for Answer<'_> {
    fn fetch(&mut self, url: &str, max_bytes: usize) -> Result<FetchedCrl, VerificationError> {
        Ok(FetchedCrl {
            bytes: self.0[..self.0.len().min(max_bytes)].to_vec(),
            final_url: url.into(),
        })
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    if mode & 1 == 0 {
        let options = VerifyOptions::trusted(&TEST_ROOT, NOW);
        let crl = include_bytes!("../../tests/fixtures/good.crl");
        let _ = verify_with_crl_source(rest, None, &options, &mut Answer(crl));
    } else {
        let options = VerifyOptions::trusted(&SEC06, NOW);
        let input = include_bytes!("../../tests/fixtures/sec10-chain-crl-dp.exe");
        let _ = verify_with_crl_source(input, None, &options, &mut Answer(rest));
    }
});
