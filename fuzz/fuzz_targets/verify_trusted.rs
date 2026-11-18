//! Complete verification against configured roots and CRLs, reaching
//! certificate path building, EKU and time policy, and CRL applicability.
//! The trust store is fixed (the test root and its CRLs), so the fuzzer mutates
//! the signed artifact and its embedded, untrusted certificates. Offline: no
//! system roots, clock, network or filesystem access.
#![no_main]

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use rssig::TrustStore;
use rssig::verify::{RevocationPolicy, VerifyOptions, verify};

/// Fixed validation time (2027-01-15T07:59:59Z), matching the pinned test clock.
const NOW: u64 = 1_799_999_999;

static TRUST: LazyLock<TrustStore> = LazyLock::new(|| {
    let mut trust = TrustStore::default();
    trust
        .add_roots(include_bytes!("../../tests/fixtures/root.der"))
        .expect("committed test root loads");
    for crl in [
        &include_bytes!("../../tests/fixtures/good.crl")[..],
        &include_bytes!("../../tests/fixtures/good-intermediate.crl")[..],
    ] {
        trust.add_crl(crl).expect("committed test CRL loads");
    }
    trust
});

fuzz_target!(|data: &[u8]| {
    for revocation in [RevocationPolicy::Required, RevocationPolicy::Disabled] {
        let mut options = VerifyOptions::trusted_with_revocation(&TRUST, NOW, revocation);
        let _ = verify(data, &options);
        options.allow_sha1 = true;
        let _ = verify(data, &options);
    }
});
