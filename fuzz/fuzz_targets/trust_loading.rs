//! Root and CRL loading from untrusted bytes, then verification of one fixed,
//! valid artifact against the resulting store. The fuzzer mutates the trust
//! inputs instead of the artifact: fuzzed roots exercise anchor extraction and
//! path building, fuzzed CRLs exercise CRL decoding, applicability, signature
//! and freshness checks under required revocation.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rssig::TrustStore;
use rssig::verify::{RevocationPolicy, VerifyOptions, verify_pe};

/// Fixed validation time (2027-01-15T07:59:59Z), matching the pinned test clock.
const NOW: u64 = 1_799_999_999;
const SIGNED: &[u8] = include_bytes!("../../tests/fixtures/good-pe64.exe");
const ROOT: &[u8] = include_bytes!("../../tests/fixtures/root.der");

fuzz_target!(|data: &[u8]| {
    // Fuzzed roots. Revocation is disabled so path building is not cut short
    // by the absence of CRLs.
    let mut roots = TrustStore::default();
    if roots.add_roots(data).is_ok() {
        let options =
            VerifyOptions::trusted_with_revocation(&roots, NOW, RevocationPolicy::Disabled);
        let _ = verify_pe(SIGNED, &options);
    }
    // The committed root with fuzzed CRLs, revocation required.
    let mut crls = TrustStore::default();
    crls.add_roots(ROOT).expect("committed test root loads");
    if crls.add_crl(data).is_ok() {
        let _ = verify_pe(SIGNED, &VerifyOptions::trusted(&crls, NOW));
    }
});
