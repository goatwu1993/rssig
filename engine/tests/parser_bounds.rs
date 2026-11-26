//! Bounded structural mutations; immutable committed fixtures are never rewritten.
#![cfg(feature = "verify")]
#[path = "common/crosscheck.rs"]
mod crosscheck;
use rssig_engine::{VerificationBundle, VerificationError, VerifyOptions};
type Verify = fn(&[u8], &VerifyOptions<'_>) -> Result<VerificationBundle, VerificationError>;

#[test]
fn parser_header_truncations_and_extreme_fields_do_not_panic() {
    let options = VerifyOptions {
        trust: None,
        check_revocation: false,
        allow_sha1: false,
        now: 1800000000,
    };
    let inputs: &[(&[u8], Verify)] = &[
        (
            include_bytes!("../../tests/fixtures/good-pe64.exe"),
            rssig_engine::verify_pe,
        ),
        (
            include_bytes!("../../tests/fixtures/msi-good-pe64.msi"),
            rssig_engine::verify_msi,
        ),
        (
            include_bytes!("../../tests/fixtures/msi-good-v4.msi"),
            rssig_engine::verify_msi,
        ),
        (
            include_bytes!("../../tests/fixtures/msp-good.msp"),
            rssig_engine::verify_msi,
        ),
        (
            include_bytes!("../../tests/fixtures/good.cab"),
            rssig_engine::verify_cab,
        ),
        (
            include_bytes!("../../tests/fixtures/good.navx"),
            rssig_engine::verify_navx,
        ),
        (
            include_bytes!("../../tests/fixtures/good-powershell.ps1"),
            rssig_engine::verify_powershell,
        ),
        (
            include_bytes!("../../tests/fixtures/good-psxml-sha384.ps1xml"),
            rssig_engine::verify_powershell_xml,
        ),
        (
            include_bytes!("../../tests/fixtures/good-wsh.wsf"),
            rssig_engine::verify_wsh,
        ),
        (
            include_bytes!("../../tests/fixtures/good.rdp"),
            rssig_engine::verify_rdp,
        ),
        (
            include_bytes!("../../tests/fixtures/good-appx-zip64.msix"),
            rssig_engine::verify_appx,
        ),
    ];
    for &(bytes, verify) in inputs {
        verify(bytes, &options).expect("baseline fixture must verify");
        for end in 0..bytes.len().min(256) {
            assert!(
                verify(&bytes[..end], &options).is_err(),
                "accepted truncated header at {end}"
            );
        }
        for at in (0..bytes.len().min(512) - 4).step_by(4) {
            for value in [0u32, u32::MAX] {
                let mut mutated = bytes.to_vec();
                mutated[at..at + 4].copy_from_slice(&value.to_le_bytes());
                // Some fields are intentionally unauthenticated. Acceptance is
                // not asserted here; any panic fails the test directly.
                if let Err(error) = verify(&mutated, &options) {
                    assert!(!error.message.is_empty());
                    assert!(serde_json::to_value(error).unwrap()["code"].is_string());
                }
            }
        }
    }
}
