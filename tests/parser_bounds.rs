//! Bounded structural mutations; immutable committed fixtures are never rewritten.
#![cfg(feature = "verify")]
use rssig::{VerificationBundle, VerificationError, VerifyOptions};
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
        (include_bytes!("fixtures/good-pe64.exe"), rssig::verify_pe),
        (
            include_bytes!("fixtures/msi-good-pe64.msi"),
            rssig::verify_msi,
        ),
        (
            include_bytes!("fixtures/msi-good-v4.msi"),
            rssig::verify_msi,
        ),
        (include_bytes!("fixtures/msp-good.msp"), rssig::verify_msi),
        (include_bytes!("fixtures/good.cab"), rssig::verify_cab),
        (include_bytes!("fixtures/good.navx"), rssig::verify_navx),
        (
            include_bytes!("fixtures/good-powershell.ps1"),
            rssig::verify_powershell,
        ),
        (
            include_bytes!("fixtures/good-psxml-sha384.ps1xml"),
            rssig::verify_powershell_xml,
        ),
        (include_bytes!("fixtures/good-wsh.wsf"), rssig::verify_wsh),
        (include_bytes!("fixtures/good.rdp"), rssig::verify_rdp),
        (
            include_bytes!("fixtures/good-appx-zip64.msix"),
            rssig::verify_appx,
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
