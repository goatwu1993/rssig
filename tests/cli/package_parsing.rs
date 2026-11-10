//! Pin the verifier contract while structural adapters become public.
use super::support::*;

#[test]
fn lib05_preserves_extended_metadata_publisher_and_bundle_identity_failures() {
    let good = run_fixture("msi-good-pe64.msi", INTEGRITY);
    expect_success(&good);
    let signature = &good.json["results"][0]["signatures"][0];
    assert_eq!(
        signature["extended_digest"]["expected"],
        signature["extended_digest"]["computed"]
    );
    for (name, code, stage) in [
        (
            "msi-bad-empty-extended.msi",
            "extended_digest_mismatch",
            "package_digest",
        ),
        ("bad-appx-publisher.msix", "appx_publisher_mismatch", "appx"),
        ("bad-appxbundle-name.msixbundle", "invalid_appx", "appx"),
    ] {
        let output = run_fixture(name, INTEGRITY);
        let error = &output.json["results"][0]["error"];
        assert_eq!(output.exit_code, 1);
        assert_eq!(error["code"], code);
        assert_eq!(error["stage"], stage);
    }
}
