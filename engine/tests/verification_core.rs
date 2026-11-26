#![cfg(feature = "verify-core")]
#[path = "common/crosscheck.rs"]
mod crosscheck;
use rssig_engine::{TrustStore, VerifyOptions};
#[test]
fn core_checks_trust_revocation_and_integrity() {
    let mut trust = TrustStore::default();
    trust
        .add_roots(include_bytes!("../../tests/fixtures/root.der"))
        .unwrap();
    trust
        .add_crl(include_bytes!("../../tests/fixtures/good.crl"))
        .unwrap();
    let options = VerifyOptions::trusted(&trust, 1800000000);
    let report = rssig_engine::verify(
        include_bytes!("../../tests/fixtures/good-pe64.exe"),
        &options,
    )
    .unwrap();
    let json = serde_json::to_value(report).unwrap();
    assert_eq!(json["signatures"][0]["chain_trusted"], true);
    assert_eq!(json["signatures"][0]["revocation_checked"], true);
    assert_eq!(
        rssig_engine::verify(
            include_bytes!("../../tests/fixtures/bad-image-digest.exe"),
            &options
        )
        .unwrap_err()
        .code,
        rssig_engine::domain::ErrorCode::ImageDigestMismatch
    );
}

#[test]
fn core_formats_and_timestamps_use_configured_trust() {
    let mut trust = TrustStore::default();
    trust
        .add_roots(include_bytes!("../../tests/fixtures/root.der"))
        .unwrap();
    trust
        .add_crl(include_bytes!("../../tests/fixtures/good.crl"))
        .unwrap();
    let options = VerifyOptions::trusted(&trust, 1800000000);
    for (bytes, format) in [
        (
            include_bytes!("../../tests/fixtures/good.cab").as_slice(),
            "cab_authenticode",
        ),
        (
            include_bytes!("../../tests/fixtures/good.navx").as_slice(),
            "navx_authenticode",
        ),
        (
            include_bytes!("../../tests/fixtures/good-powershell.ps1").as_slice(),
            "powershell_authenticode",
        ),
        (
            include_bytes!("../../tests/fixtures/good-psxml.ps1xml").as_slice(),
            "powershell_xml_authenticode",
        ),
        (
            include_bytes!("../../tests/fixtures/good-wsh.wsf").as_slice(),
            "wsf_authenticode",
        ),
        (
            include_bytes!("../../tests/fixtures/good.rdp").as_slice(),
            "rdp_signed_settings",
        ),
    ] {
        let report = rssig_engine::verify(bytes, &options).unwrap();
        assert_eq!(report.format, format);
        assert!(report.signatures[0].chain_trusted);
        assert!(report.signatures[0].revocation_checked);
    }
    for bytes in [
        include_bytes!("../../tests/fixtures/good-rfc3161.exe").as_slice(),
        include_bytes!("../../tests/fixtures/good-countersignature.exe").as_slice(),
    ] {
        let report = rssig_engine::verify(bytes, &options).unwrap();
        let timestamp = report.signatures[0]
            .timestamp_verification
            .as_ref()
            .unwrap();
        assert!(!timestamp.trust.as_ref().unwrap().chain.is_empty());
    }
    let bad = rssig_engine::verify(
        include_bytes!("../../tests/fixtures/bad-timestamp-imprint.exe"),
        &options,
    )
    .unwrap_err();
    assert_eq!(
        bad.code,
        rssig_engine::domain::ErrorCode::TimestampImprintMismatch
    );
    let mut revoked = TrustStore::default();
    revoked
        .add_roots(include_bytes!("../../tests/fixtures/root.der"))
        .unwrap();
    revoked
        .add_crl(include_bytes!("../../tests/fixtures/revoked.crl"))
        .unwrap();
    assert_eq!(
        rssig_engine::verify(
            include_bytes!("../../tests/fixtures/good-pe64.exe"),
            &VerifyOptions::trusted(&revoked, 1800000000)
        )
        .unwrap_err()
        .code,
        rssig_engine::domain::ErrorCode::CertificateRevoked
    );
}

#[cfg(not(feature = "appx"))]
#[test]
fn disabled_package_adapter_fails_closed() {
    let error = rssig_engine::verify(
        include_bytes!("../../tests/fixtures/good.msix"),
        &VerifyOptions::integrity_only(1800000000),
    )
    .unwrap_err();
    assert_eq!(error.code, rssig_engine::domain::ErrorCode::Configuration);
    assert_eq!(error.stage, rssig_engine::domain::Stage::Configuration);
}
