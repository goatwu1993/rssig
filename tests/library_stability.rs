#![cfg(feature = "verify")]
use rssig::{TrustLoadErrorKind, TrustStore, VerifyOptions, parse::Pe};
use std::error::Error;

#[test]
fn typed_load_errors_preserve_causes_and_legacy_diagnostics() {
    let mut store = TrustStore::default();
    let bad = include_bytes!("fixtures/good-pe64.exe");
    let error = store.add_roots_typed(bad).unwrap_err();
    assert_eq!(error.kind(), TrustLoadErrorKind::Roots);
    assert!(error.source().is_some());
    assert_eq!(
        error.to_string(),
        store.add_roots(bad).unwrap_err().to_string()
    );
    let error = store.add_crl_typed(bad).unwrap_err();
    assert_eq!(error.kind(), TrustLoadErrorKind::Crl);
    assert!(error.source().is_some());
    assert_eq!(
        error.to_string(),
        store.add_crl(bad).unwrap_err().to_string()
    );
    // Loading failures must not discard previously supplied good evidence.
    store
        .add_roots_typed(include_bytes!("fixtures/root.der"))
        .unwrap();
    store
        .add_crl_typed(include_bytes!("fixtures/good.crl"))
        .unwrap();
    assert!(store.add_roots_typed(bad).is_err());
    assert!(store.add_crl_typed(bad).is_err());
    rssig::verify(bad, &VerifyOptions::trusted(&store, 1800000000)).unwrap();
}

#[test]
fn verification_can_repeat_after_success_and_policy_failure() {
    let bytes = include_bytes!("fixtures/good-pe64.exe");
    let parsed = Pe::parse(bytes).unwrap();
    let original_signature = parsed.signatures().unwrap()[0];
    let mut store = TrustStore::default();
    store
        .add_roots(include_bytes!("fixtures/root.der"))
        .unwrap();
    let trusted = VerifyOptions::trusted(&store, 1800000000);
    let integrity = VerifyOptions::integrity_only(1800000000);
    let first = serde_json::to_value(rssig::verify(bytes, &integrity).unwrap()).unwrap();
    assert_eq!(
        rssig::verify(bytes, &trusted).unwrap_err().code,
        rssig::domain::ErrorCode::RevocationUnknown
    );
    assert_eq!(
        serde_json::to_value(rssig::verify(bytes, &integrity).unwrap()).unwrap(),
        first
    );
    assert_eq!(parsed.signatures().unwrap()[0], original_signature);
    assert_eq!(first["signatures"][0]["chain_trusted"], false);
}

#[test]
fn reusable_package_adapters_recover_after_policy_failure() {
    let mut store = TrustStore::default();
    store
        .add_roots(include_bytes!("fixtures/root.der"))
        .unwrap();
    let trusted = VerifyOptions::trusted(&store, 1800000000);
    let integrity = VerifyOptions::integrity_only(1800000000);
    let mut msi = rssig::parse::Msi::parse(include_bytes!("fixtures/msi-good-pe64.msi")).unwrap();
    let msi_signature = msi.signature().to_vec();
    let first =
        serde_json::to_value(rssig::verify_parsed_msi(&mut msi, &integrity).unwrap()).unwrap();
    assert_eq!(
        rssig::verify_parsed_msi(&mut msi, &trusted)
            .unwrap_err()
            .code,
        rssig::domain::ErrorCode::RevocationUnknown
    );
    assert_eq!(
        serde_json::to_value(rssig::verify_parsed_msi(&mut msi, &integrity).unwrap()).unwrap(),
        first
    );
    assert_eq!(msi.signature(), msi_signature);
    let appx = rssig::parse::Appx::parse(include_bytes!("fixtures/good.msix")).unwrap();
    let signature_pointer = appx.signature().as_ptr();
    let first =
        serde_json::to_value(rssig::verify_parsed_appx(&appx, &integrity).unwrap()).unwrap();
    assert_eq!(
        rssig::verify_parsed_appx(&appx, &trusted).unwrap_err().code,
        rssig::domain::ErrorCode::RevocationUnknown
    );
    assert_eq!(
        serde_json::to_value(rssig::verify_parsed_appx(&appx, &integrity).unwrap()).unwrap(),
        first
    );
    assert_eq!(appx.signature().as_ptr(), signature_pointer);
}
