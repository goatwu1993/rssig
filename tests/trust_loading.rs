#![cfg(feature = "verify-core")]
use rssig::{TrustLoadErrorCode as Code, TrustLoadErrorKind as Kind, TrustStore, VerifyOptions};

const IMAGE: &[u8] = include_bytes!("fixtures/good-pe64.exe");
const ROOT: &[u8] = include_bytes!("fixtures/root.der");
const CRL: &[u8] = include_bytes!("fixtures/good.crl");

fn verify(store: &TrustStore) -> Result<serde_json::Value, rssig::domain::VerificationError> {
    rssig::verify_pe(IMAGE, &VerifyOptions::trusted(store, 1800000000))
        .map(|report| serde_json::to_value(report).unwrap())
}

#[test]
fn sec07_failed_root_bundle_cannot_partially_establish_trust() {
    for (bytes, code, index) in [
        (
            include_bytes!("fixtures/sec07-roots-unsupported.pem").as_slice(),
            Code::UnsupportedAnchor,
            2,
        ),
        (
            include_bytes!("fixtures/sec07-roots-invalid.pem").as_slice(),
            Code::InvalidEncoding,
            2,
        ),
        (
            include_bytes!("fixtures/sec07-roots-invalid-first.pem").as_slice(),
            Code::InvalidEncoding,
            1,
        ),
        (
            include_bytes!("fixtures/sec07-roots-trailing.pem").as_slice(),
            Code::InvalidEncoding,
            2,
        ),
        (
            include_bytes!("fixtures/sec07-roots-truncated.pem").as_slice(),
            Code::InvalidEncoding,
            2,
        ),
    ] {
        let mut store = TrustStore::default();
        store.add_crl(CRL).unwrap();
        let error = store.add_roots_typed(bytes).unwrap_err();
        assert_eq!(error.kind(), Kind::Roots);
        assert_eq!(error.code(), code);
        assert_eq!(error.entry_index(), Some(index));
        assert!(std::error::Error::source(&error).is_some());
        assert_eq!(
            verify(&store).unwrap_err().code,
            rssig::domain::ErrorCode::UntrustedRoot
        );
        store.add_roots(ROOT).unwrap();
        let before = verify(&store).unwrap();
        assert!(store.add_roots_typed(bytes).is_err());
        assert_eq!(verify(&store).unwrap(), before);
    }
}

#[test]
fn sec07_failed_crl_bundle_cannot_partially_supply_revocation() {
    for (bytes, index) in [
        (
            include_bytes!("fixtures/sec07-crls-invalid.pem").as_slice(),
            2,
        ),
        (
            include_bytes!("fixtures/sec07-crls-invalid-first.pem").as_slice(),
            1,
        ),
        (
            include_bytes!("fixtures/sec07-crls-trailing.pem").as_slice(),
            2,
        ),
    ] {
        let mut store = TrustStore::default();
        store.add_roots(ROOT).unwrap();
        let error = store.add_crl_typed(bytes).unwrap_err();
        assert_eq!(error.kind(), Kind::Crl);
        assert_eq!(error.code(), Code::InvalidEncoding);
        assert_eq!(error.entry_index(), Some(index));
        assert_eq!(
            verify(&store).unwrap_err().code,
            rssig::domain::ErrorCode::RevocationUnknown
        );
        store.add_crl(CRL).unwrap();
        let before = verify(&store).unwrap();
        assert!(store.add_crl_typed(bytes).is_err());
        assert_eq!(verify(&store).unwrap(), before);
    }
}

#[test]
fn sec07_repeated_der_and_pem_loads_preserve_reports_and_original_bytes() {
    let mut store = TrustStore::default();
    store.add_roots(ROOT).unwrap();
    store.add_crl(CRL).unwrap();
    let before = verify(&store).unwrap();
    for _ in 0..2 {
        store.add_roots(ROOT).unwrap();
        store.add_crl(CRL).unwrap();
        store
            .add_roots(include_bytes!("fixtures/sec07-roots-duplicate.pem"))
            .unwrap();
        store
            .add_crl(include_bytes!("fixtures/sec07-crls-duplicate.pem"))
            .unwrap();
    }
    assert_eq!(verify(&store).unwrap(), before);
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let trust = &before["signatures"][0]["trust"];
    assert_eq!(trust["chain"][1]["der_hex"], hex(ROOT));
    assert_eq!(trust["revocation"]["crls"][0]["der_hex"], hex(CRL));
    assert_eq!(trust["revocation"]["crls"][0]["role"], "supplied");
}

#[test]
fn sec07_empty_or_whitespace_input_is_explicitly_rejected() {
    let mut store = TrustStore::default();
    for bytes in [b"".as_slice(), b" \r\n\t"] {
        for error in [
            store.add_roots_typed(bytes).unwrap_err(),
            store.add_crl_typed(bytes).unwrap_err(),
        ] {
            assert_eq!(error.code(), Code::EmptyInput);
            assert_eq!(error.entry_index(), None);
        }
    }
}

#[test]
fn sec07_loaded_forged_crl_is_not_authenticated_even_with_revocation_disabled() {
    let mut store = TrustStore::default();
    store.add_roots(ROOT).unwrap();
    store
        .add_crl_typed(include_bytes!("fixtures/sec07-crls-forged.pem"))
        .unwrap();
    assert_eq!(
        verify(&store).unwrap_err().code,
        rssig::domain::ErrorCode::InvalidCrlSignature
    );
    let options = VerifyOptions::trusted_with_revocation(
        &store,
        1800000000,
        rssig::RevocationPolicy::Disabled,
    );
    let report = serde_json::to_value(rssig::verify_pe(IMAGE, &options).unwrap()).unwrap();
    let sig = &report["signatures"][0];
    assert_eq!(sig["revocation_checked"], false);
    assert_eq!(sig["trust"]["revocation"]["status"], "not_checked");
    assert_eq!(sig["trust"]["revocation"]["crls"], serde_json::json!([]));
}
