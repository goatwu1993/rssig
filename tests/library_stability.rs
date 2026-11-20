#![cfg(feature = "verify")]
use rssig::{
    TrustLoadError, TrustLoadErrorCode, TrustLoadErrorKind, TrustStore, VerifyOptions, parse::Pe,
};
use std::error::Error;

// Pins the trust-loading signatures to `TrustLoadError`. It guards these three
// loaders only; AGENTS.md states the crate-wide rule that `anyhow` stays internal.
#[test]
fn trust_loading_signatures_return_trust_load_error() {
    let _: fn(&mut TrustStore, &[u8]) -> Result<(), TrustLoadError> = TrustStore::add_roots;
    let _: fn(&mut TrustStore, &[u8]) -> Result<(), TrustLoadError> = TrustStore::add_crl;
    #[cfg(feature = "system-roots")]
    {
        let _: fn() -> Result<TrustStore, TrustLoadError> = TrustStore::from_system;
        #[allow(deprecated)]
        let _: fn() -> Result<TrustStore, TrustLoadError> = TrustStore::from_system_typed;
    }
}

/// `{}` names the failure, `source()` walks its causes, and `{:#}` is exactly
/// `{}` followed by each cause once.
fn assert_causes_once(error: &dyn Error, alternate: &str) {
    let mut walked = error.to_string();
    let mut cause = error.source();
    while let Some(next) = cause {
        walked.push_str(&format!(": {next}"));
        cause = next.source();
    }
    assert_eq!(walked, alternate);
}

#[test]
#[allow(deprecated)]
fn typed_load_errors_preserve_causes_and_deprecated_aliases() {
    let mut store = TrustStore::default();
    let bad = include_bytes!("fixtures/good-pe64.exe");
    for (kind, summary, error, alias) in [
        (
            TrustLoadErrorKind::Roots,
            "invalid root encoding in trust input entry 1",
            store.add_roots(bad).unwrap_err(),
            store.add_roots_typed(bad).unwrap_err(),
        ),
        (
            TrustLoadErrorKind::Crl,
            "invalid CRL encoding in trust input entry 1",
            store.add_crl(bad).unwrap_err(),
            store.add_crl_typed(bad).unwrap_err(),
        ),
    ] {
        assert_eq!(error.kind(), kind);
        assert_eq!(error.code(), TrustLoadErrorCode::InvalidEncoding);
        assert_eq!(error.entry_index(), Some(1));
        assert_eq!(error.to_string(), summary);
        let chain = format!("{error:#}");
        // The DER decoder's cause survives below the summary, exactly once.
        assert!(chain.starts_with(&format!("{summary}: ")), "{chain}");
        assert!(chain.contains("ASN.1"), "{chain}");
        assert_eq!(chain.matches("trust input entry").count(), 1, "{chain}");
        assert_causes_once(&error, &chain);
        assert_eq!(format!("{alias:#}"), chain);
        // The CLI converts with `?` and `.with_context`; that path keeps the type.
        let wrapped = anyhow::Error::from(error).context("loading");
        assert_eq!(format!("{wrapped:#}"), format!("loading: {chain}"));
        assert_eq!(
            wrapped.downcast_ref::<TrustLoadError>().unwrap().kind(),
            kind
        );
    }
    let error = store.add_roots(b"").unwrap_err();
    assert_eq!(error.code(), TrustLoadErrorCode::EmptyInput);
    assert_eq!(format!("{error:#}"), "empty trust input");
    assert!(error.source().is_none());
    // Loading failures must not discard previously supplied good evidence.
    store
        .add_roots(include_bytes!("fixtures/root.der"))
        .unwrap();
    store.add_crl(include_bytes!("fixtures/good.crl")).unwrap();
    assert!(store.add_roots(bad).is_err());
    assert!(store.add_crl(bad).is_err());
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
