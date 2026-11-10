#![cfg(feature = "verify")]
use rssig::{
    TrustStore,
    verify::{RevocationPolicy, VerifyOptions},
};
const NOW: u64 = 1800000000;
const FILE: &[u8] = include_bytes!("fixtures/good-pe64.exe");
#[test]
fn constructors_require_explicit_time_and_keep_trust_and_revocation_enabled() {
    let mut trust = TrustStore::default();
    trust
        .add_roots(include_bytes!("fixtures/root.der"))
        .unwrap();
    let options = VerifyOptions::trusted(&trust, NOW);
    assert!(options.trust.is_some());
    assert!(options.check_revocation);
    assert!(!options.allow_sha1);
    assert_eq!(options.now, NOW);
    assert_eq!(
        rssig::verify(FILE, &options).unwrap_err().code,
        rssig::domain::ErrorCode::RevocationUnknown
    );
    trust.add_crl(include_bytes!("fixtures/good.crl")).unwrap();
    let report = rssig::verify(FILE, &VerifyOptions::trusted(&trust, NOW)).unwrap();
    assert_eq!(report.validation_time, NOW);
    assert!(report.signatures[0].chain_trusted);
    assert!(report.signatures[0].revocation_checked);
    let reduced = VerifyOptions::trusted_with_revocation(&trust, NOW, RevocationPolicy::Disabled);
    let report = rssig::verify(FILE, &reduced).unwrap();
    assert!(report.signatures[0].chain_trusted);
    assert!(!report.signatures[0].revocation_checked);
    assert!(
        VerifyOptions::trusted_with_revocation(&trust, NOW, RevocationPolicy::Required)
            .check_revocation
    );
}
#[test]
fn integrity_only_is_explicit_and_cannot_claim_revocation() {
    let options = VerifyOptions::integrity_only(NOW);
    assert!(options.trust.is_none());
    assert!(!options.check_revocation);
    assert!(!options.allow_sha1);
    let report = rssig::verify(FILE, &options).unwrap();
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["validation_time"], NOW);
    assert_eq!(json["signatures"][0]["chain_trusted"], false);
    assert_eq!(json["signatures"][0]["revocation_checked"], false);
    // Legacy public struct literals remain supported: revocation only applies with trust.
    let legacy = VerifyOptions {
        check_revocation: true,
        ..options
    };
    assert_eq!(
        serde_json::to_value(rssig::verify(FILE, &legacy).unwrap()).unwrap(),
        json
    );
    let empty = TrustStore::default();
    assert!(rssig::verify(FILE, &VerifyOptions::trusted(&empty, NOW)).is_err());
}
