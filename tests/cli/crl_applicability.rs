//! SEC-10 CRL applicability: unusable CRLs outside the chain are excluded, while
//! a CRL from a chain issuer that is stale or structurally invalid fails closed.
//! The cRLSign tests use the SEC-06 chain, whose issuer variants differ only in
//! KeyUsage.

use super::support::*;

const T: &str = "1800000000";

fn run_with(extra: &str) -> Output {
    run_fixture(
        "good-countersignature.exe",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--crl",
            &format!("fixtures/{extra}"),
            "--time",
            T,
        ],
    )
}

#[test]
fn sec10_unrelated_issuer_crls_are_excluded_whatever_their_fault() {
    for extra in [
        "sec10-unrelated-expired.crl",
        "sec10-unrelated-not-yet-valid.crl",
        "sec10-unrelated-no-next-update.crl",
    ] {
        let output = run_with(extra);
        expect_success(&output);
        assert_eq!(
            output.json["results"][0]["signatures"][0]["trust"]["revocation"]["status"], "good",
            "{extra}"
        );
    }
}

#[test]
fn sec10_chain_issuer_crl_without_next_update_is_a_typed_revocation_failure() {
    let output = run_with("sec10-root-no-next-update.crl");
    expect_failure(
        &output,
        1,
        "invalid_crl",
        "Invalid CRL",
        Some("revocation"),
        Some("nextUpdate"),
    );
}

#[test]
fn sec10_chain_issuer_stale_crl_still_fails_closed() {
    let output = run_with("expired.crl");
    expect_failure(
        &output,
        1,
        "crl_expired",
        "CRL expired",
        Some("revocation"),
        None,
    );
    assert_eq!(
        output.json["results"][0]["error"]["details"]["validation_time"],
        1_800_000_000u64
    );
}

#[test]
fn sec10_only_unrelated_crls_leave_revocation_unknown() {
    let output = run_fixture(
        "good-countersignature.exe",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/sec10-unrelated-expired.crl",
            "--time",
            T,
        ],
    );
    expect_failure(
        &output,
        1,
        "revocation_unknown",
        "Revocation status unknown",
        Some("revocation"),
        None,
    );
}

#[test]
fn sec10_crl_naming_another_authority_key_is_excluded() {
    // Same issuer name as the root, but its authorityKeyIdentifier names a
    // different key, so it cannot be the CRL of the chain's issuer.
    expect_success(&run_with("sec10-root-name-other-aki-expired.crl"));
}

#[test]
fn sec10_crl_naming_the_issuer_key_still_fails_closed_when_stale() {
    let output = run_with("sec10-root-aki-expired.crl");
    expect_failure(
        &output,
        1,
        "crl_expired",
        "CRL expired",
        Some("revocation"),
        None,
    );
}

#[test]
fn sec10_malformed_authority_key_identifier_fails_closed() {
    let output = run_with("sec10-root-malformed-aki.crl");
    expect_failure(
        &output,
        1,
        "invalid_crl",
        "Invalid CRL",
        Some("revocation"),
        Some("authorityKeyIdentifier"),
    );
}

#[test]
fn sec10_chain_issuer_signature_is_never_excluded_by_a_mismatched_aki() {
    // Signed by the root's own key, so a differing authorityKeyIdentifier
    // cannot make it irrelevant: the stale CRL still fails closed.
    let output = run_with("sec10-root-signed-other-aki-expired.crl");
    expect_failure(
        &output,
        1,
        "crl_expired",
        "CRL expired",
        Some("revocation"),
        None,
    );
}

#[test]
fn sec10_unrelated_crl_with_malformed_aki_is_excluded() {
    expect_success(&run_with("sec10-unrelated-malformed-aki.crl"));
}

#[test]
fn sec10_unsupported_crl_features_from_a_chain_issuer_are_typed() {
    for (file, reason) in [
        (
            "sec10-root-unknown-critical-extension.crl",
            "unknown_critical_extension",
        ),
        (
            "sec10-root-entry-critical-extension.crl",
            "unknown_critical_extension",
        ),
        ("sec10-root-delta.crl", "delta_crl"),
        ("sec10-root-delta-expired.crl", "delta_crl"),
        ("sec10-root-indirect.crl", "indirect_crl"),
    ] {
        let output = run_with(file);
        expect_failure(
            &output,
            1,
            "invalid_crl",
            "Invalid CRL",
            Some("revocation"),
            None,
        );
        let details = &output.json["results"][0]["error"]["details"];
        assert_eq!(details["reason"], reason, "{file}");
        assert!(details["crl"]["der_hex"].is_string(), "{file}");
    }
}

#[test]
fn sec10_unknown_noncritical_crl_extension_is_ignored() {
    expect_success(&run_with("sec10-root-unknown-noncritical-extension.crl"));
}

fn run_sec06(input: &str) -> Output {
    run_fixture(
        input,
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/sec06-root.der",
            "--time",
            T,
            "--crl",
            "fixtures/sec06-root.crl",
            "--crl",
            "fixtures/sec06-issuer.crl",
        ],
    )
}

#[test]
fn sec10_crl_from_an_issuer_without_crl_sign_is_rejected() {
    let output = run_sec06("sec10-ca-no-crl-sign.exe");
    expect_failure(
        &output,
        1,
        "invalid_key_usage",
        "Invalid key usage",
        Some("revocation"),
        None,
    );
}

#[test]
fn sec10_crl_from_an_issuer_with_crl_sign_is_used() {
    let output = run_sec06("sec10-ca-crl-sign.exe");
    expect_success(&output);
    let trust = &output.json["results"][0]["signatures"][0]["trust"];
    assert_eq!(trust["revocation"]["status"], "good");
    assert_eq!(trust["chain"].as_array().unwrap().len(), 3);
}

#[test]
fn sec10_path_building_falls_back_to_the_issuer_with_crl_sign() {
    let fallback = run_sec06("sec10-ca-crl-sign-fallback.exe");
    let usable = run_sec06("sec10-ca-crl-sign.exe");
    expect_success(&fallback);
    let chain =
        |output: &Output| output.json["results"][0]["signatures"][0]["trust"]["chain"].clone();
    assert_eq!(chain(&fallback), chain(&usable));
}
