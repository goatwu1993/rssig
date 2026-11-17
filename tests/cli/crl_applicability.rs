//! SEC-10 CRL applicability: unusable CRLs outside the chain are excluded, while
//! a CRL from a chain issuer that is stale or structurally invalid fails closed.

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
