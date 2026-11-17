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
