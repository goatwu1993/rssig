use super::support::*;
#[test]
fn lib07_policy_modes_are_explicit_in_serialized_results() {
    for (args, trusted, revocation) in [
        (TRUSTED, true, true),
        (TRUSTED_NO_REVOCATION, true, false),
        (INTEGRITY, false, false),
    ] {
        let output = run_fixture("good-pe64.exe", args);
        expect_success(&output);
        let result = &output.json["results"][0];
        assert_eq!(result["validation_time"], 1800000000u64);
        assert_eq!(result["signatures"][0]["chain_trusted"], trusted);
        assert_eq!(result["signatures"][0]["revocation_checked"], revocation);
    }
}
#[test]
fn lib08_repeated_verification_has_identical_serialized_evidence() {
    let first = run_fixture("good-pe64.exe", TRUSTED);
    let second = run_fixture("good-pe64.exe", TRUSTED);
    expect_success(&first);
    expect_success(&second);
    assert_eq!(first.json, second.json);
    assert_eq!(
        first.json["results"][0]["signatures"][0]["chain_trusted"],
        true
    );
    assert_eq!(
        first.json["results"][0]["signatures"][0]["revocation_checked"],
        true
    );
}
#[test]
fn lib09_core_policy_matches_cli_serialized_result() {
    let output = run_fixture("good-pe64.exe", TRUSTED);
    expect_success(&output);
    assert_eq!(
        output.json["results"][0]["signatures"][0]["chain_trusted"],
        true
    );
    assert_eq!(
        output.json["results"][0]["signatures"][0]["revocation_checked"],
        true
    );
}
