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
