//! SEC-08 committed timestamp structure, binding and TSA certificate cases.

use super::support::*;

#[test]
fn tsa_version() {
    let output = run_fixture("tsa-version.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_policy() {
    let output = run_fixture("tsa-policy.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_serial_negative() {
    let output = run_fixture("tsa-serial-negative.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_serial_nonminimal() {
    let output = run_fixture("tsa-serial-nonminimal.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_time_tag() {
    let output = run_fixture("tsa-time-tag.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_unknown() {
    let output = run_fixture("tsa-unknown.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_order() {
    let output = run_fixture("tsa-order.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_duplicate_optional() {
    let output = run_fixture("tsa-duplicate-optional.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_ordering_false() {
    let output = run_fixture("tsa-ordering-false.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_nonce_negative() {
    let output = run_fixture("tsa-nonce-negative.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_accuracy_range() {
    let output = run_fixture("tsa-accuracy-range.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_accuracy_order() {
    let output = run_fixture("tsa-accuracy-order.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_accuracy_unknown() {
    let output = run_fixture("tsa-accuracy-unknown.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_tsa() {
    let output = run_fixture("tsa-tsa.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_extensions() {
    let output = run_fixture("tsa-extensions.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_duplicate_rfc() {
    let output = run_fixture("tsa-duplicate-rfc.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_duplicate_counter() {
    let output = run_fixture("tsa-duplicate-counter.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_duplicate_eku_rfc() {
    // Two timestamps are counted before the first token is judged (TSA-004).
    let output = run_fixture("tsa-duplicate-eku-rfc.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_duplicate_eku_counter() {
    let output = run_fixture("tsa-duplicate-eku-counter.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_mixed() {
    let output = run_fixture("tsa-mixed.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_mixed_reverse() {
    let output = run_fixture("tsa-mixed-reverse.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_aliases() {
    let output = run_fixture("tsa-aliases.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_multi_value() {
    let output = run_fixture("tsa-multi-value.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_eku_noncritical() {
    let output = run_fixture("tsa-eku-noncritical.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_eku");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_eku_mixed() {
    let output = run_fixture("tsa-eku-mixed.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_eku");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_eku_missing() {
    let output = run_fixture("tsa-eku-missing.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_eku");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_key_usage() {
    let output = run_fixture("tsa-key-usage.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_key_usage");
    assert_eq!(error["stage"], "certificate");
}

#[test]
fn tsa_substitution() {
    let output = run_fixture("tsa-substitution.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "timestamp_imprint_mismatch");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_counter_substitution() {
    let output = run_fixture("tsa-counter-substitution.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "content_digest_mismatch");
    assert_eq!(error["stage"], "cms");
}

#[test]
fn tsa_signing_time() {
    let output = run_fixture("tsa-signing-time.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_counter_eku_noncritical() {
    let output = run_fixture("tsa-counter-eku-noncritical.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_eku");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_counter_eku_mixed() {
    let output = run_fixture("tsa-counter-eku-mixed.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_eku");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_counter_eku_missing() {
    let output = run_fixture("tsa-counter-eku-missing.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_eku");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn tsa_counter_key_usage() {
    let output = run_fixture("tsa-counter-key-usage.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_key_usage");
    assert_eq!(error["stage"], "certificate");
}

#[test]
fn tsa_good() {
    let output = run_fixture("tsa-good.exe", TRUSTED);
    expect_success(&output);
    let ts = &output.json["results"][0]["signatures"][0]["timestamp_verification"];
    assert_eq!(ts["signing_time"], 1800000000u64);
    assert_eq!(ts["kind"], "rfc3161");
    assert_eq!(ts["trust"]["revocation"]["status"], "good");
}

#[test]
fn tsa_good_optional() {
    let output = run_fixture("tsa-good-optional.exe", TRUSTED);
    expect_success(&output);
    let ts = &output.json["results"][0]["signatures"][0]["timestamp_verification"];
    assert_eq!(ts["signing_time"], 1800000000u64);
    assert_eq!(ts["kind"], "rfc3161");
    assert_eq!(ts["trust"]["revocation"]["status"], "good");
}

#[test]
fn tsa_good_counter() {
    let output = run_fixture("tsa-good-counter.exe", TRUSTED);
    expect_success(&output);
    let ts = &output.json["results"][0]["signatures"][0]["timestamp_verification"];
    assert_eq!(ts["signing_time"], 1800000000u64);
    assert_eq!(ts["kind"], "pkcs9_countersignature");
    assert_eq!(ts["trust"]["revocation"]["status"], "good");
}
