//! SEC-08 committed timestamp structure, binding and certificate policy cases.

use super::support::*;

#[test]
fn sec08_version() {
    let output = run_fixture("sec08-version.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_policy() {
    let output = run_fixture("sec08-policy.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_serial_negative() {
    let output = run_fixture("sec08-serial-negative.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_serial_nonminimal() {
    let output = run_fixture("sec08-serial-nonminimal.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_time_tag() {
    let output = run_fixture("sec08-time-tag.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_unknown() {
    let output = run_fixture("sec08-unknown.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_order() {
    let output = run_fixture("sec08-order.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_duplicate_optional() {
    let output = run_fixture("sec08-duplicate-optional.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_ordering_false() {
    let output = run_fixture("sec08-ordering-false.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_nonce_negative() {
    let output = run_fixture("sec08-nonce-negative.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_accuracy_range() {
    let output = run_fixture("sec08-accuracy-range.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_accuracy_order() {
    let output = run_fixture("sec08-accuracy-order.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_accuracy_unknown() {
    let output = run_fixture("sec08-accuracy-unknown.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_tsa() {
    let output = run_fixture("sec08-tsa.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_extensions() {
    let output = run_fixture("sec08-extensions.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_duplicate_rfc() {
    let output = run_fixture("sec08-duplicate-rfc.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_signature");
    assert_eq!(error["stage"], "cms");
}

#[test]
fn sec08_duplicate_counter() {
    let output = run_fixture("sec08-duplicate-counter.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_signature");
    assert_eq!(error["stage"], "cms");
}

#[test]
fn sec08_mixed() {
    let output = run_fixture("sec08-mixed.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_mixed_reverse() {
    let output = run_fixture("sec08-mixed-reverse.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_aliases() {
    let output = run_fixture("sec08-aliases.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_multi_value() {
    let output = run_fixture("sec08-multi-value.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_eku_noncritical() {
    let output = run_fixture("sec08-eku-noncritical.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_eku");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_eku_mixed() {
    let output = run_fixture("sec08-eku-mixed.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_eku");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_eku_missing() {
    let output = run_fixture("sec08-eku-missing.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_eku");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_key_usage() {
    let output = run_fixture("sec08-key-usage.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_key_usage");
    assert_eq!(error["stage"], "certificate");
}

#[test]
fn sec08_substitution() {
    let output = run_fixture("sec08-substitution.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "timestamp_imprint_mismatch");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_counter_substitution() {
    let output = run_fixture("sec08-counter-substitution.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "content_digest_mismatch");
    assert_eq!(error["stage"], "cms");
}

#[test]
fn sec08_signing_time() {
    let output = run_fixture("sec08-signing-time.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_timestamp");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_counter_eku_noncritical() {
    let output = run_fixture("sec08-counter-eku-noncritical.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_eku");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_counter_eku_mixed() {
    let output = run_fixture("sec08-counter-eku-mixed.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_eku");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_counter_eku_missing() {
    let output = run_fixture("sec08-counter-eku-missing.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_eku");
    assert_eq!(error["stage"], "timestamp");
}

#[test]
fn sec08_counter_key_usage() {
    let output = run_fixture("sec08-counter-key-usage.exe", TRUSTED);
    assert_eq!(output.exit_code, 1);
    let error = &output.json["results"][0]["error"];
    assert_eq!(error["code"], "invalid_key_usage");
    assert_eq!(error["stage"], "certificate");
}

#[test]
fn sec08_good() {
    let output = run_fixture("sec08-good.exe", TRUSTED);
    expect_success(&output);
    let ts = &output.json["results"][0]["signatures"][0]["timestamp_verification"];
    assert_eq!(ts["signing_time"], 1800000000u64);
    assert_eq!(ts["kind"], "rfc3161");
    assert_eq!(ts["trust"]["revocation"]["status"], "good");
}

#[test]
fn sec08_good_optional() {
    let output = run_fixture("sec08-good-optional.exe", TRUSTED);
    expect_success(&output);
    let ts = &output.json["results"][0]["signatures"][0]["timestamp_verification"];
    assert_eq!(ts["signing_time"], 1800000000u64);
    assert_eq!(ts["kind"], "rfc3161");
    assert_eq!(ts["trust"]["revocation"]["status"], "good");
}

#[test]
fn sec08_good_counter() {
    let output = run_fixture("sec08-good-counter.exe", TRUSTED);
    expect_success(&output);
    let ts = &output.json["results"][0]["signatures"][0]["timestamp_verification"];
    assert_eq!(ts["signing_time"], 1800000000u64);
    assert_eq!(ts["kind"], "pkcs9_countersignature");
    assert_eq!(ts["trust"]["revocation"]["status"], "good");
}
