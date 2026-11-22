//! TIME-T001 lifetime-signing and certificate/validation-time boundary cases.

use super::support::*;
use serde_json::{Value, json};

const T: u64 = 1_800_000_000;

/// Run a `time-` fixture file at the pinned time with these CRL fixtures;
/// no CRLs selects `--no-revocation`.
fn run_file(file: &str, crls: &[&str]) -> Output {
    run_file_at(file, T, crls)
}

fn run_file_at(file: &str, time: u64, crls: &[&str]) -> Output {
    let mut args: Vec<String> = [
        "verify",
        "--no-system-roots",
        "--roots",
        "fixtures/root.der",
    ]
    .map(String::from)
    .into();
    if crls.is_empty() {
        args.push("--no-revocation".into());
    }
    for crl in crls {
        args.extend(["--crl".into(), format!("fixtures/{crl}")]);
    }
    args.extend(["--time".into(), time.to_string()]);
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    run_fixture(&format!("time-{file}"), &args)
}

fn run(label: &str, time: u64, revocation: bool) -> Output {
    let crls: &[&str] = if revocation { &["good.crl"] } else { &[] };
    run_file_at(&format!("{label}.exe"), time, crls)
}

fn signature(output: &Output) -> &Value {
    expect_success(output);
    &output.json["results"][0]["signatures"][0]
}

fn details(output: &Output) -> &Value {
    &output.json["results"][0]["error"]["details"]
}

fn expired(output: &Output, fragment: Option<&str>) {
    expect_failure(
        output,
        1,
        "certificate_expired",
        "Certificate expired",
        Some("certificate_chain"),
        fragment,
    );
}

fn not_yet_valid(output: &Output, fragment: Option<&str>) {
    expect_failure(
        output,
        1,
        "certificate_not_yet_valid",
        "Certificate not yet valid",
        Some("certificate_chain"),
        fragment,
    );
}

#[test]
fn time_expired_timestamped_signer_is_validated_at_timestamp() {
    let output = run("expired-timestamped", T, true);
    let signature = signature(&output);
    assert_eq!(signature["timestamp"], T - 5000);
    assert_eq!(signature["trust"]["validation_time"], T - 5000);
    assert_eq!(signature["trust"]["lifetime_signing"], false);
    assert_eq!(signature["trust"]["revocation"]["status"], "good");
    let tsa = &signature["timestamp_verification"]["trust"];
    assert_eq!(tsa["validation_time"], T - 5000);
    assert_eq!(tsa["lifetime_signing"], false);
    let trust = output.success().signatures[0].trust.as_ref().unwrap();
    assert!(!trust.lifetime_signing);
    assert_eq!(trust.validation_time, T - 5000);
}

#[test]
fn time_timestamp_equal_to_validation_time_is_not_future() {
    let output = run("expired-timestamped", T - 5000, false);
    let signature = signature(&output);
    assert_eq!(
        signature["timestamp_verification"]["signing_time"],
        T - 5000
    );
    assert_eq!(signature["trust"]["validation_time"], T - 5000);
}

#[test]
fn time_timestamp_one_second_after_validation_time_is_future() {
    let output = run("expired-timestamped", T - 5001, false);
    expect_failure(
        &output,
        1,
        "timestamp_in_future",
        "Timestamp is in the future",
        Some("timestamp"),
        Some("timestamp is in the future"),
    );
    assert_eq!(details(&output)["signing_time"], T - 5000);
    assert_eq!(details(&output)["validation_time"], T - 5001);
}

#[test]
fn time_lifetime_signing_expired_signer_rejects_valid_rfc3161_timestamp() {
    let output = run("lifetime-expired", T, true);
    expired(&output, None);
    let details = details(&output);
    assert_eq!(details["lifetime_signing"], true);
    assert_eq!(details["signing_time"], T - 5000);
    assert_eq!(details["validation_time"], T);
    assert_eq!(details["not_after"], T - 1000);
    assert_eq!(details["required_eku"], "1.3.6.1.5.5.7.3.3");
}

#[test]
fn time_lifetime_signing_expired_signer_rejects_valid_countersignature() {
    let output = run("lifetime-counter-expired", T, true);
    expired(&output, None);
    let details = details(&output);
    assert_eq!(details["lifetime_signing"], true);
    assert_eq!(details["signing_time"], T - 5000);
    assert_eq!(details["validation_time"], T);
    assert_eq!(details["not_after"], T - 1000);
}

#[test]
fn time_lifetime_signing_valid_signer_is_validated_at_validation_time() {
    let output = run("lifetime-valid", T, true);
    let signature = signature(&output);
    assert_eq!(signature["timestamp"], T - 5000);
    assert_eq!(signature["trust"]["validation_time"], T);
    assert_eq!(signature["trust"]["lifetime_signing"], true);
    assert_eq!(signature["trust"]["revocation"]["status"], "good");
    // The TSA chain still uses the timestamp time and is not lifetime signed.
    let tsa = &signature["timestamp_verification"]["trust"];
    assert_eq!(tsa["validation_time"], T - 5000);
    assert_eq!(tsa["lifetime_signing"], false);
    let report = &output.success().signatures[0];
    assert!(report.trust.as_ref().unwrap().lifetime_signing);
    assert_eq!(report.trust.as_ref().unwrap().validation_time, T);
    let tsa = report.timestamp_verification.as_ref().unwrap();
    assert!(!tsa.trust.as_ref().unwrap().lifetime_signing);
}

#[test]
fn time_lifetime_signing_expires_one_second_after_not_after() {
    let output = run("lifetime-valid", T + 1, false);
    expired(&output, None);
    let details = details(&output);
    assert_eq!(details["lifetime_signing"], true);
    assert_eq!(details["signing_time"], T - 5000);
    assert_eq!(details["validation_time"], T + 1);
    assert_eq!(details["not_after"], T);
}

#[test]
fn time_lifetime_signing_requires_validity_at_signing_time() {
    let output = run("lifetime-before-not-before", T, true);
    not_yet_valid(
        &output,
        Some("lifetime-signing certificate was not valid at the signing time"),
    );
    let details = details(&output);
    assert_eq!(details["lifetime_signing"], true);
    assert_eq!(details["signing_time"], T - 5000);
    assert_eq!(details["validation_time"], T);
    assert_eq!(details["not_before"], T - 4000);
    assert_eq!(details["required_eku"], "1.3.6.1.5.5.7.3.3");
    assert_eq!(
        details["certificate"]["subject"]["display"],
        "CN=SEC-09 lifetime-before-not-before"
    );
}

#[test]
fn time_timestamp_before_signer_not_before_is_rejected() {
    let output = run("timestamp-before-not-before", T, true);
    not_yet_valid(&output, Some("CertNotValidYet"));
    let details = details(&output);
    assert_eq!(details["validation_time"], T - 5000);
    assert_eq!(details["not_before"], T - 4000);
    assert!(details.get("lifetime_signing").is_none());
}

#[test]
fn time_lifetime_signing_without_timestamp_is_reported() {
    let output = run("lifetime-untimestamped", T, true);
    let signature = signature(&output);
    assert_eq!(signature["timestamp"], Value::Null);
    assert_eq!(signature["timestamp_verification"], Value::Null);
    assert_eq!(signature["trust"]["validation_time"], T);
    assert_eq!(signature["trust"]["lifetime_signing"], true);
}

#[test]
fn time_leaf_not_after_is_inclusive_at_whole_seconds() {
    let output = run("leaf-not-after-exact", T, true);
    let signature = signature(&output);
    assert_eq!(signature["trust"]["validation_time"], T - 2000);
    assert_eq!(signature["trust"]["chain"][0]["not_after"], T - 2000);
    assert!(
        signature["timestamp_verification"]
            .get("fractional_seconds")
            .is_none()
    );
}

#[test]
fn time_leaf_fraction_after_not_after_is_expired() {
    let output = run("leaf-not-after-fraction", T, true);
    expired(
        &output,
        Some("fractional timestamp exceeds certificate validity"),
    );
    let details = details(&output);
    assert_eq!(details["validation_time"], T - 2000);
    assert_eq!(details["fractional_seconds"], "5");
    assert_eq!(
        details["certificate"]["subject"]["display"],
        "CN=SEC-09 leaf-not-after-fraction"
    );
}

#[test]
fn time_leaf_fraction_inside_not_before_second_is_valid() {
    let output = run("leaf-not-before-fraction-inside", T, true);
    let signature = signature(&output);
    assert_eq!(signature["trust"]["validation_time"], T - 3000);
    assert_eq!(signature["trust"]["chain"][0]["not_before"], T - 3000);
    let timestamp = &signature["timestamp_verification"];
    assert_eq!(timestamp["signing_time"], T - 3000);
    assert_eq!(timestamp["fractional_seconds"], "5");
}

#[test]
fn time_leaf_fraction_before_not_before_is_not_yet_valid() {
    let output = run("leaf-not-before-fraction-early", T, true);
    not_yet_valid(&output, None);
    assert_eq!(details(&output)["validation_time"], T - 3001);
    assert_eq!(details(&output)["not_before"], T - 3000);
}

fn intermediate_chain(signature: &Value) {
    let subjects: Vec<_> = signature["trust"]["chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["subject"]["display"].clone())
        .collect();
    assert_eq!(subjects.len(), 3);
    assert_eq!(
        subjects[1..],
        [json!("CN=SEC-09 intermediate"), json!("CN=rssig test root")]
    );
}

#[test]
fn time_intermediate_not_after_is_inclusive_at_whole_seconds() {
    let output = run("intermediate-not-after-exact", T, false);
    let signature = signature(&output);
    intermediate_chain(signature);
    assert_eq!(signature["trust"]["validation_time"], T - 2000);
    assert_eq!(signature["trust"]["chain"][1]["not_after"], T - 2000);
    assert_eq!(signature["trust"]["revocation"]["status"], "not_checked");
}

#[test]
fn time_intermediate_fraction_after_not_after_is_expired() {
    let output = run("intermediate-not-after-fraction", T, false);
    expired(
        &output,
        Some("fractional timestamp exceeds certificate validity"),
    );
    let details = details(&output);
    assert_eq!(details["validation_time"], T - 2000);
    assert_eq!(details["fractional_seconds"], "5");
    assert_eq!(
        details["certificate"]["subject"]["display"],
        "CN=SEC-09 intermediate"
    );
    assert_eq!(details["certificate"]["not_after"], T - 2000);
}

#[test]
fn time_intermediate_one_second_after_not_after_is_expired() {
    let output = run("intermediate-expired", T, false);
    expired(&output, Some("CertExpired"));
    assert_eq!(details(&output)["validation_time"], T - 1999);
    assert_eq!(details(&output)["not_after"], T - 2000);
}

#[test]
fn time_intermediate_fraction_inside_not_before_second_is_valid() {
    let output = run("intermediate-not-before-fraction-inside", T, false);
    let signature = signature(&output);
    intermediate_chain(signature);
    assert_eq!(signature["trust"]["validation_time"], T - 3000);
    assert_eq!(signature["trust"]["chain"][1]["not_before"], T - 3000);
    assert_eq!(
        signature["timestamp_verification"]["fractional_seconds"],
        "5"
    );
}

#[test]
fn time_intermediate_fraction_before_not_before_is_not_yet_valid() {
    let output = run("intermediate-not-before-fraction-early", T, false);
    not_yet_valid(&output, None);
    assert_eq!(details(&output)["validation_time"], T - 3001);
    assert_eq!(details(&output)["not_before"], T - 3000);
}

#[test]
fn time_untimestamped_signer_validity_is_inclusive_at_validation_time() {
    let output = run("untimestamped", T - 101, false);
    not_yet_valid(&output, None);
    assert_eq!(details(&output)["validation_time"], T - 101);
    assert_eq!(details(&output)["not_before"], T - 100);
    for time in [T - 100, T + 100] {
        let output = run("untimestamped", time, false);
        let signature = signature(&output);
        assert_eq!(signature["timestamp"], Value::Null);
        assert_eq!(signature["trust"]["validation_time"], time);
        assert_eq!(signature["trust"]["lifetime_signing"], false);
    }
    let output = run("untimestamped", T + 101, false);
    expired(&output, None);
    assert_eq!(details(&output)["validation_time"], T + 101);
    assert_eq!(details(&output)["not_after"], T + 100);
}

#[test]
fn time_expired_signer_with_countersignature_is_validated_at_timestamp() {
    let output = run("counter-expired-timestamped", T, true);
    let signature = signature(&output);
    assert_eq!(
        signature["timestamp_verification"]["kind"],
        "pkcs9_countersignature"
    );
    assert_eq!(signature["trust"]["validation_time"], T - 5000);
    assert_eq!(signature["trust"]["lifetime_signing"], false);
}

#[test]
fn time_untimestamped_lifetime_failure_reports_no_signing_time() {
    let output = run("lifetime-untimestamped", T + 9001, false);
    expired(&output, None);
    let details = details(&output);
    assert_eq!(details["lifetime_signing"], true);
    assert_eq!(details["validation_time"], T + 9001);
    assert_eq!(details["not_after"], T + 9000);
    assert!(details.get("signing_time").is_none());
}

#[test]
fn time_lifetime_signing_rejects_intermediate_issued_after_signing() {
    let output = run("lifetime-intermediate-late", T, false);
    not_yet_valid(
        &output,
        Some("lifetime-signing certificate was not valid at the signing time"),
    );
    let details = details(&output);
    assert_eq!(details["lifetime_signing"], true);
    assert_eq!(details["signing_time"], T - 5000);
    assert_eq!(details["validation_time"], T);
    assert_eq!(details["not_before"], T - 4000);
    assert_eq!(details["required_eku"], "1.3.6.1.5.5.7.3.3");
    assert_eq!(
        details["certificate"]["subject"]["display"],
        "CN=SEC-09 intermediate"
    );
}

#[test]
fn time_lifetime_signing_selects_issuer_valid_at_signing_time() {
    let output = run("lifetime-intermediate-rollover", T, false);
    let signature = signature(&output);
    intermediate_chain(signature);
    assert_eq!(signature["trust"]["validation_time"], T);
    assert_eq!(signature["trust"]["lifetime_signing"], true);
    // The first embedded issuer postdates signing; the path uses the second.
    assert_eq!(signature["trust"]["chain"][1]["not_before"], T - 9000);
    let embedded = signature["embedded_certificates"].as_array().unwrap();
    assert_eq!(embedded[2]["not_before"], T - 4000);
    assert_eq!(embedded[3]["not_before"], T - 9000);
}

#[test]
fn time_signing_time_rejection_outranks_issuer_key_usage_in_either_order() {
    for label in [
        "lifetime-intermediate-late-ca-usage",
        "lifetime-intermediate-ca-usage-late",
    ] {
        let output = run(label, T, false);
        not_yet_valid(
            &output,
            Some("lifetime-signing certificate was not valid at the signing time"),
        );
        let details = details(&output);
        assert_eq!(details["signing_time"], T - 5000, "{label}");
        assert_eq!(details["not_before"], T - 4000, "{label}");
        assert_eq!(details["required_eku"], "1.3.6.1.5.5.7.3.3", "{label}");
        assert_eq!(details["certificate"]["not_before"], T - 4000, "{label}");
        assert_eq!(
            details["certificate"]["subject"]["display"], "CN=SEC-09 intermediate",
            "{label}"
        );
    }
}

#[test]
fn time_signing_time_rejection_outranks_key_usage_within_one_path() {
    for (label, late) in [
        ("lifetime-chain-ca-usage-late", "CN=SEC-09 intermediate 1"),
        ("lifetime-chain-late-ca-usage", "CN=SEC-09 intermediate 0"),
    ] {
        let output = run(label, T, false);
        not_yet_valid(
            &output,
            Some("lifetime-signing certificate was not valid at the signing time"),
        );
        let details = details(&output);
        assert_eq!(details["signing_time"], T - 5000, "{label}");
        assert_eq!(details["not_before"], T - 4000, "{label}");
        assert_eq!(
            details["certificate"]["subject"]["display"], late,
            "{label}"
        );
    }
}

fn revocation_failure(output: &Output, code: &str, title: &str) {
    expect_failure(output, 1, code, title, Some("revocation"), None);
}

#[test]
fn time_rdp_expired_signer_is_validated_at_timestamp() {
    let output = run_file("rdp-expired-timestamped.rdp", &["good.crl"]);
    let signature = signature(&output);
    assert_eq!(output.json["results"][0]["format"], "rdp_signed_settings");
    assert_eq!(signature["timestamp"], T - 5000);
    assert_eq!(signature["trust"]["validation_time"], T - 5000);
    assert_eq!(signature["trust"]["lifetime_signing"], false);
    assert_eq!(signature["trust"]["revocation"]["status"], "good");
}

#[test]
fn time_rdp_lifetime_signing_expired_signer_rejects_valid_timestamp() {
    let output = run_file("lifetime-rdp-expired.rdp", &["good.crl"]);
    expired(&output, None);
    let details = details(&output);
    assert_eq!(details["lifetime_signing"], true);
    assert_eq!(details["signing_time"], T - 5000);
    assert_eq!(details["validation_time"], T);
    assert_eq!(details["not_after"], T - 1000);
    assert_eq!(details["required_eku"], "1.3.6.1.5.5.7.3.3");
}

#[test]
fn time_nested_expired_signer_is_validated_at_timestamp() {
    let output = run_file("nested-expired-timestamped.exe", &["good.crl"]);
    expect_success(&output);
    let signatures = output.json["results"][0]["signatures"].as_array().unwrap();
    assert_eq!(signatures.len(), 2);
    assert_eq!(signatures[0]["nested_depth"], 0);
    assert_eq!(signatures[0]["timestamp"], Value::Null);
    assert_eq!(signatures[0]["trust"]["validation_time"], T);
    assert_eq!(signatures[1]["nested_depth"], 1);
    assert_eq!(signatures[1]["timestamp"], T - 5000);
    assert_eq!(signatures[1]["trust"]["validation_time"], T - 5000);
    assert_eq!(signatures[1]["trust"]["lifetime_signing"], false);
    assert_eq!(
        signatures[1]["subject"],
        "CN=SEC-09 nested-expired-timestamped"
    );
}

#[test]
fn time_nested_lifetime_signing_expired_signer_rejects_file() {
    let output = run_file("lifetime-nested-expired.exe", &["good.crl"]);
    expired(&output, None);
    let details = details(&output);
    assert_eq!(details["lifetime_signing"], true);
    assert_eq!(details["signing_time"], T - 5000);
    assert_eq!(details["validation_time"], T);
    assert_eq!(details["not_after"], T - 1000);
    assert_eq!(
        details["certificate"]["subject"]["display"],
        "CN=SEC-09 lifetime-nested-expired"
    );
}

#[test]
fn time_lifetime_signing_through_intermediate_checks_revocation() {
    let output = run_file(
        "lifetime-intermediate-rollover.exe",
        &["good.crl", "time-intermediate.crl"],
    );
    let signature = signature(&output);
    intermediate_chain(signature);
    assert_eq!(signature["revocation_checked"], true);
    assert_eq!(signature["trust"]["validation_time"], T);
    assert_eq!(signature["trust"]["lifetime_signing"], true);
    assert_eq!(signature["trust"]["revocation"]["status"], "good");
    assert_eq!(signature["trust"]["chain"][1]["not_before"], T - 9000);

    // Without a CRL from the intermediate, the leaf's status is unknown.
    let output = run_file("lifetime-intermediate-rollover.exe", &["good.crl"]);
    revocation_failure(&output, "revocation_unknown", "Revocation status unknown");
    assert_eq!(details(&output)["lifetime_signing"], true);
    assert_eq!(details(&output)["signing_time"], T - 5000);
}

#[test]
fn time_lifetime_signing_time_check_runs_with_revocation_enabled() {
    let output = run_file(
        "lifetime-intermediate-late.exe",
        &["good.crl", "time-intermediate.crl"],
    );
    not_yet_valid(
        &output,
        Some("lifetime-signing certificate was not valid at the signing time"),
    );
    assert_eq!(
        details(&output)["certificate"]["subject"]["display"],
        "CN=SEC-09 intermediate"
    );
}

#[test]
fn time_revoked_leaf_is_reported_before_signing_time_on_the_same_path() {
    for file in [
        "lifetime-intermediate-late.exe",
        "lifetime-intermediate-rollover.exe",
    ] {
        let output = run_file(file, &["good.crl", "time-intermediate-revoked-leaf.crl"]);
        revocation_failure(&output, "certificate_revoked", "Certificate revoked");
        assert_eq!(details(&output)["lifetime_signing"], true, "{file}");
        assert_eq!(details(&output)["signing_time"], T - 5000, "{file}");
    }
}

#[test]
fn time_signing_time_rejection_outranks_revoked_issuer_on_another_path() {
    // Kept policy: the only issuer valid at signing is revoked, and the
    // rejection of the late issuer is the reported reason.
    let output = run_file(
        "lifetime-intermediate-rollover.exe",
        &[
            "time-root-revoked-intermediate.crl",
            "time-intermediate.crl",
        ],
    );
    not_yet_valid(
        &output,
        Some("lifetime-signing certificate was not valid at the signing time"),
    );
    let details = details(&output);
    assert_eq!(details["signing_time"], T - 5000);
    assert_eq!(details["certificate"]["not_before"], T - 4000);
}

#[test]
fn time_crl_freshness_is_reported_before_signer_time_checks() {
    // The TSA chain is verified first against the same store-wide CRLs, with
    // or without the lifetime EKU.
    for file in [
        "lifetime-before-not-before.exe",
        "timestamp-before-not-before.exe",
    ] {
        let output = run_file(file, &["expired.crl"]);
        revocation_failure(&output, "crl_expired", "CRL expired");
        assert_eq!(details(&output)["validation_time"], T, "{file}");
        assert!(details(&output).get("lifetime_signing").is_none(), "{file}");
    }
}

#[test]
fn time_lifetime_leaf_not_before_is_inclusive_at_signing_time() {
    let output = run("lifetime-leaf-not-before-exact", T, true);
    let signature = signature(&output);
    assert_eq!(signature["timestamp"], T - 5000);
    assert_eq!(signature["trust"]["lifetime_signing"], true);
    assert_eq!(signature["trust"]["validation_time"], T);
    assert_eq!(signature["trust"]["chain"][0]["not_before"], T - 5000);

    let output = run("lifetime-leaf-not-before-early", T, true);
    not_yet_valid(
        &output,
        Some("lifetime-signing certificate was not valid at the signing time"),
    );
    assert_eq!(details(&output)["signing_time"], T - 5000);
    assert_eq!(details(&output)["not_before"], T - 4999);
}

#[test]
fn time_lifetime_intermediate_not_before_is_inclusive_at_signing_time() {
    let crls = ["good.crl", "time-intermediate.crl"];
    let output = run_file("lifetime-intermediate-not-before-exact.exe", &crls);
    let signature = signature(&output);
    intermediate_chain(signature);
    assert_eq!(signature["trust"]["lifetime_signing"], true);
    assert_eq!(signature["trust"]["revocation"]["status"], "good");
    assert_eq!(signature["trust"]["chain"][1]["not_before"], T - 5000);

    let output = run_file("lifetime-intermediate-not-before-early.exe", &crls);
    not_yet_valid(
        &output,
        Some("lifetime-signing certificate was not valid at the signing time"),
    );
    let details = details(&output);
    assert_eq!(details["signing_time"], T - 5000);
    assert_eq!(details["not_before"], T - 4999);
    assert_eq!(
        details["certificate"]["subject"]["display"],
        "CN=SEC-09 intermediate"
    );
}
