use serde_json::Value;
use std::{path::Path, process::Command};

fn assert_problem(value: &Value, code: &str) {
    assert_eq!(
        value["type"],
        format!("https://github.com/goatwu1993/rssig/blob/main/docs/problems.md#{code}")
    );
    assert!(value["title"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(value["detail"].as_str().is_some_and(|s| !s.is_empty()));
    assert!(
        value.get("status").is_none(),
        "CLI exit codes are not HTTP statuses"
    );
}

#[test]
fn every_cli_failure_is_a_problem_details_document() {
    for (args, code, exit) in [
        (vec!["verify"], "invalid_arguments", 2),
        (
            vec![
                "verify",
                "--time",
                "1800000000",
                "tests/fixtures/good-pe64.exe",
            ],
            "configuration",
            2,
        ),
        (
            vec![
                "verify",
                "--integrity-only",
                "--time",
                "1800000000",
                "tests/fixtures/missing.exe",
            ],
            "read_failed",
            1,
        ),
        (
            vec![
                "verify",
                "--integrity-only",
                "--time",
                "1800000000",
                "tests/fixtures/good-pe64.exe",
                "tests/fixtures/bad-image-digest.exe",
                "tests/fixtures/not-pe.bin",
            ],
            "image_digest_mismatch",
            1,
        ),
        (
            vec!["test", "--cases", "tests/fixtures/not-pe.bin"],
            "invalid_test_suite",
            2,
        ),
        (
            vec!["test", "--cases", "tests/fixtures/failing-cases.json"],
            "test_assertion_failed",
            1,
        ),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_rssig"))
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args(args)
            .output()
            .unwrap();
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(output.status.code(), Some(exit));
        assert!(output.stderr.is_empty());
        assert_problem(&value, code);
        if let Some(error) = value.get("error") {
            assert_problem(error, code);
            assert_eq!(value["detail"], error["detail"]);
        }
        if code == "image_digest_mismatch" {
            assert_eq!(value["results"][0]["ok"], true);
            assert_problem(&value["results"][1]["error"], code);
            assert_problem(&value["results"][2]["error"], "invalid_pe");
        }
        if code == "test_assertion_failed" {
            assert_problem(&value["results"][0], code);
            assert_problem(
                &value["results"][0]["output"]["results"][0]["error"],
                "invalid_pe",
            );
        }
    }
}

#[test]
fn problem_details_preserve_typed_causes_and_roundtrip() {
    use rssig::domain::{ErrorCode, Stage, VerificationError};
    let original = VerificationError::new(
        ErrorCode::ImageDigestMismatch,
        Stage::ImageDigest,
        "PE image digest mismatch",
    )
    .detail(
        "digest",
        serde_json::json!({"expected": "b", "computed": "a"}),
    );
    let error = VerificationError::from_internal(
        anyhow::Error::new(original).context("verifying signed image"),
        ErrorCode::InternalError,
        Stage::Input,
    );
    let value = serde_json::to_value(&error).unwrap();
    assert_problem(&value, "image_digest_mismatch");
    assert_eq!(value["title"], "PE image digest mismatch");
    assert_eq!(value["detail"], value["message"]);
    assert_eq!(value["causes"][0], "verifying signed image");
    assert_eq!(value["details"]["digest"]["computed"], "a");
    let roundtrip: VerificationError = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(serde_json::to_value(roundtrip).unwrap(), value);
    let different = VerificationError::new(
        ErrorCode::ImageDigestMismatch,
        Stage::ImageDigest,
        "A different image has a digest mismatch",
    );
    assert_eq!(error.problem.type_uri, different.problem.type_uri);
    assert_eq!(error.problem.title, different.problem.title);
    assert_ne!(error.problem.detail, different.problem.detail);
}

#[test]
fn mismatched_image_fixture_preserves_the_original_signature() {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let good = std::fs::read(directory.join("good-pe64.exe")).unwrap();
    let bad = std::fs::read(directory.join("bad-image-digest.exe")).unwrap();
    // The good image's signature covers hash(b). Only section data changes,
    // producing hash(a) while retaining the complete original certificate table.
    let mut expected = good;
    expected[700] ^= 1;
    assert_eq!(bad, expected);
}

#[test]
fn committed_json_cases_pass_through_the_real_cli() {
    let output = Command::new(env!("CARGO_BIN_EXE_rssig"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .args(["test", "--cases", "tests/cases.json"])
        .output()
        .expect("run rssig testcase runner");
    let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "runner must emit JSON: {e}; stderr={}",
            String::from_utf8_lossy(&output.stderr)
        )
    });
    let failures: Vec<_> = report["results"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["ok"] == false)
        .collect();
    assert!(output.status.success(), "failed cases: {failures:#?}");
    assert_eq!(report["ok"], true);
    let results = report["results"].as_array().unwrap();
    let suite: Value = serde_json::from_slice(
        &std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/cases.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(results.len(), suite["cases"].as_array().unwrap().len());
    assert!(results.len() >= 20);
    assert!(output.stderr.is_empty());
}

#[test]
fn fixture_manifest_pins_the_committed_artifacts() {
    use sha2::{Digest, Sha256};
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(directory.join("manifest.json"))
            .expect("fixture provenance manifest is committed"),
    )
    .unwrap();
    for artifact in manifest["artifacts"].as_array().unwrap() {
        let bytes = std::fs::read(directory.join(artifact["file"].as_str().unwrap())).unwrap();
        let digest: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(
            artifact["sha256"], digest,
            "fixture changed without manifest review: {}",
            artifact["file"]
        );
    }
}

#[test]
fn cli_errors_and_information_are_serialized_domain_objects() {
    use rssig::domain::{CommandReport, ErrorCode, FileResult, InformationReport};
    for args in [
        vec!["verify"],
        vec!["does-not-exist"],
        vec!["verify", "--time", "invalid", "x.exe"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_rssig"))
            .args(args)
            .output()
            .unwrap();
        let report: CommandReport<FileResult> = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(report.error.unwrap().code, ErrorCode::InvalidArguments);
        assert!(output.stderr.is_empty());
    }
    for arg in ["--help", "--version"] {
        let output = Command::new(env!("CARGO_BIN_EXE_rssig"))
            .arg(arg)
            .output()
            .unwrap();
        let report: InformationReport = serde_json::from_slice(&output.stdout).unwrap();
        assert!(output.status.success() && report.ok && !report.text.is_empty());
        assert!(output.stderr.is_empty());
    }
}
