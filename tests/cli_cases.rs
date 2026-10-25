use serde_json::Value;
use std::{path::Path, process::Command};

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
