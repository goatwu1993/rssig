use serde_json::Value;
use std::path::Path;

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
