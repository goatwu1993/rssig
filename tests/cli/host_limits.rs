use super::support::*;
#[test]
fn sec03_input_and_report_limits_return_ordered_json_failures() {
    for (flag, resource) in [
        ("--max-input-bytes", "input_bytes"),
        ("--max-report-bytes", "report_bytes"),
    ] {
        let out = run_fixture(
            "good-pe64.exe",
            &[
                "verify",
                "--integrity-only",
                "--time",
                "1800000000",
                flag,
                "100",
            ],
        );
        assert_eq!(out.exit_code, 1);
        assert_eq!(out.json["ok"], false);
        let result = &out.json["results"][0];
        assert!(result.get("signatures").is_none());
        assert_eq!(result["error"]["code"], "resource_limit_exceeded");
        assert_eq!(result["error"]["stage"], "input");
        assert_eq!(result["error"]["details"]["resource"], resource);
        assert_eq!(result["error"]["details"]["limit"], 100);
    }
}

#[test]
fn sec03_batch_limits_keep_every_result_in_order() {
    let fixture = format!(
        "{}/tests/fixtures/good-pe64.exe",
        env!("CARGO_MANIFEST_DIR")
    );
    let size = std::fs::metadata(&fixture).unwrap().len().to_string();
    let mut output = Vec::new();
    let code = rssig::cli::run(
        [
            "rssig",
            "verify",
            "--integrity-only",
            "--time",
            "1800000000",
            "--max-total-input-bytes",
            &size,
            &fixture,
            &fixture,
        ],
        &mut output,
    )
    .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(code, 1);
    assert_eq!(json["results"].as_array().unwrap().len(), 2);
    assert_eq!(json["results"][0]["ok"], true);
    assert_eq!(
        json["results"][1]["error"]["details"]["resource"],
        "total_input_bytes"
    );
}

#[test]
fn sec03_invalid_limits_are_plain_configuration_errors() {
    let path = format!(
        "{}/tests/fixtures/good-pe64.exe",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = rssig::cli::run_with_writers(
        [
            "rssig",
            "verify",
            "--integrity-only",
            "--max-input-bytes",
            "0",
            &path,
        ],
        &mut stdout,
        &mut stderr,
    )
    .unwrap();
    assert_eq!(code, 2);
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .unwrap()
            .contains("max-input-bytes")
    );
}

#[test]
fn sec03_total_report_limit_preserves_prior_success() {
    let path = format!(
        "{}/tests/fixtures/good-pe64.exe",
        env!("CARGO_MANIFEST_DIR")
    );
    let baseline = run_fixture("good-pe64.exe", INTEGRITY);
    let size = serde_json::to_vec(&baseline.json["results"][0])
        .unwrap()
        .len()
        .to_string();
    let mut output = Vec::new();
    let code = rssig::cli::run(
        [
            "rssig",
            "verify",
            "--integrity-only",
            "--time",
            "1800000000",
            "--max-total-report-bytes",
            &size,
            &path,
            &path,
        ],
        &mut output,
    )
    .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(code, 1);
    assert_eq!(json["results"].as_array().unwrap().len(), 2);
    assert_eq!(json["results"][0]["ok"], true);
    assert_eq!(
        json["results"][1]["error"]["details"]["resource"],
        "total_report_bytes"
    );
}

#[test]
fn sec03_sparse_oversized_root_is_a_configuration_failure() {
    let path = std::env::temp_dir().join(format!("rssig-sec03-root-{}", std::process::id()));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    file.set_len(8 * 1024 * 1024 + 1).unwrap();
    let input = format!(
        "{}/tests/fixtures/good-pe64.exe",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let result = rssig::cli::run_with_writers(
        [
            "rssig",
            "verify",
            "--no-system-roots",
            "--no-revocation",
            "--time",
            "1800000000",
            "--roots",
            path.to_str().unwrap(),
            &input,
        ],
        &mut stdout,
        &mut stderr,
    );
    std::fs::remove_file(path).unwrap();
    assert_eq!(result.unwrap(), 2);
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .unwrap()
            .contains("root/CRL input exceeds")
    );
}

#[test]
fn sec03_batch_count_is_checked_before_reads() {
    let mut args = vec!["rssig", "verify", "--integrity-only"];
    args.extend(std::iter::repeat_n("does-not-exist", 129));
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    assert_eq!(
        rssig::cli::run_with_writers(args, &mut stdout, &mut stderr).unwrap(),
        2
    );
    assert!(stdout.is_empty());
    assert!(
        String::from_utf8(stderr)
            .unwrap()
            .contains("at most 128 file paths")
    );
}
