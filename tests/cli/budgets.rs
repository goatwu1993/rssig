use super::support::*;
use serde_json::json;

#[test]
fn sec02_wide_valid_signers_stop_before_report_65() {
    let good = run_fixture("sec02-wide-64.exe", TRUSTED);
    expect_success(&good);
    assert_eq!(good.success().signatures.len(), 64);
    for (file, resource) in [
        ("sec02-wide-65.exe", "reports"),
        ("sec02-entries-65.exe", "certificate_entries"),
    ] {
        let output = run_fixture(file, TRUSTED);
        assert_eq!(output.exit_code, 1);
        assert_eq!(output.json["ok"], false);
        let result = &output.json["results"][0];
        assert_eq!(result["ok"], false);
        assert!(result.get("signatures").is_none());
        let error = &result["error"];
        assert_eq!(error["code"], "resource_limit_exceeded");
        assert_eq!(error["stage"], "cms");
        assert_eq!(
            error["details"],
            json!({"resource":resource,"limit":64,"used":64,"requested":1})
        );
    }
}

#[test]
fn sec02_rejects_deep_malformed_child_before_decoding() {
    let good = run_fixture("sec02-depth-8.exe", TRUSTED);
    expect_success(&good);
    assert_eq!(good.success().signatures.len(), 9);
    assert_eq!(good.success().signatures[8].nested_depth, 8);
    let bad = run_fixture("sec02-depth-9-malformed.exe", TRUSTED);
    assert_eq!(bad.exit_code, 1);
    let result = &bad.json["results"][0];
    assert_eq!(result["ok"], false);
    assert!(result.get("signatures").is_none());
    assert_eq!(result["error"]["code"], "malformed_cms");
    assert_eq!(result["error"]["stage"], "cms");
    assert_eq!(
        result["error"]["details"],
        json!({"resource":"nesting","limit":8,"used":8,"requested":1})
    );
}
