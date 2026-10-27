use super::support::*;

#[test]
fn powershell_trusted() {
    let output = run_fixture(
        "good-powershell.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_success(&output);
    assert_eq!(output.success().format, "powershell_authenticode");
    let json = &output.json["results"][0]["signatures"][0];
    assert!(json.get("script_digest").is_some());
    assert!(json.get("image_digest").is_none());
    assert!(json.get("package_digest").is_none());
    assert!(json.get("extended_digest").is_none());
    assert_eq!(json["page_hashes"], serde_json::Value::Null);
}

#[test]
fn powershell_module() {
    let output = run_fixture(
        "good-powershell.psm1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_success(&output);
    assert_eq!(output.success().format, "powershell_authenticode");
    let json = &output.json["results"][0]["signatures"][0];
    assert!(json.get("script_digest").is_some());
    assert!(json.get("image_digest").is_none());
    assert!(json.get("package_digest").is_none());
    assert!(json.get("extended_digest").is_none());
    assert_eq!(json["page_hashes"], serde_json::Value::Null);
}

#[test]
fn powershell_data() {
    let output = run_fixture(
        "good-powershell.psd1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_success(&output);
    assert_eq!(output.success().format, "powershell_authenticode");
    let json = &output.json["results"][0]["signatures"][0];
    assert!(json.get("script_digest").is_some());
    assert!(json.get("image_digest").is_none());
    assert!(json.get("package_digest").is_none());
    assert!(json.get("extended_digest").is_none());
    assert_eq!(json["page_hashes"], serde_json::Value::Null);
}

#[test]
fn powershell_misnamed() {
    let output = run_fixture(
        "powershell-misnamed.bin",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_success(&output);
    assert_eq!(output.success().format, "powershell_authenticode");
    let json = &output.json["results"][0]["signatures"][0];
    assert!(json.get("script_digest").is_some());
    assert!(json.get("image_digest").is_none());
    assert!(json.get("package_digest").is_none());
    assert!(json.get("extended_digest").is_none());
    assert_eq!(json["page_hashes"], serde_json::Value::Null);
}

#[test]
fn powershell_lf() {
    let output = run_fixture(
        "good-powershell-lf.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_success(&output);
    assert_eq!(output.success().format, "powershell_authenticode");
    let json = &output.json["results"][0]["signatures"][0];
    assert!(json.get("script_digest").is_some());
    assert!(json.get("image_digest").is_none());
    assert!(json.get("package_digest").is_none());
    assert!(json.get("extended_digest").is_none());
    assert_eq!(json["page_hashes"], serde_json::Value::Null);
}

#[test]
fn powershell_no_newline() {
    let output = run_fixture(
        "good-powershell-no-newline.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_success(&output);
    assert_eq!(output.success().format, "powershell_authenticode");
    let json = &output.json["results"][0]["signatures"][0];
    assert!(json.get("script_digest").is_some());
    assert!(json.get("image_digest").is_none());
    assert!(json.get("package_digest").is_none());
    assert!(json.get("extended_digest").is_none());
    assert_eq!(json["page_hashes"], serde_json::Value::Null);
}

#[test]
fn powershell_empty() {
    let output = run_fixture(
        "good-powershell-empty.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_success(&output);
    assert_eq!(output.success().format, "powershell_authenticode");
    let json = &output.json["results"][0]["signatures"][0];
    assert!(json.get("script_digest").is_some());
    assert!(json.get("image_digest").is_none());
    assert!(json.get("package_digest").is_none());
    assert!(json.get("extended_digest").is_none());
    assert_eq!(json["page_hashes"], serde_json::Value::Null);
}

#[test]
fn powershell_utf8_bom() {
    let output = run_fixture(
        "good-powershell-utf8-bom.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_success(&output);
    assert_eq!(output.success().format, "powershell_authenticode");
    let json = &output.json["results"][0]["signatures"][0];
    assert!(json.get("script_digest").is_some());
    assert!(json.get("image_digest").is_none());
    assert!(json.get("package_digest").is_none());
    assert!(json.get("extended_digest").is_none());
    assert_eq!(json["page_hashes"], serde_json::Value::Null);
}

#[test]
fn powershell_utf16le() {
    let output = run_fixture(
        "good-powershell-utf16le.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_success(&output);
    assert_eq!(output.success().format, "powershell_authenticode");
    let json = &output.json["results"][0]["signatures"][0];
    assert!(json.get("script_digest").is_some());
    assert!(json.get("image_digest").is_none());
    assert!(json.get("package_digest").is_none());
    assert!(json.get("extended_digest").is_none());
    assert_eq!(json["page_hashes"], serde_json::Value::Null);
}

#[test]
fn powershell_utf16be() {
    let output = run_fixture(
        "good-powershell-utf16be.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_success(&output);
    assert_eq!(output.success().format, "powershell_authenticode");
    let json = &output.json["results"][0]["signatures"][0];
    assert!(json.get("script_digest").is_some());
    assert!(json.get("image_digest").is_none());
    assert!(json.get("package_digest").is_none());
    assert!(json.get("extended_digest").is_none());
    assert_eq!(json["page_hashes"], serde_json::Value::Null);
}

#[test]
fn powershell_integrity() {
    let output = run_fixture(
        "good-powershell.ps1",
        &["verify", "--integrity-only", "--time", "1800000000"],
    );
    expect_success(&output);
    assert_eq!(output.success().format, "powershell_authenticode");
    let json = &output.json["results"][0]["signatures"][0];
    assert!(json.get("script_digest").is_some());
    assert!(json.get("image_digest").is_none());
    assert!(json.get("package_digest").is_none());
    assert!(json.get("extended_digest").is_none());
    assert_eq!(json["page_hashes"], serde_json::Value::Null);
}

#[test]
fn powershell_no_revocation() {
    let output = run_fixture(
        "good-powershell.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--no-revocation",
            "--time",
            "1800000000",
        ],
    );
    expect_success(&output);
    assert_eq!(output.success().format, "powershell_authenticode");
    let json = &output.json["results"][0]["signatures"][0];
    assert!(json.get("script_digest").is_some());
    assert!(json.get("image_digest").is_none());
    assert!(json.get("package_digest").is_none());
    assert!(json.get("extended_digest").is_none());
    assert_eq!(json["page_hashes"], serde_json::Value::Null);
}

#[test]
fn powershell_sha384() {
    let output = run_fixture(
        "good-powershell-sha384.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_success(&output);
    assert_eq!(output.success().format, "powershell_authenticode");
    let json = &output.json["results"][0]["signatures"][0];
    assert!(json.get("script_digest").is_some());
    assert!(json.get("image_digest").is_none());
    assert!(json.get("package_digest").is_none());
    assert!(json.get("extended_digest").is_none());
    assert_eq!(json["page_hashes"], serde_json::Value::Null);
}

#[test]
fn powershell_sha512() {
    let output = run_fixture(
        "good-powershell-sha512.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_success(&output);
    assert_eq!(output.success().format, "powershell_authenticode");
    let json = &output.json["results"][0]["signatures"][0];
    assert!(json.get("script_digest").is_some());
    assert!(json.get("image_digest").is_none());
    assert!(json.get("package_digest").is_none());
    assert!(json.get("extended_digest").is_none());
    assert_eq!(json["page_hashes"], serde_json::Value::Null);
}

#[test]
fn powershell_sha1_denied() {
    let output = run_fixture(
        "legacy-powershell-sha1.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "weak_algorithm",
        "Weak algorithm disallowed",
        Some("script_digest"),
        None,
    );
}

#[test]
fn powershell_sha1_allowed() {
    let output = run_fixture(
        "legacy-powershell-sha1.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
            "--allow-sha1",
        ],
    );
    expect_success(&output);
    assert_eq!(output.success().format, "powershell_authenticode");
    let json = &output.json["results"][0]["signatures"][0];
    assert!(json.get("script_digest").is_some());
    assert!(json.get("image_digest").is_none());
    assert!(json.get("package_digest").is_none());
    assert!(json.get("extended_digest").is_none());
    assert_eq!(json["page_hashes"], serde_json::Value::Null);
}

#[test]
fn powershell_nested() {
    let output = run_fixture(
        "good-powershell-nested.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_success(&output);
    assert_eq!(output.success().format, "powershell_authenticode");
    let json = &output.json["results"][0]["signatures"][0];
    assert!(json.get("script_digest").is_some());
    assert!(json.get("image_digest").is_none());
    assert!(json.get("package_digest").is_none());
    assert!(json.get("extended_digest").is_none());
    assert_eq!(json["page_hashes"], serde_json::Value::Null);
}

#[test]
fn powershell_rfc3161() {
    let output = run_fixture(
        "good-powershell-rfc3161.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_success(&output);
    assert_eq!(output.success().format, "powershell_authenticode");
    let json = &output.json["results"][0]["signatures"][0];
    assert!(json.get("script_digest").is_some());
    assert!(json.get("image_digest").is_none());
    assert!(json.get("package_digest").is_none());
    assert!(json.get("extended_digest").is_none());
    assert_eq!(json["page_hashes"], serde_json::Value::Null);
}

#[test]
fn powershell_expired_with_rfc3161() {
    let output = run_fixture(
        "good-powershell-rfc3161.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--no-revocation",
            "--time",
            "1800020000",
        ],
    );
    expect_success(&output);
    assert_eq!(output.success().format, "powershell_authenticode");
    let json = &output.json["results"][0]["signatures"][0];
    assert!(json.get("script_digest").is_some());
    assert!(json.get("image_digest").is_none());
    assert!(json.get("package_digest").is_none());
    assert!(json.get("extended_digest").is_none());
    assert_eq!(json["page_hashes"], serde_json::Value::Null);
}

#[test]
fn powershell_countersignature() {
    let output = run_fixture(
        "good-powershell-countersignature.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_success(&output);
    assert_eq!(output.success().format, "powershell_authenticode");
    let json = &output.json["results"][0]["signatures"][0];
    assert!(json.get("script_digest").is_some());
    assert!(json.get("image_digest").is_none());
    assert!(json.get("package_digest").is_none());
    assert!(json.get("extended_digest").is_none());
    assert_eq!(json["page_hashes"], serde_json::Value::Null);
}

#[test]
fn powershell_expired_with_countersignature() {
    let output = run_fixture(
        "good-powershell-countersignature.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--no-revocation",
            "--time",
            "1800020000",
        ],
    );
    expect_success(&output);
    assert_eq!(output.success().format, "powershell_authenticode");
    let json = &output.json["results"][0]["signatures"][0];
    assert!(json.get("script_digest").is_some());
    assert!(json.get("image_digest").is_none());
    assert!(json.get("package_digest").is_none());
    assert!(json.get("extended_digest").is_none());
    assert_eq!(json["page_hashes"], serde_json::Value::Null);
}

#[test]
fn powershell_digest() {
    let output = run_fixture(
        "bad-powershell-digest.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "script_digest_mismatch",
        "Script digest mismatch",
        Some("script_digest"),
        None,
    );
    let digest = &output.json["results"][0]["error"]["details"]["digest"];
    assert_eq!(digest["algorithm"], "Sha256");
    assert_ne!(digest["expected"], digest["computed"]);
}

#[test]
fn powershell_line_endings() {
    let output = run_fixture(
        "bad-powershell-line-endings.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "script_digest_mismatch",
        "Script digest mismatch",
        Some("script_digest"),
        None,
    );
    let digest = &output.json["results"][0]["error"]["details"]["digest"];
    assert_eq!(digest["algorithm"], "Sha256");
    assert_ne!(digest["expected"], digest["computed"]);
}

#[test]
fn powershell_missing_bom() {
    let output = run_fixture(
        "bad-powershell-missing-bom.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "script_digest_mismatch",
        "Script digest mismatch",
        Some("script_digest"),
        None,
    );
    let digest = &output.json["results"][0]["error"]["details"]["digest"];
    assert_eq!(digest["algorithm"], "Sha256");
    assert_ne!(digest["expected"], digest["computed"]);
}

#[test]
fn powershell_bad_cms_signature() {
    let output = run_fixture(
        "bad-powershell-cms-signature.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "invalid_signature",
        "Invalid signature",
        Some("cms"),
        None,
    );
}

#[test]
fn powershell_bad_nested() {
    let output = run_fixture(
        "bad-powershell-nested.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "invalid_signature",
        "Invalid signature",
        Some("cms"),
        None,
    );
}

#[test]
fn powershell_timestamp_imprint() {
    let output = run_fixture(
        "bad-powershell-timestamp-imprint.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "timestamp_imprint_mismatch",
        "Timestamp imprint mismatch",
        Some("timestamp"),
        None,
    );
}

#[test]
fn powershell_duplicate() {
    let output = run_fixture(
        "bad-powershell-duplicate.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "invalid_powershell",
        "Invalid PowerShell script",
        Some("powershell"),
        None,
    );
}

#[test]
fn powershell_trailing() {
    let output = run_fixture(
        "bad-powershell-trailing.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "invalid_powershell",
        "Invalid PowerShell script",
        Some("powershell"),
        None,
    );
}

#[test]
fn powershell_missing_end() {
    let output = run_fixture(
        "bad-powershell-missing-end.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "invalid_powershell",
        "Invalid PowerShell script",
        Some("powershell"),
        None,
    );
}

#[test]
fn powershell_missing_begin() {
    let output = run_fixture(
        "bad-powershell-missing-begin.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "invalid_powershell",
        "Invalid PowerShell script",
        Some("powershell"),
        None,
    );
}

#[test]
fn powershell_marker_lf() {
    let output = run_fixture(
        "bad-powershell-marker-lf.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "invalid_powershell",
        "Invalid PowerShell script",
        Some("powershell"),
        None,
    );
}

#[test]
fn powershell_base64() {
    let output = run_fixture(
        "bad-powershell-base64.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "invalid_powershell",
        "Invalid PowerShell script",
        Some("powershell"),
        None,
    );
}

#[test]
fn powershell_comment() {
    let output = run_fixture(
        "bad-powershell-comment.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "invalid_powershell",
        "Invalid PowerShell script",
        Some("powershell"),
        None,
    );
}

#[test]
fn powershell_empty_signature() {
    let output = run_fixture(
        "bad-powershell-empty-signature.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "invalid_powershell",
        "Invalid PowerShell script",
        Some("powershell"),
        None,
    );
}

#[test]
fn powershell_utf8() {
    let output = run_fixture(
        "bad-powershell-utf8.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "invalid_powershell",
        "Invalid PowerShell script",
        Some("powershell"),
        None,
    );
}

#[test]
fn powershell_odd_utf16() {
    let output = run_fixture(
        "bad-powershell-odd-utf16.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "invalid_powershell",
        "Invalid PowerShell script",
        Some("powershell"),
        None,
    );
}

#[test]
fn powershell_surrogate() {
    let output = run_fixture(
        "bad-powershell-surrogate.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "invalid_powershell",
        "Invalid PowerShell script",
        Some("powershell"),
        None,
    );
}

#[test]
fn powershell_no_utf16_bom() {
    let output = run_fixture(
        "bad-powershell-no-utf16-bom.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "invalid_powershell",
        "Invalid PowerShell script",
        Some("powershell"),
        None,
    );
}

#[test]
fn powershell_sip_version() {
    let output = run_fixture(
        "bad-powershell-sip-version.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "malformed_cms",
        "Malformed CMS data",
        Some("cms"),
        None,
    );
}

#[test]
fn powershell_sip_uuid() {
    let output = run_fixture(
        "bad-powershell-sip-uuid.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "malformed_cms",
        "Malformed CMS data",
        Some("cms"),
        None,
    );
}

#[test]
fn powershell_sip_reserved() {
    let output = run_fixture(
        "bad-powershell-sip-reserved.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "malformed_cms",
        "Malformed CMS data",
        Some("cms"),
        None,
    );
}

#[test]
fn powershell_sip_type() {
    let output = run_fixture(
        "bad-powershell-sip-type.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "malformed_cms",
        "Malformed CMS data",
        Some("cms"),
        None,
    );
}

#[test]
fn powershell_cms_trailing() {
    let output = run_fixture(
        "bad-powershell-cms-trailing.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "malformed_cms",
        "Malformed CMS data",
        Some("cms"),
        None,
    );
}

#[test]
fn powershell_malformed_cms() {
    let output = run_fixture(
        "bad-powershell-malformed-cms.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "malformed_cms",
        "Malformed CMS data",
        Some("cms"),
        None,
    );
}

#[test]
fn powershell_unsigned() {
    let output = run_fixture(
        "unsigned-powershell.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "unsigned",
        "Missing embedded signature",
        Some("powershell"),
        None,
    );
}

#[test]
fn powershell_revoked() {
    let output = run_fixture(
        "good-powershell.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/revoked.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "certificate_revoked",
        "Certificate revoked",
        Some("revocation"),
        None,
    );
}

#[test]
fn powershell_expired_crl() {
    let output = run_fixture(
        "good-powershell.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/expired.crl",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "crl_expired",
        "CRL expired",
        Some("revocation"),
        None,
    );
}

#[test]
fn powershell_untrusted() {
    let output = run_fixture(
        "good-powershell.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/unrelated-root.der",
            "--no-revocation",
            "--time",
            "1800000000",
        ],
    );
    expect_failure(
        &output,
        1,
        "untrusted_root",
        "Untrusted root certificate",
        Some("certificate_chain"),
        None,
    );
}

#[test]
fn powershell_expired() {
    let output = run_fixture(
        "good-powershell.ps1",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--no-revocation",
            "--time",
            "1800020000",
        ],
    );
    expect_failure(
        &output,
        1,
        "certificate_expired",
        "Certificate expired",
        Some("certificate_chain"),
        None,
    );
}

#[test]
fn powershell_independent_jsign() {
    let output = run_fixture("powershell-independent-jsign.ps1", INTEGRITY);
    expect_success(&output);
    assert_eq!(output.success().format, "powershell_authenticode");
    let signature = &output.success().signatures[0];
    assert_eq!(
        signature.certificate.subject.common_names,
        ["rssig independent MSI test signer"]
    );
    assert!(!signature.chain_trusted);
    assert!(!signature.revocation_checked);
}

#[test]
fn powershell_independent_jsign_utf16le() {
    let output = run_fixture("powershell-independent-jsign-utf16le.ps1", INTEGRITY);
    expect_success(&output);
    assert_eq!(output.success().format, "powershell_authenticode");
    let signature = &output.success().signatures[0];
    assert_eq!(
        signature.certificate.subject.common_names,
        ["rssig independent MSI test signer"]
    );
    assert!(!signature.chain_trusted);
    assert!(!signature.revocation_checked);
}

#[test]
fn powershell_independent_jsign_utf16be() {
    let output = run_fixture("powershell-independent-jsign-utf16be.ps1", INTEGRITY);
    expect_success(&output);
    assert_eq!(output.success().format, "powershell_authenticode");
    let signature = &output.success().signatures[0];
    assert_eq!(
        signature.certificate.subject.common_names,
        ["rssig independent MSI test signer"]
    );
    assert!(!signature.chain_trusted);
    assert!(!signature.revocation_checked);
}

#[test]
fn powershell_independent_tampered() {
    let output = run_fixture("bad-powershell-independent-digest.ps1", INTEGRITY);
    expect_failure(
        &output,
        1,
        "script_digest_mismatch",
        "Script digest mismatch",
        Some("script_digest"),
        None,
    );
}

#[test]
fn powershell_payload_no_crlf() {
    let output = run_fixture("bad-powershell-payload-no-crlf.ps1", TRUSTED);
    expect_failure(
        &output,
        1,
        "invalid_powershell",
        "Invalid PowerShell script",
        Some("powershell"),
        Some("PowerShell signature payload requires CRLF lines"),
    );
}

#[test]
fn powershell_binary_precedence() {
    let output = run_fixture("powershell-binary-precedence.ps1", TRUSTED);
    expect_success(&output);
    assert_eq!(output.success().format, "pe_authenticode");
    let signature = &output.success().signatures[0];
    assert!(signature.image_digest.is_some());
    assert!(signature.script_digest.is_none());
    assert!(signature.chain_trusted);
    assert!(signature.revocation_checked);
}
