use super::support::*;

fn expect_rdp_success(output: &Output) {
    expect_success(output);
    assert_eq!(output.success().format, "rdp_signed_settings");
    let rdp = &output.json["results"][0]["rdp"];
    assert_eq!(rdp["full_file_signed"], false);
    assert!(!rdp["signed_settings"].as_array().unwrap().is_empty());
    assert_eq!(rdp["canonical_sha256"].as_str().unwrap().len(), 64);
    for signature in output.json["results"][0]["signatures"].as_array().unwrap() {
        for field in [
            "image_digest",
            "package_digest",
            "script_digest",
            "extended_digest",
        ] {
            assert!(signature.get(field).is_none());
        }
    }
}

#[test]
fn rdp_trusted() {
    let output = run_fixture(
        "good.rdp",
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
    expect_rdp_success(&output);
}

#[test]
fn rdp_attributes() {
    let output = run_fixture(
        "good-rdp-attributes.rdp",
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
    expect_rdp_success(&output);
}

#[test]
fn rdp_utf8_bom() {
    let output = run_fixture(
        "good-rdp-utf8-bom.rdp",
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
    expect_rdp_success(&output);
}

#[test]
fn rdp_utf16le() {
    let output = run_fixture(
        "good-rdp-utf16le.rdp",
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
    expect_rdp_success(&output);
}

#[test]
fn rdp_utf16be() {
    let output = run_fixture(
        "good-rdp-utf16be.rdp",
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
    expect_rdp_success(&output);
}

#[test]
fn rdp_lf() {
    let output = run_fixture(
        "good-rdp-lf.rdp",
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
    expect_rdp_success(&output);
}

#[test]
fn rdp_no_final_newline() {
    let output = run_fixture(
        "good-rdp-no-final-newline.rdp",
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
    expect_rdp_success(&output);
}

#[test]
fn rdp_rsa() {
    let output = run_fixture(
        "good-rdp-rsa.rdp",
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
    expect_rdp_success(&output);
}

#[test]
fn rdp_server_auth() {
    let output = run_fixture(
        "good-rdp-server-auth.rdp",
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
    expect_rdp_success(&output);
}

#[test]
fn rdp_remote_auth() {
    let output = run_fixture(
        "good-rdp-remote-auth.rdp",
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
    expect_rdp_success(&output);
}

#[test]
fn rdp_unicode_unsigned() {
    let output = run_fixture(
        "good-rdp-unicode-unsigned.rdp",
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
    expect_rdp_success(&output);
}

#[test]
fn rdp_misnamed() {
    let output = run_fixture(
        "rdp-misnamed.bin",
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
    expect_rdp_success(&output);
}

#[test]
fn rdp_integrity() {
    let output = run_fixture(
        "good.rdp",
        &["verify", "--integrity-only", "--time", "1800000000"],
    );
    expect_rdp_success(&output);
}

#[test]
fn rdp_no_revocation() {
    let output = run_fixture(
        "good.rdp",
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
    expect_rdp_success(&output);
}

#[test]
fn rdp_unsigned_change() {
    let output = run_fixture(
        "good-rdp-unsigned-change.rdp",
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
    expect_rdp_success(&output);
}

#[test]
fn rdp_rfc3161() {
    let output = run_fixture(
        "good-rdp-rfc3161.rdp",
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
    expect_rdp_success(&output);
}

#[test]
fn rdp_expired_with_rfc3161() {
    let output = run_fixture(
        "good-rdp-rfc3161.rdp",
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
    expect_rdp_success(&output);
}

#[test]
fn rdp_countersignature() {
    let output = run_fixture(
        "good-rdp-countersignature.rdp",
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
    expect_rdp_success(&output);
}

#[test]
fn rdp_expired_with_countersignature() {
    let output = run_fixture(
        "good-rdp-countersignature.rdp",
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
    expect_rdp_success(&output);
}

#[test]
fn rdp_sha384() {
    let output = run_fixture(
        "good-rdp-sha384.rdp",
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
    expect_rdp_success(&output);
}

#[test]
fn rdp_sha512() {
    let output = run_fixture(
        "good-rdp-sha512.rdp",
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
    expect_rdp_success(&output);
}

#[test]
fn rdp_sha1_denied() {
    let output = run_fixture(
        "legacy-rdp-sha1.rdp",
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
        Some("cms"),
        None,
    );
}

#[test]
fn rdp_sha1_allowed() {
    let output = run_fixture(
        "legacy-rdp-sha1.rdp",
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
    expect_rdp_success(&output);
}

#[test]
fn rdp_setting() {
    let output = run_fixture(
        "bad-rdp-setting.rdp",
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
fn rdp_scope_order() {
    let output = run_fixture(
        "bad-rdp-scope-order.rdp",
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
fn rdp_cms_signature() {
    let output = run_fixture(
        "bad-rdp-cms-signature.rdp",
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
fn rdp_attributes_setting() {
    let output = run_fixture(
        "bad-rdp-attributes-setting.rdp",
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
        "content_digest_mismatch",
        "Content digest mismatch",
        Some("cms"),
        None,
    );
}

#[test]
fn rdp_timestamp_imprint() {
    let output = run_fixture(
        "bad-rdp-timestamp-imprint.rdp",
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
fn rdp_duplicate() {
    let output = run_fixture(
        "bad-rdp-duplicate.rdp",
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
        "invalid_rdp",
        "Invalid RDP file",
        Some("rdp"),
        None,
    );
}

#[test]
fn rdp_case_duplicate() {
    let output = run_fixture(
        "bad-rdp-case-duplicate.rdp",
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
        "invalid_rdp",
        "Invalid RDP file",
        Some("rdp"),
        None,
    );
}

#[test]
fn rdp_duplicate_signature() {
    let output = run_fixture(
        "bad-rdp-duplicate-signature.rdp",
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
        "invalid_rdp",
        "Invalid RDP file",
        Some("rdp"),
        None,
    );
}

#[test]
fn rdp_duplicate_scope() {
    let output = run_fixture(
        "bad-rdp-duplicate-scope.rdp",
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
        "invalid_rdp",
        "Invalid RDP file",
        Some("rdp"),
        None,
    );
}

#[test]
fn rdp_missing_setting() {
    let output = run_fixture(
        "bad-rdp-missing-setting.rdp",
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
        "invalid_rdp",
        "Invalid RDP file",
        Some("rdp"),
        None,
    );
}

#[test]
fn rdp_wrong_type() {
    let output = run_fixture(
        "bad-rdp-wrong-type.rdp",
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
        "invalid_rdp",
        "Invalid RDP file",
        Some("rdp"),
        None,
    );
}

#[test]
fn rdp_invalid_integer() {
    let output = run_fixture(
        "bad-rdp-invalid-integer.rdp",
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
        "invalid_rdp",
        "Invalid RDP file",
        Some("rdp"),
        None,
    );
}

#[test]
fn rdp_missing_scope() {
    let output = run_fixture(
        "bad-rdp-missing-scope.rdp",
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
        "invalid_rdp",
        "Invalid RDP file",
        Some("rdp"),
        None,
    );
}

#[test]
fn rdp_empty_scope() {
    let output = run_fixture(
        "bad-rdp-empty-scope.rdp",
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
        "invalid_rdp",
        "Invalid RDP file",
        Some("rdp"),
        None,
    );
}

#[test]
fn rdp_scope_no_host() {
    let output = run_fixture(
        "bad-rdp-scope-no-host.rdp",
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
        "invalid_rdp",
        "Invalid RDP file",
        Some("rdp"),
        None,
    );
}

#[test]
fn rdp_blank_line() {
    let output = run_fixture(
        "bad-rdp-blank-line.rdp",
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
        "invalid_rdp",
        "Invalid RDP file",
        Some("rdp"),
        None,
    );
}

#[test]
fn rdp_lone_cr() {
    let output = run_fixture(
        "bad-rdp-lone-cr.rdp",
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
        "invalid_rdp",
        "Invalid RDP file",
        Some("rdp"),
        None,
    );
}

#[test]
fn rdp_empty_host() {
    let output = run_fixture(
        "bad-rdp-empty-host.rdp",
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
        "invalid_rdp",
        "Invalid RDP file",
        Some("rdp"),
        None,
    );
}

#[test]
fn rdp_invalid_line() {
    let output = run_fixture(
        "bad-rdp-invalid-line.rdp",
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
        "invalid_rdp",
        "Invalid RDP file",
        Some("rdp"),
        None,
    );
}

#[test]
fn rdp_base64() {
    let output = run_fixture(
        "bad-rdp-base64.rdp",
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
        "invalid_rdp",
        "Invalid RDP file",
        Some("rdp"),
        None,
    );
}

#[test]
fn rdp_header() {
    let output = run_fixture(
        "bad-rdp-header.rdp",
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
        "invalid_rdp",
        "Invalid RDP file",
        Some("rdp"),
        None,
    );
}

#[test]
fn rdp_version() {
    let output = run_fixture(
        "bad-rdp-version.rdp",
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
        "invalid_rdp",
        "Invalid RDP file",
        Some("rdp"),
        None,
    );
}

#[test]
fn rdp_length() {
    let output = run_fixture(
        "bad-rdp-length.rdp",
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
        "invalid_rdp",
        "Invalid RDP file",
        Some("rdp"),
        None,
    );
}

#[test]
fn rdp_short_header() {
    let output = run_fixture(
        "bad-rdp-short-header.rdp",
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
        "invalid_rdp",
        "Invalid RDP file",
        Some("rdp"),
        None,
    );
}

#[test]
fn rdp_utf8() {
    let output = run_fixture(
        "bad-rdp-utf8.rdp",
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
        "invalid_rdp",
        "Invalid RDP file",
        Some("rdp"),
        None,
    );
}

#[test]
fn rdp_odd_utf16() {
    let output = run_fixture(
        "bad-rdp-odd-utf16.rdp",
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
        "invalid_rdp",
        "Invalid RDP file",
        Some("rdp"),
        None,
    );
}

#[test]
fn rdp_unknown_scope() {
    let output = run_fixture(
        "bad-rdp-unknown-scope.rdp",
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
        "unsupported_rdp_scope",
        "Unsupported RDP signature scope",
        Some("rdp"),
        None,
    );
}

#[test]
fn rdp_cms_trailing() {
    let output = run_fixture(
        "bad-rdp-cms-trailing.rdp",
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
fn rdp_malformed_cms() {
    let output = run_fixture(
        "bad-rdp-malformed-cms.rdp",
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
fn rdp_attached_cms() {
    let output = run_fixture(
        "bad-rdp-attached-cms.rdp",
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
fn rdp_eku() {
    let output = run_fixture(
        "bad-rdp-eku.rdp",
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
        "invalid_eku",
        "Invalid extended key usage",
        Some("certificate"),
        None,
    );
}

#[test]
fn rdp_no_eku() {
    let output = run_fixture(
        "bad-rdp-no-eku.rdp",
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
        "invalid_eku",
        "Invalid extended key usage",
        Some("certificate"),
        None,
    );
}

#[test]
fn rdp_key_usage() {
    let output = run_fixture(
        "bad-rdp-key-usage.rdp",
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
        "invalid_key_usage",
        "Invalid key usage",
        Some("certificate"),
        None,
    );
}

#[test]
fn rdp_unsigned() {
    let output = run_fixture(
        "unsigned.rdp",
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
        Some("rdp"),
        None,
    );
}

#[test]
fn rdp_revoked() {
    let output = run_fixture(
        "good.rdp",
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
fn rdp_expired_crl() {
    let output = run_fixture(
        "good.rdp",
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
fn rdp_untrusted() {
    let output = run_fixture(
        "good.rdp",
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
fn rdp_expired() {
    let output = run_fixture(
        "good.rdp",
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
fn rdp_independent_nfedera() {
    let output = run_fixture("rdp-independent-nfedera.rdp", INTEGRITY);
    expect_rdp_success(&output);
}

#[test]
fn bad_rdp_independent_setting() {
    let output = run_fixture("bad-rdp-independent-setting.rdp", INTEGRITY);
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
fn good_rdp_independent_unsigned_change() {
    let output = run_fixture("good-rdp-independent-unsigned-change.rdp", INTEGRITY);
    expect_rdp_success(&output);
}

#[test]
fn rdp_pe_requires_attributes() {
    let output = run_fixture("bad-rdp-pe-no-attributes.exe", TRUSTED);
    expect_failure(
        &output,
        1,
        "invalid_signature",
        "Invalid signature",
        Some("cms"),
        Some("authenticated attributes"),
    );
}
#[test]
fn rdp_nested_unsupported() {
    let output = run_fixture("bad-rdp-nested.rdp", TRUSTED);
    expect_failure(
        &output,
        1,
        "malformed_cms",
        "Malformed CMS data",
        Some("cms"),
        Some("nested RDP signatures"),
    );
}
#[test]
fn rdp_powershell_comment() {
    let output = run_fixture("good-rdp-powershell-comment.bin", TRUSTED);
    expect_success(&output);
    assert_eq!(output.success().format, "powershell_authenticode");
    assert!(output.json["results"][0].get("rdp").is_none());
}
