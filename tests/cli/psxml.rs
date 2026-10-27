use super::support::*;

fn expect_xml(output: &Output) {
    expect_success(output);
    assert_eq!(output.success().format, "powershell_xml_authenticode");
    for signature in &output.success().signatures {
        let digest = signature.script_digest.as_ref().unwrap();
        assert_eq!(digest.expected, digest.computed);
        assert!(signature.image_digest.is_none() && signature.package_digest.is_none());
    }
    assert!(output.json["results"][0].get("rdp").is_none());
}

#[test]
fn psxml_trusted() {
    let output = run_fixture(
        "good-psxml.ps1xml",
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
    expect_xml(&output);
}

#[test]
fn psxml_lf() {
    let output = run_fixture(
        "good-psxml-lf.ps1xml",
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
    expect_xml(&output);
}

#[test]
fn psxml_ascii_bom() {
    let output = run_fixture(
        "good-psxml-ascii-bom.ps1xml",
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
    expect_xml(&output);
}

#[test]
fn psxml_utf8_bom() {
    let output = run_fixture(
        "good-psxml-utf8-bom.ps1xml",
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
    expect_xml(&output);
}

#[test]
fn psxml_utf16le() {
    let output = run_fixture(
        "good-psxml-utf16le.ps1xml",
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
    expect_xml(&output);
}

#[test]
fn psxml_utf16be() {
    let output = run_fixture(
        "good-psxml-utf16be.ps1xml",
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
    expect_xml(&output);
}

#[test]
fn psxml_misnamed() {
    let output = run_fixture(
        "psxml-misnamed.bin",
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
    expect_xml(&output);
}

#[test]
fn psxml_integrity() {
    let output = run_fixture(
        "good-psxml.ps1xml",
        &["verify", "--integrity-only", "--time", "1800000000"],
    );
    expect_xml(&output);
}

#[test]
fn psxml_no_revocation() {
    let output = run_fixture(
        "good-psxml.ps1xml",
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
    expect_xml(&output);
}

#[test]
fn psxml_sha384() {
    let output = run_fixture(
        "good-psxml-sha384.ps1xml",
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
    expect_xml(&output);
}

#[test]
fn psxml_sha512() {
    let output = run_fixture(
        "good-psxml-sha512.ps1xml",
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
    expect_xml(&output);
}

#[test]
fn psxml_sha1_denied() {
    let output = run_fixture(
        "legacy-psxml-sha1.ps1xml",
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
fn psxml_sha1_allowed() {
    let output = run_fixture(
        "legacy-psxml-sha1.ps1xml",
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
    expect_xml(&output);
}

#[test]
fn psxml_nested() {
    let output = run_fixture(
        "good-psxml-nested.ps1xml",
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
    expect_xml(&output);
}

#[test]
fn psxml_rfc3161() {
    let output = run_fixture(
        "good-psxml-rfc3161.ps1xml",
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
    expect_xml(&output);
}

#[test]
fn psxml_expired_with_rfc3161() {
    let output = run_fixture(
        "good-psxml-rfc3161.ps1xml",
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
    expect_xml(&output);
}

#[test]
fn psxml_countersignature() {
    let output = run_fixture(
        "good-psxml-countersignature.ps1xml",
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
    expect_xml(&output);
}

#[test]
fn psxml_expired_with_countersignature() {
    let output = run_fixture(
        "good-psxml-countersignature.ps1xml",
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
    expect_xml(&output);
}

#[test]
fn psxml_digest() {
    let output = run_fixture(
        "bad-psxml-digest.ps1xml",
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
}

#[test]
fn psxml_line_endings() {
    let output = run_fixture(
        "bad-psxml-line-endings.ps1xml",
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
}

#[test]
fn psxml_missing_bom() {
    let output = run_fixture(
        "bad-psxml-missing-bom.ps1xml",
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
}

#[test]
fn psxml_ambiguous_utf8() {
    let output = run_fixture(
        "bad-psxml-ambiguous-utf8.ps1xml",
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
fn psxml_duplicate() {
    let output = run_fixture(
        "bad-psxml-duplicate.ps1xml",
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
fn psxml_trailing() {
    let output = run_fixture(
        "bad-psxml-trailing.ps1xml",
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
fn psxml_missing_end() {
    let output = run_fixture(
        "bad-psxml-missing-end.ps1xml",
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
fn psxml_marker_lf() {
    let output = run_fixture(
        "bad-psxml-marker-lf.ps1xml",
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
fn psxml_payload_no_crlf() {
    let output = run_fixture(
        "bad-psxml-payload-no-crlf.ps1xml",
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
fn psxml_comment_end() {
    let output = run_fixture(
        "bad-psxml-comment-end.ps1xml",
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
fn psxml_base64() {
    let output = run_fixture(
        "bad-psxml-base64.ps1xml",
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
fn psxml_hash_style() {
    let output = run_fixture(
        "bad-psxml-hash-style.ps1xml",
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
fn psxml_encoding() {
    let output = run_fixture(
        "bad-psxml-encoding.ps1xml",
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
fn psxml_odd_utf16() {
    let output = run_fixture(
        "bad-psxml-odd-utf16.ps1xml",
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
fn psxml_sip() {
    let output = run_fixture(
        "bad-psxml-sip.ps1xml",
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
fn psxml_cms_trailing() {
    let output = run_fixture(
        "bad-psxml-cms-trailing.ps1xml",
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
fn psxml_cms_signature() {
    let output = run_fixture(
        "bad-psxml-cms-signature.ps1xml",
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
fn psxml_timestamp_imprint() {
    let output = run_fixture(
        "bad-psxml-timestamp-imprint.ps1xml",
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
fn psxml_unsigned() {
    let output = run_fixture(
        "unsigned.ps1xml",
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
fn psxml_revoked() {
    let output = run_fixture(
        "good-psxml.ps1xml",
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
fn psxml_untrusted() {
    let output = run_fixture(
        "good-psxml.ps1xml",
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
fn psxml_expired() {
    let output = run_fixture(
        "good-psxml.ps1xml",
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
fn psxml_independent_ascii() {
    let output = run_fixture("psxml-independent-jsign-ascii.ps1xml", INTEGRITY);
    expect_xml(&output);
}

#[test]
fn psxml_independent_utf8_bom() {
    let output = run_fixture("psxml-independent-jsign-utf8-bom.ps1xml", INTEGRITY);
    expect_xml(&output);
}

#[test]
fn psxml_independent_utf16le() {
    let output = run_fixture("psxml-independent-jsign-utf16le.ps1xml", INTEGRITY);
    expect_xml(&output);
}

#[test]
fn psxml_independent_utf16be() {
    let output = run_fixture("psxml-independent-jsign-utf16be.ps1xml", INTEGRITY);
    expect_xml(&output);
}

#[test]
fn psxml_independent_windows1252() {
    let output = run_fixture("psxml-independent-jsign-windows1252.ps1xml", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_powershell",
        "Invalid PowerShell script",
        Some("powershell"),
        Some("must be ASCII"),
    );
}

#[test]
fn psxml_independent_tampered() {
    let output = run_fixture("bad-psxml-independent-digest.ps1xml", INTEGRITY);
    expect_failure(
        &output,
        1,
        "script_digest_mismatch",
        "Script digest mismatch",
        Some("script_digest"),
        None,
    );
}
