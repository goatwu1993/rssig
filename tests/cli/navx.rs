use super::support::*;

#[test]
fn navx_good() {
    let output = run_fixture(
        "good.navx",
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
    assert_eq!(output.success().format, "navx_authenticode");
    let digest = output.success().signatures[0]
        .package_digest
        .as_ref()
        .unwrap();
    assert_eq!(digest.expected, digest.computed);
    assert!(output.success().signatures[0].image_digest.is_none());
    assert!(
        output.json["results"][0]["signatures"][0]
            .get("image_digest")
            .is_none()
    );
}

#[test]
fn navx_good_navx_sha384() {
    let output = run_fixture(
        "good-navx-sha384.navx",
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
    assert_eq!(output.success().format, "navx_authenticode");
    let digest = output.success().signatures[0]
        .package_digest
        .as_ref()
        .unwrap();
    assert_eq!(digest.expected, digest.computed);
    assert!(output.success().signatures[0].image_digest.is_none());
    assert!(
        output.json["results"][0]["signatures"][0]
            .get("image_digest")
            .is_none()
    );
}

#[test]
fn navx_good_navx_sha512() {
    let output = run_fixture(
        "good-navx-sha512.navx",
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
    assert_eq!(output.success().format, "navx_authenticode");
    let digest = output.success().signatures[0]
        .package_digest
        .as_ref()
        .unwrap();
    assert_eq!(digest.expected, digest.computed);
    assert!(output.success().signatures[0].image_digest.is_none());
    assert!(
        output.json["results"][0]["signatures"][0]
            .get("image_digest")
            .is_none()
    );
}

#[test]
fn navx_good_navx_nested() {
    let output = run_fixture(
        "good-navx-nested.navx",
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
    assert_eq!(output.success().format, "navx_authenticode");
    let digest = output.success().signatures[0]
        .package_digest
        .as_ref()
        .unwrap();
    assert_eq!(digest.expected, digest.computed);
    assert!(output.success().signatures[0].image_digest.is_none());
    assert!(
        output.json["results"][0]["signatures"][0]
            .get("image_digest")
            .is_none()
    );
}

#[test]
fn navx_good_navx_rfc3161() {
    let output = run_fixture(
        "good-navx-rfc3161.navx",
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
    assert_eq!(output.success().format, "navx_authenticode");
    let digest = output.success().signatures[0]
        .package_digest
        .as_ref()
        .unwrap();
    assert_eq!(digest.expected, digest.computed);
    assert!(output.success().signatures[0].image_digest.is_none());
    assert!(
        output.json["results"][0]["signatures"][0]
            .get("image_digest")
            .is_none()
    );
}

#[test]
fn navx_good_navx_countersignature() {
    let output = run_fixture(
        "good-navx-countersignature.navx",
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
    assert_eq!(output.success().format, "navx_authenticode");
    let digest = output.success().signatures[0]
        .package_digest
        .as_ref()
        .unwrap();
    assert_eq!(digest.expected, digest.computed);
    assert!(output.success().signatures[0].image_digest.is_none());
    assert!(
        output.json["results"][0]["signatures"][0]
            .get("image_digest")
            .is_none()
    );
}

#[test]
fn navx_navx_misnamed() {
    let output = run_fixture(
        "navx-misnamed.ps1",
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
    assert_eq!(output.success().format, "navx_authenticode");
    let digest = output.success().signatures[0]
        .package_digest
        .as_ref()
        .unwrap();
    assert_eq!(digest.expected, digest.computed);
    assert!(output.success().signatures[0].image_digest.is_none());
    assert!(
        output.json["results"][0]["signatures"][0]
            .get("image_digest")
            .is_none()
    );
}

#[test]
fn navx_integrity() {
    let output = run_fixture(
        "good.navx",
        &["verify", "--integrity-only", "--time", "1800000000"],
    );
    expect_success(&output);
    assert_eq!(output.success().format, "navx_authenticode");
    let digest = output.success().signatures[0]
        .package_digest
        .as_ref()
        .unwrap();
    assert_eq!(digest.expected, digest.computed);
    assert!(output.success().signatures[0].image_digest.is_none());
    assert!(
        output.json["results"][0]["signatures"][0]
            .get("image_digest")
            .is_none()
    );
}

#[test]
fn navx_independent() {
    let output = run_fixture(
        "navx-independent-jsign.navx",
        &["verify", "--integrity-only", "--time", "1800000000"],
    );
    expect_success(&output);
    assert_eq!(output.success().format, "navx_authenticode");
    let digest = output.success().signatures[0]
        .package_digest
        .as_ref()
        .unwrap();
    assert_eq!(digest.expected, digest.computed);
    assert!(output.success().signatures[0].image_digest.is_none());
    assert!(
        output.json["results"][0]["signatures"][0]
            .get("image_digest")
            .is_none()
    );
}

#[test]
fn navx_independent_digest() {
    let output = run_fixture(
        "bad-navx-independent-digest.navx",
        &["verify", "--integrity-only", "--time", "1800000000"],
    );
    expect_failure(
        &output,
        1,
        "navx_digest_mismatch",
        "NAVX digest mismatch",
        Some("package_digest"),
        None,
    );
}

#[test]
fn navx_sha1_denied() {
    let output = run_fixture(
        "legacy-navx-sha1.navx",
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
        Some("package_digest"),
        None,
    );
}

#[test]
fn navx_sha1_allowed() {
    let output = run_fixture(
        "legacy-navx-sha1.navx",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/root.der",
            "--crl",
            "fixtures/good.crl",
            "--allow-sha1",
            "--time",
            "1800000000",
        ],
    );
    expect_success(&output);
    assert_eq!(output.success().format, "navx_authenticode");
    let digest = output.success().signatures[0]
        .package_digest
        .as_ref()
        .unwrap();
    assert_eq!(digest.expected, digest.computed);
    assert!(output.success().signatures[0].image_digest.is_none());
    assert!(
        output.json["results"][0]["signatures"][0]
            .get("image_digest")
            .is_none()
    );
}

#[test]
fn navx_revoked() {
    let output = run_fixture(
        "good.navx",
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
fn navx_untrusted() {
    let output = run_fixture(
        "good.navx",
        &[
            "verify",
            "--no-system-roots",
            "--roots",
            "fixtures/unrelated-root.der",
            "--crl",
            "fixtures/good.crl",
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
fn navx_block() {
    let output = run_fixture(
        "bad-navx-block.navx",
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
        "invalid_navx",
        "Invalid NAVX container",
        Some("navx"),
        None,
    );
}

#[test]
fn navx_header() {
    let output = run_fixture(
        "bad-navx-header.navx",
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
        "invalid_navx",
        "Invalid NAVX container",
        Some("navx"),
        None,
    );
}

#[test]
fn navx_size() {
    let output = run_fixture(
        "bad-navx-size.navx",
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
        "invalid_navx",
        "Invalid NAVX container",
        Some("navx"),
        None,
    );
}

#[test]
fn navx_offset() {
    let output = run_fixture(
        "bad-navx-offset.navx",
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
        "invalid_navx",
        "Invalid NAVX container",
        Some("navx"),
        None,
    );
}

#[test]
fn navx_trailer() {
    let output = run_fixture(
        "bad-navx-trailer.navx",
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
        "invalid_navx",
        "Invalid NAVX container",
        Some("navx"),
        None,
    );
}

#[test]
fn navx_trailing() {
    let output = run_fixture(
        "bad-navx-trailing.navx",
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
        "invalid_navx",
        "Invalid NAVX container",
        Some("navx"),
        None,
    );
}

#[test]
fn navx_truncated() {
    let output = run_fixture(
        "bad-navx-truncated.navx",
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
        "invalid_navx",
        "Invalid NAVX container",
        Some("navx"),
        None,
    );
}

#[test]
fn navx_sip_type() {
    let output = run_fixture(
        "bad-navx-sip-type.navx",
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
fn navx_sip_version() {
    let output = run_fixture(
        "bad-navx-sip-version.navx",
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
fn navx_sip_uuid() {
    let output = run_fixture(
        "bad-navx-sip-uuid.navx",
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
fn navx_sip_reserved() {
    let output = run_fixture(
        "bad-navx-sip-reserved.navx",
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
fn navx_cms_trailing() {
    let output = run_fixture(
        "bad-navx-cms-trailing.navx",
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
fn navx_malformed_cms() {
    let output = run_fixture(
        "bad-navx-malformed-cms.navx",
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
fn navx_cms_signature() {
    let output = run_fixture(
        "bad-navx-cms-signature.navx",
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
fn navx_digest() {
    let output = run_fixture(
        "bad-navx-digest.navx",
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
        "navx_digest_mismatch",
        "NAVX digest mismatch",
        Some("package_digest"),
        None,
    );
}

#[test]
fn navx_timestamp_imprint() {
    let output = run_fixture(
        "bad-navx-timestamp-imprint.navx",
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
fn navx_bad_nested() {
    let output = run_fixture(
        "bad-navx-bad-nested.navx",
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
fn navx_unsigned() {
    let output = run_fixture(
        "unsigned.navx",
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
        Some("navx"),
        None,
    );
}
