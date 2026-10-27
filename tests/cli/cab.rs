use super::support::*;

#[test]
fn cab_trusted() {
    let output = run_fixture(
        "good.cab",
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
    let bundle = output.success();
    assert_eq!(bundle.format, "cab_authenticode");
    assert!(
        bundle
            .signatures
            .iter()
            .all(|s| s.image_digest.is_none() && s.package_digest.is_some())
    );
}

#[test]
fn cab_integrity() {
    let output = run_fixture(
        "good.cab",
        &["verify", "--integrity-only", "--time", "1800000000"],
    );
    expect_success(&output);
    let bundle = output.success();
    assert_eq!(bundle.format, "cab_authenticode");
    assert!(
        bundle
            .signatures
            .iter()
            .all(|s| s.image_digest.is_none() && s.package_digest.is_some())
    );
}

#[test]
fn cab_sha384() {
    let output = run_fixture(
        "good-cab-sha384.cab",
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
    let bundle = output.success();
    assert_eq!(bundle.format, "cab_authenticode");
    assert!(
        bundle
            .signatures
            .iter()
            .all(|s| s.image_digest.is_none() && s.package_digest.is_some())
    );
}

#[test]
fn cab_sha512() {
    let output = run_fixture(
        "good-cab-sha512.cab",
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
    let bundle = output.success();
    assert_eq!(bundle.format, "cab_authenticode");
    assert!(
        bundle
            .signatures
            .iter()
            .all(|s| s.image_digest.is_none() && s.package_digest.is_some())
    );
}

#[test]
fn cab_sha1_denied() {
    let output = run_fixture(
        "legacy-cab-sha1.cab",
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
fn cab_sha1_allowed() {
    let output = run_fixture(
        "legacy-cab-sha1.cab",
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
    let bundle = output.success();
    assert_eq!(bundle.format, "cab_authenticode");
    assert!(
        bundle
            .signatures
            .iter()
            .all(|s| s.image_digest.is_none() && s.package_digest.is_some())
    );
}

#[test]
fn cab_nested() {
    let output = run_fixture(
        "good-cab-nested.cab",
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
    let bundle = output.success();
    assert_eq!(bundle.format, "cab_authenticode");
    assert!(
        bundle
            .signatures
            .iter()
            .all(|s| s.image_digest.is_none() && s.package_digest.is_some())
    );
}

#[test]
fn cab_rfc3161() {
    let output = run_fixture(
        "good-cab-rfc3161.cab",
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
    let bundle = output.success();
    assert_eq!(bundle.format, "cab_authenticode");
    assert!(
        bundle
            .signatures
            .iter()
            .all(|s| s.image_digest.is_none() && s.package_digest.is_some())
    );
}

#[test]
fn cab_countersignature() {
    let output = run_fixture(
        "good-cab-countersignature.cab",
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
    let bundle = output.success();
    assert_eq!(bundle.format, "cab_authenticode");
    assert!(
        bundle
            .signatures
            .iter()
            .all(|s| s.image_digest.is_none() && s.package_digest.is_some())
    );
}

#[test]
fn cab_digest() {
    let output = run_fixture(
        "bad-cab-digest.cab",
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
        "cab_digest_mismatch",
        "CAB digest mismatch",
        Some("package_digest"),
        None,
    );
}

#[test]
fn cab_cms_signature() {
    let output = run_fixture(
        "bad-cab-cms-signature.cab",
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
fn cab_timestamp_imprint() {
    let output = run_fixture(
        "bad-cab-timestamp-imprint.cab",
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
fn cab_malformed_cms() {
    let output = run_fixture(
        "bad-cab-malformed-cms.cab",
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
fn cab_wrong_sip() {
    let output = run_fixture(
        "bad-cab-sip.cab",
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
fn cab_unsigned() {
    let output = run_fixture(
        "unsigned.cab",
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
        Some("cab"),
        None,
    );
}

#[test]
fn cab_flags() {
    let output = run_fixture(
        "bad-cab-flags.cab",
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
        "invalid_cab",
        "Invalid CAB container",
        Some("cab"),
        None,
    );
}

#[test]
fn cab_reserve() {
    let output = run_fixture(
        "bad-cab-reserve.cab",
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
        "invalid_cab",
        "Invalid CAB container",
        Some("cab"),
        None,
    );
}

#[test]
fn cab_offset() {
    let output = run_fixture(
        "bad-cab-offset.cab",
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
        "invalid_cab",
        "Invalid CAB container",
        Some("cab"),
        None,
    );
}

#[test]
fn cab_folder_offset() {
    let output = run_fixture(
        "bad-cab-folder-offset.cab",
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
        "invalid_cab",
        "Invalid CAB container",
        Some("cab"),
        None,
    );
}

#[test]
fn cab_trailing() {
    let output = run_fixture(
        "bad-cab-trailing.cab",
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
        "invalid_cab",
        "Invalid CAB container",
        Some("cab"),
        None,
    );
}

#[test]
fn cab_truncated() {
    let output = run_fixture(
        "bad-cab-truncated.cab",
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
        "invalid_cab",
        "Invalid CAB container",
        Some("cab"),
        None,
    );
}

#[test]
fn cab_revoked() {
    let output = run_fixture(
        "good.cab",
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
fn cab_untrusted() {
    let output = run_fixture(
        "good.cab",
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
fn cab_digest_fixture_only_changes_payload() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut good = std::fs::read(dir.join("good.cab")).unwrap();
    good[96] ^= 1;
    assert_eq!(good, std::fs::read(dir.join("bad-cab-digest.cab")).unwrap());
}

#[test]
fn cab_independent_jsign() {
    let output = run_fixture("cab-independent-jsign.cab", INTEGRITY);
    expect_success(&output);
    assert_eq!(output.success().format, "cab_authenticode");
    let signature = &output.success().signatures[0];
    assert!(!signature.chain_trusted);
    assert!(!signature.revocation_checked);
    let digest = signature.package_digest.as_ref().unwrap();
    assert_eq!(digest.expected, digest.computed);
    assert_eq!(
        signature.certificate.subject.common_names,
        ["rssig independent MSI test signer"]
    );
}
#[test]
fn cab_independent_tampered() {
    let output = run_fixture("bad-cab-independent-digest.cab", INTEGRITY);
    expect_failure(
        &output,
        1,
        "cab_digest_mismatch",
        "CAB digest mismatch",
        Some("package_digest"),
        None,
    );
    let digest = &output.json["results"][0]["error"]["details"]["digest"];
    assert_eq!(digest["algorithm"], "Sha256");
    assert_ne!(digest["expected"], digest["computed"]);
}
