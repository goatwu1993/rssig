use super::support::*;
fn expect_appx(output: &Output) {
    expect_success(output);
    assert_eq!(output.success().format, "appx_authenticode");
    let value = &output.json["results"][0];
    assert!(value.get("appx").is_some());
    assert!(value.get("rdp").is_none());
    for s in &output.success().signatures {
        let digest = s.package_digest.as_ref().unwrap();
        assert_eq!(digest.expected, digest.computed);
        assert!(s.image_digest.is_none() && s.script_digest.is_none());
    }
}

#[test]
fn appx_trusted() {
    let output = run_fixture(
        "good.msix",
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
    expect_appx(&output);
}

#[test]
fn appx_appx_extension() {
    let output = run_fixture(
        "good.appx",
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
    expect_appx(&output);
}

#[test]
fn appx_misnamed() {
    let output = run_fixture(
        "appx-misnamed.bin",
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
    expect_appx(&output);
}

#[test]
fn appx_integrity() {
    let output = run_fixture(
        "good.msix",
        &["verify", "--integrity-only", "--time", "1800000000"],
    );
    expect_appx(&output);
}

#[test]
fn appx_no_revocation() {
    let output = run_fixture(
        "good.msix",
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
    expect_appx(&output);
}

#[test]
fn appx_zip64() {
    let output = run_fixture(
        "good-appx-zip64.msix",
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
    expect_appx(&output);
}

#[test]
fn appx_descriptor() {
    let output = run_fixture(
        "good-appx-descriptor.msix",
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
    expect_appx(&output);
}

#[test]
fn appx_deflate() {
    let output = run_fixture(
        "good-appx-deflate.msix",
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
    expect_appx(&output);
}

#[test]
fn appx_multi() {
    let output = run_fixture(
        "good-appx-multi.msix",
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
    expect_appx(&output);
}

#[test]
fn appx_empty() {
    let output = run_fixture(
        "good-appx-empty.msix",
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
    expect_appx(&output);
}

#[test]
fn appx_nested() {
    let output = run_fixture(
        "good-appx-nested.msix",
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
    expect_appx(&output);
}

#[test]
fn appx_catalog() {
    let output = run_fixture(
        "good-appx-catalog.msix",
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
    expect_appx(&output);
}

#[test]
fn appx_rfc3161() {
    let output = run_fixture(
        "good-appx-rfc3161.msix",
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
    expect_appx(&output);
}

#[test]
fn appx_expired_with_rfc3161() {
    let output = run_fixture(
        "good-appx-rfc3161.msix",
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
    expect_appx(&output);
}

#[test]
fn appx_countersignature() {
    let output = run_fixture(
        "good-appx-countersignature.msix",
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
    expect_appx(&output);
}

#[test]
fn appx_expired_with_countersignature() {
    let output = run_fixture(
        "good-appx-countersignature.msix",
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
    expect_appx(&output);
}

#[test]
fn appx_sha384() {
    let output = run_fixture(
        "good-appx-sha384.msix",
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
    expect_appx(&output);
}

#[test]
fn appx_sha512() {
    let output = run_fixture(
        "good-appx-sha512.msix",
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
    expect_appx(&output);
}

#[test]
fn appx_digest_axpc() {
    let output = run_fixture(
        "bad-appx-digest-AXPC.msix",
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
        "appx_digest_mismatch",
        "MSIX/AppX package digest mismatch",
        Some("package_digest"),
        None,
    );
}

#[test]
fn appx_digest_axcd() {
    let output = run_fixture(
        "bad-appx-digest-AXCD.msix",
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
        "appx_digest_mismatch",
        "MSIX/AppX package digest mismatch",
        Some("package_digest"),
        None,
    );
}

#[test]
fn appx_digest_axct() {
    let output = run_fixture(
        "bad-appx-digest-AXCT.msix",
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
        "appx_digest_mismatch",
        "MSIX/AppX package digest mismatch",
        Some("package_digest"),
        None,
    );
}

#[test]
fn appx_digest_axbm() {
    let output = run_fixture(
        "bad-appx-digest-AXBM.msix",
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
        "appx_digest_mismatch",
        "MSIX/AppX package digest mismatch",
        Some("package_digest"),
        None,
    );
}

#[test]
fn appx_payload() {
    let output = run_fixture(
        "bad-appx-payload.msix",
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
        "appx_digest_mismatch",
        "MSIX/AppX package digest mismatch",
        Some("package_digest"),
        None,
    );
}

#[test]
fn appx_block_hash() {
    let output = run_fixture(
        "bad-appx-block-hash.msix",
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
        "block_hash_mismatch",
        "Block-map hash mismatch",
        Some("block_map"),
        None,
    );
}

#[test]
fn appx_block_missing() {
    let output = run_fixture(
        "bad-appx-block-missing.msix",
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
        "invalid_appx",
        "Invalid MSIX/AppX package",
        Some("block_map"),
        None,
    );
}

#[test]
fn appx_block_extra() {
    let output = run_fixture(
        "bad-appx-block-extra.msix",
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
        "invalid_appx",
        "Invalid MSIX/AppX package",
        Some("block_map"),
        None,
    );
}

#[test]
fn appx_lfh() {
    let output = run_fixture(
        "bad-appx-lfh.msix",
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
        "invalid_appx",
        "Invalid MSIX/AppX package",
        Some("block_map"),
        None,
    );
}

#[test]
fn appx_dtd() {
    let output = run_fixture(
        "bad-appx-dtd.msix",
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
        "invalid_appx",
        "Invalid MSIX/AppX package",
        Some("block_map"),
        None,
    );
}

#[test]
fn appx_namespace() {
    let output = run_fixture(
        "bad-appx-namespace.msix",
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
        "invalid_appx",
        "Invalid MSIX/AppX package",
        Some("block_map"),
        None,
    );
}

#[test]
fn appx_block_algorithm() {
    let output = run_fixture(
        "bad-appx-block-algorithm.msix",
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
        "unsupported_algorithm",
        "Unsupported algorithm",
        Some("block_map"),
        None,
    );
}

#[test]
fn appx_publisher() {
    let output = run_fixture(
        "bad-appx-publisher.msix",
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
        "appx_publisher_mismatch",
        "Package publisher mismatch",
        Some("appx"),
        None,
    );
}

#[test]
fn appx_content_types() {
    let output = run_fixture(
        "bad-appx-content-types.msix",
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
        "invalid_appx",
        "Invalid MSIX/AppX package",
        Some("appx"),
        None,
    );
}

#[test]
fn appx_pkcx() {
    let output = run_fixture(
        "bad-appx-pkcx.msix",
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
        "invalid_appx",
        "Invalid MSIX/AppX package",
        Some("appx"),
        None,
    );
}

#[test]
fn appx_signature_order() {
    let output = run_fixture(
        "bad-appx-signature-order.msix",
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
        "invalid_appx",
        "Invalid MSIX/AppX package",
        Some("appx"),
        None,
    );
}

#[test]
fn appx_duplicate() {
    let output = run_fixture(
        "bad-appx-duplicate.msix",
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
        "invalid_appx",
        "Invalid MSIX/AppX package",
        Some("appx"),
        None,
    );
}

#[test]
fn appx_path() {
    let output = run_fixture(
        "bad-appx-path.msix",
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
        "invalid_appx",
        "Invalid MSIX/AppX package",
        Some("appx"),
        None,
    );
}

#[test]
fn appx_trailing() {
    let output = run_fixture(
        "bad-appx-trailing.msix",
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
        "invalid_appx",
        "Invalid MSIX/AppX package",
        Some("appx"),
        None,
    );
}

#[test]
fn appx_truncated() {
    let output = run_fixture(
        "bad-appx-truncated.msix",
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
        "invalid_appx",
        "Invalid MSIX/AppX package",
        Some("appx"),
        None,
    );
}

#[test]
fn appx_bundle() {
    let output = run_fixture(
        "bad-appx-bundle.msix",
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
        "unsupported_appx",
        "Unsupported MSIX/AppX package",
        Some("appx"),
        None,
    );
}

#[test]
fn appx_cms_trailing() {
    let output = run_fixture(
        "bad-appx-cms-trailing.msix",
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
fn appx_cms_signature() {
    let output = run_fixture(
        "bad-appx-cms-signature.msix",
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
fn appx_timestamp_imprint() {
    let output = run_fixture(
        "bad-appx-timestamp-imprint.msix",
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
fn appx_unsigned() {
    let output = run_fixture(
        "unsigned.msix",
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
        Some("appx"),
        None,
    );
}

#[test]
fn appx_appx_jsign_input() {
    let output = run_fixture(
        "appx-jsign-input.msix",
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
        Some("appx"),
        None,
    );
}

#[test]
fn appx_revoked() {
    let output = run_fixture(
        "good.msix",
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
fn appx_untrusted() {
    let output = run_fixture(
        "good.msix",
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
fn appx_expired() {
    let output = run_fixture(
        "good.msix",
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
fn appx_independent_jsign() {
    let output = run_fixture("appx-independent-jsign.msix", INTEGRITY);
    expect_appx(&output);
}

#[test]
fn appx_independent_signtool() {
    let output = run_fixture("appx-independent-signtool.msix", INTEGRITY);
    expect_appx(&output);
}

#[test]
fn appx_independent_tampered() {
    let output = run_fixture("bad-appx-independent-payload.msix", INTEGRITY);
    expect_failure(
        &output,
        1,
        "appx_digest_mismatch",
        "MSIX/AppX package digest mismatch",
        Some("package_digest"),
        None,
    );
}

#[test]
fn appx_compressed_size() {
    let output = run_fixture("bad-appx-compressed-size.msix", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_appx",
        "Invalid MSIX/AppX package",
        Some("block_map"),
        None,
    );
}
