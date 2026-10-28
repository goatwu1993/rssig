use super::support::*;
fn output(file: &str, integrity: bool) -> Output {
    if integrity {
        run_fixture(
            file,
            &["verify", "--integrity-only", "--time", "1800000000"],
        )
    } else {
        run_fixture(
            file,
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
        )
    }
}
fn success(file: &str, integrity: bool, count: usize) {
    let out = output(file, integrity);
    expect_success(&out);
    let appx = out.success().appx.as_ref().unwrap();
    assert_eq!(appx.kind, rssig::domain::AppxKind::Bundle);
    let packages = appx.bundle_packages.as_ref().unwrap();
    assert_eq!(packages.len(), count);
    if file.contains("multi") {
        assert_eq!(
            packages
                .iter()
                .map(|p| p.architecture.as_deref())
                .collect::<Vec<_>>(),
            [Some("x64"), Some("arm64")]
        );
    }
    for p in packages {
        assert_eq!(
            p.verification.appx.as_ref().unwrap().kind,
            rssig::domain::AppxKind::Package
        );
        assert!(
            p.verification
                .appx
                .as_ref()
                .unwrap()
                .bundle_packages
                .is_none()
        );
        assert_eq!(
            p.verification.signatures[0].certificate_sha256,
            out.success().signatures[0].certificate_sha256
        );
        assert_eq!(p.verification.signatures[0].chain_trusted, !integrity);
        assert_eq!(p.verification.signatures[0].revocation_checked, !integrity);
        if file.contains("rfc3161") || file.contains("countersignature") {
            assert!(out.success().signatures[0].timestamp_verification.is_some());
            assert!(
                p.verification.signatures[0]
                    .timestamp_verification
                    .is_some()
            );
        }
    }
    assert_eq!(out.json["results"][0]["appx"]["kind"], "bundle");
}
fn failure(file: &str, integrity: bool, code: &str, title: &str, stage: &str) {
    expect_failure(&output(file, integrity), 1, code, title, Some(stage), None);
}

#[test]
fn appxbundle_msix_extension() {
    success("good.msixbundle", false, 1);
}

#[test]
fn appxbundle_multi() {
    success("good-appxbundle-multi.msixbundle", false, 2);
}

#[test]
fn appxbundle_zip64() {
    success("good-appxbundle-zip64.msixbundle", false, 1);
}

#[test]
fn appxbundle_descriptor() {
    success("good-appxbundle-descriptor.msixbundle", false, 1);
}

#[test]
fn appxbundle_schema5() {
    success("good-appxbundle-schema5.msixbundle", false, 1);
}

#[test]
fn appxbundle_integrity() {
    success("good.appxbundle", true, 1);
}

#[test]
fn appxbundle_offset() {
    failure(
        "bad-appxbundle-offset.msixbundle",
        false,
        "invalid_appx",
        "Invalid MSIX/AppX package",
        "appx",
    );
}

#[test]
fn appxbundle_size() {
    failure(
        "bad-appxbundle-size.msixbundle",
        false,
        "invalid_appx",
        "Invalid MSIX/AppX package",
        "appx",
    );
}

#[test]
fn appxbundle_duplicate() {
    failure(
        "bad-appxbundle-duplicate.msixbundle",
        false,
        "invalid_appx",
        "Invalid MSIX/AppX package",
        "appx",
    );
}

#[test]
fn appxbundle_missing() {
    failure(
        "bad-appxbundle-missing.msixbundle",
        false,
        "invalid_appx",
        "Invalid MSIX/AppX package",
        "appx",
    );
}

#[test]
fn appxbundle_orphan() {
    failure(
        "bad-appxbundle-orphan.msixbundle",
        false,
        "invalid_appx",
        "Invalid MSIX/AppX package",
        "appx",
    );
}

#[test]
fn appxbundle_architecture() {
    failure(
        "bad-appxbundle-architecture.msixbundle",
        false,
        "invalid_appx",
        "Invalid MSIX/AppX package",
        "appx",
    );
}

#[test]
fn appxbundle_version() {
    failure(
        "bad-appxbundle-version.msixbundle",
        false,
        "invalid_appx",
        "Invalid MSIX/AppX package",
        "appx",
    );
}

#[test]
fn appxbundle_name() {
    failure(
        "bad-appxbundle-name.msixbundle",
        false,
        "invalid_appx",
        "Invalid MSIX/AppX package",
        "appx",
    );
}

#[test]
fn appxbundle_namespace() {
    failure(
        "bad-appxbundle-namespace.msixbundle",
        false,
        "invalid_appx",
        "Invalid MSIX/AppX package",
        "appx",
    );
}

#[test]
fn appxbundle_unknown() {
    failure(
        "bad-appxbundle-unknown.msixbundle",
        false,
        "invalid_appx",
        "Invalid MSIX/AppX package",
        "appx",
    );
}

#[test]
fn appxbundle_empty() {
    failure(
        "bad-appxbundle-empty.msixbundle",
        false,
        "invalid_appx",
        "Invalid MSIX/AppX package",
        "appx",
    );
}

#[test]
fn appxbundle_compressed() {
    failure(
        "bad-appxbundle-compressed.msixbundle",
        false,
        "invalid_appx",
        "Invalid MSIX/AppX package",
        "appx",
    );
}

#[test]
fn appxbundle_content_types() {
    failure(
        "bad-appxbundle-content-types.msixbundle",
        false,
        "invalid_appx",
        "Invalid MSIX/AppX package",
        "appx",
    );
}

#[test]
fn appxbundle_stub() {
    failure(
        "bad-appxbundle-stub.msixbundle",
        false,
        "invalid_appx",
        "Invalid MSIX/AppX package",
        "appx",
    );
}

#[test]
fn appxbundle_flat() {
    failure(
        "bad-appxbundle-flat.msixbundle",
        false,
        "invalid_appx",
        "Invalid MSIX/AppX package",
        "appx",
    );
}

#[test]
fn appxbundle_publisher() {
    failure(
        "bad-appxbundle-publisher.msixbundle",
        false,
        "appx_publisher_mismatch",
        "Package publisher mismatch",
        "appx",
    );
}

#[test]
fn appxbundle_child_digest() {
    failure(
        "bad-appxbundle-child-digest.msixbundle",
        false,
        "appx_digest_mismatch",
        "MSIX/AppX package digest mismatch",
        "package_digest",
    );
}

#[test]
fn appxbundle_child_signature() {
    failure(
        "bad-appxbundle-child-signature.msixbundle",
        false,
        "invalid_signature",
        "Invalid signature",
        "cms",
    );
}

#[test]
fn appxbundle_child_unsigned() {
    failure(
        "bad-appxbundle-child-unsigned.msixbundle",
        false,
        "unsigned",
        "Missing embedded signature",
        "appx",
    );
}

#[test]
fn appxbundle_different_signer() {
    failure(
        "bad-appxbundle-different-signer.msixbundle",
        true,
        "appx_publisher_mismatch",
        "Package publisher mismatch",
        "appx",
    );
}

#[test]
fn appxbundle_nested_bundle() {
    failure(
        "bad-appxbundle-nested-bundle.msixbundle",
        false,
        "unsupported_appx",
        "Unsupported MSIX/AppX package",
        "appx",
    );
}

#[test]
fn appxbundle_block_hash() {
    failure(
        "bad-appxbundle-block-hash.msixbundle",
        false,
        "block_hash_mismatch",
        "Block-map hash mismatch",
        "block_map",
    );
}

#[test]
fn appxbundle_sip() {
    failure(
        "bad-appxbundle-sip.msixbundle",
        false,
        "malformed_cms",
        "Malformed CMS data",
        "cms",
    );
}

#[test]
fn appxbundle_independent_jsign() {
    success("appxbundle-independent-jsign.msixbundle", true, 1);
}

#[test]
fn appxbundle_independent_payload() {
    failure(
        "bad-appxbundle-independent-payload.msixbundle",
        true,
        "appx_digest_mismatch",
        "MSIX/AppX package digest mismatch",
        "package_digest",
    );
}

#[test]
fn appxbundle_jsign_input() {
    failure(
        "appxbundle-jsign-input.msixbundle",
        true,
        "unsigned",
        "Missing embedded signature",
        "appx",
    );
}

#[test]
fn appxbundle_resource_id() {
    failure(
        "bad-appxbundle-resource-id.msixbundle",
        false,
        "invalid_appx",
        "Invalid MSIX/AppX package",
        "appx",
    );
}

#[test]
fn appxbundle_resource_type() {
    failure(
        "bad-appxbundle-resource-type.msixbundle",
        false,
        "invalid_appx",
        "Invalid MSIX/AppX package",
        "appx",
    );
}

#[test]
fn appxbundle_architecture_default() {
    failure(
        "bad-appxbundle-architecture-default.msixbundle",
        false,
        "invalid_appx",
        "Invalid MSIX/AppX package",
        "appx",
    );
}

#[test]
fn appxbundle_package_child() {
    failure(
        "bad-appxbundle-package-child.msixbundle",
        false,
        "invalid_appx",
        "Invalid MSIX/AppX package",
        "appx",
    );
}

#[test]
fn appxbundle_package_ctype() {
    failure(
        "bad-appxbundle-package-ctype.msixbundle",
        false,
        "invalid_appx",
        "Invalid MSIX/AppX package",
        "appx",
    );
}

#[test]
fn appxbundle_resource() {
    let out = output("good-appxbundle-resource.msixbundle", false);
    expect_success(&out);
    let package = &out.json["results"][0]["appx"]["bundle_packages"][0];
    assert_eq!(package["package_type"], "resource");
    assert_eq!(package["resource_id"], "en-us");
    assert_eq!(
        package["verification"]["appx"]["identity"]["resource_id"],
        "en-us"
    );
    let package = &out
        .success()
        .appx
        .as_ref()
        .unwrap()
        .bundle_packages
        .as_ref()
        .unwrap()[0];
    assert_eq!(package.resource_id.as_deref(), Some("en-us"));
    assert_eq!(
        package
            .verification
            .appx
            .as_ref()
            .unwrap()
            .identity
            .resource_id
            .as_deref(),
        Some("en-us")
    );
}

#[test]
fn appxbundle_child_crc() {
    failure(
        "bad-appxbundle-child-crc.msixbundle",
        false,
        "invalid_appx",
        "Invalid MSIX/AppX package",
        "appx",
    );
}

#[test]
fn appxbundle_orphan_other() {
    failure(
        "bad-appxbundle-orphan-other.msixbundle",
        false,
        "invalid_appx",
        "Invalid MSIX/AppX package",
        "appx",
    );
}

#[test]
fn appxbundle_sha384() {
    success("good-appxbundle-sha384.msixbundle", false, 1);
}

#[test]
fn appxbundle_sha512() {
    success("good-appxbundle-sha512.msixbundle", false, 1);
}

#[test]
fn appxbundle_rfc3161() {
    success("good-appxbundle-rfc3161.msixbundle", false, 1);
}

#[test]
fn appxbundle_countersignature() {
    success("good-appxbundle-countersignature.msixbundle", false, 1);
}

#[test]
fn appxbundle_child_timestamp() {
    failure(
        "bad-appxbundle-child-timestamp.msixbundle",
        false,
        "timestamp_imprint_mismatch",
        "Timestamp imprint mismatch",
        "timestamp",
    );
}

#[test]
fn appxbundle_resource_boolean() {
    failure(
        "bad-appxbundle-resource-boolean.msixbundle",
        false,
        "invalid_appx",
        "Invalid MSIX/AppX package",
        "appx",
    );
}
