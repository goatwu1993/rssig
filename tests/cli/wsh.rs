use super::support::*;
fn output(file: &str, mode: &str) -> Output {
    let mut args = vec!["verify"];
    if mode == "integrity" {
        args.push("--integrity-only");
    } else {
        args.extend([
            "--no-system-roots",
            "--roots",
            if mode == "untrusted" {
                "fixtures/unrelated-root.der"
            } else {
                "fixtures/root.der"
            },
        ]);
        if mode == "no-revocation" {
            args.push("--no-revocation");
        } else {
            args.extend([
                "--crl",
                if mode == "revoked" {
                    "fixtures/revoked.crl"
                } else {
                    "fixtures/good.crl"
                },
            ]);
        }
    }
    if mode == "sha1" {
        args.push("--allow-sha1");
    }
    args.extend(["--time", "1800000000"]);
    run_fixture(file, &args)
}
fn success(file: &str, mode: &str, format: &str) {
    let out = output(file, mode);
    expect_success(&out);
    let bundle = out.success();
    assert_eq!(bundle.format, format);
    for signature in &bundle.signatures {
        assert_eq!(signature.chain_trusted, mode != "integrity");
        assert_eq!(
            signature.revocation_checked,
            mode != "integrity" && mode != "no-revocation"
        );
        if format != "pe_authenticode" {
            let digest = signature.script_digest.as_ref().unwrap();
            assert_eq!(digest.expected, digest.computed);
            assert!(signature.image_digest.is_none());
            assert!(signature.package_digest.is_none());
            assert!(signature.extended_digest.is_none());
            assert!(signature.page_hashes.is_none());
        }
    }
    assert!(bundle.appx.is_none() && bundle.rdp.is_none());
    if file.contains("nested") {
        assert_eq!(bundle.signatures.len(), 2);
        assert_eq!(bundle.signatures[1].nested_depth, 1);
    }
    if file.contains("rfc3161") || file.contains("countersignature") {
        assert!(bundle.signatures[0].timestamp_verification.is_some());
    }
}
fn failure(file: &str, mode: &str, code: &str, title: &str, stage: &str) {
    expect_failure(&output(file, mode), 1, code, title, Some(stage), None);
}

#[test]
fn wsh_bad_attributes_wsf() {
    failure(
        "bad-wsh-attributes.wsf",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_bad_nested_js() {
    failure(
        "bad-wsh-bad-nested.js",
        "trusted",
        "invalid_signature",
        "Invalid signature",
        "cms",
    );
}

#[test]
fn wsh_bad_bad_nested_vbs() {
    failure(
        "bad-wsh-bad-nested.vbs",
        "trusted",
        "invalid_signature",
        "Invalid signature",
        "cms",
    );
}

#[test]
fn wsh_bad_bad_nested_wsf() {
    failure(
        "bad-wsh-bad-nested.wsf",
        "trusted",
        "invalid_signature",
        "Invalid signature",
        "cms",
    );
}

#[test]
fn wsh_bad_base64_js() {
    failure(
        "bad-wsh-base64.js",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_base64_vbs() {
    failure(
        "bad-wsh-base64.vbs",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_base64_wsf() {
    failure(
        "bad-wsh-base64.wsf",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_bomless_unicode_js() {
    failure(
        "bad-wsh-bomless-unicode.js",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_bomless_unicode_vbs() {
    failure(
        "bad-wsh-bomless-unicode.vbs",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_cdata_wsf() {
    failure(
        "bad-wsh-cdata.wsf",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_cms_signature_js() {
    failure(
        "bad-wsh-cms-signature.js",
        "trusted",
        "invalid_signature",
        "Invalid signature",
        "cms",
    );
}

#[test]
fn wsh_bad_cms_signature_vbs() {
    failure(
        "bad-wsh-cms-signature.vbs",
        "trusted",
        "invalid_signature",
        "Invalid signature",
        "cms",
    );
}

#[test]
fn wsh_bad_cms_signature_wsf() {
    failure(
        "bad-wsh-cms-signature.wsf",
        "trusted",
        "invalid_signature",
        "Invalid signature",
        "cms",
    );
}

#[test]
fn wsh_bad_cms_trailing_js() {
    failure(
        "bad-wsh-cms-trailing.js",
        "trusted",
        "malformed_cms",
        "Malformed CMS data",
        "cms",
    );
}

#[test]
fn wsh_bad_cms_trailing_vbs() {
    failure(
        "bad-wsh-cms-trailing.vbs",
        "trusted",
        "malformed_cms",
        "Malformed CMS data",
        "cms",
    );
}

#[test]
fn wsh_bad_cms_trailing_wsf() {
    failure(
        "bad-wsh-cms-trailing.wsf",
        "trusted",
        "malformed_cms",
        "Malformed CMS data",
        "cms",
    );
}

#[test]
fn wsh_bad_digest_js() {
    failure(
        "bad-wsh-digest.js",
        "trusted",
        "script_digest_mismatch",
        "Script digest mismatch",
        "script_digest",
    );
}

#[test]
fn wsh_bad_digest_jse() {
    failure(
        "bad-wsh-digest.jse",
        "trusted",
        "script_digest_mismatch",
        "Script digest mismatch",
        "script_digest",
    );
}

#[test]
fn wsh_bad_digest_vbe() {
    failure(
        "bad-wsh-digest.vbe",
        "trusted",
        "script_digest_mismatch",
        "Script digest mismatch",
        "script_digest",
    );
}

#[test]
fn wsh_bad_digest_vbs() {
    failure(
        "bad-wsh-digest.vbs",
        "trusted",
        "script_digest_mismatch",
        "Script digest mismatch",
        "script_digest",
    );
}

#[test]
fn wsh_bad_digest_wsf() {
    failure(
        "bad-wsh-digest.wsf",
        "trusted",
        "script_digest_mismatch",
        "Script digest mismatch",
        "script_digest",
    );
}

#[test]
fn wsh_bad_dtd_wsf() {
    failure(
        "bad-wsh-dtd.wsf",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_duplicate_js() {
    failure(
        "bad-wsh-duplicate.js",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_duplicate_vbs() {
    failure(
        "bad-wsh-duplicate.vbs",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_duplicate_wsf() {
    failure(
        "bad-wsh-duplicate.wsf",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_empty_signature_js() {
    failure(
        "bad-wsh-empty-signature.js",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_empty_signature_vbs() {
    failure(
        "bad-wsh-empty-signature.vbs",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_empty_signature_wsf() {
    failure(
        "bad-wsh-empty-signature.wsf",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_independent_digest_utf8_bom_js() {
    failure(
        "bad-wsh-independent-digest-utf8-bom.js",
        "integrity",
        "script_digest_mismatch",
        "Script digest mismatch",
        "script_digest",
    );
}

#[test]
fn wsh_bad_independent_digest_utf8_bom_vbs() {
    failure(
        "bad-wsh-independent-digest-utf8-bom.vbs",
        "integrity",
        "script_digest_mismatch",
        "Script digest mismatch",
        "script_digest",
    );
}

#[test]
fn wsh_bad_independent_digest_utf8_bom_wsf() {
    failure(
        "bad-wsh-independent-digest-utf8-bom.wsf",
        "integrity",
        "script_digest_mismatch",
        "Script digest mismatch",
        "script_digest",
    );
}

#[test]
fn wsh_bad_independent_digest_js() {
    failure(
        "bad-wsh-independent-digest.js",
        "integrity",
        "script_digest_mismatch",
        "Script digest mismatch",
        "script_digest",
    );
}

#[test]
fn wsh_bad_independent_digest_jse() {
    failure(
        "bad-wsh-independent-digest.jse",
        "integrity",
        "script_digest_mismatch",
        "Script digest mismatch",
        "script_digest",
    );
}

#[test]
fn wsh_bad_independent_digest_vbe() {
    failure(
        "bad-wsh-independent-digest.vbe",
        "integrity",
        "script_digest_mismatch",
        "Script digest mismatch",
        "script_digest",
    );
}

#[test]
fn wsh_bad_independent_digest_vbs() {
    failure(
        "bad-wsh-independent-digest.vbs",
        "integrity",
        "script_digest_mismatch",
        "Script digest mismatch",
        "script_digest",
    );
}

#[test]
fn wsh_bad_independent_digest_wsf() {
    failure(
        "bad-wsh-independent-digest.wsf",
        "integrity",
        "script_digest_mismatch",
        "Script digest mismatch",
        "script_digest",
    );
}

#[test]
fn wsh_bad_long_line_js() {
    failure(
        "bad-wsh-long-line.js",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_long_line_vbs() {
    failure(
        "bad-wsh-long-line.vbs",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_long_line_wsf() {
    failure(
        "bad-wsh-long-line.wsf",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_malformed_cms_js() {
    failure(
        "bad-wsh-malformed-cms.js",
        "trusted",
        "malformed_cms",
        "Malformed CMS data",
        "cms",
    );
}

#[test]
fn wsh_bad_malformed_cms_vbs() {
    failure(
        "bad-wsh-malformed-cms.vbs",
        "trusted",
        "malformed_cms",
        "Malformed CMS data",
        "cms",
    );
}

#[test]
fn wsh_bad_malformed_cms_wsf() {
    failure(
        "bad-wsh-malformed-cms.wsf",
        "trusted",
        "malformed_cms",
        "Malformed CMS data",
        "cms",
    );
}

#[test]
fn wsh_bad_marker_lf_js() {
    failure(
        "bad-wsh-marker-lf.js",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_marker_lf_vbs() {
    failure(
        "bad-wsh-marker-lf.vbs",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_marker_lf_wsf() {
    failure(
        "bad-wsh-marker-lf.wsf",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_missing_begin_js() {
    failure(
        "bad-wsh-missing-begin.js",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_missing_begin_vbs() {
    failure(
        "bad-wsh-missing-begin.vbs",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_missing_begin_wsf() {
    failure(
        "bad-wsh-missing-begin.wsf",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_missing_end_js() {
    failure(
        "bad-wsh-missing-end.js",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_missing_end_vbs() {
    failure(
        "bad-wsh-missing-end.vbs",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_missing_end_wsf() {
    failure(
        "bad-wsh-missing-end.wsf",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_mixed_vbs() {
    failure(
        "bad-wsh-mixed.vbs",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_multijob_wsf() {
    failure(
        "bad-wsh-multijob.wsf",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_nested_job_wsf() {
    failure(
        "bad-wsh-nested-job.wsf",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_no_offset_js() {
    failure(
        "bad-wsh-no-offset.js",
        "trusted",
        "script_digest_mismatch",
        "Script digest mismatch",
        "script_digest",
    );
}

#[test]
fn wsh_bad_no_offset_vbs() {
    failure(
        "bad-wsh-no-offset.vbs",
        "trusted",
        "script_digest_mismatch",
        "Script digest mismatch",
        "script_digest",
    );
}

#[test]
fn wsh_bad_no_offset_wsf() {
    failure(
        "bad-wsh-no-offset.wsf",
        "trusted",
        "script_digest_mismatch",
        "Script digest mismatch",
        "script_digest",
    );
}

#[test]
fn wsh_bad_nul_vbs() {
    failure(
        "bad-wsh-nul.vbs",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_odd_utf16_vbs() {
    failure(
        "bad-wsh-odd-utf16.vbs",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_offset_js() {
    failure(
        "bad-wsh-offset.js",
        "trusted",
        "script_digest_mismatch",
        "Script digest mismatch",
        "script_digest",
    );
}

#[test]
fn wsh_bad_offset_vbs() {
    failure(
        "bad-wsh-offset.vbs",
        "trusted",
        "script_digest_mismatch",
        "Script digest mismatch",
        "script_digest",
    );
}

#[test]
fn wsh_bad_offset_wsf() {
    failure(
        "bad-wsh-offset.wsf",
        "trusted",
        "script_digest_mismatch",
        "Script digest mismatch",
        "script_digest",
    );
}

#[test]
fn wsh_bad_placement_wsf() {
    failure(
        "bad-wsh-placement.wsf",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_sip_cross_js() {
    failure(
        "bad-wsh-sip-cross.js",
        "trusted",
        "malformed_cms",
        "Malformed CMS data",
        "cms",
    );
}

#[test]
fn wsh_bad_sip_cross_vbs() {
    failure(
        "bad-wsh-sip-cross.vbs",
        "trusted",
        "malformed_cms",
        "Malformed CMS data",
        "cms",
    );
}

#[test]
fn wsh_bad_sip_cross_wsf() {
    failure(
        "bad-wsh-sip-cross.wsf",
        "trusted",
        "malformed_cms",
        "Malformed CMS data",
        "cms",
    );
}

#[test]
fn wsh_bad_sip_reserved_js() {
    failure(
        "bad-wsh-sip-reserved.js",
        "trusted",
        "malformed_cms",
        "Malformed CMS data",
        "cms",
    );
}

#[test]
fn wsh_bad_sip_reserved_vbs() {
    failure(
        "bad-wsh-sip-reserved.vbs",
        "trusted",
        "malformed_cms",
        "Malformed CMS data",
        "cms",
    );
}

#[test]
fn wsh_bad_sip_reserved_wsf() {
    failure(
        "bad-wsh-sip-reserved.wsf",
        "trusted",
        "malformed_cms",
        "Malformed CMS data",
        "cms",
    );
}

#[test]
fn wsh_bad_sip_type_js() {
    failure(
        "bad-wsh-sip-type.js",
        "trusted",
        "malformed_cms",
        "Malformed CMS data",
        "cms",
    );
}

#[test]
fn wsh_bad_sip_type_vbs() {
    failure(
        "bad-wsh-sip-type.vbs",
        "trusted",
        "malformed_cms",
        "Malformed CMS data",
        "cms",
    );
}

#[test]
fn wsh_bad_sip_type_wsf() {
    failure(
        "bad-wsh-sip-type.wsf",
        "trusted",
        "malformed_cms",
        "Malformed CMS data",
        "cms",
    );
}

#[test]
fn wsh_bad_sip_uuid_js() {
    failure(
        "bad-wsh-sip-uuid.js",
        "trusted",
        "malformed_cms",
        "Malformed CMS data",
        "cms",
    );
}

#[test]
fn wsh_bad_sip_uuid_vbs() {
    failure(
        "bad-wsh-sip-uuid.vbs",
        "trusted",
        "malformed_cms",
        "Malformed CMS data",
        "cms",
    );
}

#[test]
fn wsh_bad_sip_uuid_wsf() {
    failure(
        "bad-wsh-sip-uuid.wsf",
        "trusted",
        "malformed_cms",
        "Malformed CMS data",
        "cms",
    );
}

#[test]
fn wsh_bad_sip_version_js() {
    failure(
        "bad-wsh-sip-version.js",
        "trusted",
        "malformed_cms",
        "Malformed CMS data",
        "cms",
    );
}

#[test]
fn wsh_bad_sip_version_vbs() {
    failure(
        "bad-wsh-sip-version.vbs",
        "trusted",
        "malformed_cms",
        "Malformed CMS data",
        "cms",
    );
}

#[test]
fn wsh_bad_sip_version_wsf() {
    failure(
        "bad-wsh-sip-version.wsf",
        "trusted",
        "malformed_cms",
        "Malformed CMS data",
        "cms",
    );
}

#[test]
fn wsh_bad_surrogate_js() {
    failure(
        "bad-wsh-surrogate.js",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_tail_wsf() {
    failure(
        "bad-wsh-tail.wsf",
        "trusted",
        "script_digest_mismatch",
        "Script digest mismatch",
        "script_digest",
    );
}

#[test]
fn wsh_bad_timestamp_imprint_js() {
    failure(
        "bad-wsh-timestamp-imprint.js",
        "trusted",
        "timestamp_imprint_mismatch",
        "Timestamp imprint mismatch",
        "timestamp",
    );
}

#[test]
fn wsh_bad_timestamp_imprint_vbs() {
    failure(
        "bad-wsh-timestamp-imprint.vbs",
        "trusted",
        "timestamp_imprint_mismatch",
        "Timestamp imprint mismatch",
        "timestamp",
    );
}

#[test]
fn wsh_bad_timestamp_imprint_wsf() {
    failure(
        "bad-wsh-timestamp-imprint.wsf",
        "trusted",
        "timestamp_imprint_mismatch",
        "Timestamp imprint mismatch",
        "timestamp",
    );
}

#[test]
fn wsh_bad_trailing_js() {
    failure(
        "bad-wsh-trailing.js",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_trailing_vbs() {
    failure(
        "bad-wsh-trailing.vbs",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_utf8_wsf() {
    failure(
        "bad-wsh-utf8.wsf",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_wrong_style_js() {
    failure(
        "bad-wsh-wrong-style.js",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_bad_xml_wsf() {
    failure(
        "bad-wsh-xml.wsf",
        "trusted",
        "invalid_wsh",
        "Invalid Windows Script Host file",
        "wsh",
    );
}

#[test]
fn wsh_good_bomless_unicode_wsf() {
    success(
        "good-wsh-bomless-unicode.wsf",
        "trusted",
        "wsf_authenticode",
    );
}

#[test]
fn wsh_good_countersignature_js() {
    success(
        "good-wsh-countersignature.js",
        "trusted",
        "jscript_authenticode",
    );
}

#[test]
fn wsh_good_countersignature_vbs() {
    success(
        "good-wsh-countersignature.vbs",
        "trusted",
        "vbscript_authenticode",
    );
}

#[test]
fn wsh_good_countersignature_wsf() {
    success(
        "good-wsh-countersignature.wsf",
        "trusted",
        "wsf_authenticode",
    );
}

#[test]
fn wsh_good_nested_js() {
    success("good-wsh-nested.js", "trusted", "jscript_authenticode");
}

#[test]
fn wsh_good_nested_vbs() {
    success("good-wsh-nested.vbs", "trusted", "vbscript_authenticode");
}

#[test]
fn wsh_good_nested_wsf() {
    success("good-wsh-nested.wsf", "trusted", "wsf_authenticode");
}

#[test]
fn wsh_good_rfc3161_js() {
    success("good-wsh-rfc3161.js", "trusted", "jscript_authenticode");
}

#[test]
fn wsh_good_rfc3161_vbs() {
    success("good-wsh-rfc3161.vbs", "trusted", "vbscript_authenticode");
}

#[test]
fn wsh_good_rfc3161_wsf() {
    success("good-wsh-rfc3161.wsf", "trusted", "wsf_authenticode");
}

#[test]
fn wsh_good_sha1_js() {
    failure(
        "good-wsh-sha1.js",
        "trusted",
        "weak_algorithm",
        "Weak algorithm disallowed",
        "script_digest",
    );
}

#[test]
fn wsh_good_sha1_js_allowed() {
    success("good-wsh-sha1.js", "sha1", "jscript_authenticode");
}

#[test]
fn wsh_good_sha1_vbs() {
    failure(
        "good-wsh-sha1.vbs",
        "trusted",
        "weak_algorithm",
        "Weak algorithm disallowed",
        "script_digest",
    );
}

#[test]
fn wsh_good_sha1_vbs_allowed() {
    success("good-wsh-sha1.vbs", "sha1", "vbscript_authenticode");
}

#[test]
fn wsh_good_sha1_wsf() {
    failure(
        "good-wsh-sha1.wsf",
        "trusted",
        "weak_algorithm",
        "Weak algorithm disallowed",
        "script_digest",
    );
}

#[test]
fn wsh_good_sha1_wsf_allowed() {
    success("good-wsh-sha1.wsf", "sha1", "wsf_authenticode");
}

#[test]
fn wsh_good_sha384_js() {
    success("good-wsh-sha384.js", "trusted", "jscript_authenticode");
}

#[test]
fn wsh_good_sha384_vbs() {
    success("good-wsh-sha384.vbs", "trusted", "vbscript_authenticode");
}

#[test]
fn wsh_good_sha384_wsf() {
    success("good-wsh-sha384.wsf", "trusted", "wsf_authenticode");
}

#[test]
fn wsh_good_sha512_js() {
    success("good-wsh-sha512.js", "trusted", "jscript_authenticode");
}

#[test]
fn wsh_good_sha512_vbs() {
    success("good-wsh-sha512.vbs", "trusted", "vbscript_authenticode");
}

#[test]
fn wsh_good_sha512_wsf() {
    success("good-wsh-sha512.wsf", "trusted", "wsf_authenticode");
}

#[test]
fn wsh_good_utf16be_js() {
    success("good-wsh-utf16be.js", "trusted", "jscript_authenticode");
}

#[test]
fn wsh_good_utf16be_vbs() {
    success("good-wsh-utf16be.vbs", "trusted", "vbscript_authenticode");
}

#[test]
fn wsh_good_utf16be_wsf() {
    success("good-wsh-utf16be.wsf", "trusted", "wsf_authenticode");
}

#[test]
fn wsh_good_utf16le_js() {
    success("good-wsh-utf16le.js", "trusted", "jscript_authenticode");
}

#[test]
fn wsh_good_utf16le_vbs() {
    success("good-wsh-utf16le.vbs", "trusted", "vbscript_authenticode");
}

#[test]
fn wsh_good_utf16le_wsf() {
    success("good-wsh-utf16le.wsf", "trusted", "wsf_authenticode");
}

#[test]
fn wsh_good_utf8_bom_js() {
    success("good-wsh-utf8-bom.js", "trusted", "jscript_authenticode");
}

#[test]
fn wsh_good_utf8_bom_vbs() {
    success("good-wsh-utf8-bom.vbs", "trusted", "vbscript_authenticode");
}

#[test]
fn wsh_good_utf8_bom_wsf() {
    success("good-wsh-utf8-bom.wsf", "trusted", "wsf_authenticode");
}

#[test]
fn wsh_good_js() {
    success("good-wsh.js", "trusted", "jscript_authenticode");
}

#[test]
fn wsh_good_jse() {
    success("good-wsh.jse", "trusted", "jscript_authenticode");
}

#[test]
fn wsh_good_vbe() {
    success("good-wsh.vbe", "trusted", "vbscript_authenticode");
}

#[test]
fn wsh_good_vbs() {
    success("good-wsh.vbs", "trusted", "vbscript_authenticode");
}

#[test]
fn wsh_good_wsf() {
    success("good-wsh.wsf", "trusted", "wsf_authenticode");
}

#[test]
fn wsh_unsigned_js() {
    failure(
        "unsigned-wsh.js",
        "trusted",
        "unsigned",
        "Missing embedded signature",
        "wsh",
    );
}

#[test]
fn wsh_unsigned_vbs() {
    failure(
        "unsigned-wsh.vbs",
        "trusted",
        "unsigned",
        "Missing embedded signature",
        "wsh",
    );
}

#[test]
fn wsh_unsigned_wsf() {
    failure(
        "unsigned-wsh.wsf",
        "trusted",
        "unsigned",
        "Missing embedded signature",
        "wsh",
    );
}

#[test]
fn wsh_wsh_binary_precedence_js() {
    success("wsh-binary-precedence.js", "trusted", "pe_authenticode");
}

#[test]
fn wsh_wsh_independent_jsign_utf8_bom_js() {
    success(
        "wsh-independent-jsign-utf8-bom.js",
        "integrity",
        "jscript_authenticode",
    );
}

#[test]
fn wsh_wsh_independent_jsign_utf8_bom_vbs() {
    success(
        "wsh-independent-jsign-utf8-bom.vbs",
        "integrity",
        "vbscript_authenticode",
    );
}

#[test]
fn wsh_wsh_independent_jsign_utf8_bom_wsf() {
    success(
        "wsh-independent-jsign-utf8-bom.wsf",
        "integrity",
        "wsf_authenticode",
    );
}

#[test]
fn wsh_wsh_independent_jsign_js() {
    success(
        "wsh-independent-jsign.js",
        "integrity",
        "jscript_authenticode",
    );
}

#[test]
fn wsh_wsh_independent_jsign_jse() {
    success(
        "wsh-independent-jsign.jse",
        "integrity",
        "jscript_authenticode",
    );
}

#[test]
fn wsh_wsh_independent_jsign_vbe() {
    success(
        "wsh-independent-jsign.vbe",
        "integrity",
        "vbscript_authenticode",
    );
}

#[test]
fn wsh_wsh_independent_jsign_vbs() {
    success(
        "wsh-independent-jsign.vbs",
        "integrity",
        "vbscript_authenticode",
    );
}

#[test]
fn wsh_wsh_independent_jsign_wsf() {
    success("wsh-independent-jsign.wsf", "integrity", "wsf_authenticode");
}

#[test]
fn wsh_wsh_jsign_input_js() {
    failure(
        "wsh-jsign-input.js",
        "trusted",
        "unsigned",
        "Missing embedded signature",
        "wsh",
    );
}

#[test]
fn wsh_wsh_jsign_input_jse() {
    failure(
        "wsh-jsign-input.jse",
        "trusted",
        "unsigned",
        "Missing embedded signature",
        "wsh",
    );
}

#[test]
fn wsh_wsh_jsign_input_vbe() {
    failure(
        "wsh-jsign-input.vbe",
        "trusted",
        "unsigned",
        "Missing embedded signature",
        "wsh",
    );
}

#[test]
fn wsh_wsh_jsign_input_vbs() {
    failure(
        "wsh-jsign-input.vbs",
        "trusted",
        "unsigned",
        "Missing embedded signature",
        "wsh",
    );
}

#[test]
fn wsh_wsh_jsign_input_wsf() {
    failure(
        "wsh-jsign-input.wsf",
        "trusted",
        "unsigned",
        "Missing embedded signature",
        "wsh",
    );
}

#[test]
fn wsh_wsh_jsign_utf8_bom_input_js() {
    failure(
        "wsh-jsign-utf8-bom-input.js",
        "trusted",
        "unsigned",
        "Missing embedded signature",
        "wsh",
    );
}

#[test]
fn wsh_wsh_jsign_utf8_bom_input_vbs() {
    failure(
        "wsh-jsign-utf8-bom-input.vbs",
        "trusted",
        "unsigned",
        "Missing embedded signature",
        "wsh",
    );
}

#[test]
fn wsh_wsh_jsign_utf8_bom_input_wsf() {
    failure(
        "wsh-jsign-utf8-bom-input.wsf",
        "trusted",
        "unsigned",
        "Missing embedded signature",
        "wsh",
    );
}

#[test]
fn wsh_wsh_misnamed_js_bin() {
    success("wsh-misnamed-js.bin", "trusted", "jscript_authenticode");
}

#[test]
fn wsh_wsh_misnamed_vbs_bin() {
    success("wsh-misnamed-vbs.bin", "trusted", "vbscript_authenticode");
}

#[test]
fn wsh_wsh_misnamed_wsf_bin() {
    success("wsh-misnamed-wsf.bin", "trusted", "wsf_authenticode");
}

#[test]
fn wsh_integrity() {
    success("good-wsh.vbs", "integrity", "vbscript_authenticode");
}

#[test]
fn wsh_no_revocation() {
    success("good-wsh.vbs", "no-revocation", "vbscript_authenticode");
}

#[test]
fn wsh_revoked() {
    failure(
        "good-wsh.vbs",
        "revoked",
        "certificate_revoked",
        "Certificate revoked",
        "revocation",
    );
}

#[test]
fn wsh_untrusted() {
    failure(
        "good-wsh.vbs",
        "untrusted",
        "untrusted_root",
        "Untrusted root certificate",
        "certificate_chain",
    );
}
