//! MSP uses the MSI SIP and JSON contract; no original MSI is supplied.
use super::support::*;

fn successful_patch(name: &str, extended: bool) {
    let output = run_fixture(name, TRUSTED);
    expect_success(&output);
    let bundle = output.success();
    assert_eq!(bundle.format, "msi_authenticode");
    assert_eq!(bundle.signatures.len(), 1);
    let sig = &bundle.signatures[0];
    assert!(sig.chain_trusted);
    assert!(sig.revocation_checked);
    assert_eq!(
        sig.certificate.subject.common_names,
        ["rssig test publisher"]
    );
    assert_eq!(sig.trust.as_ref().unwrap().chain.len(), 2);
    let digest = sig.package_digest.as_ref().unwrap();
    assert_eq!(digest.algorithm, "Sha256");
    assert_eq!(digest.expected, digest.computed);
    assert_eq!(sig.extended_digest.is_some(), extended);
    assert!(sig.image_digest.is_none());
    let json = &output.json["results"][0];
    assert_eq!(json["format"], "msi_authenticode");
    assert_eq!(json["signatures"][0]["chain_trusted"], true);
    assert_eq!(json["signatures"][0]["revocation_checked"], true);
    assert!(json["signatures"][0].get("image_digest").is_none());
}

#[test]
fn trusted_without_original_msi() {
    successful_patch("msp-good.msp", true);
}
#[test]
fn legacy() {
    successful_patch("msp-good-legacy.msp", false);
}
#[test]
fn cfb_v4() {
    successful_patch("msp-good-v4.msp", true);
}
fn digest_failure(name: &str) {
    let output = run_fixture(name, INTEGRITY);
    expect_failure(
        &output,
        1,
        "package_digest_mismatch",
        "MSI package digest mismatch",
        Some("package_digest"),
        None,
    );
    let digest = &output.json["results"][0]["error"]["details"]["digest"];
    assert_ne!(digest["expected"], digest["computed"]);
}
#[test]
fn tampered_transform() {
    digest_failure("msp-bad-transform.msp");
}
#[test]
fn tampered_cab() {
    digest_failure("msp-bad-cab.msp");
}
#[test]
fn tampered_patch_clsid() {
    digest_failure("msp-bad-clsid.msp");
}
#[test]
fn tampered_metadata() {
    let output = run_fixture("msp-bad-metadata.msp", INTEGRITY);
    expect_failure(
        &output,
        1,
        "extended_digest_mismatch",
        "MSI extended digest mismatch",
        Some("package_digest"),
        None,
    );
}
#[test]
fn tampered_signature() {
    let output = run_fixture("msp-bad-cms.msp", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_signature",
        "Invalid signature",
        Some("cms"),
        Some("CMS signature verification"),
    );
}
#[test]
fn unsigned() {
    let output = run_fixture("msp-unsigned.msp", INTEGRITY);
    expect_failure(
        &output,
        1,
        "unsigned",
        "Missing embedded signature",
        Some("msi"),
        None,
    );
}
#[test]
fn revoked() {
    let output = run_fixture("msp-good.msp", REVOKED);
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
fn untrusted() {
    let output = run_fixture("msp-good.msp", UNRELATED_ROOT);
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
fn rfc3161() {
    let output = run_fixture("msp-good-rfc3161.msp", INTEGRITY);
    expect_success(&output);
    let sig = &output.success().signatures[0];
    assert_eq!(sig.timestamp, Some(1800000000));
    assert_eq!(sig.timestamp_verification.as_ref().unwrap().kind, "rfc3161");
}
#[test]
fn nested() {
    let output = run_fixture("msp-good-nested.msp", INTEGRITY);
    expect_success(&output);
    assert_eq!(output.success().signatures.len(), 2);
    assert_eq!(output.success().signatures[0].nested_depth, 0);
    assert_eq!(output.success().signatures[1].nested_depth, 1);
}
#[test]
fn independent_jsign() {
    let output = run_fixture("msp-independent-jsign.msp", INTEGRITY);
    expect_success(&output);
    let sig = &output.success().signatures[0];
    assert!(!sig.chain_trusted);
    assert!(!sig.revocation_checked);
    assert_eq!(
        sig.certificate.subject.common_names,
        ["rssig independent MSI test signer"]
    );
    assert_eq!(
        sig.package_digest.as_ref().unwrap().expected,
        sig.package_digest.as_ref().unwrap().computed
    );
    assert!(sig.extended_digest.is_none());
}
#[test]
fn independent_jsign_tampered() {
    digest_failure("msp-independent-jsign-tampered.msp");
}
#[test]
fn help_advertises_msp() {
    let mut stdout = Vec::new();
    assert_eq!(
        rssig::cli::run(["rssig", "--help"], &mut stdout).unwrap(),
        0
    );
    let json: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert!(json["text"].as_str().unwrap().contains("MSP"));
}

#[test]
fn library_dispatch_uses_the_msi_family_without_a_filename() {
    let bytes = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/msp-good.msp"
    ))
    .unwrap();
    let options = rssig::VerifyOptions {
        trust: None,
        check_revocation: true,
        allow_sha1: false,
        now: 1800000000,
    };
    let auto = rssig::verify(&bytes, &options).unwrap();
    let explicit = rssig::verify_msi(&bytes, &options).unwrap();
    assert_eq!(
        serde_json::to_value(auto).unwrap(),
        serde_json::to_value(explicit).unwrap()
    );
}
