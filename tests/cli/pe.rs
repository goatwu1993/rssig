//! In-process CLI regressions against committed PE fixtures.
use super::support::*;
use serde_json::json;

#[test]
fn pe32() {
    let output = run_fixture("good-pe32.exe", TRUSTED_NO_REVOCATION);
    expect_success(&output);
    let report = output.success();
    let signature = &report.signatures[0];
    assert_eq!(report.signatures.len(), 1);
    assert!(signature.chain_trusted);
    assert!(!signature.revocation_checked);
    assert_eq!(signature.digest_algorithm, "Sha256");
}

#[test]
fn pe64() {
    let output = run_fixture("good-pe64.exe", TRUSTED_NO_REVOCATION);
    expect_success(&output);
    let report = output.success();
    let signature = &report.signatures[0];
    assert_eq!(report.signatures.len(), 1);
    assert!(signature.chain_trusted);
    assert!(!signature.revocation_checked);
    assert_eq!(signature.digest_algorithm, "Sha256");
    assert_eq!(signature.certificate.subject.common_names.len(), 1);
    assert_eq!(
        signature.certificate.subject.common_names[0],
        "rssig test publisher"
    );
    assert_eq!(
        signature
            .certificate
            .extended_key_usage
            .as_ref()
            .unwrap()
            .usages
            .len(),
        1
    );
    assert_eq!(
        signature
            .certificate
            .extended_key_usage
            .as_ref()
            .unwrap()
            .usages[0]
            .oid,
        "1.3.6.1.5.5.7.3.3"
    );
    assert_eq!(
        signature
            .certificate
            .extended_key_usage
            .as_ref()
            .unwrap()
            .usages[0]
            .name
            .as_deref(),
        Some("code_signing")
    );
    assert_eq!(signature.trust.as_ref().unwrap().chain.len(), 2);
    assert_eq!(
        signature.trust.as_ref().unwrap().chain[0]
            .subject
            .common_names
            .len(),
        1
    );
    assert_eq!(
        signature.trust.as_ref().unwrap().chain[0]
            .subject
            .common_names[0],
        "rssig test publisher"
    );
    assert_eq!(
        signature.trust.as_ref().unwrap().chain[1]
            .subject
            .common_names
            .len(),
        1
    );
    assert_eq!(
        signature.trust.as_ref().unwrap().chain[1]
            .subject
            .common_names[0],
        "rssig test root"
    );
}

#[test]
fn page_hashes() {
    let output = run_fixture("good-page-hashes.exe", TRUSTED_NO_REVOCATION);
    expect_success(&output);
    let report = output.success();
    let signature = &report.signatures[0];
    assert_eq!(report.signatures.len(), 1);
    assert!(signature.chain_trusted);
    assert!(!signature.revocation_checked);
    assert_eq!(signature.digest_algorithm, "Sha256");
}

#[test]
fn checksum_excluded() {
    let output = run_fixture("good-modified-checksum.exe", TRUSTED_NO_REVOCATION);
    expect_success(&output);
    let report = output.success();
    let signature = &report.signatures[0];
    assert_eq!(report.signatures.len(), 1);
    assert!(signature.chain_trusted);
    assert!(!signature.revocation_checked);
    assert_eq!(signature.digest_algorithm, "Sha256");
}

#[test]
fn integrity_only() {
    let output = run_fixture("good-pe64.exe", INTEGRITY);
    expect_success(&output);
    let report = output.success();
    let signature = &report.signatures[0];
    assert_eq!(report.signatures.len(), 1);
    assert!(!signature.chain_trusted);
    assert!(!signature.revocation_checked);
}

#[test]
fn nested_signatures() {
    let output = run_fixture("good-nested.exe", TRUSTED_NO_REVOCATION);
    expect_success(&output);
    let report = output.success();
    assert_eq!(report.signatures.len(), 2);
    assert_eq!(report.signatures[0].nested_depth, 0);
    assert_eq!(report.signatures[1].nested_depth, 1);
}

#[test]
fn current_crl() {
    let output = run_fixture("good-pe64.exe", TRUSTED);
    expect_success(&output);
    let report = output.success();
    let signature = &report.signatures[0];
    assert_eq!(report.signatures.len(), 1);
    assert!(signature.chain_trusted);
    assert!(signature.revocation_checked);
    assert!(matches!(
        signature.trust.as_ref().unwrap().revocation.status,
        rssig::domain::RevocationStatus::Good
    ));
    assert_eq!(
        signature
            .trust
            .as_ref()
            .unwrap()
            .revocation
            .method
            .as_deref(),
        Some("crl")
    );
    assert_eq!(signature.trust.as_ref().unwrap().revocation.crls.len(), 1);
    assert_eq!(
        signature.trust.as_ref().unwrap().revocation.crls[0]
            .issuer
            .common_names
            .len(),
        1
    );
    assert_eq!(
        signature.trust.as_ref().unwrap().revocation.crls[0]
            .issuer
            .common_names[0],
        "rssig test root"
    );
    assert_eq!(
        signature.trust.as_ref().unwrap().revocation.crls[0].this_update,
        1799999900
    );
    assert_eq!(
        signature.trust.as_ref().unwrap().revocation.crls[0].next_update,
        Some(1800001000)
    );
}

#[test]
fn tampered_image() {
    let output = run_fixture("bad-image-digest.exe", INTEGRITY);
    expect_failure(
        &output,
        1,
        "image_digest_mismatch",
        "PE image digest mismatch",
        Some("image_digest"),
        Some("PE image digest mismatch"),
    );
    assert_eq!(
        output.json["results"][0]["error"]["details"]["digest"]["algorithm"],
        json!("Sha256")
    );
    assert_eq!(
        output.json["results"][0]["error"]["details"]["digest"]["computed"],
        json!("821ba3d28e9ea20b53901de76a090d109e9dced8426ca75f2f844543b59cd243")
    );
    assert_eq!(
        output.json["results"][0]["error"]["details"]["digest"]["expected"],
        json!("dea5b51087a941e1757bc435b116fc1a7dfc9c8343bf4cb27b7fc9431a9dd30f")
    );
}

#[test]
fn bad_cms() {
    let output = run_fixture("bad-cms-signature.exe", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_signature",
        "Invalid signature",
        None,
        Some("CMS signature verification"),
    );
}

#[test]
fn bad_page_hashes() {
    let output = run_fixture("bad-page-hashes.exe", INTEGRITY);
    expect_failure(
        &output,
        1,
        "page_hash_mismatch",
        "Page hash mismatch",
        None,
        Some("page hash mismatch"),
    );
}

#[test]
fn bad_imprint() {
    let output = run_fixture("bad-timestamp-imprint.exe", INTEGRITY);
    expect_failure(
        &output,
        1,
        "timestamp_imprint_mismatch",
        "Timestamp imprint mismatch",
        None,
        Some("timestamp imprint mismatch"),
    );
}

#[test]
fn future_timestamp() {
    let output = run_fixture("bad-future-timestamp.exe", INTEGRITY);
    expect_failure(
        &output,
        1,
        "timestamp_in_future",
        "Timestamp is in the future",
        None,
        Some("timestamp is in the future"),
    );
}

#[test]
fn unsigned() {
    let output = run_fixture("unsigned.exe", INTEGRITY);
    expect_failure(
        &output,
        1,
        "unsigned",
        "Missing embedded signature",
        None,
        Some("no embedded signature"),
    );
}

#[test]
fn not_pe() {
    let output = run_fixture("not-pe.bin", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_pe",
        "Invalid PE image",
        None,
        Some("missing MZ"),
    );
}

#[test]
fn truncated() {
    let output = run_fixture("bad-truncated.exe", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_pe",
        "Invalid PE image",
        None,
        Some("truncated optional header"),
    );
}

#[test]
fn trailing_data() {
    let output = run_fixture("bad-trailing-data.exe", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_pe",
        "Invalid PE image",
        None,
        Some("certificate table must end at EOF"),
    );
}

#[test]
fn wrong_tsa_eku() {
    let output = run_fixture("bad-timestamp-eku.exe", TRUSTED_NO_REVOCATION);
    expect_failure(
        &output,
        1,
        "invalid_eku",
        "Invalid extended key usage",
        None,
        Some("TSA EKU"),
    );
}

#[test]
fn rfc3161() {
    let output = run_fixture("good-rfc3161.exe", TRUSTED_NO_REVOCATION);
    expect_success(&output);
    let report = output.success();
    let signature = &report.signatures[0];
    assert_eq!(report.signatures.len(), 1);
    assert_eq!(signature.timestamp, Some(1800000000));
    assert!(signature.chain_trusted);
    assert_eq!(
        signature.timestamp_verification.as_ref().unwrap().kind,
        "rfc3161"
    );
    assert_eq!(
        signature
            .timestamp_verification
            .as_ref()
            .unwrap()
            .signing_time,
        1800000000
    );
    assert_eq!(
        signature
            .timestamp_verification
            .as_ref()
            .unwrap()
            .certificate
            .subject
            .common_names
            .len(),
        1
    );
    assert_eq!(
        signature
            .timestamp_verification
            .as_ref()
            .unwrap()
            .certificate
            .subject
            .common_names[0],
        "rssig test TSA"
    );
}

#[test]
fn legacy_counter() {
    let output = run_fixture("good-countersignature.exe", TRUSTED_NO_REVOCATION);
    expect_success(&output);
    let report = output.success();
    let signature = &report.signatures[0];
    assert_eq!(report.signatures.len(), 1);
    assert_eq!(signature.timestamp, Some(1800000000));
    assert!(signature.chain_trusted);
}

#[test]
fn expired_without_timestamp() {
    let output = run_fixture("good-pe64.exe", AFTER_CERTIFICATE_EXPIRY);
    expect_failure(
        &output,
        1,
        "certificate_expired",
        "Certificate expired",
        None,
        Some("CertExpired"),
    );
}

#[test]
fn expired_with_rfc3161() {
    let output = run_fixture("good-rfc3161.exe", AFTER_CERTIFICATE_EXPIRY);
    expect_success(&output);
    let report = output.success();
    let signature = &report.signatures[0];
    assert_eq!(report.signatures.len(), 1);
    assert_eq!(signature.timestamp, Some(1800000000));
    assert!(signature.chain_trusted);
}

#[test]
fn expired_with_counter() {
    let output = run_fixture("good-countersignature.exe", AFTER_CERTIFICATE_EXPIRY);
    expect_success(&output);
    let report = output.success();
    let signature = &report.signatures[0];
    assert_eq!(report.signatures.len(), 1);
    assert_eq!(signature.timestamp, Some(1800000000));
    assert!(signature.chain_trusted);
}

#[test]
fn revoked() {
    let output = run_fixture("good-pe64.exe", REVOKED);
    expect_failure(
        &output,
        1,
        "certificate_revoked",
        "Certificate revoked",
        None,
        Some("CertRevoked"),
    );
}

#[test]
fn expired_crl() {
    let output = run_fixture("good-pe64.exe", EXPIRED_CRL);
    expect_failure(
        &output,
        1,
        "crl_expired",
        "CRL expired",
        None,
        Some("CRL has expired"),
    );
}

#[test]
fn forged_crl() {
    let output = run_fixture("good-pe64.exe", FORGED_CRL);
    expect_failure(
        &output,
        1,
        "invalid_crl_signature",
        "Invalid CRL signature",
        None,
        Some("InvalidCrlSignature"),
    );
}

#[test]
fn unknown_root() {
    let output = run_fixture("good-pe64.exe", UNRELATED_ROOT);
    expect_failure(
        &output,
        1,
        "untrusted_root",
        "Untrusted root certificate",
        None,
        Some("UnknownIssuer"),
    );
}

#[test]
fn missing_crl_policy() {
    let output = run_fixture("good-pe64.exe", MISSING_CRL_POLICY);
    expect_failure(
        &output,
        2,
        "configuration",
        "Invalid configuration",
        None,
        Some("supply --crl"),
    );
}

#[test]
fn missing_input() {
    let output = run_fixture("missing.exe", INTEGRITY);
    expect_failure(
        &output,
        1,
        "read_failed",
        "Input read failed",
        None,
        Some("reading"),
    );
}

#[test]
fn intermediate_without_eku() {
    let output = run_fixture("good-intermediate.exe", TRUSTED_NO_REVOCATION);
    expect_success(&output);
}

#[test]
fn ca_key_usage() {
    let output = run_fixture("bad-ca-key-usage.exe", TRUSTED_NO_REVOCATION);
    expect_failure(
        &output,
        1,
        "invalid_key_usage",
        "Invalid key usage",
        None,
        None,
    );
}

#[test]
fn unsupported_signature() {
    let output = run_fixture("unsupported-signature-algorithm.exe", INTEGRITY);
    expect_failure(
        &output,
        1,
        "unsupported_algorithm",
        "Unsupported algorithm",
        Some("cms"),
        None,
    );
    assert_eq!(
        output.json["results"][0]["error"]["details"]["oid"],
        json!("1.2.840.10045.4.3.127")
    );
}

#[test]
fn unsupported_digest() {
    let output = run_fixture("unsupported-digest-algorithm.exe", INTEGRITY);
    expect_failure(
        &output,
        1,
        "unsupported_algorithm",
        "Unsupported algorithm",
        Some("cms"),
        None,
    );
    assert_eq!(
        output.json["results"][0]["error"]["details"]["oid"],
        json!("2.16.840.1.101.3.4.2.127")
    );
}

#[test]
fn certificate_payload() {
    let output = run_fixture("bad-certificate-payload.exe", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_certificate_table",
        "Invalid certificate table",
        Some("certificate_table"),
        None,
    );
}

#[test]
fn rfc9457_invalid_arguments() {
    let output = run_fixture("good-pe64.exe", INVALID_TIME);
    expect_failure(
        &output,
        2,
        "invalid_arguments",
        "Invalid arguments",
        Some("arguments"),
        Some("invalid"),
    );
}

#[test]
fn bad_cms_content_digest() {
    let output = run_fixture("bad-cms-content-digest.exe", INTEGRITY);
    expect_failure(
        &output,
        1,
        "content_digest_mismatch",
        "Content digest mismatch",
        Some("cms"),
        Some("CMS content digest mismatch"),
    );
}

#[test]
fn bad_cms_content_type() {
    let output = run_fixture("bad-cms-content-type.exe", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_signature",
        "Invalid signature",
        Some("cms"),
        Some("signed contentType mismatch"),
    );
}

#[test]
fn bad_signer_issuer() {
    let output = run_fixture("bad-signer-issuer.exe", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_signature",
        "Invalid signature",
        Some("cms"),
        Some("signer certificate missing"),
    );
}

#[test]
fn bad_signer_serial() {
    let output = run_fixture("bad-signer-serial.exe", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_signature",
        "Invalid signature",
        Some("cms"),
        Some("signer certificate missing"),
    );
}

#[test]
fn bad_cms_digest_set() {
    let output = run_fixture("bad-cms-digest-set.exe", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_signature",
        "Invalid signature",
        Some("cms"),
        Some("signer digest absent from SignedData digestAlgorithms"),
    );
}

#[test]
fn bad_signature_digest_algorithm() {
    let output = run_fixture("bad-signature-digest-algorithm.exe", INTEGRITY);
    expect_failure(
        &output,
        1,
        "unsupported_algorithm",
        "Unsupported algorithm",
        Some("cms"),
        Some("unsupported signature algorithm"),
    );
}

#[test]
fn bad_signature_key_algorithm() {
    let output = run_fixture("bad-signature-key-algorithm.exe", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_signature",
        "Invalid signature",
        Some("cms"),
        Some("unknown/unsupported algorithm OID: 1.2.840.113549.1.1.1"),
    );
}

#[test]
fn bad_signer_public_key() {
    let output = run_fixture("bad-signer-public-key.exe", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_signature",
        "Invalid signature",
        Some("cms"),
        Some("signature error"),
    );
}

#[test]
fn bad_countersignature_digest() {
    let output = run_fixture("bad-countersignature-digest.exe", INTEGRITY);
    expect_failure(
        &output,
        1,
        "content_digest_mismatch",
        "Content digest mismatch",
        Some("cms"),
        Some("CMS content digest mismatch"),
    );
}

#[test]
fn bad_timestamp_signature() {
    let output = run_fixture("bad-timestamp-signature.exe", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_timestamp",
        "Invalid timestamp",
        Some("timestamp"),
        Some("signature error"),
    );
}

#[test]
fn bad_countersignature_signature() {
    let output = run_fixture("bad-countersignature-signature.exe", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_timestamp",
        "Invalid timestamp",
        Some("timestamp"),
        Some("signature error"),
    );
}

#[test]
fn bad_nested_signature() {
    let output = run_fixture("bad-nested-signature.exe", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_signature",
        "Invalid signature",
        Some("cms"),
        Some("signature error"),
    );
}

#[test]
fn bad_certificate_not_yet_valid() {
    let output = run_fixture("bad-certificate-not-yet-valid.exe", TRUSTED);
    expect_failure(
        &output,
        1,
        "certificate_not_yet_valid",
        "Certificate not yet valid",
        Some("certificate_chain"),
        Some("CertNotValidYet"),
    );
}

#[test]
fn bad_certificate_expired() {
    let output = run_fixture("bad-certificate-expired.exe", TRUSTED);
    expect_failure(
        &output,
        1,
        "certificate_expired",
        "Certificate expired",
        Some("certificate_chain"),
        Some("CertExpired"),
    );
}

#[test]
fn bad_signer_eku() {
    let output = run_fixture("bad-signer-eku.exe", TRUSTED);
    expect_failure(
        &output,
        1,
        "invalid_eku",
        "Invalid extended key usage",
        Some("certificate"),
        Some("signer certificate lacks required EKU"),
    );
}

#[test]
fn bad_signer_key_usage() {
    let output = run_fixture("bad-signer-key-usage.exe", TRUSTED);
    expect_failure(
        &output,
        1,
        "invalid_key_usage",
        "Invalid key usage",
        Some("certificate"),
        Some("signer KeyUsage lacks digitalSignature"),
    );
}

#[test]
fn bad_certificate_signature() {
    let output = run_fixture("bad-certificate-signature.exe", TRUSTED);
    expect_failure(
        &output,
        1,
        "certificate_chain_invalid",
        "Invalid certificate chain",
        Some("certificate_chain"),
        Some("InvalidSignatureForPublicKey"),
    );
}

#[test]
fn bad_intermediate_signature() {
    let output = run_fixture("bad-intermediate-signature.exe", INTERMEDIATE_CRLS);
    expect_failure(
        &output,
        1,
        "certificate_chain_invalid",
        "Invalid certificate chain",
        Some("certificate_chain"),
        Some("InvalidSignatureForPublicKey"),
    );
}

#[test]
fn bad_crl_not_yet_valid() {
    let output = run_fixture("good-pe64.exe", FUTURE_CRL);
    expect_failure(
        &output,
        1,
        "crl_not_yet_valid",
        "CRL not yet valid",
        Some("revocation"),
        Some("CRL thisUpdate is in the future"),
    );
}

#[test]
fn intermediate_current_crls() {
    let output = run_fixture("good-intermediate.exe", INTERMEDIATE_CRLS);
    expect_success(&output);
    let report = output.success();
    let signature = &report.signatures[0];
    assert_eq!(report.signatures.len(), 1);
    assert!(signature.chain_trusted);
    assert!(signature.revocation_checked);
}
