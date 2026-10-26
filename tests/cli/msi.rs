//! In-process CLI regressions against committed MSI fixtures.
use super::support::*;
use serde_json::json;

#[test]
fn pe64() {
    let output = run_fixture("msi-good-pe64.msi", TRUSTED_NO_REVOCATION);
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
    assert_eq!(
        signature.package_digest.as_ref().unwrap().algorithm,
        "Sha256"
    );
    assert_eq!(
        signature.package_digest.as_ref().unwrap().expected,
        "6613892dcd2f9bff6155defe44398120c1358c4fc45a6c2d799058a5654239f5"
    );
    assert_eq!(
        signature.package_digest.as_ref().unwrap().computed,
        "6613892dcd2f9bff6155defe44398120c1358c4fc45a6c2d799058a5654239f5"
    );
    assert_eq!(
        signature.extended_digest.as_ref().unwrap().algorithm,
        "Sha256"
    );
    assert_eq!(
        signature.extended_digest.as_ref().unwrap().expected,
        "68512dac13784bb8786e1c30adf8f458d7b30421b0d1d9dcaf845026cb14bc9d"
    );
    assert_eq!(
        signature.extended_digest.as_ref().unwrap().computed,
        "68512dac13784bb8786e1c30adf8f458d7b30421b0d1d9dcaf845026cb14bc9d"
    );
    assert_eq!(report.format, "msi_authenticode");
}

#[test]
fn integrity_only() {
    let output = run_fixture("msi-good-pe64.msi", INTEGRITY);
    expect_success(&output);
    let report = output.success();
    let signature = &report.signatures[0];
    assert_eq!(report.signatures.len(), 1);
    assert!(!signature.chain_trusted);
    assert!(!signature.revocation_checked);
    assert_eq!(report.format, "msi_authenticode");
}

#[test]
fn nested_signatures() {
    let output = run_fixture("msi-good-nested.msi", TRUSTED_NO_REVOCATION);
    expect_success(&output);
    let report = output.success();
    assert_eq!(report.signatures.len(), 2);
    assert_eq!(report.signatures[0].nested_depth, 0);
    assert_eq!(report.signatures[1].nested_depth, 1);
    assert_eq!(report.format, "msi_authenticode");
}

#[test]
fn current_crl() {
    let output = run_fixture("msi-good-pe64.msi", TRUSTED);
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
    assert_eq!(report.format, "msi_authenticode");
}

#[test]
fn bad_cms() {
    let output = run_fixture("msi-bad-cms-signature.msi", INTEGRITY);
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
fn bad_imprint() {
    let output = run_fixture("msi-bad-timestamp-imprint.msi", INTEGRITY);
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
    let output = run_fixture("msi-bad-future-timestamp.msi", INTEGRITY);
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
fn wrong_tsa_eku() {
    let output = run_fixture("msi-bad-timestamp-eku.msi", TRUSTED_NO_REVOCATION);
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
    let output = run_fixture("msi-good-rfc3161.msi", TRUSTED_NO_REVOCATION);
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
    assert_eq!(report.format, "msi_authenticode");
}

#[test]
fn legacy_counter() {
    let output = run_fixture("msi-good-countersignature.msi", TRUSTED_NO_REVOCATION);
    expect_success(&output);
    let report = output.success();
    let signature = &report.signatures[0];
    assert_eq!(report.signatures.len(), 1);
    assert_eq!(signature.timestamp, Some(1800000000));
    assert!(signature.chain_trusted);
    assert_eq!(report.format, "msi_authenticode");
}

#[test]
fn expired_without_timestamp() {
    let output = run_fixture("msi-good-pe64.msi", AFTER_CERTIFICATE_EXPIRY);
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
    let output = run_fixture("msi-good-rfc3161.msi", AFTER_CERTIFICATE_EXPIRY);
    expect_success(&output);
    let report = output.success();
    let signature = &report.signatures[0];
    assert_eq!(report.signatures.len(), 1);
    assert_eq!(signature.timestamp, Some(1800000000));
    assert!(signature.chain_trusted);
    assert_eq!(report.format, "msi_authenticode");
}

#[test]
fn expired_with_counter() {
    let output = run_fixture("msi-good-countersignature.msi", AFTER_CERTIFICATE_EXPIRY);
    expect_success(&output);
    let report = output.success();
    let signature = &report.signatures[0];
    assert_eq!(report.signatures.len(), 1);
    assert_eq!(signature.timestamp, Some(1800000000));
    assert!(signature.chain_trusted);
    assert_eq!(report.format, "msi_authenticode");
}

#[test]
fn revoked() {
    let output = run_fixture("msi-good-pe64.msi", REVOKED);
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
    let output = run_fixture("msi-good-pe64.msi", EXPIRED_CRL);
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
    let output = run_fixture("msi-good-pe64.msi", FORGED_CRL);
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
    let output = run_fixture("msi-good-pe64.msi", UNRELATED_ROOT);
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
    let output = run_fixture("msi-good-pe64.msi", MISSING_CRL_POLICY);
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
fn intermediate_without_eku() {
    let output = run_fixture("msi-good-intermediate.msi", TRUSTED_NO_REVOCATION);
    expect_success(&output);
}

#[test]
fn ca_key_usage() {
    let output = run_fixture("msi-bad-ca-key-usage.msi", TRUSTED_NO_REVOCATION);
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
    let output = run_fixture("msi-unsupported-signature-algorithm.msi", INTEGRITY);
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
    let output = run_fixture("msi-unsupported-digest-algorithm.msi", INTEGRITY);
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
fn rfc9457_invalid_arguments() {
    let output = run_fixture("msi-good-pe64.msi", INVALID_TIME);
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
    let output = run_fixture("msi-bad-cms-content-digest.msi", INTEGRITY);
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
    let output = run_fixture("msi-bad-cms-content-type.msi", INTEGRITY);
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
    let output = run_fixture("msi-bad-signer-issuer.msi", INTEGRITY);
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
    let output = run_fixture("msi-bad-signer-serial.msi", INTEGRITY);
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
    let output = run_fixture("msi-bad-cms-digest-set.msi", INTEGRITY);
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
    let output = run_fixture("msi-bad-signature-digest-algorithm.msi", INTEGRITY);
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
    let output = run_fixture("msi-bad-signature-key-algorithm.msi", INTEGRITY);
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
    let output = run_fixture("msi-bad-signer-public-key.msi", INTEGRITY);
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
    let output = run_fixture("msi-bad-countersignature-digest.msi", INTEGRITY);
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
    let output = run_fixture("msi-bad-timestamp-signature.msi", INTEGRITY);
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
    let output = run_fixture("msi-bad-countersignature-signature.msi", INTEGRITY);
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
    let output = run_fixture("msi-bad-nested-signature.msi", INTEGRITY);
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
    let output = run_fixture("msi-bad-certificate-not-yet-valid.msi", TRUSTED);
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
    let output = run_fixture("msi-bad-certificate-expired.msi", TRUSTED);
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
    let output = run_fixture("msi-bad-signer-eku.msi", TRUSTED);
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
    let output = run_fixture("msi-bad-signer-key-usage.msi", TRUSTED);
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
    let output = run_fixture("msi-bad-certificate-signature.msi", TRUSTED);
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
    let output = run_fixture("msi-bad-intermediate-signature.msi", INTERMEDIATE_CRLS);
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
    let output = run_fixture("msi-good-pe64.msi", FUTURE_CRL);
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
    let output = run_fixture("msi-good-intermediate.msi", INTERMEDIATE_CRLS);
    expect_success(&output);
    let report = output.success();
    let signature = &report.signatures[0];
    assert_eq!(report.signatures.len(), 1);
    assert!(signature.chain_trusted);
    assert!(signature.revocation_checked);
    assert_eq!(report.format, "msi_authenticode");
}

#[test]
fn bad_stream_content() {
    let output = run_fixture("msi-bad-stream-content.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "package_digest_mismatch",
        "MSI package digest mismatch",
        Some("package_digest"),
        Some("MSI package digest mismatch"),
    );
}

#[test]
fn bad_legacy_stream() {
    let output = run_fixture("msi-bad-legacy-stream.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "package_digest_mismatch",
        "MSI package digest mismatch",
        Some("package_digest"),
        Some("MSI package digest mismatch"),
    );
}

#[test]
fn bad_legacy_clsid() {
    let output = run_fixture("msi-bad-legacy-clsid.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "package_digest_mismatch",
        "MSI package digest mismatch",
        Some("package_digest"),
        Some("MSI package digest mismatch"),
    );
}

#[test]
fn bad_extended_digest() {
    let output = run_fixture("msi-bad-extended-digest.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "extended_digest_mismatch",
        "MSI extended digest mismatch",
        Some("package_digest"),
        Some("MSI extended digest mismatch"),
    );
}

#[test]
fn bad_extended_size() {
    let output = run_fixture("msi-bad-extended-size.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "extended_digest_mismatch",
        "MSI extended digest mismatch",
        Some("package_digest"),
        Some("MSI extended digest mismatch"),
    );
}

#[test]
fn bad_empty_extended() {
    let output = run_fixture("msi-bad-empty-extended.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "extended_digest_mismatch",
        "MSI extended digest mismatch",
        Some("package_digest"),
        Some("MSI extended digest mismatch"),
    );
}

#[test]
fn bad_metadata_flags() {
    let output = run_fixture("msi-bad-metadata-flags.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "extended_digest_mismatch",
        "MSI extended digest mismatch",
        Some("package_digest"),
        Some("MSI extended digest mismatch"),
    );
}

#[test]
fn bad_metadata_time() {
    let output = run_fixture("msi-bad-metadata-time.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "extended_digest_mismatch",
        "MSI extended digest mismatch",
        Some("package_digest"),
        Some("MSI extended digest mismatch"),
    );
}

#[test]
fn bad_metadata_name() {
    let output = run_fixture("msi-bad-metadata-name.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "extended_digest_mismatch",
        "MSI extended digest mismatch",
        Some("package_digest"),
        Some("MSI extended digest mismatch"),
    );
}

#[test]
fn bad_stream_size() {
    let output = run_fixture("msi-bad-stream-size.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "extended_digest_mismatch",
        "MSI extended digest mismatch",
        Some("package_digest"),
        Some("MSI extended digest mismatch"),
    );
}

#[test]
fn bad_storage_clsid() {
    let output = run_fixture("msi-bad-storage-clsid.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "extended_digest_mismatch",
        "MSI extended digest mismatch",
        Some("package_digest"),
        Some("MSI extended digest mismatch"),
    );
}

#[test]
fn bad_truncated() {
    let output = run_fixture("msi-bad-truncated.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_msi",
        "Invalid MSI container",
        Some("msi"),
        Some("MSI"),
    );
}

#[test]
fn bad_sector_size() {
    let output = run_fixture("msi-bad-sector-size.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_msi",
        "Invalid MSI container",
        Some("msi"),
        Some("MSI"),
    );
}

#[test]
fn bad_directory_cycle() {
    let output = run_fixture("msi-bad-directory-cycle.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_msi",
        "Invalid MSI container",
        Some("msi"),
        Some("MSI"),
    );
}

#[test]
fn bad_stream_chain() {
    let output = run_fixture("msi-bad-stream-chain.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_msi",
        "Invalid MSI container",
        Some("msi"),
        Some("MSI"),
    );
}

#[test]
fn bad_stream_overflow() {
    let output = run_fixture("msi-bad-stream-overflow.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_msi",
        "Invalid MSI container",
        Some("msi"),
        Some("MSI"),
    );
}

#[test]
fn bad_name_length() {
    let output = run_fixture("msi-bad-name-length.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_msi",
        "Invalid MSI container",
        Some("msi"),
        Some("MSI"),
    );
}

#[test]
fn bad_signature_storage() {
    let output = run_fixture("msi-bad-signature-storage.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_msi",
        "Invalid MSI container",
        Some("msi"),
        Some("MSI"),
    );
}

#[test]
fn bad_extended_storage() {
    let output = run_fixture("msi-bad-extended-storage.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_msi",
        "Invalid MSI container",
        Some("msi"),
        Some("MSI"),
    );
}

#[test]
fn bad_nested_signature_stream() {
    let output = run_fixture("msi-bad-nested-signature-stream.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_msi",
        "Invalid MSI container",
        Some("msi"),
        Some("MSI"),
    );
}

#[test]
fn bad_signature_name_case() {
    let output = run_fixture("msi-bad-signature-name-case.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_msi",
        "Invalid MSI container",
        Some("msi"),
        Some("MSI"),
    );
}

#[test]
fn bad_empty_signature() {
    let output = run_fixture("msi-bad-empty-signature.msi", INTEGRITY);
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
fn bad_malformed_cms() {
    let output = run_fixture("msi-bad-malformed-cms.msi", INTEGRITY);
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
fn bad_cms_trailer() {
    let output = run_fixture("msi-bad-cms-trailer.msi", INTEGRITY);
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
fn bad_sip_type() {
    let output = run_fixture("msi-bad-sip-type.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "malformed_cms",
        "Malformed CMS data",
        Some("cms"),
        Some("MSI SIP"),
    );
}

#[test]
fn bad_sip_uuid() {
    let output = run_fixture("msi-bad-sip-uuid.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "malformed_cms",
        "Malformed CMS data",
        Some("cms"),
        Some("MSI SIP"),
    );
}

#[test]
fn bad_sip_version() {
    let output = run_fixture("msi-bad-sip-version.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "malformed_cms",
        "Malformed CMS data",
        Some("cms"),
        Some("MSI SIP"),
    );
}

#[test]
fn bad_sip_reserved() {
    let output = run_fixture("msi-bad-sip-reserved.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "malformed_cms",
        "Malformed CMS data",
        Some("cms"),
        Some("MSI SIP"),
    );
}

#[test]
fn unsigned() {
    let output = run_fixture("msi-unsigned.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "unsigned",
        "Missing embedded signature",
        Some("msi"),
        Some("no embedded MSI signature"),
    );
}

#[test]
fn good_sha1() {
    let output = run_fixture("msi-good-sha1.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "weak_algorithm",
        "Weak algorithm disallowed",
        Some("package_digest"),
        Some("SHA-1"),
    );
}

#[test]
fn good_legacy() {
    let output = run_fixture("msi-good-legacy.msi", TRUSTED);
    expect_success(&output);
    let report = output.success();
    let signature = &report.signatures[0];
    assert_eq!(report.format, "msi_authenticode");
    assert_eq!(report.signatures.len(), 1);
    assert!(signature.chain_trusted);
    assert!(signature.revocation_checked);
    assert_eq!(
        signature.package_digest.as_ref().unwrap().algorithm,
        "Sha256"
    );
}

#[test]
fn good_v4() {
    let output = run_fixture("msi-good-v4.msi", TRUSTED);
    expect_success(&output);
    let report = output.success();
    let signature = &report.signatures[0];
    assert_eq!(report.format, "msi_authenticode");
    assert_eq!(report.signatures.len(), 1);
    assert!(signature.chain_trusted);
    assert!(signature.revocation_checked);
    assert_eq!(
        signature.package_digest.as_ref().unwrap().algorithm,
        "Sha256"
    );
}

#[test]
fn good_sha384() {
    let output = run_fixture("msi-good-sha384.msi", TRUSTED);
    expect_success(&output);
    let report = output.success();
    let signature = &report.signatures[0];
    assert_eq!(report.format, "msi_authenticode");
    assert_eq!(report.signatures.len(), 1);
    assert!(signature.chain_trusted);
    assert!(signature.revocation_checked);
    assert_eq!(
        signature.package_digest.as_ref().unwrap().algorithm,
        "Sha384"
    );
}

#[test]
fn good_sha512() {
    let output = run_fixture("msi-good-sha512.msi", TRUSTED);
    expect_success(&output);
    let report = output.success();
    let signature = &report.signatures[0];
    assert_eq!(report.format, "msi_authenticode");
    assert_eq!(report.signatures.len(), 1);
    assert!(signature.chain_trusted);
    assert!(signature.revocation_checked);
    assert_eq!(
        signature.package_digest.as_ref().unwrap().algorithm,
        "Sha512"
    );
}

#[test]
fn sha1_explicit_opt_in() {
    let output = run_fixture("msi-good-sha1.msi", ALLOW_SHA1_TRUSTED);
    expect_success(&output);
    let report = output.success();
    let signature = &report.signatures[0];
    assert_eq!(report.format, "msi_authenticode");
    assert_eq!(report.signatures.len(), 1);
    assert_eq!(signature.package_digest.as_ref().unwrap().algorithm, "Sha1");
}

#[test]
fn independent_signtool() {
    let output = run_fixture("msi-independent-signtool.msi", ALLOW_SHA1_INTEGRITY);
    expect_failure(
        &output,
        1,
        "weak_algorithm",
        "Weak algorithm disallowed",
        Some("cms"),
        Some("RSA keys shorter than 2048"),
    );
    assert_eq!(
        output.json["results"][0]["error"]["details"]["key_bits"],
        json!(1024)
    );
    assert_eq!(
        output.json["results"][0]["error"]["details"]["minimum_key_bits"],
        json!(2048)
    );
}

#[test]
fn independent_jsign() {
    let output = run_fixture("msi-independent-jsign.msi", INTEGRITY);
    expect_success(&output);
    let report = output.success();
    let signature = &report.signatures[0];
    assert_eq!(report.format, "msi_authenticode");
    assert_eq!(report.signatures.len(), 1);
    assert!(!signature.chain_trusted);
    assert!(!signature.revocation_checked);
    assert_eq!(
        signature.package_digest.as_ref().unwrap().algorithm,
        "Sha256"
    );
    assert_eq!(
        signature.package_digest.as_ref().unwrap().expected,
        "9790a1dbf5efb7c35e96ebd247edfc5533909e11c7e49dd62f38ebc708f14eac"
    );
    assert_eq!(
        signature.package_digest.as_ref().unwrap().computed,
        "9790a1dbf5efb7c35e96ebd247edfc5533909e11c7e49dd62f38ebc708f14eac"
    );
}

#[test]
fn bad_trailing_data() {
    let output = run_fixture("msi-bad-trailing-data.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_msi",
        "Invalid MSI container",
        Some("msi"),
        Some("MSI"),
    );
}

#[test]
fn bad_oversized_extended() {
    let output = run_fixture("msi-bad-oversized-extended.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_msi",
        "Invalid MSI container",
        Some("msi"),
        Some("MSI extended digest stream"),
    );
}

#[test]
fn bad_storage_depth() {
    let output = run_fixture("msi-bad-storage-depth.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_msi",
        "Invalid MSI container",
        Some("msi"),
        Some("MSI storage nesting limit"),
    );
}

#[test]
fn bad_total_stream_size() {
    let output = run_fixture("msi-bad-total-stream-size.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_msi",
        "Invalid MSI container",
        Some("msi"),
        Some("MSI total stream size"),
    );
}

#[test]
fn bad_encoded_signature() {
    let output = run_fixture("msi-bad-encoded-signature.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "invalid_msi",
        "Invalid MSI container",
        Some("msi"),
        Some("MSI signature stream"),
    );
}

#[test]
fn bad_empty_signer_set() {
    let output = run_fixture("msi-bad-empty-signer-set.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "malformed_cms",
        "Malformed CMS data",
        Some("cms"),
        Some("invalid signer count"),
    );
}

#[test]
fn bad_signer_count() {
    let output = run_fixture("msi-bad-signer-count.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "malformed_cms",
        "Malformed CMS data",
        Some("cms"),
        Some("invalid signer count"),
    );
}

#[test]
fn bad_nested_depth() {
    let output = run_fixture("msi-bad-nested-depth.msi", INTEGRITY);
    expect_failure(
        &output,
        1,
        "malformed_cms",
        "Malformed CMS data",
        Some("cms"),
        Some("too many nested signatures"),
    );
}
