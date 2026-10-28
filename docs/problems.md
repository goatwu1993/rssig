# rssig Problem Details

Every failed CLI invocation emits one JSON Problem Details document using the
[RFC 9457](https://www.rfc-editor.org/rfc/rfc9457.html) data model. Each library
`VerificationError` serializes as the same kind of object. Successful commands
(including help and version) retain their existing JSON format.

`type` is the primary machine-readable identifier, `title` is fixed per type,
and `detail` explains this occurrence. Type URIs are absolute and stable:
`https://github.com/goatwu1993/rssig/blob/main/docs/problems.md#<code>`.

The CLI omits optional `status` because it has no HTTP response; exit codes
remain 0 (success), 1 (verification/assertion failure), and 2 (arguments or
configuration failure). It omits optional `instance` because it does not assign
occurrence URIs. A file path alone does not identify a unique occurrence.

An HTTP adapter must send `application/problem+json` and, if it includes
`status`, match the actual HTTP response status. The table below documents
recommended HTTP statuses for adapters; those are never CLI exit codes.

## Extensions and multiple failures

Existing `code`, `stage`, `message`, `details`, and `causes` remain error
extensions. `message` preserves the previous API and equals `detail` for emitted
errors. Prefer `type` (or the typed Rust `ErrorCode`) over parsing prose.
`details` holds structured evidence such as expected/computed digests; `causes`
holds causal diagnostics. Consumers must ignore unknown extension members.

The root document retains `schema_version`, `command`, `ok`, and `results`.
For a command-level failure, `error` contains the full error and the root repeats
its Problem Details members. For `verify`, the first failed input supplies the
root problem; `results` retains successful inputs and every per-file error in
input order. Every nested `error` is itself a Problem Details object.

The former product `test --cases` command has been retired. `invalid_test_suite` and
`test_assertion_failed` remain reserved for deserializing historical reports;
the current CLI exposes verification, help, and version. Tests run through Cargo.

## Problem types

| Code / URI fragment | Title | HTTP status | Meaning and corrective action |
| --- | --- | --- | --- |
| <a id="invalid_appx"></a>`invalid_appx` | Invalid MSIX/AppX package | 422 | Supply a bounded single package with consistent ZIP records, footprint XML, and complete block-map coverage. |
| <a id="unsupported_appx"></a>`unsupported_appx` | Unsupported MSIX/AppX package | 422 | Supply a supported package or embedded-package bundle; nested bundles and unsupported ZIP/compression profiles are rejected. See MSIX/AppX limits. |
| <a id="appx_digest_mismatch"></a>`appx_digest_mismatch` | MSIX/AppX package digest mismatch | 422 | Signed package components differ; inspect `details.component` and digest evidence. |
| <a id="block_hash_mismatch"></a>`block_hash_mismatch` | Block-map hash mismatch | 422 | A payload block differs from its signed block-map hash. |
| <a id="appx_publisher_mismatch"></a>`appx_publisher_mismatch` | Package publisher mismatch | 422 | The manifest Publisher differs from the signing certificate subject. |
| <a id="invalid_rdp"></a>`invalid_rdp` | Invalid RDP file | 422 | Supply supported Unicode RDP text, an unambiguous signature scope, and a valid signature frame. |
| <a id="unsupported_rdp_scope"></a>`unsupported_rdp_scope` | Unsupported RDP signature scope | 422 | A scope entry has no supported key/type mapping; inspect `details.scope`. |
| <a id="invalid_powershell"></a>`invalid_powershell` | Invalid PowerShell script | 422 | Supply supported Unicode text with one complete terminal hash-comment signature block. |
| <a id="script_digest_mismatch"></a>`script_digest_mismatch` | Script digest mismatch | 422 | The computed UTF-16LE script digest differs from its signed digest. Obtain the original signed text, including BOM and line endings, or re-sign it. |
| <a id="invalid_cab"></a>`invalid_cab` | Invalid CAB container | 422 | Supply a complete supported single-volume cabinet; see CAB layout limits. |
| <a id="cab_digest_mismatch"></a>`cab_digest_mismatch` | CAB digest mismatch | 422 | The computed cabinet digest differs from its signed digest. Obtain the original signed cabinet or re-sign it. |
| <a id="invalid_pe"></a>`invalid_pe` | Invalid PE image | 422 | Supply a complete supported PE image. |
| <a id="unsigned"></a>`unsigned` | Missing embedded signature | 422 | Supply a supported PE, MSI, CAB, PowerShell script, or RDP file with an embedded Authenticode signature. |
| <a id="invalid_certificate_table"></a>`invalid_certificate_table` | Invalid certificate table | 422 | Replace the damaged or unsupported certificate table with a valid signed artifact. |
| <a id="malformed_cms"></a>`malformed_cms` | Malformed CMS data | 422 | Supply a well-formed supported CMS signature. |
| <a id="unsupported_algorithm"></a>`unsupported_algorithm` | Unsupported algorithm | 422 | Use a supported digest and signature algorithm. |
| <a id="weak_algorithm"></a>`weak_algorithm` | Weak algorithm disallowed | 422 | Re-sign with SHA-256 or stronger; allow SHA-1 only through the explicit legacy policy. |
| <a id="image_digest_mismatch"></a>`image_digest_mismatch` | PE image digest mismatch | 422 | The computed PE digest differs from the digest covered by the signature. Obtain the original signed image or re-sign the changed image. |
| <a id="page_hash_mismatch"></a>`page_hash_mismatch` | Page hash mismatch | 422 | The image page hashes differ from the signed values. Obtain the original image or re-sign it. |
| <a id="invalid_signature"></a>`invalid_signature` | Invalid signature | 422 | The cryptographic signature is invalid. Obtain a correctly signed artifact. |
| <a id="content_digest_mismatch"></a>`content_digest_mismatch` | Content digest mismatch | 422 | CMS content differs from its signed digest. Obtain an intact signature. |
| <a id="invalid_timestamp"></a>`invalid_timestamp` | Invalid timestamp | 422 | Supply a valid supported timestamp. |
| <a id="timestamp_imprint_mismatch"></a>`timestamp_imprint_mismatch` | Timestamp imprint mismatch | 422 | The timestamp is bound to different signature bytes. Obtain a correctly timestamped signature. |
| <a id="timestamp_in_future"></a>`timestamp_in_future` | Timestamp is in the future | 422 | Check the validation time and timestamp; supply a timestamp no later than validation time. |
| <a id="certificate_expired"></a>`certificate_expired` | Certificate expired | 422 | Supply a certificate valid at the applicable validation time or an acceptable timestamp. |
| <a id="certificate_not_yet_valid"></a>`certificate_not_yet_valid` | Certificate not yet valid | 422 | Check the validation time and certificate validity interval. |
| <a id="untrusted_root"></a>`untrusted_root` | Untrusted root certificate | 422 | Configure an independently trusted root for this certificate chain. |
| <a id="invalid_eku"></a>`invalid_eku` | Invalid extended key usage | 422 | Use a certificate with the required code-signing or timestamping EKU. |
| <a id="invalid_key_usage"></a>`invalid_key_usage` | Invalid key usage | 422 | Use certificates with key usage appropriate to their role. |
| <a id="certificate_revoked"></a>`certificate_revoked` | Certificate revoked | 422 | Replace the revoked signing certificate and obtain a new signature. |
| <a id="crl_expired"></a>`crl_expired` | CRL expired | 422 | Supply a fresh, locally available CRL for the applicable issuer. |
| <a id="crl_not_yet_valid"></a>`crl_not_yet_valid` | CRL not yet valid | 422 | Check the validation time and supply a CRL already valid at that time. |
| <a id="invalid_crl_signature"></a>`invalid_crl_signature` | Invalid CRL signature | 422 | Supply a CRL signed by the correct issuer. |
| <a id="revocation_unknown"></a>`revocation_unknown` | Revocation status unknown | 422 | Supply the required current CRLs for the complete chain. |
| <a id="invalid_crl"></a>`invalid_crl` | Invalid CRL | 422 | Supply a well-formed supported CRL. |
| <a id="invalid_certificate"></a>`invalid_certificate` | Invalid certificate | 422 | Supply a well-formed supported certificate. |
| <a id="certificate_chain_invalid"></a>`certificate_chain_invalid` | Invalid certificate chain | 422 | Supply valid intermediate certificates and a configured trust anchor. |
| <a id="read_failed"></a>`read_failed` | Input read failed | 404 | Check the input path and file access permissions. |
| <a id="invalid_arguments"></a>`invalid_arguments` | Invalid arguments | 400 | Correct the command arguments; consult JSON help output. |
| <a id="configuration"></a>`configuration` | Invalid configuration | 400 | Correct the configured roots, CRLs, or verification policy described in detail. |
| <a id="invalid_test_suite"></a>`invalid_test_suite` | Invalid testcase suite | 400 | Supply an existing, valid testcase suite matching the supported schema. |
| <a id="test_assertion_failed"></a>`test_assertion_failed` | Testcase assertions failed | 422 | Inspect each result and its failures; fix the behavior or incorrect test configuration. |
| <a id="internal_error"></a>`internal_error` | Internal error | 500 | Inspect the diagnostic extensions and report the failure with a reproducing input. |
| <a id="invalid_msi"></a>`invalid_msi` | Invalid MSI container | 422 | Supply a complete, supported CFB container with unambiguous signature streams and valid stream chains. |
| <a id="package_digest_mismatch"></a>`package_digest_mismatch` | MSI package digest mismatch | 422 | The package content/CLSID digest differs from the signed digest. Obtain the original package or re-sign it. |
| <a id="extended_digest_mismatch"></a>`extended_digest_mismatch` | MSI extended digest mismatch | 422 | The extended metadata hash differs from the supplied Ex stream. Obtain the original metadata or re-sign the package. |
