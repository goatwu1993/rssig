# PATH-T010 fix: Report an embedded certificate whose extension does not decode instead of failing the signature

Task detail for **PATH-T010** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox.

Today every embedded certificate is reported, and the report decodes
basicConstraints, keyUsage and extKeyUsage. A certificate whose value for one
of them does not decode cannot be reported, so the signature fails with
`invalid_certificate` at `certificate`, also in integrity-only mode and also
when the path goes around the certificate
(`path-013-bad-ca-malformed-bc-first`).

**Owner decision (PR #97, 2026-11-27): follow OpenSSL.** OpenSSL decodes a
certificate's extensions only when it validates a path
(`crypto/x509/v3_purp.c`, `ossl_x509v3_cache_extensions`, reached from
`x509_vfy.c` and `X509_check_purpose`), not when it parses one
(`crypto/x509/x_x509.c`), and with chain verification off
(`CMS_NO_SIGNER_CERT_VERIFY` in `crypto/cms/cms_smime.c`, `PKCS7_NOVERIFY` in
`crypto/pkcs7/pk7_smime.c`) it checks none. So:

- The report must not fail on an extension that does not decode, for the
  signer too: it marks the extension as undecodable (a new field, with spec
  cases and Rust assertions before the schema changes), and the raw DER stays
  in `extensions[]`.
- [PATH-013](../path.md#path-013-a-path-certificate-whose-extension-does-not-decode-fails-the-path)
  alone judges path certificates, so a trusted verification is unchanged.
- Integrity-only verification of a signer whose basicConstraints, keyUsage or
  extKeyUsage does not decode then verifies, as one with a malformed
  subjectKeyIdentifier already does
  (`path-013-good-integrity-only-leaf-malformed-ski`).
- Cases that change: `path-013-bad-ca-malformed-bc-first` (verifies), and the
  integrity-only results for the `bad-path-{leaf,ca}-malformed-{bc,ku,eku}`
  fixtures that `certificate_paths_fixtures_preserve_image_cms_and_certificate_signatures`
  expects to fail.
