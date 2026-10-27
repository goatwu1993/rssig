# PowerShell XML Authenticode (.ps1xml)

`rssig verify types.ps1xml` verifies embedded PowerShell Authenticode signatures
whose lines are wrapped in XML comments. Library callers can use
`verify_powershell_xml` to require this format explicitly. No PowerShell host is
started and XML content is never loaded or executed.

This verifies signed text, not XMLDSig. It does not parse an XML tree, apply XML
canonicalization, process entities/DTDs, validate PowerShell type/format schemas,
or establish that the XML is well formed or safe to load.

## Encoding and hashing

The initial encoding policy accepts BOM-less ASCII and Unicode with a UTF-8,
UTF-16LE, or UTF-16BE BOM. Invalid Unicode, NULs, unpaired surrogates, odd UTF-16
byte counts, UTF-32, and non-ASCII text without a BOM are rejected. XML encoding
declarations do not override this policy.

This is deliberately narrower than jsign's BOM-less Windows-1252 fallback for
`.ps1xml`: UTF-8 and Windows-1252 can interpret the same non-ASCII bytes
differently. Requiring a BOM for Unicode avoids guessing. The existing
hash-comment PowerShell API retains its separate BOM-less UTF-8 policy.

The decoded original body is encoded as UTF-16LE for hashing. A BOM contributes
U+FEFF to the digest. Every original body line ending, space, comment, and XML
character remains significant. The inserted CRLF immediately before the
signature block and the block itself are excluded. XML-equivalent edits are not
normalized; they require re-signing if the signed text changes.

## Signature block and detection

Exactly one block must terminate the file:

```text
<original XML text>\r\n
<!-- SIG # Begin signature block -->\r\n
<!-- <base64 CMS, at most 64 characters per line> -->\r\n
<!-- SIG # End signature block -->\r\n
```

Signature marker and payload lines require literal CRLF endings and exact
opening/closing comment delimiters. Base64 uses the same canonical standard
encoding, padding, line-length, and 16 MiB encoded-block limit as hash-comment
PowerShell. The CMS must be one complete DER object without trailing bytes.
Missing/duplicate/mixed-style markers, malformed comments, invalid base64, and
any text after the block fail closed. Marker text inside the body also counts
against the single-block rule; the verifier does not parse XML to disambiguate it.

The CLI recognizes `.ps1xml` case-insensitively, including unsigned or malformed
files, while binary PE/MSI/CAB magic retains precedence. Signed XML-comment
blocks are also detected by bytes, independent of filename. Existing hash-comment
PowerShell markers retain detection priority; ambiguous cross-format inputs
should use the explicit format API. Hash-style blocks in `.ps1xml` files are
rejected. `.psc1`, `.cdxml`, `.mof`, and general XMLDSig are not added by this change.

## CMS, policy, and JSON

The SIP identity is the same as hash-comment PowerShell: `SPC_SIPINFO_OBJID`
`1.3.6.1.4.1.311.2.1.30`, version 65536, UUID
`1FCC3B60-594B-084E-B724-D2C6297EF351`, and five zero reserved integers. Other
identities are rejected. Existing CMS/signature algorithms, nested signatures,
RFC 3161 and PKCS#9 timestamps, code-signing EKU, configured root trust, key usage,
certificate validity, and local CRL policies are reused unchanged. SHA-1 script
or CMS digests require `--allow-sha1`; SHA-1 certificate/CRL chains remain unsupported.

Success returns `format: "powershell_xml_authenticode"` and each signature's
existing `script_digest` (`algorithm`, `expected`, `computed`). Existing parsed
certificate/RDN, EKU, validity, trust-chain, timestamp-signer, and CRL reports
retain their domain types. Image/package/extended digest fields and `rdp` are
omitted; `page_hashes` is null. Explicit integrity-only and revocation-disabled
modes retain the existing JSON fields. No additional public result fields or
error variants are introduced.

Malformed or unsupported text/blocks return `invalid_powershell` at stage
`powershell`; missing blocks return `unsigned` at that stage. Changed signed text
returns `script_digest_mismatch` at stage `script_digest`, with `details.digest`.
Wrong SIP identities or trailing CMS return `malformed_cms` at stage `cms`;
remaining cryptographic, timestamp, trust, and revocation errors retain their
existing stable codes.

## Fixtures and maintenance

Committed fixture pairs isolate XML body changes, line-ending changes, and BOM
removal while preserving the complete valid CMS. Additional cases cover malformed
comment framing, encodings, SHA-1 opt-in, SHA-256/384/512 script digests, nested
signatures, both timestamp forms, trust, revocation, and expiry. Unit tests verify
signature math independently of the changed body and reject truncated prefixes.
Normal tests read committed files only and never regenerate or execute them.

Independent jsign 7.6 artifacts use inert XML text and the existing public,
deterministic RSA-2048 identity exported by `export_msi_test_identity` (certificate
CN `rssig independent MSI test signer`). They verify in explicit integrity-only
mode. ASCII without BOM and BOM-marked UTF-8/UTF-16LE/BE succeed. A signed BOM-less
Windows-1252 artifact is intentionally rejected by the encoding policy, and the
ASCII digest-tampered counterpart changes only `Types` to `TypeS`. Artifact hashes,
provenance, and exact expected cases are pinned in the manifest. These are specific
interoperability checks, not Windows trust-policy validation.

For intentional maintenance, regenerate synthetic fixtures and export the public
test identity with the existing ignored tests:

```sh
cargo test --locked regenerate_cli_fixtures -- --ignored
cargo test --locked export_msi_test_identity -- --ignored
```

The exporter writes test-only `key.pem` and `certificate.pem` under
`std::env::temp_dir()/rssig-msi-test-signing`. Create independent input files in a
temporary directory: ASCII `<Types />\r\n`, or Unicode
`<Types><!-- café 😀 --></Types>\r\n` with the appropriate BOM. The intentionally
unsupported Windows-1252 input is `<Types><!-- café --></Types>\r\n`, encoded without
BOM. Preserve the committed independent filenames, then run jsign 7.6 with a JRE:

```sh
java -jar jsign-7.6.jar --keyfile key.pem --certfile certificate.pem \
  --alg SHA-256 psxml-independent-jsign-*.ps1xml
```

Review/copy the outputs, derive the tampered pair, and update manifest hashes.
Neither jsign nor Java is required for the verifier, builds, or ordinary tests.
No dependencies are added by this feature.

Read-only format references:

- [jsign PowerShellXMLScript and SignableScript, revision cf5d2ce](https://github.com/ebourg/jsign/tree/cf5d2ceaf2ec80cb793f7377749ef811d4be4d34/jsign-core/src/main/java/net/jsign/script)
- [relic PowerShell signature styles, revision 02c54d5](https://github.com/sassoftware/relic/blob/02c54d584ca9eaa8f648763cd53bc77c4ff3d19c/lib/authenticode/powershell.go)
