# PowerShell Authenticode verification

`rssig verify script.ps1` verifies hash-comment signature blocks used by `.ps1`,
`.psm1`, and `.psd1` files. Scripts are never executed. CMS, certificates, trust
chains, local CRLs, nested signatures, RFC 3161 timestamps, and PKCS#9
countersignatures use the existing pure Rust verification engine.

## Detection and encoding

The CLI recognizes these three extensions case-insensitively, including unsigned
or malformed scripts. Binary PE/MSI/CAB magic takes precedence over an extension.
Signed scripts are also recognized by their hash-comment signature marker bytes
in UTF-8, UTF-16LE, or UTF-16BE, so a signed script need not have one of those
extensions. A filename alone never establishes signature validity.

Library `verify` detects signed scripts by marker bytes after checking binary
formats. `verify_powershell` explicitly requires a hash-comment PowerShell script
and reports unsigned scripts without depending on filenames.

Supported text encodings are strict UTF-8, with or without a BOM, and UTF-16LE or
UTF-16BE with a BOM. Invalid UTF-8, odd UTF-16 byte counts, unpaired surrogates,
NULs, UTF-16 without a BOM, UTF-32, and legacy code-page encodings are rejected.
There is no lossy decoding or platform-dependent ANSI fallback. BOM-less UTF-8
is an explicit rssig encoding policy; these checks do not establish how every
Windows PowerShell version interprets a script.

## Hashing and block rules

The original decoded script body is encoded as UTF-16LE and hashed, including
U+FEFF if a BOM was present. Original body CRLF/LF line endings are preserved.
The separator CRLF immediately before the signature block and the block itself
are excluded. Converting body line endings or removing a signed BOM changes the
digest. Transcoding between the supported encodings while preserving decoded
text and BOM presence can preserve the script digest; `file_sha256` still hashes
the actual file bytes.

Exactly one signature block must terminate the file:

```text
<original script body>\r\n
# SIG # Begin signature block\r\n
# <base64 CMS, at most 64 characters per line>\r\n
# SIG # End signature block\r\n
```

The `<original script body>` may itself end in CRLF or LF, or be empty. Marker
and payload lines require literal CRLF endings and exact comment prefixes.
Base64 lines must be nonempty and have a length divisible by four, use canonical
standard padded base64 when padding is needed, and contain no additional spaces.
The encoded block is limited to 16 MiB. The decoded CMS must be one complete DER
object without trailing bytes. Duplicate, missing, reversed, or malformed
markers and any data after the final marker are rejected. Even occurrences of
these exact markers inside script strings/comments count toward the single-block
restriction; rssig does not parse PowerShell syntax to disambiguate them.

The signed indirect data must use `SPC_SIPINFO_OBJID`
(`1.3.6.1.4.1.311.2.1.30`), SIP version 65536, PowerShell UUID
`1FCC3B60-594B-084E-B724-D2C6297EF351`, and five zero reserved integers. Other
SIP identities are rejected. Script SHA-256/384/512 digests are supported;
SHA-1 requires `--allow-sha1`. Certificate/CRL SHA-1 remains unsupported.

XML-style PowerShell files (`.ps1xml`, `.psc1`, `.cdxml`), MOF, other script
signature styles, detached signatures, execution-policy enforcement, script
syntax validation, and Windows trust-policy equivalence are outside this scope.

## JSON contract

Success returns `format: "powershell_authenticode"`. Each signature includes
`script_digest` with `algorithm`, `expected`, and `computed`. `image_digest`,
`package_digest`, and `extended_digest` are omitted; `page_hashes` is null.
Existing certificate names/RDNs, EKUs, key usage, validity, selected trust chain,
timestamp signer, and supplied CRL artifacts retain their domain types. Explicit
integrity-only and revocation-disabled modes retain their existing JSON fields.

Malformed or unsupported script text/blocks return `invalid_powershell` at stage
`powershell`; a missing block returns `unsigned` at that stage. Script digest
mismatches return `script_digest_mismatch` at stage `script_digest`, with
`details.digest` containing the expected/computed values. Wrong SIP identities
return `malformed_cms` at stage `cms`. Shared CMS, trust, timestamp, and revocation
errors retain their existing codes.

## Fixtures and maintenance

The portable cases, named Rust CLI tests, and committed fixture manifest cover
all three extensions, supported encodings, Unicode including a supplementary
character, BOM binding, CRLF/LF preservation, empty/no-final-newline bodies,
malformed blocks and text, script and CMS tampering, SIP identity, SHA-1 opt-in,
nested signatures, both timestamp forms, expiry, trust, and revocation.
Parser unit tests cover truncated prefixes, base64 canonicalization, and the
signature-size limit. Cryptographic invariant tests verify that digest-tampered
fixtures retain valid CMS signatures and malformed SIP fixtures are correctly
signed. Existing PE/MSI/CAB expectations are preserved.

Synthetic fixtures use public deterministic test-only keys and comment-only
bodies. The independent artifacts `powershell-independent-jsign.ps1`,
`powershell-independent-jsign-utf16le.ps1`, and
`powershell-independent-jsign-utf16be.ps1` are signed by jsign 7.6 with a public
RSA-2048 test identity. They are tested in explicit integrity-only mode. Their
certificate is named `rssig independent MSI test signer` because the existing
MSI test-identity exporter is reused. The bad independent counterpart changes
only the `t` in `test-only` to `T`, preserving the complete signature block.
These are specific interoperability checks, not general Windows validation.

Normal tests only read the committed artifacts. To intentionally regenerate
synthetic fixtures and export the independent test identity:

```sh
cargo test --locked regenerate_cli_fixtures -- --ignored
cargo test --locked export_msi_test_identity -- --ignored
```

The exporter writes public test-only `key.pem` and `certificate.pem` under
`std::env::temp_dir()/rssig-msi-test-signing`. In a temporary directory, write the
exact source text `# rssig independent jsign test-only\r\n# café 😀\n` in UTF-8
with BOM, UTF-16LE with BOM, and UTF-16BE with BOM to the corresponding independent
fixture filenames. With jsign 7.6 and a JRE, sign those files:

```sh
java -jar jsign-7.6.jar --keyfile key.pem --certfile certificate.pem \
  --alg SHA-256 powershell-independent-jsign*.ps1
```

Review and copy the results into the fixture directory, derive the tampered
counterpart, and update the manifest hashes. Never execute fixtures. Java/jsign
are maintenance tools only, with no build/runtime/test dependency.
`base64ct` is the existing RustCrypto base64 crate, now an explicit dependency;
its resolved version is unchanged. Dependency-feature review confirms webpki
uses only `std`/`alloc`, without native crypto adapters.

Read-only implementation references:

- [jsign PowerShellScript and SignableScript, revision cf5d2ce](https://github.com/ebourg/jsign/tree/cf5d2ceaf2ec80cb793f7377749ef811d4be4d34/jsign-core/src/main/java/net/jsign/script)
- [relic PowerShell Authenticode, revision 02c54d5](https://github.com/sassoftware/relic/blob/02c54d584ca9eaa8f648763cd53bc77c4ff3d19c/lib/authenticode/powershell.go)
