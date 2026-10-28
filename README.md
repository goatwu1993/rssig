# rssig

Verify Windows PE, MSI, CAB, NAVX, PowerShell, Windows Script Host, and MSIX/AppX Authenticode signatures and signed RDP
settings on macOS and Linux with a Rust CLI. PE/MSI/CAB/NAVX/PowerShell/WSH/MSIX hashing, CMS signatures, certificate chains, timestamps, and CRLs
use pure Rust. The OS supplies root certificates only. OpenSSL is not required.

This project is **vibe coded** with AI assistance and developed through local
fixtures, a portable JSON specification, and native Rust tests. It is inspired by
[jsign](https://github.com/ebourg/jsign) and
[relic](https://github.com/sassoftware/relic), whose source code serves as a
reference for PE/MSI Authenticode hashing, signatures, and verification behavior.
[osslsigncode](https://github.com/mtrojnar/osslsigncode) and
[rcodesign](https://github.com/indygreg/apple-platform-rs/tree/main/apple-codesign)
also inform the project's design discussions. These projects are not runtime
dependencies, and this attribution does not imply their endorsement or verified
compatibility.

## Windows file formats

This checklist tracks Windows Authenticode files and related signed settings in
the project's scope; it is not an inventory of every Windows file extension.
Formats marked ✅ are implemented. When a format is added, its row moves to the
supported list with a green check.

### Supported

| Status | Format | Extensions | Coverage |
| --- | --- | --- | --- |
| ✅ | PE images | `.exe`, `.dll`, `.sys`, and other PE32/PE32+ files | Embedded Authenticode signatures, image/page hashes, nested signatures, timestamps, trust, and CRLs. |
| ✅ | Windows Installer package | `.msi` | CFB v3/v4 package signatures and package/extended metadata hashes. See [MSI support](docs/msi.md). |
| ✅ | Dynamics extension | `.navx` | Embedded NAVX Authenticode signatures. See [NAVX support](docs/navx.md). |
| ✅ | Cabinet archive | `.cab` | Standard-reserve single-volume CAB signatures. See [CAB support](docs/cab.md). |
| ✅ | PowerShell scripts and data | `.ps1`, `.psm1`, `.psd1` | Hash-comment Authenticode signatures. See [PowerShell support](docs/powershell.md). |
| ✅ | PowerShell XML | `.ps1xml` | XML-comment Authenticode signatures (not XMLDSig). See [PowerShell XML support](docs/powershell-xml.md). |
| ✅ | Windows Script Host scripts | `.vbs`, `.vbe`, `.js`, `.jse`, `.wsf` | VBScript/JScript comment blocks and single-job WSF signatures; encoded scripts are hashed as stored. See [WSH support and encoding limits](docs/wsh.md). |
| ✅ | Remote Desktop settings | `.rdp` | Detached CMS signatures over the supported scoped settings. See [RDP support](docs/rdp.md). |
| ✅ | Single AppX/MSIX packages | `.appx`, `.msix` | Embedded package signature, package digests, block map, and Publisher binding. See [AppX/MSIX support](docs/appx.md). |
| ✅ | AppX/MSIX bundles | `.appxbundle`, `.msixbundle` | Bundle signature and manifest, plus every embedded application's or resource package's signature, identity, digests, timestamps, trust, and CRLs. See [bundle limits](docs/appx.md#bundles). |

### Not implemented

| Format | Extensions | Notes |
| --- | --- | --- |
| Catalog files | `.cat` | Standalone catalog signature and catalog membership verification. |
| Windows Installer patches | `.msp` | Patch signatures and patch-specific hashing. |
| Detached Authenticode sidecars | `.sig`, `.p7s` with the signed file | Generic detached signature inputs beyond the RDP-specific verifier. |

`Report.wer` files are Windows Error Reporting metadata, not a separate
Authenticode file format, so they are not on this verification checklist.

```sh
cargo build --release --locked

# System roots and explicit current CRLs for every issuer in the chain.
rssig verify application.exe --crl issuer.crl --crl root-issuer.crl

# Explicit test/private roots, with revocation disabled and reported as such.
rssig verify application.exe --no-system-roots --roots roots.pem --no-revocation

# Mathematical signature and image integrity; certificate trust is not claimed.
rssig verify application.exe --integrity-only

# MSI packages use the same trust and revocation policy.
rssig verify installer.msi --no-system-roots --roots roots.pem --crl issuer.crl

# CAB archives use the same trust, timestamp, and revocation policy.
rssig verify archive.cab --no-system-roots --roots roots.pem --crl issuer.crl

# PowerShell scripts/modules/data files share the same trust policy.
rssig verify script.ps1 module.psm1 data.psd1 --no-system-roots --roots roots.pem --crl issuer.crl

# PowerShell XML uses XML-comment signature blocks.
rssig verify types.ps1xml --no-system-roots --roots roots.pem --crl issuer.crl

# RDP signatures cover selected settings; JSON distinguishes unsigned settings.
rssig verify connection.rdp --no-system-roots --roots roots.pem --crl issuer.crl

# Single MSIX/AppX packages include package, block-map, and publisher checks.
rssig verify app.msix --no-system-roots --roots roots.pem --crl issuer.crl

# Bundles also verify every embedded application and resource package.
rssig verify app.msixbundle --no-system-roots --roots roots.pem --crl issuer.crl

# Run native tests and the JSON specification through the CLI library.
cargo test --locked

# Run the same tests with coverage; write Cobertura XML and openable HTML.
make coverage
```

All output is JSON, including help/version and argument errors. Exit codes are 0 for
success, 1 for a failed verification/assertion, and 2 for invalid configuration
or arguments. `verify` accepts multiple files. `--time UNIX_SECONDS` fixes the
validation time for reproducible tests; otherwise the current time is used.

Successes serialize a verification bundle with image/package/script digests, parsed certificate
CN/RDNs, EKUs, key usage, validity, trust chain, timestamp signer, and CRL
artifacts. Every failed invocation and nested error uses the RFC 9457 Problem
Details data model: `type`, `title`, and `detail`, with existing error codes,
stages, messages, structured details, and causes retained as extensions. CLI
output omits HTTP `status`; process exit codes keep their existing meaning.
See [the error contract and problem type registry](docs/problems.md). The public
Serde types are in `src/domain.rs`. Example error object:

```json
{
  "type": "https://github.com/goatwu1993/rssig/blob/main/docs/problems.md#image_digest_mismatch",
  "title": "PE image digest mismatch",
  "detail": "PE image digest mismatch (file was modified)",
  "code": "image_digest_mismatch",
  "stage": "image_digest",
  "message": "PE image digest mismatch (file was modified)",
  "details": {"digest": {"algorithm": "Sha256", "expected": "...", "computed": "..."}},
  "causes": []
}
```

The fixture suite covers good/bad PE and MSI signatures, image/page digest tampering,
nested signatures, timestamp binding and EKU, expiry, trust roots, and CRLs.
See [the negative fixture coverage](docs/mismatch-fixtures.md) for isolated
CMS, timestamp, certificate, and algorithm mismatch cases.
See [MSI support and fixture provenance](docs/msi.md) for container hashing,
extended metadata, format-specific JSON fields, and limits.
See [AGENTS.md](AGENTS.md) for the TDD workflow and
[tests/cases.json](tests/cases.json) for the portable CLI specification and
[tests/cli](tests/cli) for individually named Rust regressions.
See [CAB support and fixture provenance](docs/cab.md) for supported layouts,
hashing, and CAB JSON fields.
See [PowerShell support and fixture provenance](docs/powershell.md) for encodings,
text hashing, signature-block limits, and script JSON fields.
See [PowerShell XML support](docs/powershell-xml.md) for `.ps1xml` signature blocks
and its BOM-less ASCII / BOM-marked Unicode encoding policy.
See [RDP support and fixture provenance](docs/rdp.md) for signed-setting coverage,
canonicalization, and trust-policy limits.
See [MSIX/AppX support and provenance](docs/appx.md) for ZIP limits, block maps,
manifest publisher binding, and optional embedded catalog reporting.
See [testing and coverage](docs/testing.md) for the testable Clap interface,
Cobertura XML, and HTML reports.

This is an initial verifier, not a Windows trust-policy replacement. It requires
embedded certificates and supplied CRLs; automatic CRL/AIA downloads and OCSP
are not implemented. System root sets can differ from Windows publisher roots,
and the native root loader follows its platform's trust settings. Use explicit
roots for controlled publisher policies. See `AGENTS.md` for supported algorithms
and additional compatibility limits. GitHub Actions runs formatting, Clippy,
and Rust tests on Linux and macOS. A coverage job publishes Cobertura XML and
openable HTML reports. External signing tools are not required for CI.
