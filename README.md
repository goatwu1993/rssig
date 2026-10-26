# rssig

Verify embedded Windows PE and MSI Authenticode signatures on macOS and Linux with a
Rust CLI. PE/MSI hashing, CMS signatures, certificate chains, timestamps, and CRLs
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

# Run native tests and the JSON specification through the CLI library.
cargo test --locked

# Run the same tests with coverage; write Cobertura XML and openable HTML.
make coverage
```

All output is JSON, including help/version and argument errors. Exit codes are 0 for
success, 1 for a failed verification/assertion, and 2 for invalid configuration
or arguments. `verify` accepts multiple files. `--time UNIX_SECONDS` fixes the
validation time for reproducible tests; otherwise the current time is used.

Successes serialize a verification bundle with image digests, parsed certificate
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
