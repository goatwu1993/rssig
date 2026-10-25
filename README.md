# rssig

Verify embedded Windows PE Authenticode signatures on macOS and Linux with a
Rust CLI. PE hashing, CMS signatures, certificate chains, timestamps, and CRLs
use pure Rust. The OS supplies root certificates only. OpenSSL is not required.

```sh
cargo build --release --locked

# System roots and explicit current CRLs for every issuer in the chain.
rssig verify application.exe --crl issuer.crl --crl root-issuer.crl

# Explicit test/private roots, with revocation disabled and reported as such.
rssig verify application.exe --no-system-roots --roots roots.pem --no-revocation

# Mathematical signature and image integrity; certificate trust is not claimed.
rssig verify application.exe --integrity-only

# Run all committed JSON cases; stdout is a JSON test report.
cargo run --locked -- test --cases tests/cases.json
cargo test --locked
```

All output is JSON, including help/version and argument errors. Exit codes are 0 for
success, 1 for a failed verification/assertion, and 2 for invalid configuration
or arguments. `verify` accepts multiple files. `--time UNIX_SECONDS` fixes the
validation time for reproducible tests; otherwise the current time is used.

Successes serialize a verification bundle with image digests, parsed certificate
CN/RDNs, EKUs, key usage, validity, trust chain, timestamp signer, and CRL
artifacts. Failures serialize a stable error code, stage, message, details, and
causes. The public Serde types are in `src/domain.rs`. Example failure:

```json
{
  "code": "image_digest_mismatch",
  "stage": "image_digest",
  "message": "PE image digest mismatch (file was modified)",
  "details": {"digest": {"algorithm": "Sha256", "expected": "...", "computed": "..."}},
  "causes": []
}
```

The fixture suite covers good/bad PE signatures, image/page digest tampering,
nested signatures, timestamp binding and EKU, expiry, trust roots, and CRLs.
See [AGENT.md](AGENT.md) for the TDD workflow and
[tests/cases.json](tests/cases.json) for executable test definitions.

This is an initial verifier, not a Windows trust-policy replacement. It requires
embedded certificates and supplied CRLs; automatic CRL/AIA downloads and OCSP
are not implemented. System root sets can differ from Windows publisher roots,
and the native root loader follows its platform's trust settings. Use explicit
roots for controlled publisher policies. See `AGENT.md` for supported algorithms
and additional compatibility limits. Validation has been run on macOS; Linux
execution still needs to be verified in Linux CI.
