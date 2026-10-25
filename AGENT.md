# rssig

rssig is a Rust CLI and library for verifying embedded Windows PE Authenticode
signatures on **macOS and Linux**. The local `jsign/` and `relic/` clones are
read-only implementation references. Use them to understand formats, hashing,
nested signatures, timestamps, and verification behavior. Do not require either
project at build or runtime.

## Architecture and constraints

- Use pure Rust for PE parsing/hashing, CMS/PKCS#7, signature verification,
  certificate path validation, timestamps, and revocation validation.
- The OS may supply root certificates only. `rustls-native-certs` is the current
  adapter. macOS framework calls are allowed for root enumeration, never for
  signature, chain, timestamp, or revocation verification.
- Do not introduce OpenSSL (system or vendored), ring, aws-lc, WinVerifyTrust,
  native certificate validation, or subprocess crypto tools into the engine.
- RustCrypto implements the cryptographic primitives. webpki path and CRL
  validation uses our RustCrypto algorithm adapter with native crypto features
  disabled. Review the resolved dependency graph when changing dependencies.
- Trust anchors must come from the configured root store. Embedded certificates
  are untrusted chain candidates. A mathematically valid signature alone is not
  a trusted signature.
- Fail closed for malformed/unsupported data and unknown revocation status.
  Any integrity-only or revocation-disabled mode must be explicit and reflected
  in JSON. Unsupported policies must be documented; do not claim Windows policy
  equivalence.
- Every CLI invocation emits exactly one JSON document, including failures,
  help, and version. Keep logs off stdout.
- Public verification results are Serde domain types in `src/domain.rs`.
  Successful bundles include parsed certificate names (CN and all RDNs), EKUs,
  key usage, validity, the selected trust chain, timestamp signer, and supplied
  CRL artifacts. Preserve DER encodings for unfamiliar values. A supplied CRL
  must not be labeled individually verified merely because it was loaded.
- Errors carry a typed stable `code`, verification `stage`, readable `message`,
  structured `details`, and causal diagnostics. Consumers match enum codes,
  never prose. Add JSON cases for domain fields before extending the schema.

## Required TDD workflow

1. Before changing behavior, commit or add the smallest fixture reproducing it
   under `tests/fixtures/`. Pair a good artifact with a narrowly changed bad
   artifact when possible. Never execute PE fixtures.
2. Add a case to `tests/cases.json` describing its unique `id`, fixture `input`,
   CLI `command` argv, and expected exit code and JSON. Pin `--time`, use
   `--no-system-roots` with explicit test roots, and provide local CRLs so tests
   are independent of wall time, network, OS root contents, and machine paths.
3. Run that case through the real CLI and observe the intended **failure**.
   A parser/setup failure is not evidence of the target cryptographic failure.
4. Make the smallest production change that passes the testcase. Preserve all
   existing good and bad expectations; never relax expected failures to hide a
   verifier regression.
5. Run the complete JSON suite and `cargo test --locked`. Add focused unit tests
   for parser bounds and cryptographic invariants where black-box cases cannot
   isolate the issue. Refactor only while the suite stays green.
6. Run `cargo fmt --check` and `cargo clippy --all-targets --locked -- -D warnings`.
   Record any validation that could not run, including missing target platforms.

## JSON testcases and runner

`cargo run --locked -- test --cases tests/cases.json` invokes the same executable
once per testcase. It emits a JSON report with `total`, `passed`, `failed`, and
per-case command, actual exit code, parsed output, and assertion failures.
Exit 0 means all cases pass, 1 means assertion failures, and 2 means invalid
configuration. `cargo test --locked` includes an integration test for this runner.

The suite schema is in `tests/cases.schema.json`. Example case:

```json
{
  "id": "tampered-image",
  "input": "bad-image-digest.exe",
  "command": ["verify", "--integrity-only", "--time", "1800000000"],
  "expect": {
    "exit_code": 1,
    "json": {"ok": false, "results": [{"error": {"code": "image_digest_mismatch"}}]},
    "contains": {"/results/0/error/message": "PE image digest mismatch"}
  }
}
```

`input` is relative to the suite's `fixtures` directory. Argument paths such as
`--roots fixtures/root.der` are relative to the suite file's directory.
Commands are argv arrays passed directly to rssig, never shell strings.
The runner accepts `verify` commands only, preventing recursive suite execution.
`expect.json` matches object subsets, exact array lengths/order, and exact scalar
values. `expect.contains` checks strings at JSON Pointer locations. Every case
also requires valid JSON stdout and empty stderr. Prefer stable fields and
specific error fragments over full OS-dependent error messages.

## Fixtures

Commit binary fixtures and their provenance, SHA-256 digests, and intended
outcomes in `tests/fixtures/manifest.json`. Ordinary tests consume committed
fixtures; they must never regenerate expected data or overwrite fixtures.
Generated fixtures use public, deterministic **test-only** keys and a fixed
validation time. These are synthetic PE containers, not runnable applications.
Do not put real private keys or proprietary binaries in the repository.

The explicit maintenance command is:

```sh
cargo test --locked regenerate_cli_fixtures -- --ignored
```

After intentional regeneration, review all binary changes and update the
manifest. Add independent jsign/relic-produced or publicly redistributable
fixtures with source/version/license information when extending interoperability.
The existing synthetic corpus alone is not evidence of full interoperability.

Windows-oracle integration is deferred. The current development loop runs the
committed fixtures and JSON expectations locally; it requires no Windows
environment or external verifier. Passing these expectations must not be
described as Windows compatibility validation.

## Current boundaries

Embedded PE32/PE32+ signatures, SHA-256/384/512, RSA PKCS#1 v1.5 (2048+ bits),
ECDSA P-256/SHA-256 and P-384/SHA-384, nested signatures, page hashes, RFC 3161,
and PKCS#9 countersignatures are supported. SHA-1 image/CMS/timestamp digests
require `--allow-sha1`; SHA-1 certificate/CRL chains are not supported.

CRLs are supplied as local PEM/DER files, checked for signature, authority,
freshness, and revocation across the chain. Automatic CRL/AIA fetching, OCSP,
catalog signatures, delta/indirect CRLs, RSA-PSS, arbitrary PE section layouts,
Windows-specific trust lists, and Windows policy parity are not implemented.
Revocation of a timestamped signer is handled conservatively: an entry on a
current CRL rejects it even if its revocation date is after the signing time.
