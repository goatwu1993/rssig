# rssig

rssig is a Rust CLI and library for verifying embedded Windows PE/MSI Authenticode
signatures on **macOS and Linux**. The local `jsign/` and `relic/` clones are
read-only implementation references. Use them to understand formats, hashing,
nested signatures, timestamps, and verification behavior. Do not require either
project at build or runtime.

## Architecture and constraints

- Use pure Rust for PE/MSI parsing/hashing, CMS/PKCS#7, signature verification,
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
  never prose. Add Rust assertions for serialized domain fields before extending the schema.

## Required TDD workflow

1. Before changing behavior, commit or add the smallest fixture reproducing it
   under `tests/fixtures/`. Pair a good artifact with a narrowly changed bad
   artifact when possible. Never execute PE/MSI fixtures.
2. Add a named Rust test under `tests/cli/` for the fixture, CLI argv, exit
   code, and serialized domain result. Invoke the Clap-based `rssig::cli::run`
   directly with an argument array and captured writer; never spawn the binary.
   Pin `--time`, use `--no-system-roots` with explicit test roots, and provide
   local CRLs so tests are independent of wall time, network, OS roots, and paths.
3. Run the focused Cargo test and observe the intended **failure**. A parser or
   setup failure is not evidence of the target cryptographic failure.
4. Make the smallest production change that passes the testcase. Preserve all
   existing good and bad expectations; never relax expected failures to hide a
   verifier regression.
5. Run `cargo test --locked` for the complete suite. Add focused unit tests
   for parser bounds and cryptographic invariants where black-box cases cannot
   isolate the issue. Refactor only while the suite stays green.
6. Run `cargo fmt --check` and `cargo clippy --all-targets --locked -- -D warnings`.
   Record any validation that could not run, including missing target platforms.

## Native Rust tests and coverage

`cargo test --locked` is the single entry point for all parser, crypto, CLI,
fixture, and domain tests. The 142 migrated fixture cases are individually named
Rust tests under `tests/cli/pe.rs` and `tests/cli/msi.rs`; shared helpers only
capture output and assert the domain contract. CLI syntax, configuration errors,
help/version, multiple files, and writer failures live in `tests/cli_interface.rs`.

The public CLI entry point accepts argv including the program name and any
`std::io::Write` sink, returns an exit code, and never exits the calling process.
Tests use absolute fixture paths without changing the process working directory
or invoking a child executable. Prefer stable error codes/stages, exact arrays
and serialized fields, and specific diagnostic fragments over OS error prose.
Do not recreate a JSON case runner or add test commands to the product CLI.

Example fixture-first regression:

```rust
#[test]
fn rejects_modified_image() {
    let input = format!("{}/tests/fixtures/bad-image-digest.exe", env!("CARGO_MANIFEST_DIR"));
    let mut stdout = Vec::new();
    let code = rssig::cli::run(
        ["rssig", "verify", "--integrity-only", "--time", "1800000000", &input],
        &mut stdout,
    ).unwrap();
    let report: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(code, 1);
    assert_eq!(report["results"][0]["error"]["code"], "image_digest_mismatch");
}
```

CI runs formatting, Clippy, and Cargo tests on Linux and macOS. A coverage job
uses cargo-llvm-cov to run the same tests with instrumentation and publishes
Cobertura XML and standalone HTML. See `docs/testing.md` for local commands.
Fixture builders and Rust test source files are excluded from coverage reports;
production source, including the thin process adapter, remains included.

## Fixtures

Commit binary fixtures and their provenance, SHA-256 digests, and intended
outcomes in `tests/fixtures/manifest.json`. Ordinary tests consume committed
fixtures; they must never regenerate expected data or overwrite fixtures.
Generated fixtures use public, deterministic **test-only** keys and a fixed
validation time. Synthetic fixtures are PE/CFB containers, not runnable applications; externally signed artifacts have per-artifact provenance.
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

Embedded PE32/PE32+ and MSI CFB v3/v4 signatures, SHA-256/384/512, RSA PKCS#1 v1.5 (2048+ bits),
ECDSA P-256/SHA-256 and P-384/SHA-384, nested signatures, page hashes, RFC 3161,
and PKCS#9 countersignatures are supported. SHA-1 image/CMS/timestamp digests
require `--allow-sha1`; SHA-1 certificate/CRL chains are not supported.
MSI package/extended metadata hashes and limits are documented in `docs/msi.md`.
`verify` detects formats; `verify_pe` and `verify_msi` select one explicitly.

CRLs are supplied as local PEM/DER files, checked for signature, authority,
freshness, and revocation across the chain. Automatic CRL/AIA fetching, OCSP,
catalog signatures, delta/indirect CRLs, RSA-PSS, arbitrary PE section layouts,
Windows-specific trust lists, and Windows policy parity are not implemented.
Revocation of a timestamped signer is handled conservatively: an entry on a
current CRL rejects it even if its revocation date is after the signing time.
