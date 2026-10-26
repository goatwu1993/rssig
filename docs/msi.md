# MSI verification

`rssig verify` detects CFB containers from their bytes and verifies embedded MSI
Authenticode signatures. `verify` is also the library entry point for detection;
`verify_msi` and the existing `verify_pe` explicitly select a format. MSI
verification parses the compound file, not the Windows Installer database schema.
It does not execute an installer or verify external CABs or embedded applications
as separate signed objects.

## Container hashing

The pure Rust `cfb` parser runs in strict mode for CFB versions 3 and 4. Mini
streams, regular streams, nested storages, and encoded MSI table names are
supported. Children are sorted by their original UTF-16LE name bytes, including
prefix ordering; the decoded display name is not the hash ordering key.

Legacy MSI hashing recursively hashes stream contents and then each storage's
serialized CLSID. The root `\u0005DigitalSignature` and
`\u0005MsiDigitalSignatureEx` streams are excluded from that traversal.
Allocation layout and unused padding are not authenticated as logical content.

If `MsiDigitalSignatureEx` is present, its value must equal a recomputed metadata
hash. Metadata is traversed in preorder: names (without NUL), storage CLSIDs or
32-bit stream lengths, state bits, and non-root creation/modification FILETIMEs.
The root contributes its CLSID and state bits only. The verified metadata digest
prefixes the package-content hash. Empty, truncated, oversized, or incorrect Ex
streams fail; presence never silently downgrades verification to legacy hashing.
Legacy signatures authenticate the legacy content digest without claiming
extended metadata protection.

Signatures must be exact, root-level streams. Storage objects at those names,
case variants, encoded aliases, and nested reserved signature names are rejected
to prevent ambiguous interpretations. Containers must be sector aligned. The
walker allows at most 64 storage levels and 100,000 entries; extended metadata
supports stream lengths up to `u32::MAX`. CMS retains its limits of eight nested
signature levels and 64 reports. MSI SIP versions 1 and 2 with the MSI UUID and
zero reserved fields are supported; unrecognized SIP values fail closed.

The common engine checks CMS content binding and signature math, nested
signatures, RFC 3161/PKCS#9 timestamps, certificate chains, and supplied local
CRLs. PE page hashes remain PE-specific. SHA-1 package digests require explicit
`--allow-sha1`; weak RSA keys remain rejected even with that flag.

## JSON contract

MSI success has `format: "msi_authenticode"`. Each signature includes
`package_digest` and, when present, `extended_digest`, with algorithm, expected,
and computed values. PE successes retain `image_digest`; it is omitted for MSI.
The Rust `SignatureReport.image_digest` field is now optional to represent this
format distinction. Trust and revocation claims use the same explicit policy as
PE verification.

MSI-specific Problem Details codes are `invalid_msi` at stage `msi`, and
`package_digest_mismatch` / `extended_digest_mismatch` at stage `package_digest`.
Shared CMS/trust failures retain their existing codes and stages. All failures
follow [the RFC 9457 contract](problems.md).

## Fixtures and independent references

[The manifest](../tests/fixtures/manifest.json) pins every artifact's SHA-256,
size, provenance, good/bad pairing, declarative case IDs, and Rust test names.
The portable contract remains in `tests/cases.json`; `tests/spec.rs` loads it
with Serde and invokes the CLI library under Cargo tests and `make coverage`. Native Rust CLI tests under `tests/cli/msi.rs` cover
legacy/extended signatures, both CFB versions, SHA-256/384/512, SHA-1 opt-in,
content/metadata/CLSID/extended-digest tampering, invalid signature streams,
malformed containers/SIP/CMS, resource limits, and MSI counterparts of the
existing CMS, timestamp, key, certificate, chain, and revocation failures. A
focused test exercises the entry budget using a committed small container.

Synthetic package hashes come from an independent fixture recipe with an
explicit byte order; ordinary tests never regenerate fixtures. Maintenance uses
`cargo test --locked regenerate_cli_fixtures -- --ignored`.

Two external signing artifacts are committed:

- `msi-independent-jsign.msi`: signed independently by jsign 7.6 with a public,
  deterministic RSA-2048 test key. Integrity verification passes. The optional
  `export_msi_test_identity` ignored test exports that test-only identity to a
  temporary directory for maintenance. jsign and a JRE are required only to
  intentionally recreate this external artifact, never to build or run rssig.
- `msi-independent-signtool.msi`: an unmodified upstream jsign test resource,
  identified there as signtool-signed (exact signtool version is unrecorded).
  Its SHA-1 package digest and sign-padded certificate serial are checked, then
  the CLI rejects its RSA-1024 key. It is not a trusted-success fixture.

Algorithm references are the read-only local clones at these pinned revisions:

- [jsign MSIFile](https://github.com/ebourg/jsign/blob/cf5d2ceaf2ec80cb793f7377749ef811d4be4d34/jsign-core/src/main/java/net/jsign/msi/MSIFile.java)
  and MSIStreamName (Apache-2.0, Emmanuel Bourg).
- [relic msiverify.go](https://github.com/sassoftware/relic/blob/02c54d584ca9eaa8f648763cd53bc77c4ff3d19c/lib/authenticode/msiverify.go)
  (Apache-2.0, SAS Institute Inc.).

These fixtures establish specific interoperability checks, not comprehensive
Windows policy equivalence. The local clones are not build/runtime dependencies.
CI runs `cargo test --locked` on Linux and macOS without Java, Go, external signers,
or network-based certificate/revocation lookup.
