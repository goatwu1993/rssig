# MSI and MSP verification

`rssig verify` detects CFB containers from their bytes and verifies embedded MSI
and MSP Authenticode signatures. `verify` is also the library entry point for detection;
`verify_msi` and the existing `verify_pe` explicitly select a format. MSI
verification parses the compound file, not the Windows Installer database schema.
It does not execute an installer or verify external CABs or embedded applications
as separate signed objects.

## MSP patches

`rssig verify update.msp` verifies the patch package by itself. No original MSI,
installed application, Windows environment, or patch execution is required.
The library's `verify` and `verify_msi` accept the same patch bytes. MSP uses the
existing MSI SIP, CFB traversal, signature streams, and legacy or extended hashing;
there is no separate patch hashing algorithm or CLI option.

The package digest covers transform substorages and embedded cabinet streams as
logical CFB content. It also covers the root patch CLSID and transform storage
CLSIDs. Extended signatures additionally authenticate the metadata described
below. Embedded cabinets are hashed as streams, without extraction or separate
CAB signature verification.

MSP results keep `format: "msi_authenticode"`, `package_digest`, the optional
`extended_digest`, and the existing MSI error codes/stages. This value identifies
the signature family; it does not distinguish an installer from a patch or
assert that either is installable. Detection uses bytes rather than extensions.
The verifier does not validate patch database semantics, target products or
versions, patch applicability or sequencing, UAC patch authorization, or the
result of applying a patch. Trust, timestamps, and revocation follow the existing
verification policy, with no Windows policy equivalence claim.

Microsoft documents the [patch package structure](https://learn.microsoft.com/en-us/windows/win32/msi/patch-packages)
and the distinct [patch and transform storage class IDs](https://devblogs.microsoft.com/setup/identifying-windows-installer-file-types/).

### MSP fixtures

The committed `msp-*.msp` fixtures use the patch root CLSID
`000c1086-0000-0000-c000-000000000046`, two transform substorages with CLSID
`000c1082-0000-0000-c000-000000000046`, an inert summary placeholder, and a
committed unsigned cabinet. They are synthetic CFB containers, not installable
patches. Tests cover legacy/extended hashing, CFB v3/v4, local CRL trust and
revocation, nested signatures, RFC 3161 timestamps, missing signatures, and
isolated transform/cabinet/CLSID/metadata/CMS mutations.

`msp-independent-jsign.msp` is a copy of `msp-unsigned.msp`, independently signed
by Jsign 7.6 with the public deterministic RSA-2048 test identity already used by
the MSI fixture. Jsign produces a legacy SHA-256 signature here, without an
extended digest or timestamp. Its counterpart changes exactly one byte of a
transform stream while preserving the valid CMS signature. This checks shared
SIP/hash interoperability on a synthetic structure, not real patch installability
or Microsoft SignTool/Windows validation. The manifest records hashes, tool
version, license, commands, and expected results.

For intentional maintenance, run the repository fixture regeneration command,
then export the test identity with
`cargo test --locked export_msi_test_identity -- --ignored`. The helper writes
`key.pem` and `certificate.pem` under `std::env::temp_dir()/rssig-msi-test-signing`.
Copy `msp-unsigned.msp` to `msp-independent-jsign.msp` and sign the copy:

```sh
java -jar jsign-7.6.jar --keyfile <temporary-test-key.pem> \
  --certfile <temporary-test-certificate.pem> --alg SHA-256 \
  tests/fixtures/msp-independent-jsign.msp
cargo test --locked regenerate_msp_jsign_mutation -- --ignored
```

Review binary changes and update the manifest after regeneration. Jsign and Java
are maintenance tools only; builds, ordinary tests, and verification use Rust.

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
