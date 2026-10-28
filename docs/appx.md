# MSIX/AppX package and bundle verification

`rssig verify app.msix`, `rssig verify app.appx`, and their `.msixbundle`/`.appxbundle`
counterparts verify the embedded `AppxSignature.p7x` signature and package integrity.
Bundles also verify every embedded application or resource package. The library entry point is
`verify_appx`; generic `verify` recognizes ZIP file-record magic before text
signature markers. The CLI also uses MSIX/AppX extensions to classify malformed
input. A filename alone never establishes authenticity. Files are never extracted,
installed, launched, or passed to an external verifier.

## What is verified

The verifier checks all of the following in pure Rust:

1. Consistent, bounded ZIP file records, central directory, data descriptors,
   compression streams, and CRCs.
2. A `PKCX`-prefixed, complete CMS/PKCS#7 Authenticode signature, with no trailing
   DER bytes, using the matching package or bundle SIP identity.
3. All required signed package digest components:
   - `AXPC`: raw ZIP file records before the final signature record.
   - `AXCD`: the central directory and end records reconstructed without the
     signature entry, with corrected offsets, byte counts, and entry counts.
   - `AXCT`: decompressed `[Content_Types].xml`.
   - `AXBM`: decompressed `AppxBlockMap.xml`.
   - `AXCI`: decompressed `AppxMetadata/CodeIntegrity.cat`, when present.
4. Block-map coverage of every non-footprint payload part, including the manifest,
   with exact names, order, sizes, local-header sizes, 64 KiB block counts, hashes,
   and supported DEFLATE block boundaries.
5. Manifest Publisher binding to every selected signing certificate's complete
   subject DN, followed by the shared code-signing trust, timestamp, and local-CRL
   checks when those checks are configured.

The signed DigestInfo carries `APPX` plus component labels and digest bytes,
not a second hash of that bundle. Component order is `AXPC`, `AXCD`, `AXCT`, `AXBM`,
then optional `AXCI`; unknown, duplicate, or reordered labels are rejected.
The SIP uses `SPC_SIPINFO_OBJID` (`1.3.6.1.4.1.311.2.1.30`), version `0x01010000`,
UUID `4BDFC50A-07CE-E24D-B76E-23C839A09FD1` for packages or
`B3585F0F-DEAA-9A4B-A434-95742D92ECEB` for bundles, and five zero reserved integers.
The SIP kind must match the manifest kind.

SHA-256, SHA-384, and SHA-512 package/block-map digests are supported. The block-map
algorithm must match the signed package DigestInfo algorithm. SHA-1 package/block
hashes remain unsupported even with `--allow-sha1`. CMS signing algorithms retain
the shared RustCrypto limits; a legacy CMS digest still follows the explicit
SHA-1 policy. Nested signatures and RFC 3161/PKCS#9 timestamps use the existing
engine and fail if any selected verification fails.

## ZIP and compression scope

Supported archives are single-volume, nonempty ZIP32 or bounded ZIP64 packages
with contiguous local records in central-directory order, beginning at byte zero.
The signature must be the final local record. ZIP64 end records/locators and
central ZIP64 size/offset extra fields are supported within the same size limits.
Local size fields must be ordinary 32-bit sizes or zero fields accompanied by
matching streaming descriptors; local headers requiring ZIP64 size sentinels are
outside this initial profile. Streaming descriptors support 32-bit and 64-bit
sizes, with or without descriptor signatures.

Stored and raw-DEFLATE methods are supported. Compressed mapped payload blocks
must produce exactly the declared uncompressed block length from their declared
compressed `Size`. Their sizes must exclude the final two-byte stream terminator,
which must end the stream without producing further payload. This supports the
flush-per-block form used by the independent fixtures. Footprint XML/signature
entries can use ordinary complete raw-DEFLATE streams.

The file-size limits are 256 MiB input, 256 MiB total declared uncompressed data,
64 MiB per entry, 8 MiB per XML/optional catalog footprint, 4 MiB for the package
signature, 4,096 entries, and 100,000 nodes per XML document. Decompression must
consume exactly the compressed bytes and emit exactly the declared byte count;
truncation, expansion beyond bounds, trailing compressed streams, and CRC errors
are rejected.

Entry names are canonical ASCII paths, compared case-insensitively for duplicate
detection. Absolute/traversal paths, empty path components, backslashes in ZIP
names, colons, percent-encoded paths, controls, and trailing-dot/space components
are rejected. Block-map directory separators use backslashes and must map exactly
to the ZIP names. Unicode entry names, alternate Unicode name extra fields,
directory entries, symlinks, encryption, unsupported compression/flags/versions,
archive/entry comments, split archives, gaps/overlaps, and appended data are
outside the supported profile. Unknown extra fields are bounded and preserved as
signed raw metadata; fields do not provide an alternative filename view.

Encrypted packages are not supported.

## Bundles

Supported bundles contain stored (uncompressed) `.appx` or `.msix` package entries
and `AppxMetadata/AppxBundleManifest.xml`. The bundle manifest uses the 2013 bundle
namespace and the core Identity/Packages layout of schema versions 1.0 through 5.0.
It must contain exactly one Identity and one nonempty Packages list. Every listed
package must exist exactly once with the declared ZIP data offset and byte size;
unlisted payload parts and duplicate filenames are rejected. ZIP CRCs are checked
for embedded packages as well as the footprint files.

The outer block map covers the bundle manifest and omits embedded package entries.
Those bytes are authenticated by the outer `AXPC` digest and by each package's own
signature, component digests, and complete block map. Every embedded package must
have a supported signature; unsigned packages fail even when the outer bundle is
signed. A bundle cannot contain another bundle.

Each package's Name must match the bundle Name. Its Version, effective architecture
(defaulting to neutral), ResourceId, and ResourcePackage flag must match its package
entry. The primary signing certificate must be identical to the bundle's primary
signing certificate. Every selected package signature and timestamp is verified
with the same configured trust roots, CRLs, time, and algorithm policy as the bundle.
Bundle Version may differ from the per-package versions.

Resources qualifiers and base/2018 TargetDeviceFamily dependency metadata are
authenticated and parsed as bounded XML. Deployment selection, capability policy,
device applicability, and installability are not evaluated. Unknown manifest
elements/attributes, flat or external package references, optional bundles, stub
packages, compressed package entries, and nested bundles are outside this profile.
The existing ZIP limits apply to both levels: each embedded package is at most
64 MiB, and the entire bundle is at most 256 MiB.

## XML, identity, and catalogs

Package XML is decoded as UTF-8 (a UTF-8 BOM is accepted); encoding declarations
do not select another decoder. DTDs are disabled, no external entities/resources
are fetched, and XML namespace identity is checked. Block-map files/blocks and
content-type entries reject unsupported elements/attributes and duplicate entries.
Content types must cover payload/footprint parts, with the expected manifest,
block-map, signature, and optional catalog MIME types.

Manifest root namespaces supported here are the Windows 10 foundation namespace
and the 2010 AppX manifest namespace. Exactly one direct `Identity` is selected.
The report includes Name, Publisher, four-component Version, optional supported
ProcessorArchitecture, and optional ResourceId. Manifest application/capability semantics and installability
are not validated.

Publisher DNs use the Rust X.509 parser's RFC 4514 spelling. RDN sequence, all
attribute OIDs, and decoded string values must match the signer, while recognized
ASN.1 string encodings and ordering within an RDN set are normalized. Unfamiliar
values retain their DER-based comparison. This is deliberately strict: Windows
`S=` aliases, alternative DN orderings/case/spacing conventions, and arbitrary
Windows name-comparison policy are not inferred. Code-signing EKU, configured roots,
key usage, certificate times, verified timestamps, and revocation remain required
under the existing selected policy. Embedded certificates are untrusted candidates.

An optional CodeIntegrity catalog is authenticated as package content through
`AXPC`/`AXCI`, but its own catalog signature, membership, and Windows code-integrity
policy are not independently verified. Its report explicitly sets
`signature_verified: false`. This feature does not implement standalone/detached
catalog verification, automatic catalog discovery, Windows publisher policy,
Microsoft Store acceptance, installation checks, OCSP, or Windows policy parity.

## JSON and errors

Success returns `format: "appx_authenticode"`. Every signature includes the existing
`package_digest` with the algorithm and expected/computed component-bundle hex.
Certificate names/RDNs, EKUs, key usage, validity, selected chain, timestamps, and
supplied CRL artifacts retain their existing domain types and trust-mode fields.
Image/script/extended digests and `rdp` are omitted; `page_hashes` is null.

The optional `appx` domain object contains:

- `kind`: `package` or `bundle`.
- `identity`: `name`, `publisher`, `version`, `processor_architecture`, and optional `resource_id`.
- `block_map`: `algorithm`, `files_verified`, `blocks_verified`,
  `uncompressed_bytes`.
- `components`: ordered entries with `component` and `digest` (algorithm,
  expected/computed hex). All reported digests match on success.
- Optional `code_integrity_catalog`: `sha256` and `signature_verified: false`.
- For bundles, `bundle_packages`: entries in manifest order, each with `file_name`,
  `package_type`, `architecture`, optional `resource_id`, `version`, `offset`, `size`,
  and `verification`. Each `verification` is a complete package verification bundle,
  including its own signature/certificate/trust/timestamp and AppX reports. It uses
  `kind: "package"` and omits `bundle_packages`.

When deserializing older single-package reports, a missing `kind` defaults to
`package`. New verification output always includes it.

Other formats omit `appx` entirely. The JSON remains one document per invocation.

New stable error codes are:

| Code | Stage | Meaning |
| --- | --- | --- |
| `invalid_appx` | `appx` or `block_map` | Malformed ZIP/footprint metadata, missing parts, bad framing, or structural block-map mismatch. |
| `unsupported_appx` | `appx` | Nested bundle or unsupported ZIP/package profile. |
| `appx_digest_mismatch` | `package_digest` | Signed package components differ; `details.component` identifies the differing component where possible, and `details.digest` preserves expected/computed evidence. |
| `block_hash_mismatch` | `block_map` | Payload differs from a signed block hash; details include file, zero-based block index, and digest evidence. |
| `appx_publisher_mismatch` | `appx` | Manifest Publisher differs from the signing certificate subject. |

Missing embedded signatures return `unsigned` at `appx`. Unsupported algorithms,
CMS/SIP, timestamps, certificates, and revocation retain shared typed errors.

## Fixtures and validation limits

The committed synthetic fixtures are small, inert ZIP containers containing test
text and a synthetic manifest; they are not installable applications. Never install
or execute them. A separate multi-block fixture exercises 64 KiB boundaries.
Deterministic public test-only keys, fixed time `1800000000`, configured test roots,
and local CRLs make ordinary tests independent of OS roots, network, and wall time.
The builder independently constructs ZIP records, block maps, and signature digest
bundles without calling the production hasher. Dedicated invariant tests prove
that payload-tampered packages retain valid original CMS signatures and that
invalid signed block maps/publishers have valid package digests and signature math.

`appx-independent-jsign.msix` is `appx-jsign-input.msix` independently signed by
jsign 7.6 with the public deterministic RSA-2048 test identity exported by the
existing `export_msi_test_identity` helper. Its manifest publisher is the identity's
CN `rssig independent MSI test signer`. The bad counterpart changes one stored
payload byte while preserving its complete original signature.

`appx-independent-signtool.msix` is an unmodified upstream jsign test resource,
`minimal-signed-by-signtool.msix`, from pinned revision
`cf5d2ceaf2ec80cb793f7377749ef811d4be4d34`, under the upstream Apache-2.0 license.
The exact signtool version is not recorded. Manifest creation metadata mentions
MSIX Packaging Tool 1.2023.319.0, which is not a signtool-version claim. Its ZIP64
streaming DEFLATE structure, signed package components, all five payload blocks,
CMS signature, and publisher binding are verified in explicit integrity-only mode.
This is a specific independent-artifact check, not a Windows oracle or general
interoperability/trust-policy validation. Per-artifact provenance and SHA-256 hashes
are committed in the fixture manifest.

Bundle fixtures cover multiple embedded packages, resource packages, ZIP64,
streaming descriptors, SHA-256/384/512, RFC 3161 and PKCS#9 timestamps, manifest
binding, inner signature/digest/timestamp faults, ZIP CRCs, and unlisted payloads.
Invariant tests confirm that targeted inner-package and manifest faults retain
valid outer CMS signatures and package digests.

`appxbundle-independent-jsign.msixbundle` contains the committed
`appx-independent-jsign.msix`, is assembled by the independent test ZIP recipe,
and is signed externally by jsign 7.6 with the same public test identity. Both
outer and inner signatures are verified. This is a synthetic container signed by
an independent signer, not a MakeAppx- or Windows-produced bundle. Its bad pair
changes byte 90 while preserving the complete original outer signature.

Normal tests consume committed artifacts only. To intentionally regenerate the
synthetic corpus and export public test credentials:

```sh
cargo test --locked regenerate_cli_fixtures -- --ignored
cargo test --locked export_msi_test_identity -- --ignored
```

Copy `appx-jsign-input.msix` to `appx-independent-jsign.msix` in a maintenance
directory. The exporter writes `key.pem` and `certificate.pem` under
`std::env::temp_dir()/rssig-msi-test-signing`. Sign with a JRE and jsign 7.6:

```sh
java -jar jsign-7.6.jar --keyfile key.pem --certfile certificate.pem \
  --alg SHA-256 appx-independent-jsign.msix
```

Review/copy the result, derive the payload mutation, and update manifest hashes.
For the independent bundle, copy `appxbundle-jsign-input.msixbundle` to
`appxbundle-independent-jsign.msixbundle` and sign it with the same command and
credentials. Its embedded package is already independently signed. The maintenance
generator consumes that committed package; normal tests only read committed files.
External signing tools are never required for normal builds, verification, or
Cargo tests. The new runtime dependencies are pure Rust `flate2` with only the
`rust_backend` (miniz_oxide), `crc32fast`, and `roxmltree`. Resolved-feature review
confirms no zlib/native compression or forbidden crypto backends; webpki retains
only its existing `std`/`alloc` features and RustCrypto adapter.

Read-only implementation references:

- [Microsoft bundle Package schema](https://learn.microsoft.com/en-us/uwp/schemas/bundlemanifestschema/element-package)
- [Microsoft bundle signing](https://learn.microsoft.com/en-us/windows/msix/package/sign-app-package-using-signtool)
- [jsign APPXFile and ZIP records, revision cf5d2ce](https://github.com/ebourg/jsign/tree/cf5d2ceaf2ec80cb793f7377749ef811d4be4d34/jsign-core/src/main/java/net/jsign)
- [relic signappx and ZIP normalization, revision 02c54d5](https://github.com/sassoftware/relic/tree/02c54d584ca9eaa8f648763cd53bc77c4ff3d19c/lib/signappx)
