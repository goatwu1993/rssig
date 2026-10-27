# CAB Authenticode verification

`rssig verify archive.cab` detects CAB files by their `MSCF` magic, independent
of filename. Library callers may use `verify_cab` to require CAB explicitly.
The verifier parses and hashes cabinet bytes in Rust and shares the PE/MSI CMS,
certificate-chain, nested-signature, timestamp, and local-CRL verification engine.
It never extracts, decompresses, or executes cabinet contents.

## Supported layout

The initial implementation accepts CAB version 1.3 with one volume, cabinet
index zero, nonempty folder/file tables, and the standard 20-byte cabinet reserve:
empty structure1, a 16-byte structure2 pointing to an appended CMS signature,
and zero unused fields. Per-folder and per-data reserves must be empty. Folder
data must follow the file table contiguously, with bounded, complete data blocks.
File ranges must fit their folders' declared uncompressed lengths. Compression
payloads are opaque signed bytes; verifying a signature does not validate their
decompression or the contained applications' signatures. Data checksums are not
recomputed. Reserved cabinet-header fields must be zero.

Multipart/split cabinets, empty cabinets, additional reserve data, inline CMS
in the header reserve, noncontiguous folder layouts, and unknown versions or
flags are rejected. The signature must start at `cbCabinet` and its declared
length must cover exactly the remaining file. At most seven zero padding bytes
may follow the CMS DER object. Appended unsigned data is rejected.

For this layout, the digest covers the magic, header bytes 8 through 33,
four zero bytes (cabinet index and empty structure1 length), and all bytes from
the folder table at offset 60 through `cbCabinet`. It excludes the header
checksum and signature reserve metadata. The indirect-data type must be
`SPC_CAB_DATA_OBJID` (`1.3.6.1.4.1.311.2.1.25`); PE/MSI signatures cannot be
substituted. SHA-256/384/512 are supported; SHA-1 requires `--allow-sha1`.
CMS signing algorithms and trust policies retain the shared engine's limits.

## JSON contract

Success returns `format: "cab_authenticode"`. Each signature has a
`package_digest` with `algorithm`, `expected`, and `computed`; `image_digest`
and `extended_digest` are omitted, and `page_hashes` is null. Certificate names,
EKUs, key usage, validity, trust chain, timestamp signer, and supplied CRL artifacts
use the existing domain types. Integrity-only and revocation-disabled modes are
explicitly reflected in the existing trust/revocation fields.

Malformed/unsupported CAB containers return `invalid_cab` at stage `cab`;
missing signatures return `unsigned` at stage `cab`. Digest mismatches return
`cab_digest_mismatch` at stage `package_digest`, with a `details.digest` report.
CMS, certificate, timestamp, and revocation errors retain their existing codes.

## Fixtures and provenance

Committed fixtures include a valid synthetic cabinet containing the inert text
`test`, a counterpart with only payload byte 96 changed, malformed container and
CMS cases, SHA-1/256/384/512 digests, nested signatures, and both timestamp forms.
The synthetic fixture builder assembles the digest input independently of the
production hasher. Named Rust tests also verify that tampered-payload fixtures
retain mathematically valid CMS signatures and that the bad CMS-signature fixture
retains a correct cabinet digest. Ordinary tests only read committed artifacts.

`cab-independent-jsign.cab` is the synthetic `unsigned.cab` container signed by
jsign 7.6 using the public deterministic RSA-2048 test identity already used for
MSI interoperability fixtures. Its certificate is named `rssig independent MSI
test signer`. It is tested in explicit integrity-only mode; it is not a trusted
publisher fixture. `bad-cab-independent-digest.cab` changes only payload byte 96.
The artifact hashes, provenance, and expected cases are in the fixture manifest.
These checks do not establish general interoperability or Windows policy parity.

To intentionally recreate the independent signature, first regenerate the
synthetic fixtures and export the public test identity:

```sh
cargo test --locked regenerate_cli_fixtures -- --ignored
cargo test --locked export_msi_test_identity -- --ignored
```

Copy `tests/fixtures/unsigned.cab` to `cab-independent-jsign.cab` in a temporary
directory. The exporter writes `key.pem` and `certificate.pem` to
`std::env::temp_dir()/rssig-msi-test-signing`. With a JRE and jsign 7.6, run:

```sh
java -jar jsign-7.6.jar --keyfile key.pem --certfile certificate.pem \
  --alg SHA-256 cab-independent-jsign.cab
```

Review the resulting artifact, replace the committed independent fixture, derive
its bad counterpart by XORing byte 96 with 1, and update the manifest. Neither
Java nor jsign is required by normal builds, verification, or tests. All signing
keys involved are public test material; never use them outside tests.

Implementation references (read-only local clones):

- [jsign CFHeader and MSCabinetFile, revision cf5d2ce](https://github.com/ebourg/jsign/tree/cf5d2ceaf2ec80cb793f7377749ef811d4be4d34/jsign-core/src/main/java/net/jsign/mscab)
- [relic cabfile, revision 02c54d5](https://github.com/sassoftware/relic/tree/02c54d584ca9eaa8f648763cd53bc77c4ff3d19c/lib/cabfile)
