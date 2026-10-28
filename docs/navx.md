# NAVX signatures

`rssig verify extension.navx` detects Microsoft Dynamics extension containers by
`NAVX` magic. `verify_navx` selects this format explicitly for library callers.
Binary magic takes precedence over script extensions.

The supported envelope has a 40-byte header with `NAVX` markers at offsets 0
and 36 and a little-endian u32 content length at offset 28. The digest covers
all 40 header bytes and exactly that many payload bytes. Header fields whose
meaning is unknown remain opaque and are covered by the digest. The payload is
opaque; verification does not unpack or validate the extension's contents.

A signed file appends `NXSB`, one complete DER CMS ContentInfo, the little-endian
u32 offset of that initial `NXSB`, and a closing `NXSB`. Both markers and the
back-pointer must agree with the header's content boundary. Empty/truncated
wrappers, trailing bytes, and CMS padding are rejected. An exact header and
payload without a signature reports `unsigned` at stage `navx`.

The signed indirect data must use SPC_SIPINFO_OBJID (`1.3.6.1.4.1.311.2.1.30`),
version 1, UUID `12341234-F804-0000-781D-123412341234` in its stored octet order,
and five zero reserved integers. Other SIP identities fail as `malformed_cms`.
SHA-256/384/512 are supported; SHA-1 requires `--allow-sha1`. Signature algorithms,
nested signatures, RFC 3161 and PKCS#9 timestamps, certificate trust, and local
CRL checks use the shared verifier and its documented restrictions.

JSON uses `format: "navx_authenticode"`, `package_digest` on each signature,
and no `image_digest`. Malformed envelopes report `invalid_navx` at stage
`navx`. A changed payload or header reports `navx_digest_mismatch` at stage
`package_digest`, including `details.digest` with algorithm, expected, and
computed values. Integrity-only verification explicitly leaves chain trust and
revocation unchecked. Embedded certificates never become trusted roots.

## Fixtures and scope

The committed synthetic fixtures use deterministic public test-only identities
and a fixed validation time. They cover valid and altered payloads, headers,
wrapper offsets/markers, CMS/SIP failures, SHA-1 policy, nested signatures,
timestamps, trust, and revocation. Ordinary tests only read them. Regenerate
intentionally with `cargo test --locked regenerate_cli_fixtures -- --ignored`.

`navx-independent-jsign.navx` is `unsigned.navx` signed independently by jsign
7.6 (Apache-2.0) using the RSA-2048 identity exported by
`cargo test --locked export_msi_test_identity -- --ignored`. The exporter writes
`key.pem` and `certificate.pem` beneath the system temporary directory in
`rssig-msi-test-signing`. Copy `unsigned.navx` to a temporary directory under the
independent fixture name and run:

```sh
java -jar jsign-7.6.jar --keyfile key.pem --certfile certificate.pem \
  --alg SHA-256 navx-independent-jsign.navx
```

The paired bad artifact XORs payload byte 40 with 1 while retaining CMS bytes.
Review all generated artifacts and update the manifest hashes intentionally.
Java and jsign are maintenance tools only; builds, tests, and verification need
neither. These fixtures establish specific format/signature checks, not Windows
policy equivalence or broad real-world Dynamics package compatibility. No
Windows oracle or Microsoft-produced NAVX signature has been validated.

Read-only implementation reference: [jsign NAVX classes at cf5d2ce](https://github.com/ebourg/jsign/tree/cf5d2ceaf2ec80cb793f7377749ef811d4be4d34/jsign-core/src/main/java/net/jsign/navx).
