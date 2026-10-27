# RDP signed-settings verification

`rssig verify connection.rdp` verifies the detached CMS signature in an RDP file.
It parses text, reconstructs the scoped settings, verifies the signature, and
validates certificates and local CRLs entirely in Rust. It never opens an RDP
client or connects to the named host.

## Coverage and JSON

RDP signs selected settings, not all file bytes. Success returns
`format: "rdp_signed_settings"` with a typed `rdp` coverage object:

```json
{
  "full_file_signed": false,
  "signscope": ["Full Address", "Server Port", "RedirectClipboard"],
  "signed_settings": [
    {"name": "full address", "value_type": "s", "value": "example.invalid"},
    {"name": "server port", "value_type": "i", "value": "3389"},
    {"name": "redirectclipboard", "value_type": "i", "value": "0"}
  ],
  "unsigned_settings": [
    {"name": "desktopwidth", "value_type": "i", "value": "1024"}
  ],
  "canonical_sha256": "<SHA-256 of the reconstructed signed content>"
}
```

`signscope` and `signed_settings` follow signed scope order; `unsigned_settings`
follows input order and excludes signature metadata. Values are strings preserving
the signed lexical representation. Types `s`, `i`, and `b` represent string,
signed 32-bit integer, and hexadecimal binary data. Returned values include all
settings supplied in the file; use test-only identities and nonsecret values in
fixtures. `canonical_sha256` is diagnostic, not an independently signed expected
digest. `file_sha256` covers the original bytes but is also diagnostic.

An unsigned setting can change without invalidating the signature. Its new value
remains in `unsigned_settings`; it is never presented as authenticated. Even when
all application settings are scoped, `full_file_signed` remains false because
canonicalization and signature metadata exclude parts of the original file.
Signature verification does not decide whether a connection or its settings are
safe or enforce Windows RDP client policy.

Signatures retain the existing certificate names/RDNs, EKUs, key usage, validity,
selected trust chain, timestamp signer, and CRL domain reports. RDP signatures
omit `image_digest`, `package_digest`, `script_digest`, and `extended_digest`;
`page_hashes` is null. Other formats omit `rdp` entirely. Integrity-only and
revocation-disabled modes remain explicit in the existing JSON fields.

## Parsing and canonical content

The CLI recognizes `.rdp` case-insensitively, including unsigned and malformed
files. Binary magic takes precedence. Library `verify` recognizes signed RDP
metadata in UTF-8 and UTF-16 bytes; PowerShell signature markers retain precedence
so RDP-looking text inside a signed PowerShell comment does not change formats.
Use `verify_rdp` to require RDP explicitly or to classify unsigned files without
a filename. Ambiguous cross-format input should use an explicit format API.

Supported encodings are strict UTF-8 with or without BOM, and UTF-16LE/BE with BOM.
The file BOM is excluded from the signed settings. Invalid encoding, unpaired
surrogates, NULs, BOM-less UTF-16, UTF-32, and legacy code-page input are rejected.
CRLF and LF files are accepted and canonicalized to CRLF; a final newline is
optional. Empty, padded, malformed, or lone-CR lines are rejected. Property keys
must use canonical lowercase ASCII alphanumeric/space names and lowercase types;
duplicate keys, including case variants and signature metadata, are rejected.
Controls in values and invalid integer/binary values are rejected. Files are
limited to 16 MiB and 4,096 total properties, including metadata.

Exactly one string `signscope` and string `signature` property are required for
signed files. Scope names must match the pinned display-name/key/type mapping in
`src/rdp.rs`; unknown names return `unsupported_rdp_scope`, rather than being
omitted from the signature calculation. Every scoped setting must exist once
with the correct type, and scope must include a nonempty `Full Address`. Duplicate
scope names and empty scope are rejected. Unknown unscoped property names are
preserved as unsigned settings when their key/type/value syntax is supported.

Canonical content is constructed by concatenating, in `signscope` order, each
original scoped property line followed by CRLF, then the exact
`signscope:s:<comma-separated names>` line followed by CRLF and one NUL character.
This text is encoded as UTF-16LE without BOM. File property order does not replace
scope order. Values are not trimmed or guessed. Any change to signed settings or
scope must pass the cryptographic check; formatting changes can preserve the
canonical content and therefore the signature.

The canonical standard base64 `signature` value decodes to little-endian DWORDs
`0x00010001`, `1`, and the CMS byte count, followed by exactly that many bytes.
Unknown headers, inconsistent lengths, empty/truncated signatures, trailing
payload, and trailing CMS DER bytes are rejected.

## CMS and trust policy

The RDP entry point requires version-1 detached `id-data` CMS and issuer/serial
SignerInfo identities. It supports signers with authenticated attributes and
legacy direct signatures without them. If signed attributes are present,
contentType, messageDigest, DER ordering, signature parameters, and signed-data
digest membership are checked. Direct signatures verify the canonical settings
bytes themselves. Existing Authenticode and timestamp countersignature entry
points continue requiring authenticated attributes; the new mode is not an
implicit fallback in those paths. Attached Authenticode/CMS content is rejected
as an RDP signature.

Supported RSA PKCS#1 v1.5 and ECDSA algorithms retain the shared engine's limits;
SHA-1 CMS requires `--allow-sha1`. RSA-PSS and SHA-1 certificate/CRL chains remain
unsupported. Up to 64 CMS signers are accepted and all must verify. Nested RDP
signatures are explicitly unsupported. Optional RFC 3161 and PKCS#9 timestamps
use shared binding/EKU/trust checks; this does not claim that `rdpsign.exe`
produces timestamps or that Windows honors these extensions.

For trusted RDP verification, the signer must explicitly contain at least one of
codeSigning (`1.3.6.1.5.5.7.3.3`), serverAuth (`1.3.6.1.5.5.7.3.1`), or Remote
Desktop Authentication (`1.3.6.1.4.1.311.54.1.2`). The verifier tries applicable
purposes in that order, validates the whole selected path for that purpose, and
reports it in `trust.required_eku`. An unrestricted/absent leaf EKU is not accepted
by this policy. Digital-signature key usage, configured roots, certificate times,
and current local CRLs retain their existing checks. Embedded certificates remain
untrusted candidates. Root enumeration is the only OS trust integration.

This is rssig's explicit policy, not Windows equivalence. Windows trusted-publisher
thumbprint lists, Group Policy, RDP hostname/TLS validation, execution/connection
policy, AIA fetching, OCSP, and Windows-specific distrust lists are not implemented.
A CMS signingTime attribute alone never substitutes for a verified timestamp or
extends an expired certificate's validity.

## Errors

`invalid_rdp` at stage `rdp` identifies malformed text, framing, or missing/duplicate
scoped settings. `unsupported_rdp_scope` at that stage includes `details.scope`.
Unsigned files return `unsigned` at stage `rdp`. Malformed, attached, trailing,
or unsupported nested CMS returns `malformed_cms` at stage `cms`.

For direct signatures, changing signed settings or signature bytes returns
`invalid_signature` at stage `cms`: there is no separate signed digest to compare.
With signed attributes, content tampering returns `content_digest_mismatch` and
expected/computed evidence. Certificate, timestamp, algorithm, and revocation
errors retain their existing typed codes and stages.

## Fixtures and provenance

The committed synthetic corpus uses deterministic public test-only keys, fixed
time `1800000000`, explicit roots/CRLs, and reserved `example.invalid` hosts.
Never open any fixture in an RDP client. The builder independently assembles
canonical bytes instead of calling the production RDP parser. Cases cover bare
and attributed CMS, signed/unsigned mutation pairs, framing and text faults,
scope order and identity, supported encodings, SHA-1 opt-in, RSA SHA-256/384/512,
ECDSA SHA-256, both timestamps, trust, EKUs, expiry, and CRLs. Additional unit tests
check bounds, truncated prefixes, signature math, and serialized coverage.

`rdp-independent-nfedera.rdp` was signed by the Apache-2.0
[nfedera/rdpsign reference](https://github.com/nfedera/rdpsign/blob/89cd08646ea5a91988820e319b3c5eef030b0fcf/rdpsign.py),
revision `89cd08646ea5a91988820e319b3c5eef030b0fcf`, with the existing exported public
deterministic RSA-2048 identity named `rssig independent MSI test signer`.
The signer also adds and signs `Alternate Full Address`. This artifact is tested
in integrity-only mode, with one counterpart changing only the first signed host
and another changing only unsigned desktopwidth. Manifest hashes and per-artifact
provenance pin all bytes and outcomes.

The reference tool invokes OpenSSL externally during fixture maintenance only.
No OpenSSL code, tool invocation, or runtime/build dependency is added to rssig.
An independently `rdpsign.exe`-produced redistributable fixture is still missing;
these checks establish only the specified synthetic/reference-tool behavior.

To intentionally recreate fixtures:

```sh
cargo test --locked regenerate_cli_fixtures -- --ignored
cargo test --locked export_msi_test_identity -- --ignored
```

For the independent artifact, obtain the reference tool at the pinned revision,
and create UTF-8 input with these exact lines and CRLF after each:

```text
desktopwidth:i:1024
redirectclipboard:i:0
full address:s:example.invalid
server port:i:3389
```

The existing exporter writes public `key.pem` and `certificate.pem` under
`std::env::temp_dir()/rssig-msi-test-signing`. In a maintenance directory, run:

```sh
python3 rdpsign.py input.rdp output.rdp certificate.pem -k key.pem -e utf-8
```

Review/copy the resulting UTF-16LE artifact, derive the mutation pairs, and update
the manifest. Ordinary Cargo tests consume only committed fixtures; they require
neither the reference tool, Python, OpenSSL, Windows, nor an RDP client.

Other background references:

- [Microsoft rdpsign](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rdpsign)
- [Microsoft RDS certificate documentation](https://learn.microsoft.com/en-us/windows-server/remote/remote-desktop-services/remote-desktop-services-certificates)
