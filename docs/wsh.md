# Windows Script Host Authenticode

`rssig verify file.vbs file.vbe file.js file.jse file.wsf` verifies embedded WSH
Authenticode signatures using the shared Rust CMS, trust, timestamp, and CRL
engine. No script host or Script Encoder decoder is invoked. Library callers can
use `verify_wsh` to detect the comment style, or `verify` for format detection.
The CLI recognizes these extensions case-insensitively and requires the matching
signature style. Binary PE/MSI/CAB/ZIP magic takes precedence over extensions.
Signed blocks are detected from bytes even under another extension.

## Text and digest

VBScript (`.vbs`/`.vbe`) and JScript (`.js`/`.jse`) accept BOM-less ASCII or
BOM-marked UTF-8/UTF-16LE/UTF-16BE. WSF accepts strict BOM-less UTF-8 and the same
BOM-marked encodings. Invalid Unicode, NUL, odd UTF-16 length, unpaired surrogates,
and UTF-32 fail closed. BOM-less Windows-1252 and other locale-dependent encodings
are unsupported. XML declarations do not select alternate encodings.

The initial BOM is excluded. Hash input is the original unsigned text encoded as
UTF-16LE, followed by the four-byte little-endian signature insertion position,
measured in UTF-16 code units. Line endings, whitespace, and every unsigned WSF
suffix byte after decoding remain significant. No XML canonicalization or Unicode
normalization is performed. The inserted CRLF and signature block are excluded.
VBScript/JScript insert at the end; WSF inserts immediately before `</job>`.

Encoded `.vbe` and `.jse` content is hashed as stored, using the VBScript/JScript
SIP respectively. Verification does not decode, validate, or certify the runtime
behavior of Script Encoder payloads. Current encoded fixtures contain synthetic
empty Script Encoder-shaped text; they test stored-text signature interoperability,
not encoded program execution or Windows host compatibility.

## Strict block profile

VBScript uses `'' SIG '' Begin signature block`, payload prefix `'' SIG '' `,
and `'' SIG '' End signature block`. JScript uses the corresponding `// SIG // `
markers and payload prefix. Exactly one block must terminate the file, including
the final CRLF. WSF uses `<signature>`, payload prefix `** SIG ** `, and
`</signature>`, immediately followed by `</job>` after the final CRLF.

All styles require a preceding CRLF, literal CRLF marker/payload lines, canonical
standard base64 with padding, and payload lines of 4–64 characters in multiples
of four. Missing, duplicate, mixed, or mismatched markers fail closed, including
marker-like text embedded in the unsigned body. CMS is exactly one DER object;
trailing bytes, including zero padding, are rejected.

WSF is parsed as XML with DTDs disabled and a 100,000-node limit. It requires one
unqualified `job` root with no nested jobs and exactly one unqualified `signature`
element, without attributes, directly under the root as its last element child.
The parsed node must coincide exactly with the text block; CDATA/comment lookalikes
and ambiguous insertion positions are rejected. Multi-job packages, namespace
variants, detached signatures, and arbitrary XMLDSig are unsupported. This is not
WSF schema or script runtime validation; external script references are never
fetched. Each input is limited to 64 MiB and encoded signature text to 16 MiB.

## SIP, policy, and JSON

The signed indirect data requires `SPC_SIPINFO_OBJID` (`1.3.6.1.4.1.311.2.1.30`),
version 1, five zero reserved integers, and the exact style-specific SIP bytes:

| Style | SIP UUID bytes, grouped in wire order |
| --- | --- |
| VBScript / VBE | `4EF02916-9927-B54D-8FE5-ACE10F17EBAB` |
| JScript / JSE | `10E0C906-CE38-D411-A2A3-00104BD35090` |
| WSF | `7005611A-CE38-D411-A2A3-00104BD35090` |

The existing PowerShell SIP remains separate. Supported signature algorithms,
nested signatures, RFC 3161/PKCS#9 timestamps, configured-root chain validation,
code-signing EKU, certificate validity, and local CRLs use the existing engine.
SHA-1 script/CMS digests require `--allow-sha1`. Native Windows trust lists and
script execution policy are not implemented; these results do not establish
Windows policy equivalence.

Success formats are `vbscript_authenticode`, `jscript_authenticode`, and
`wsf_authenticode`. Each signature uses the existing `script_digest` domain field
with `algorithm`, `expected`, and `computed`, plus the existing certificate, chain,
timestamp, and CRL reports. Integrity-only and revocation-disabled modes remain
explicit in JSON. No new successful-result fields are added.

Malformed/unsupported text or blocks return `invalid_wsh` at `wsh`; missing
signatures return `unsigned` at `wsh`. Changed text or insertion offsets return
`script_digest_mismatch` at `script_digest`, including `details.digest`. Wrong SIP
identities and malformed/trailing CMS return `malformed_cms` at `cms`. Other
cryptographic, trust, timestamp, and revocation errors retain their stable codes.

## Fixtures and maintenance

151 portable cases and individually named Rust CLI tests cover the five
extensions, encoding, SHA-1 opt-in, SHA-256/384/512, digest mutations, SIP identity,
CMS signatures, nested signatures, both timestamps, trust, CRLs, and malformed
blocks/WSF. Additional unit tests isolate signature math from changed text/SIP
metadata, exercise truncated inputs, and check library dispatch/domain serialization.
Ordinary tests consume committed fixtures and never execute or regenerate them.

Eight independent jsign 7.6 signatures cover the five extensions plus Unicode
UTF-8 BOM VBScript/JScript/WSF. They use the existing public deterministic RSA-2048
identity from `export_msi_test_identity` (CN `rssig independent MSI test signer`)
and are tested explicitly in integrity-only mode. Tampered counterparts change
only one unsigned body byte and preserve the complete CMS. Manifest entries pin
hashes, provenance, licenses, and expected cases. These are specific format checks,
not full interoperability validation.

Intentional synthetic maintenance:

```sh
cargo test --locked regenerate_cli_fixtures -- --ignored
cargo test --locked export_msi_test_identity -- --ignored
```

The exporter writes public test-only `key.pem`/`certificate.pem` to
`std::env::temp_dir()/rssig-msi-test-signing`. Copy each committed
`wsh-jsign-input.<ext>` (and `wsh-jsign-utf8-bom-input.<ext>`) to its corresponding
`wsh-independent-jsign.<ext>` or `wsh-independent-jsign-utf8-bom.<ext>` name
in a temporary directory. Sign each with jsign 7.6 and a JRE:

```sh
java -jar jsign-7.6.jar --keyfile key.pem --certfile certificate.pem \
  --alg SHA-256 wsh-independent-jsign.vbs
```

For `bad-wsh-independent-digest` counterparts, replace the first ASCII `test-only`
with `Test-only`; for VBE/JSE replace the first `AAAAAA==` with `BAAAAA==`. Review
all outputs and update manifest hashes. Java/jsign are maintenance tools only;
there are no new engine dependencies.

Read-only format references: [jsign WSHScript, VBScript, JScript, WindowsScript,
and SignableScript at cf5d2ce](https://github.com/ebourg/jsign/tree/cf5d2ceaf2ec80cb793f7377749ef811d4be4d34/jsign-core/src/main/java/net/jsign/script).
