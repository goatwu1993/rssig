# Parsing and verification

`rssig::parse::Pe` parses supported signed PE headers and ranges. Its
`signatures()` method extracts CMS bytes and checks certificate-table framing
and padding. It neither hashes the image nor authenticates its signatures.
The existing signed-PE layout restrictions still apply: this is not a general
PE loader or unsigned-image inspection API.

`rssig::parse::SignedData` parses attached CMS, legacy PKCS#7, and detached CMS
envelopes. It exposes content type, encoded content, digest algorithm OIDs and
parameters, certificate choices, embedded revocation choices, and raw
SignerInfo encodings. It preserves unfamiliar algorithms rather than requiring
that the verifier support them. Content-specific structures, SignerInfo bodies,
nested signatures, and timestamps are interpreted later by the verifier.
For example, a certificate-only CMS envelope with no signers can be inspected
but cannot pass verification.

These types borrow immutable input and have private fields. Parsing does not
consult a clock, read files, load roots, perform cryptography, or fetch URLs.
It does not produce trusted/valid flags. Parse failures use the existing typed
`VerificationError` contract (`invalid_pe`, `unsigned`,
`invalid_certificate_table`, or `malformed_cms`, as applicable).

`rssig::verify::verify_parsed_pe` consumes a parsed PE and explicit
`VerifyOptions`. It reuses the PE layout while performing all the normal image
and page hashes, CMS signature/content binding, timestamp, certificate trust,
and configured CRL checks. Inspecting a CMS envelope does not cache a verified
verdict; verification parses and authenticates the embedded signatures itself.
The existing `verify`, `verify_pe`, and other format-specific functions retain
their behavior and crate-root exports. The CLI continues to use them.

## CertificateChoices

[RFC 5652 section 10.2.2](https://www.rfc-editor.org/rfc/rfc5652.html#section-10.2.2)
defines alternatives to ordinary X.509 certificates in a CMS CertificateSet.
Microsoft timestamp tokens can contain a context-specific `[1]` entry.

Ordinary X.509 entries are decoded as certificates and remain untrusted signer
or chain candidates. Other defined choices (`[0]` through `[3]`) retain their
complete DER. Their outer envelope and constructed-value framing are checked,
with a limit of 32 nesting levels and 16,384 elements per opaque choice.
Their internal semantics and signatures are not verified. Unknown choice tags,
truncated encodings, and malformed envelopes are rejected.

Successful signature and RFC 3161 timestamp reports include the following
field when such entries are present:

```json
"unverified_certificate_choices": [
  { "tag": 161, "der": "a1..." }
]
```

`tag` includes the ASN.1 class and constructed bits: 160 is `[0]`, 161 is `[1]`,
162 is `[2]`, and 163 is `[3]`. `der` is the complete original hex encoding
(abbreviated above). These entries cannot replace a missing X.509 signer or
issuer, become trust anchors, or bypass a failed signature check. The field is
omitted when empty; older reports deserialize with an empty list.

## Fractional timestamps

Canonical UTC GeneralizedTime values with fractional seconds are supported,
including leading fractional zeroes such as `.009Z`. The parser accepts up to
64 fractional digits, preserves them as a string, and rejects empty fractions,
trailing zeroes, comma separators, offsets, and invalid dates/times.

`TimestampReport.signing_time` and the signature's existing `timestamp` field
remain whole Unix seconds. The optional `fractional_seconds` field supplies
the exact decimal digits: `1790974170` with `"009"` means `1790974170.009`.
It is omitted for timestamps without a fraction and defaults to absent when
reading older reports. No floating-point rounding is used.

Validation time is supplied in whole seconds. A timestamp with a nonzero
fraction in that same second is in the future and is rejected. Certificate
paths are checked at the whole second (including notBefore), then the selected
leaf and intermediates are checked against the fractional expiry boundary.
A timestamp even slightly after notAfter is rejected for both the TSA and the
publisher chain. Configured trust anchors retain the existing webpki validity
policy. `TrustReport.validation_time` records the whole-second part; consult
the timestamp's `fractional_seconds` for its full precision.

## Regression evidence

The Microsoft Sysinternals artifact downloaded from
[Sigcheck.zip](https://download.sysinternals.com/files/Sigcheck.zip) on 2026-10-30
contained `sigcheck64.exe` (528,184 bytes, SHA-256
`f3d671b4bab4714746d0034104363d4f6deef591e979e8e37170803e8960487d`).
It exposed two consecutive failures: an attribute CertificateChoice in its TSA
token, followed by fractional GeneralizedTime. After these fixes, its PE/CMS
and timestamp integrity verification succeeds:

```sh
cargo run --locked -- verify target/real-world/sigcheck/sigcheck64.exe \
  --integrity-only --time 1800000000
```

This command assumes the artifact has been downloaded and extracted at that
path. The binary was never executed and is not committed. This manual check
uses no trust anchors or CRLs and does not establish a trusted publisher or
Windows policy equivalence. Downloads may change; use the recorded digest when
reproducing the result.

Offline tests use small synthetic artifacts with deterministic public test keys
and provenance in `tests/fixtures/manifest.json`. Paired failures cover malformed
choices, unsupported tags, missing TSA certificates, changed timestamp
signatures, noncanonical fractions, future fractions, and fractions past
certificate expiry. Public API tests also confirm that parsing a tampered image
or signature succeeds while verification rejects it.

## Next extraction steps

The project remains one `std`-using crate with unchanged dependencies. The new
module boundary covers PE and CMS; other format parsers remain internal.
Separate parser and verifier crates require moving shared error/DER types out
of verification-oriented modules, defining the remaining container interfaces,
and isolating CLI/native-root dependencies. A later `no_std + alloc` parser
would require a dependency/feature audit and its own build checks. Neither
crate extraction nor `no_std` support is claimed by this change.
