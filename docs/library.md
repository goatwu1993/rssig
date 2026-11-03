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
It does not produce trusted/valid flags. Parse failures use `parse::Error`,
which implements `core::error::Error` and exposes an `ErrorKind` through
`kind()`: `InvalidPe`, `Unsigned`, `InvalidCertificateTable`, or `MalformedCms`.
Its source chain retains diagnostic causes without depending on domain reports.
With `verify` enabled, `VerificationError::from` maps these to the existing
serialized codes/stages/causes. The CLI JSON contract is unchanged.

`Pe::authenticode_chunks()` returns three borrowed slices in digest order,
excluding the checksum, security directory, and certificate table. Feed the
slices to any incremental hasher. The verifier uses the same slices, avoiding
a whole-image copy. This interface carries no claimed digest or trust verdict.
`SignedData::signer_infos()` returns a borrowed slice of DER slices, so reading
the signer encodings does not allocate. X.509 certificates and parser metadata
still use allocations; `no_std` does not mean allocation-free.

`rssig::verify::verify_parsed_pe` consumes a parsed PE and explicit
`VerifyOptions`. It reuses the PE layout while performing all the normal image
and page hashes, CMS signature/content binding, timestamp, certificate trust,
and configured CRL checks. Inspecting a CMS envelope does not cache a verified
verdict; verification parses and authenticates the embedded signatures itself.
The existing `verify`, `verify_pe`, and other format-specific functions retain
their behavior and crate-root exports. The CLI uses the same verification engine.

## Parse command

```sh
rssig parse application.exe library.dll
rssig parse --format pe application.exe
rssig parse --format cms signature.p7s
```

The default format is signed PE. `--format cms` selects a standalone DER
CMS/PKCS#7 SignedData envelope, including detached envelopes; PEM and other
container formats are not supported by this command. The selected format
applies to all files in the invocation. Signed-PE layout restrictions still
apply, so an unsigned PE returns `unsigned` rather than an empty signature list.

Parsing emits one JSON document on stdout, with `schema_version: 1`,
`command: "parse"`, `ok`, and ordered per-file `results`. Each successful file
has `file`, `ok: true`, `format` (`pe` or `cms`),
`verification_performed: false`, and a `signatures` array. A standalone CMS
input contributes one envelope to this array, even if its signer set is empty.
`ok` means the selected structure and reported metadata were decoded; it does
not establish file integrity, signature validity, certificate trust, or freshness.

Each signature envelope contains:

| Field | Meaning |
| --- | --- |
| `version_der` | Original DER INTEGER, encoded as lowercase hex. |
| `content_type` | Content-type OID in dotted notation. |
| `content_der` | Original encoded inner content, or `null` for detached CMS. |
| `digest_algorithms` | Ordered entries with `oid`, original `der`, and `parameters_der` (hex or `null`). Unknown algorithms are preserved. |
| `certificate_choices` | Ordered entries with the ASN.1 `tag`, original `der`, and `certificate` metadata for X.509 choices; opaque alternatives have `certificate: null`. |
| `revocation_choices_der` | Raw embedded revocation choices as hex strings; neither loaded into the trust store nor validated. |
| `signer_infos_der` | Raw SignerInfo encodings as hex strings. Signer bodies, nested signatures, and timestamps are not interpreted recursively. |

Certificate metadata uses the existing `CertificateReport` fields, including
names/RDNs, EKUs, key usage, validity, extensions, DER, and a SHA-256 certificate
fingerprint. Fingerprint calculation is for identification, not signature or
file-integrity verification. The report contains no selected chain, trust
verdict, revocation verdict, or validation time. Verification policy flags such
as `--roots`, `--crl`, `--time`, and `--integrity-only` are rejected by `parse`.

Exit codes are 0 when every file parses, 1 for any per-file read/parse/report
failure, and 2 for invalid arguments. Per-file failures use the existing typed
Problem Details contract; all inputs are retained, and the first failure also
supplies the root problem. Usage errors are plain text on stderr; help/version
are plain text on stdout. The public report types are `ParseReport`,
`ParsedCmsReport`, `ParsedAlgorithmReport`, `ParsedCertificateChoice`,
`ParseFileSuccess`, and `ParseFileResult` in `rssig::domain`.

The CLI/report adapter requires `std`; the underlying parser builds on
`core + alloc` without CLI, native-root, or verification dependencies. See the
[feature boundary and module responsibility map](architecture.md).

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

## Feature selection and migration from PR #17

```toml
# Signed PE/CMS inspection on core + alloc (an allocator is required).
rssig = { version = "0.1", default-features = false }

# Alternatively: all verifiers and reports, with explicit roots and CRLs.
# rssig = { version = "0.1", default-features = false, features = ["verify"] }
```

The default `cli` and `system-roots` features preserve the complete command-line
tool. `verify` enables `std`, all supported format verifiers, and Serde domain
types, without Clap or the native root loader. `system-roots` separately enables
`TrustStore::from_system()`; explicit `TrustStore::add_roots`/`add_crl` work with
`verify` alone. `std` alone enables standard-library support for the parser.
All configurations retain RustCrypto verification and configured-root trust.

Two library signatures change from PR #17: parser methods return `parse::Error`
instead of `VerificationError`, and `SignedData::signer_infos()` returns
`&[&[u8]]` instead of `Vec<&[u8]>`. Match parser errors with `error.kind()`;
use `VerificationError::from(error)` when a report is needed. Functions returning
`VerificationError` can continue using `?`. Use `.iter().copied()` for signer
iteration or `.to_vec()` if an owned list is needed. Verification functions,
options, and JSON types retain their existing signatures and semantics.

The parser supports 32-bit and 64-bit targets and is compile-checked on a target
without `std`. Full verification still requires `std`; the CFB reader and AppX
archive/XML path have not been ported. Other container parsers remain internal.
