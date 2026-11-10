# Parsing and verification

`rssig::parse::Pe` parses supported signed PE headers and ranges. Its
`signatures()` method extracts CMS bytes and checks certificate-table framing
and padding. It neither hashes the image nor authenticates its signatures.
The existing signed-PE layout restrictions still apply: this is not a general
PE loader or unsigned-image inspection API.

`rssig::parse::Cab` and `rssig::parse::Navx` parse the supported signed container
layouts without decompression or payload interpretation. `as_bytes()` borrows the
original file, and `signature()` borrows the opaque embedded signature: CAB
includes its declared padding; NAVX excludes the NXSB wrapper. Container parsing
does not decode CMS or validate its padding. Those checks still run immediately
before signature verification: CAB permits at most seven zero bytes after the
CMS object, while NAVX permits none. A malformed CMS envelope or a changed payload
can therefore still be inspected as a structurally valid container.

Both expose `authenticode_chunks()`, an array of borrowed slices in digest order.
CAB returns four chunks: magic, header bytes 8..34, four validated zero reserve
bytes at 56..60, and cabinet bytes 60..cbCabinet. Borrowing those zero bytes is
equivalent to hashing the canonical zero cabinet index and empty structure1
length. NAVX returns one chunk containing its entire 40-byte header and payload.
Every chunk borrows the original input; accessing chunks or signatures allocates
nothing. CAB parsing uses temporary allocations for folder/file bounds checks.
The existing [CAB](cab.md) and [NAVX](navx.md) layout restrictions still apply.

```rust
use rssig::parse::Cab;
use sha2::{Digest, Sha256};

fn cabinet_digest(bytes: &[u8]) -> Result<Vec<u8>, rssig::parse::Error> {
    let cab = Cab::parse(bytes)?;
    let mut hash = Sha256::new();
    for chunk in cab.authenticode_chunks() {
        hash.update(chunk);
    }
    Ok(hash.finalize().to_vec()) // A computed digest, not an integrity/trust verdict.
}
```

## MSI/MSP and AppX structural adapters

The optional `msi` and `appx` features enable public structural parsers without
verification, Serde reports, CLI, clocks, roots, or filesystem reads. Both require
`std`: `msi` uses the Rust CFB adapter; `appx` uses the bounded Rust ZIP/DEFLATE
and XML adapters. The `verify` feature enables both. These
features do not change the base `no_std + alloc` parser support.

`parse::Msi` borrows the original CFB bytes and owns the extracted CMS and optional
extended digest streams. `extended_digest()` distinguishes an absent stream from
an empty present stream. `update_metadata()` and `update_content()` stream the
canonical bytes into any RustCrypto `digest::Update` sink, in the existing MSI
name order, omitting both signature streams. The caller computes and compares
the extended digest and, for extended signing, prefixes that computed digest to
the content hash. These methods require `&mut Msi` only for the CFB read cursor;
they store no computed digests or verification claims. An error can leave the
caller's sink partially updated; discard it before retrying. MSP uses this same
parser and does not require an original MSI or perform patch applicability checks.

`parse::Appx` borrows immutable ZIP bytes and owns the extracted opaque CMS.
`parts()` exposes borrowed ZIP records, offsets, sizes, compression methods and
compressed bytes. `AppxPart::read(limit)` bounds decoding and checks exact
DEFLATE termination and CRC. CRC checks detect archive corruption; they do not
authenticate the package. `digest_inputs()` returns the canonical AXPC, AXCD,
AXCT, AXBM, and optional AXCI inputs in signed order. AXPC borrows the original
file bytes; the rewritten unsigned directory and decoded parts are owned.
Repeated calls produce the same inputs and never populate reports.

Manifest/content-type and block-map parsing is explicit and deferred.
`identity()`, `content_types()`, `resource_package()` and `bundle_identity()`
decode the supported XML profiles; `bundle_packages()` returns entries with
exact borrowed payload ranges and preserves offset/size, CRC, duplicate, orphan,
and supported-profile checks. None authenticates a signer, binds the Publisher,
or verifies a child package. `BlockMap::parse(&appx.block_map_bytes()?)` decodes
bounded XML; `hash_method()` preserves its URI even if verification does not
support it. File attributes, blocks, hash bytes, and compressed sizes are decoded
on demand in document order. Successful XML parsing alone does not assert that
the map covers the ZIP or that any payload hash matches. Compressed boundary
checks are separately available on `AppxPart` without authenticating block hashes.
DTDs and external entities remain forbidden.

```rust
# #[cfg(all(feature = "appx", feature = "verify"))] {
use rssig::{parse::{Appx, BlockMap}, verify::{verify_parsed_appx, VerifyOptions}};
# let bytes = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/good.msix"));
let package = Appx::parse(bytes)?;
let xml = package.block_map_bytes()?;
let map = BlockMap::parse(&xml)?;
assert!(!map.files().is_empty()); // Untrusted structure only.
let options = VerifyOptions {
    trust: None, check_revocation: false, allow_sha1: false, now: 1800000000,
};
let report = verify_parsed_appx(&package, &options)?;
assert!(!report.signatures[0].chain_trusted);
# }
# Ok::<(), rssig::VerificationError>(())
```

`verify_parsed_msi(&mut msi, options)` and
`verify_parsed_appx(&appx, options)` recheck integrity, CMS, timestamps, trust,
and revocation for each call. Byte-oriented verification uses these same
structures. AppX reports and digest components are per-call results; hashing
cannot confer verification state on the parsed package. The signer pipeline
still checks component digests before metadata/block hashes, then CMS, Publisher,
timestamps and configured trust; bundle identity and child signer binding remain
mandatory. Catalog reports retain `signature_verified: false`.

`rssig::parse::SignedData` parses attached CMS, legacy PKCS#7, and detached CMS
envelopes. It exposes content type, encoded content, digest algorithm OIDs and
parameters, certificate choices, embedded revocation choices, and raw
SignerInfo encodings. It preserves unfamiliar algorithms rather than requiring
that the verifier support them. `parse` leaves content-specific structures, nested signatures, and timestamps opaque.
`SignedData::inspect` explicitly decodes the supported recursive structures.
Signer bodies can be inspected explicitly with `SignerInfo::parse`.
For example, a certificate-only CMS envelope with no signers can be inspected
but cannot pass verification.

`SignerInfo::parse(cms.signer_infos()[index])` returns a borrowed signer view
with original `as_der()` and `version_der()`, `identifier()`/`identifier_der()`,
`digest_algorithm()`, `signature_algorithm()`, signature bytes, and optional
`signed_attributes()`/`unsigned_attributes()`. `SignerIdentifier` supports
issuer/serial (original issuer Name SEQUENCE and serial INTEGER DER) and
subject-key-identifier bytes. The issuer Name is opaque beyond its sequence
framing. Versions and serials must be canonical nonnegative integers; unfamiliar
version numbers are preserved without asserting that verification supports them.
Identity/version compatibility and certificate matching remain verification policy.

`AlgorithmIdentifier::parse` also decodes standalone identifiers. Unknown valid
OIDs, absent parameters, NULL parameters, and unfamiliar parameter DER are
preserved. Each `Attribute` exposes `oid_bytes()`, original DER and borrowed `Content`
values. `oid()` optionally decodes the OID through the fixed-size adapter; valid
encodings outside its limits (including OIDs longer than 39 bytes) return `None`
while their original octets remain available. Canonical base-128 OID framing is
validated independently of those adapter limits. Algorithm/content-type OIDs
retain their existing fixed-size adapter limits. `Attributes::parse` accepts implicit signed `[0]` and unsigned `[1]` sets,
preserving their original tags and bytes. Signed attribute order must be canonical;
both sets reject duplicate OIDs and attributes with empty value sets. Empty
attribute sets are inspectable, but cannot meet mandatory verification attributes.
Unsigned attribute order and opaque value semantics are not authenticated by
inspection. Values are not recursively decoded or sorted by this API.

`SignedData::content()` returns an optional `Content` view with `tag()`, `as_der()`
and `value()` (tag/length excluded). It retains the CMS OCTET STRING or legacy ANY
wrapper. Detached CMS returns `None`. The same opaque view represents attribute
values, including nested signatures and timestamps; recursive inspection is opt-in through `SignedData::inspect`. The existing `content_der()` and `signer_infos()` APIs retain their
behavior. In particular, envelope parsing can succeed while explicit structured
signer parsing fails. The parse CLI reports both raw signer DER and bounded recursive metadata by default.

`SignedData::inspect(bytes, &mut InspectionBudget::default())` returns an
`InspectedCms` tree containing the envelope, structured `InspectedSigner` values,
and recognized unsigned-attribute children. `InspectionKind` identifies nested
Authenticode CMS, RFC 3161 tokens (Microsoft and standard CMS attribute OIDs),
and PKCS#9 countersignatures. Every value in a recognized attribute is visited;
multiple timestamps are inspectable even when verification policy rejects them.
Unknown attributes remain available as opaque values in each `SignerInfo`.

RFC 3161 tokens expose `TstInfo`: original DER, version DER, policy OID, imprint
algorithm/parameters, imprint bytes, serial DER, `parsed_time`, and optional
field DER. Optional fields have ordered, unique envelope tags; accuracy, TSA
names, and extensions retain opaque semantics. Versions, policy OIDs, algorithms,
and imprint lengths are not checked against verification policy. PKCS#9 children
contain a countersigner and its optional signed `signingTime` assertion.
Missing signingTime is inspectable; malformed or multiple signingTime values
fail. `ParsedTime` exposes original DER, nonnegative Unix seconds, and an optional
exact fractional digit string (including leading zeroes). UTC/GeneralizedTime
must use canonical DER; GeneralizedTime fractions have at most 64 digits and
no trailing zero. TSTInfo requires GeneralizedTime. These assertions are never
verified signing times: no signature, imprint binding, certificate, clock, trust,
or revocation checks run. The verifier shares time decoding while retaining
its own authentication and time-policy checks.

`InspectionBudget` is consumable across siblings, timestamp/countersigner edges,
and repeated top-level calls. Defaults are depth eight (root zero), 64 decoded
objects (CMS, signer, or TSTInfo), 16 MiB cumulative input bytes, and 65,536 DER
preflight nodes. Nested bytes/nodes are charged again when decoded; budgets
never reset between branches. `InspectionLimits` can adjust work limits, but
cannot raise depth above eight. Constructed DER framing also has a hard depth
limit of 96. Unknown constructed values receive bounded framing preflight,
without interpretation. Exhaustion returns `ErrorKind::InspectionLimit`; no
partial tree is returned. The library method `SignedData::parse` retains its
earlier limits and deferred signer decoding; the CLI always uses bounded recursive inspection.

Malformed field counts, tags, integers, OIDs, lengths, or attribute structure
return `ErrorKind::MalformedCms`. The existing DER reader limits each child list
to 16,384 entries, forbids indefinite lengths and high-tag-number encodings, and
checks ranges before slicing. View metadata allocates, while DER, signature,
identifier and content slices borrow the input. Accessors do not allocate.
Verification reuses algorithm framing, signer framing and attribute decoding at
the existing stages; algorithm support, digest binding, signature authentication,
and configured-root trust remain in the verifier.

These types borrow immutable input and have private fields. Parsing does not
consult a clock, read files, load roots, perform cryptography, or fetch URLs.
It does not produce trusted/valid flags. Parse failures use `parse::Error`,
which implements `core::error::Error` and exposes an `ErrorKind` through
`kind()`: `InvalidPe`, `Unsigned` (PE), `InvalidCertificateTable`, `MalformedCms`,
`InvalidCab`, `UnsignedCab`, `InvalidNavx`, `UnsignedNavx`, or `InspectionLimit`. The format-specific
unsigned kinds preserve the original verification stage when converted.
Its source chain retains diagnostic causes without depending on domain reports.
With `verify` enabled, `VerificationError::from` maps these to the existing
serialized codes/stages/causes. CLI reports always include the recursive `inspection` tree.

`Pe::authenticode_chunks()` returns three borrowed slices in digest order,
excluding the checksum, security directory, and certificate table. Feed the
slices to any incremental hasher. `authenticode_digest(&view, &mut hasher)`
accepts an external `PeTrait` implementation and a RustCrypto `digest::Update`
sink. The verifier calls this function too; both interfaces share byte selection
without copying the image. This interface carries no claimed digest or trust verdict.

The generic function checks field widths/order, header bounds, section ranges,
and the certificate table before writing anything to the sink. Invalid layouts
return `PeOffsetError` with the sink unchanged. Nonempty sections are sorted by
file offset and must be contiguous with each other, without overlapping headers
or certificates. A gap before the first section and an overlay after the last
section are permitted and hashed exactly once, in file order. A present
certificate table must be nonempty, eight-byte aligned in offset and size, and
end at EOF. External views can report no certificate table to hash an unsigned
image; `Pe::parse` still requires an embedded signature. Views must supply offsets
from the actual PE encoding; range validation does not reparse the headers.

This is rssig's existing bounded layout policy, not arbitrary Windows layout
support. In particular, generic hashing no longer applies Google's sum-of-section-
sizes suffix calculation to gapped layouts: that could hash section bytes twice
and disagree with verification. Gaps between nonempty sections are rejected.

`SignedData::signer_infos()` returns a borrowed slice of DER slices, so reading
the signer encodings does not allocate. X.509 certificates and parser metadata
still use allocations; `no_std` does not mean allocation-free.

`rssig::verify::verify_parsed_pe` consumes a parsed PE and explicit
`VerifyOptions`. It reuses the PE layout while performing all the normal image
and page hashes, CMS signature/content binding, timestamp, certificate trust,
and configured CRL checks. Inspecting a CMS envelope does not cache a verified
verdict; verification parses and authenticates the embedded signatures itself.
`verify_parsed_cab` and `verify_parsed_navx` similarly consume `parse::Cab` and
`parse::Navx`, reusing their validated layouts while performing all normal
framing, digest, CMS, timestamp, and configured trust/revocation checks. These
functions are exported from both `rssig::verify` and the crate root. The existing
`verify`, `verify_pe`, `verify_cab`, `verify_navx`, and other format-specific
functions retain their behavior. The CLI uses the same verification engine.

## Script and RDP parsing

`parse::Powershell::parse(bytes)` and `parse_xml(bytes)` decode hash-comment and
XML-comment signature blocks without interpreting script code, XML content, CMS,
or trust. `parse::Wsh::parse(bytes, WshKind)` supports VBScript, JScript, and WSF;
`Wsh::detect(bytes)` identifies comment style from signature markers. Encoded
VBE/JSE text remains opaque; no script decoder or host runs.

These objects borrow exact original input through `as_bytes()` and expose
`encoding(): TextEncoding`, decoded `body()`, and decoded `signature()` CMS bytes.
`TextEncoding` distinguishes UTF-8, UTF-8 BOM, UTF-16LE BOM, and UTF-16BE BOM. The
signature and body allocate; their accessors borrow existing storage. PowerShell
retains U+FEFF in the body and hash input; WSH strips its encoding BOM. Stored
line endings and Unicode code units retain the existing format-specific rules.
`authenticode_bytes()` allocates canonical UTF-16LE input; `update_digest(&mut
impl digest::Update)` streams the same bytes without materializing that buffer.
WSH appends the little-endian `insertion_position()` measured in UTF-16 code
units. WSF removes only the signature block and retains the closing job tag and
trailing text in its body. Neither method asserts that the hash matches a signer.

`parse::Rdp::parse(bytes)` exposes original `as_bytes()`, `encoding()`, original
line endings in `decoded_text()` (BOM excluded), decoded detached `signature()`,
`signscope()`, `signed_settings()`, `unsigned_settings()`, and borrowed
`canonical_bytes()`. Each parser `RdpSetting` has a name, `RdpValueType`, and
stored value. These parser types require no Serde or verification dependencies;
the verifier projects them into the existing domain types. Canonical input is
UTF-16LE scoped setting lines in scope order, followed by signscope, CRLF, and a
NUL code unit. Unscoped settings never enter that input. Scope membership is an
unauthenticated assertion until verification succeeds; the whole file is never
claimed signed. Unsupported scopes fail with `UnsupportedRdpScope` and expose
the original entry through `Error::rdp_scope_entry()`.

All text parsers use `core + alloc`. PowerShell XML comments require no XML
library. WSF requires the optional `xml` feature for the bounded single-job XML
and signature-placement adapter; without it, valid WSF input fails with
`UnsupportedWsfXml` rather than falling back to comment framing. The XML adapter
also builds without `std` using roxmltree with default features disabled. DTDs
remain disabled and the existing 100,000-node limit applies. `verify` enables
`xml` automatically. Base64 decoding now belongs to the parser dependency set;
no dependency versions or cryptographic providers change.

Malformed text/block errors are `InvalidPowershell`, `InvalidWsh`, or `InvalidRdp`;
missing signatures use the corresponding `UnsignedPowershell`, `UnsignedWsh`, or
`UnsignedRdp`. The verifier maps these to its existing codes/stages, preserving
unsupported-scope details, error order, and diagnostics. The existing documented
encoding, marker, signature-size, RDP-setting, and WSF-layout limits still apply.
Verification uses these same parsing and hash-input boundaries. CLI format
selection and JSON schemas are unchanged; `parse` still selects PE or CMS.

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
| `signer_infos_der` | Raw SignerInfo encodings as hex strings. |
| `inspection` | Required structural signer/timestamp tree described below. |

`inspection` contains `signers` and `tst_info` (or `null`).
Each signer has original `der` and ordered `children`. Each child has `kind`
(`nested`, `rfc3161`, or `pkcs9_countersignature`), `value_der`, optional `cms`
(a complete recursive envelope report), optional `countersigner`, and optional
`parsed_time`. Absent values are `null`. Times contain `der`, `unix_seconds`,
and `fractional_seconds` (a digit string or `null`), never `signing_time`.
TSTInfo reports contain `der`, `policy`, `imprint_algorithm`, `imprint`,
`serial_number_der`, `parsed_time`, and `optional_fields_der`. All DER and
imprint bytes use lowercase hex. `verification_performed` remains false.
The CLI shares one default budget across a PE file's top-level signatures;
each input file has its own budget. Limit failures serialize as `malformed_cms`
at `cms` stage. Malformed signer bodies or recognized children fail the whole
file. Library callers can still use `SignedData::parse` to inspect their opaque enclosing
envelopes. There is no shallow CLI mode or recursion flag.

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
# Containers, scripts, RDP and CMS on core + alloc (an allocator is required).
rssig = { version = "0.1", default-features = false }

# WSF structural inspection without std: add features = ["xml"].
# MSI/MSP or AppX structural inspection with std, without verification:
# features = ["msi"] or ["appx"], or both.
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
without `std`. Full verification still requires `std`. MSI/MSP and AppX structural parsing also
requires `std` through explicit optional adapters. The `parse` CLI still selects
PE, CMS, CAB, or NAVX; the other container parsers are library APIs.

## Format selection

With `verify` enabled, `format::Format` and `format::detect(bytes, filename)`
expose the verifier's classification rules without filesystem paths or reads.
The optional hint is a filename string. Binary magic wins over filename hints;
recognized text/package extensions win over signature markers. WSH mixed-style
errors remain typed, and unknown bytes retain the historical PE fallback.
Detection only selects a parser; it does not validate or authenticate input.

`verify::verify_with_hint(bytes, filename, options)` uses those rules with explicit
verification policy. `verify::verify_as(bytes, format, options)` bypasses detection
and invokes the selected parser, including explicit WSH comment styles through
`Format::Wsh(parse::WshKind)`. Existing format-specific entry points remain available.
These selection APIs currently require `verify`/`std`; parser-only consumers use
the existing explicit parser constructors.

The inspection CLI additionally accepts `--format cab` and `--format navx`.
It reports their embedded CMS using the existing unverified inspection contract,
including nested signatures and timestamps. CAB zero padding is checked before
CMS inspection. Container digest checks and trust are not performed. The default
remains PE; CMS still requires explicit selection. MSI/AppX and text/RDP CLI
inspection remain deferred until their format-specific report contracts are
specified; their structural library APIs remain available.

## Explicit verification policy construction

`VerifyOptions::trusted(&store, unix_seconds)` requires configured-root trust
and applicable local CRLs by default. Missing or unusable revocation evidence
fails closed. An empty store remains an empty store; no constructor substitutes
system roots or switches to integrity-only verification.

`VerifyOptions::trusted_with_revocation(&store, unix_seconds,
RevocationPolicy::Disabled)` explicitly disables revocation while retaining
certificate-chain validation. Use `RevocationPolicy::Required` to require CRLs.
Successful reports reflect this decision in `chain_trusted` and
`revocation_checked`. Supplied CRLs are not thereby individually authenticated.

`VerifyOptions::integrity_only(unix_seconds)` explicitly selects integrity checks
without configured-root or revocation claims. Every constructor requires time
and disables SHA-1 by default. A caller may explicitly set `allow_sha1 = true`
for legacy content signatures; this never enables SHA-1 certificate/CRL chains.
Constructors perform no I/O, load no roots, fetch no revocation data, and read no
clock. The CLI remains responsible for root/CRL loading and its documented
current-time default, and constructs the same explicit library policies.

Public fields and existing entry points remain source-compatible. For legacy
struct literals, `trust: None` means integrity-only regardless of
`check_revocation`; a true flag in that combination is ignored and reports never
claim revocation was checked. Prefer the integrity-only constructor to express
that policy without redundant flags. A configured store with revocation disabled
still validates certificate chains. No implicit `Default` policy is provided.
CLI integrity-only flags continue to conflict with roots, CRLs, and revocation
flags. The existing `--no-revocation --crl` combination still loads supplied
artifacts but does not claim that their revocation evidence was checked.
