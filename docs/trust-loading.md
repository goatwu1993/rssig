# Root and CRL loading (TRUST-T00001)

Every explicit load is atomic. `TrustStore::add_roots` and
`add_crl` validate the entire input before adding anything. A failure
leaves all previously loaded roots and CRLs unchanged. Separate successful
calls remain committed if a later call fails. The CLI stops on any loading
failure before verifying files: exit 2, plain stderr naming the source file
and failing entry, empty stdout. It does not emit a partial verification report.

## Accepted input and duplicates

| Input | Rule |
| --- | --- |
| DER | Exactly one certificate or CRL, with no prefix or trailing bytes. |
| Root PEM | One or more complete `CERTIFICATE` blocks. |
| CRL PEM | One or more complete `X509 CRL` blocks. |
| PEM whitespace | ASCII whitespace is allowed before, between and after blocks. |
| Empty or whitespace-only input | Reject; never a successful empty load. |
| Mixed valid/invalid blocks | Reject the entire input in either order. |
| Wrong labels, preambles, comments, invalid Base64, unterminated blocks or trailing junk | Reject; no ignored input. |
| Exact DER duplicates | Accept idempotently within a bundle and across calls, preserving first occurrence order. |
| Distinct DER with equal subject/key | Retain both, including different constraints or cross-signatures. |

Stored certificates and CRLs retain the exact DER supplied directly or decoded
from PEM. They are not decoded and re-encoded for storage. Deduplication compares
complete DER bytes; it neither merges trust policies nor selects among competing
CRLs. The [CLI host limits](host-limits.md) still bound source bytes before decoding
and retained artifact counts/bytes after loading. Duplicate source bytes count
toward input limits; only retained unique DER counts toward artifact limits.
Library loaders perform no filesystem or network I/O and have no CLI byte caps.

## Roots and native enumeration

Every configured root must decode as an X.509 certificate and support webpki's
`anchor_from_trusted_cert` extraction. Failure rejects the load at that root's
one-based entry position, even if another valid root would verify the file.
Verification no longer silently filters out unsupported anchors.

Anchor extraction is **not** signature verification or general root checks
validation. It does not check the root's self-signature, expiry, CA flag, KU,
EKU or unfamiliar critical extensions; configured roots are already trusted by
the caller. Extraction also does not establish that an arbitrary public-key
algorithm can verify a chain. Actual certificate signatures still require the
supported RustCrypto algorithms. Name constraints remain path inputs. The
[certificate paths](certificate-paths.md) and its existing
expired/profile/constrained-root fixtures pin these boundaries.

`from_system` treats native enumeration as one atomic operation:

- Any enumeration error rejects the complete result, including partial results.
  Diagnostics include the returned certificate count and every native error
  message, each stated once in a single cause with no further `source()`.
- An error-free empty result is rejected.
- Every returned certificate passes the same X.509 decoding and anchor extraction
  checks as explicit roots; the first failure rejects the whole result.
- Exact duplicates are deduplicated. No store is returned on failure.

The OS supplies roots only. No native signature, chain, timestamp or revocation
validation is used. Native enumeration may allocate before returning; atomicity
does not add a bound on the platform adapter's internal work. Native tests inject
enumeration results without reading OS roots or changing environment variables.

`TrustStore::default()` intentionally remains an empty store: callers can build
it incrementally. Trusted verification against it fails with `untrusted_root`
at `certificate_chain`; embedded certificates never replace configured anchors.

## Typed diagnostics and verification evidence

Typed loaders retain `TrustLoadErrorKind::{Roots,Crl,SystemRoots}` and add
`TrustLoadError::code()` and `entry_index()`. `TrustLoadErrorCode` is
non-exhaustive:

| Code | Meaning |
| --- | --- |
| `EmptyInput` | Empty explicit input or empty successful native enumeration. |
| `InvalidEncoding` | Invalid DER/PEM or wrong PEM label. |
| `UnsupportedAnchor` | X.509-decodable root rejected by anchor extraction. |
| `NativeEnumeration` | One or more native enumeration errors. |

Entry positions are one-based: DER uses 1, PEM uses block order, native roots use
enumeration order. Empty-input and enumeration errors have no entry position.
Match typed kinds/codes, not prose or dependency error strings. `{}` is a summary
built from the kind, code and entry position (for example
`invalid root encoding in trust input entry 2`, or
`unsupported trust anchor in system root store entry 5` for a native root),
`{:#}` appends every cause once,
and `source()` walks those causes, so a reporter that walks the chain prints each
cause once. Native enumeration lists every native error in one cause and reports
no further `source()`. `add_roots`, `add_crl` and `from_system` return
`TrustLoadError` directly; the `_typed` names are deprecated aliases. No public
signature names `anyhow`.

CRL loading checks syntax only. A syntactically valid forged, stale, unsupported
or unrelated CRL may load; required revocation validation must still authenticate
and apply evidence and fails closed. A loaded forged-CRL fixture fails with
`invalid_crl_signature` at `revocation`. Disabling revocation remains explicit
and reports `not_checked`. Successful reports retain `CrlReport.role = "supplied"`,
not an individually verified label. Selection/applicability rules and reporting
the CRLs actually used remain CRL-T00001/CRL-T00002. No verification JSON schema changes
are introduced by these loading rules.

## Compatibility and evidence

This intentionally tightens previous behavior: unsupported anchors and partial
native enumeration no longer disappear silently. Correct the rejected source,
or explicitly configure a controlled root bundle using `--no-system-roots`
and `--roots`. There is no automatic fallback to weaker verification. CRL PEM
bundles and surrounding PEM whitespace are now accepted; exact duplicates no
longer inflate the stored artifact list or report. All prior successful and
failing fixture expectations remain enforced.

The first focused test run reproduced a success after adding a v2 root that
X.509 decoding accepted but anchor extraction rejected. Adding the root to an
otherwise valid store now fails at load time. Paired committed DER/PEM fixtures,
manifest digests/provenance, portable cases and named CLI tests cover supported
input, mixed failures, duplicates, empty stores and unauthenticated CRLs.
Library tests assert atomicity through subsequent verification, exact report/DER
preservation and typed diagnostics. Unit tests cover parser boundaries, distinct
anchor retention and injected partial/total/empty/unsupported native results.
The maintenance generator reproduces fixtures; ordinary tests only consume them.

This is loading-policy evidence, not Windows policy equivalence or a general
cryptographic audit. Linux runtime validation remains in CI; local validation
uses macOS and the installed bare-metal compile target.

Validation passed: `cargo test --locked`, `cargo fmt --check`,
`cargo clippy --all-targets --locked -- -D warnings`, full tests with
`--no-default-features --features verify-core` and with
`--no-default-features --features cli`, and verifier-core library Clippy on
`thumbv7em-none-eabi` with native crypto features disabled. Explicit fixture
regeneration reproduced all recorded SHA-256 digests, including existing
artifacts. The portable specification now contains 796 cases, including 18
TRUST-T00001 cases. No dependency changes were required.

PR review found that fetched PEM bundles could bypass the retrieval layer's
64-CRL limit, which had assumed one CRL per response. A fixture-first regression
confirmed success with 65 distinct, correctly signed CRLs before the fix.
Retrieval now checks the combined retained count after each load and before
final verification. Two additional deterministic bundles and three portable
cases cover 64 accepted, 65 rejected, and 64 fetched plus one supplied rejected.
The specification now has 799 cases (21 for TRUST-T00001).
The follow-up passes the full locked suite, formatting, all-target Clippy,
and the `crl-fetch` feature suite without default features on macOS.
