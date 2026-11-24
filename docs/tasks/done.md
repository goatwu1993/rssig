# Completed tasks

Full records of finished `TODO.md` items, moved here verbatim when
`TODO.md` was trimmed to one line per finished item.

## LIMIT-T001 fix: Audit arithmetic and structural bounds across every parser

Cover PE/CFB/CAB/NAVX/ZIP offsets, DER lengths, script encodings, RDP framing,
and XML counts. Exercise truncations, zero/maximum counts, overlapping ranges,
inconsistent lengths, and 32-bit conversions. Extend PR #18's maximum-offset
regression; malformed input must return typed errors without panics or
unchecked allocations. Completed the structural audit and fixes with
[bounds evidence and limits](../../docs/parser-bounds.md), a DER regression fixture,
CAB extreme-offset tests, and cross-format header mutation coverage. Aggregate
budgets, host reads, fuzzing, and 32-bit execution remain separate tasks.

## LIMIT-T002 fix: Enforce aggregate verification budgets

Added one consumable
per-file budget across certificate-table entries, every signer, nested CMS,
timestamps, RDP and embedded bundle children. Limits cover decoded/hash bytes,
certificate candidates and report copies, reports, nesting, path search and
RustCrypto signature operations; exhaustion returns typed details with no
partial success. [Inventory, limits and evidence](../../docs/verification-budgets.md)
document conservative reservations and webpki's per-search bounds. Committed
valid 64/65-signer and 65-entry fixtures plus depth-eight/depth-nine malformed
children, portable cases, named CLI/domain assertions and counter/sharing tests.
The 63-plus-two-signer regression first returned success with 65 reports.
A multi-EKU RDP regression also pins immediate propagation of a later retry
budget failure, preserving ordinary first-policy-error behavior. Callback
exhaustion retains the first failed charge’s exact usage and requested amount.
Full locked tests, fmt, Clippy, parser-only and verify-core/verify/cli feature
tests, structural-adapter Clippy and bare-metal verify-core Clippy pass on
macOS. Dependencies are unchanged; Linux runtime validation remains in CI.
Host reads and CLI batch/report buffering are covered by LIMIT-T003.

## LIMIT-T003 fix: Bound host input and report memory

Added bounded streaming
reads for CLI inputs and root/CRL files, per-file and batch byte/report limits,
path/count limits, and regular-file checks after nonblocking opens. Successful
reports are counted before retention; bounded failure reserves preserve one
JSON document and ordered per-file outcomes. [Host limits](../../docs/host-limits.md)
document defaults, lowering options, native-root enumeration boundaries and
conservative failed-read reservations. Portable cases reuse committed fixtures;
named CLI and unit tests cover oversized sparse files, growing/short streams,
nonregular inputs, exact EOF, batch exhaustion and oversized failure evidence.
Full locked tests, fmt, Clippy, CLI-without-system-roots tests and bare-metal
verify-core Clippy pass on macOS. Dependency review found only a direct optional
CLI edge to the already-locked libc version for O_NONBLOCK; no native crypto.
Linux runtime validation remains in CI. Automatic CRL/AIA fetching is CRL-T030.

## CMS-T001 fix: Audit CMS structure and signature binding

Checked
SignedData/SignerInfo versions, supported signer identifiers, canonical
INTEGER/SET encodings, duplicate/empty attributes, digest-set membership,
algorithm parameters, and contentType/messageDigest binding. Preserve exact
signed bytes; never normalize malformed signed encodings into valid ones.
Keep RDP direct-signature allowances out of Authenticode/countersignatures.
Added version, signed-value ordering and ECDSA-parameter rejection, paired
fixtures and signature-math assertions. `docs/cms-security.md` records the
audit and explicit legacy/opaque-encoding compatibility boundaries.

## CMS-T002 fix: Define ambiguous signer-certificate handling

Cover duplicate
certificates, identical issuer/serial identifiers with different keys, missing
signer certificates, and reordered candidate sets. Ensure candidate selection
cannot accidentally trust embedded certificates or depend on a permissive
first match. Identical certificates are accepted as duplicate candidates;
distinct matches fail with `ambiguous_signer_certificate` before crypto/trust
selection. Paired/reordered fixtures cover different keys, same-key identity
conflicts and missing signers. Shared-path tests cover RFC3161, countersigners
and direct RDP signatures. Rules: `docs/cms-security.md`.

## PATH-T001 fix: Expand certificate-path rule coverage

Added 38 portable
cases and named in-process CLI tests for BasicConstraints, path length,
permitted/excluded DNS constraints, unknown critical extensions, leaf/CA
EKU and KeyUsage, cross-signing, same-subject/different-key issuers and cycles.
Exact selected-chain hashes/DER and typed failures are pinned with explicit
roots, time and local CRLs. Signature-math checks isolate path-check faults.
The initial selected-anchor regression reported a same-subject/key root whose
name constraints rejected the path; reporting now matches name constraints
too. [Rule inventory and limits](../../docs/certificate-paths.md) document
webpki's profile and configured-anchor validity/constraint treatment. Full
locked tests, fmt, Clippy, verify-core and CLI-without-system-roots tests, and
bare-metal verify-core Clippy pass on macOS. Dependencies are unchanged; Linux
execution remains in CI. No Windows policy equivalence is claimed.

## TRUST-T001 fix: Make root/CRL loading diagnostics explicit

Atomic DER/PEM
loading rejects malformed input, unsupported anchors and partial native-root
enumeration with typed codes, entry positions and causal diagnostics. Exact
DER duplicates are deduplicated; distinct constrained anchors are retained.
Fetched bundles enforce the combined 64-CRL limit before final verification.
Added 18 fixtures and 21 portable cases covering mixed bundles, empty stores,
duplicates, native loading failures and retrieval limits. Loaded CRLs remain
supplied artifacts without individual authentication claims. See
[loading rules, migration and validation evidence](../../docs/trust-loading.md).
Full locked tests (799 cases), formatting, Clippy and documented feature/target
checks pass on macOS. Dependencies are unchanged; Linux runtime validation
remains in CI. CRL selection/evidence remain CRL-T001/CRL-T002.

## TSA-T001 fix: Complete timestamp structure and multiplicity tests

Shared
TSTInfo parsing now validates mandatory fields, canonical optional ordering and
accuracy bounds; verification requires version 1 and rejects unsupported tsa
identity/extensions explicitly. Added 35 committed fixtures/portable cases and
named CLI tests for structure, duplicate/mixed timestamps, TSA critical and
exclusive EKU/KeyUsage, parent substitution and malformed signingTime.
Independent signature-math/image/issuer checks isolate the intended faults;
parser tests cover accuracy bounds and truncation. Focused tests first accepted
malformed correctly signed tokens. Multiple timestamps remain unsupported;
existing CMS duplicate-attribute failure precedence is preserved. See
[profile, limits and evidence](../../docs/timestamp-profile.md).

## TIME-T001 fix: Define lifetime-signing and time-boundary rules

[PR #43](https://github.com/goatwu1993/rssig/pull/43).

A leaf with the
lifetime-signing EKU is validated at the validation time instead of its
timestamp, and must also be valid (leaf and intermediates notBefore) at the
signing time; the intermediate check runs during path building so a
rolled-over issuer valid at both times is still selected.
`TrustReport.lifetime_signing` reports this. Certificate-path failures add
`lifetime_signing` (and, when timestamped, `signing_time`) details; CRL
loading and freshness errors do not. The rule lives in the shared trust path
(all formats, nested signatures and RDP). Added 32 deterministic signed
fixtures and 3 CRLs, 47 portable cases and 37 named CLI tests: paired expired
signer with and without the EKU (RFC 3161 and PKCS#9; PE, nested PE and RDP),
rolled-over/late intermediates and keyCertSign precedence (across and within
paths), revocation through an intermediate, the inclusive signing-time
boundary, lifetime notAfter/notBefore,
leaf/intermediate whole-second and fractional notAfter/notBefore, and
untimestamped/timestamp validation-time boundaries. Before the change, the lifetime fixtures were
accepted at the timestamp time. Non-lifetime boundaries already matched and
are pinned. Signer, TSA, anchor and CRL time rules:
[validation time](../../docs/validation-time.md). Full locked tests, fmt, Clippy,
verify-core/verify/cli feature tests and bare-metal verify-core Clippy pass on
macOS. Dependencies are unchanged; Linux runtime validation remains in CI.
Review items decided against or deferred are recorded in TIME-T002.

## CRL-T003 fix: Select CRLs against the selected chain, not every candidate

Done in PR #60: CRLs are evaluated per certificate on each candidate path,
authenticated under the issuer key that path uses, and the scope rule applies
to that certificate only. Original notes follow.
Deliberately skipped in PRs #44 to #46. CRL applicability currently matches
each CRL's issuer name (and AKI) against every configured root and every
embedded candidate certificate, not the path webpki selects. An untrusted
embedded certificate can therefore make a stale CRL count as applicable and
reject the request (fail closed). A CRL is also not tied to the specific
certificate that issues it. Move applicability into path building, or
re-check it against the selected chain, with paired fixtures.
The distribution-point scope rule (PR #48) has the same shape: it rejects a
CRL that names a point when any embedded candidate issued under the CRL's
issuer name lists no cRLDistributionPoints, whether or not that candidate is
on the selected path. It tests only for the extension's presence and treats
an undecodable issuingDistributionPoint as naming a point. No fixture has an
off-path candidate.

## CRL-T008 fix: Revisit revocation_unknown precedence over path errors

Done in PR #60: with no applicable CRL the path is still built, so an
untrusted chain is `untrusted_root` and, with `--fetch-crls`, nothing is
requested for it (`crl-011-fetch-untrusted-chain-requests-nothing`). Original
notes follow.
Deliberately kept in PR #44. When no supplied CRL applies, revocation_unknown
is returned before path building, so it hides untrusted_root and other chain
errors. This extends the existing empty-CRL-set precedence. Revisit together
with TIME-T002's error-precedence notes if consumers need the chain error first.

## CRL-T009 fix: Bind listed-serial revocation to the verified path

Done in PR #60: a listing counts only in a CRL that verifies under the path
issuer's key, from an issuer with cRLSign (anchors exempt); an unmappable
signature algorithm is `invalid_crl` (`unsupported_signature_algorithm`), and
a listing in an authenticated CRL counts even if its authorityKeyIdentifier
is malformed. Later in PR #60 the listing rule was narrowed to follow
OpenSSL and Bouncy Castle: it counts only from a current CRL that covers
the certificate and is at least as new as the deciding CRL (see
`docs/tasks/crl-t001.md`, "Case reasons"). Original notes follow. From PR
#48 and #49 reviews. The "revoked in any applicable CRL" check in the path
callback matches a listing by issuer name and serial only. It accepts a CRL
whose signature verified under any name-matching candidate key, or whose
signature algorithm `signed_by` cannot map (`unwrap_or(true)`), and it does
not require the issuer's cRLSign. With two same-name issuers (key rollover),
the old key's CRL can therefore reject a signer issued under the new key; a
valid signature fails closed as `certificate_revoked` on evidence webpki
would not accept from an authoritative CRL. Count a listing only when the
CRL verifies under the issuer key the path uses and that issuer may sign
CRLs (anchors exempt, per PATH-T001), and decide whether an applicable CRL with
an unmappable signature algorithm is `invalid_crl`. With that binding, on
webpki's unknown status re-run path building without webpki revocation and
apply the same check to every path certificate, so a signer or intermediate
listed only by a non-authoritative CRL reports `certificate_revoked`
(PR #49 tried this for the signer alone by rewriting the final error and
reverted it). Identify the listing CRL in `details` instead of reusing
webpki's `CertRevoked` message. Paired fixtures: same-name rollover issuers,
an issuer without cRLSign, an unmappable algorithm.

## PE-T001 fix: Follow up on generic PE digest correctness

PR #21.

Validate header,
section, and EOF certificate-table ranges before updating the digest sink.
Verification now calls the generic function and shares byte selection with
`Pe::authenticode_chunks`; initial gaps and overlay are hashed once. Covered
by committed gap/overlay and certificate-range fixtures, portable cases,
named CLI tests, and external-view bounds/unchanged-sink regressions in
`tests/parse_core.rs`. Full locked tests, fmt, Clippy, parser-only tests, and
`thumbv7em-none-eabi` no-default-features check pass on macOS; Linux runs in CI.
Arbitrary PE layouts remain unsupported.

## LIB-T001 feat: Expose CAB and NAVX parsing on `no_std + alloc`

[PR #23](https://github.com/goatwu1993/rssig/pull/23).

Added `parse::Cab` and `parse::Navx` with typed structural errors, borrowed
signature bytes, and borrowed digest chunks. `verify_parsed_cab` and
`verify_parsed_navx` reuse the layouts with the existing verification pipeline;
byte-oriented entry points, framing rules, failure order, and trust policy
remain unchanged. Public API tests first failed on the missing exports.
Added paired framing/digest fault fixtures, manifest provenance, portable cases,
named CLI checks, parser bounds tests, and corpus-wide parsed/byte API parity
across five policies. All 678 specification reports matched exactly before
and after extraction. Full locked tests, fmt, Clippy, no-default/std/verify/cli
feature tests, and `thumbv7em-none-eabi` no-default Clippy passed on macOS.
Parser dependency graph has no verifier, CLI, or native-root dependencies;
dependency versions are unchanged. Linux runtime validation runs in CI.

## LIB-T002 feat: Expose structured CMS signer and attribute inspection

[PR #24](https://github.com/goatwu1993/rssig/pull/24).

Added borrowed `SignerInfo`, `SignerIdentifier`, `Attribute`, `Attributes`, and
`Content` views, standalone algorithm parsing, and `SignedData::content()`.
Unknown OIDs/parameters and original DER remain available. Shared algorithm,
signer framing and attribute helpers run at the existing verification stages;
algorithm support and trust remain verifier checks. Added committed paired CMS
fixtures, portable cases, named CLI checks, and parser-only API/bounds tests;
API tests first failed on missing exports. All 678 previous specification
reports compared exactly equal; the full suite now covers 682 portable cases.
Full locked tests, fmt, Clippy, no-default/std/verify/cli feature tests, and
`thumbv7em-none-eabi` no-default Clippy pass on macOS. Dependencies are unchanged;
parser-only dependencies exclude verifier/CLI/native roots. Linux runs in CI.
Self-review added long/short unknown attribute OID preservation independent of
the fixed-size OID adapter, plus a malformed-encoding counterpart.
Nested signatures/timestamps remain opaque for LIB-T003; CLI schema is unchanged.

## LIB-T003 feat: Add bounded nested-signature and timestamp inspection

Added
`SignedData::inspect` with borrowed nested CMS, RFC 3161 TSTInfo and PKCS#9
countersigner views on `no_std + alloc`. One consumable budget covers siblings,
timestamp edges, decoded objects, input bytes, and DER nodes; depth has a hard
cap of eight. Parsed time assertions preserve exact fractional digits and DER
without authentication or trust claims. The verifier shares time decoding.
`parse` always includes bounded Serde inspection metadata; verification policy
remains unchanged. Added paired malformed-time and depth
fixtures, provenance/digests, seven portable cases, named CLI/domain assertions,
and borrowing, budget-sharing, truncation, depth, and unauthenticated-input tests.
Focused tests first failed on missing APIs and default recursive inspection.
Full locked tests, fmt,
Clippy, no-default/std/verify/cli feature tests and bare-metal no-default Clippy
pass on macOS. Dependencies are unchanged; Linux validation remains in CI.

## LIB-T004 refactor: Extract script and RDP parsing boundaries

Added public
`parse::Powershell`, `Wsh`/`WshKind`, `Rdp`, `TextEncoding`, and parser-only RDP
settings/value types. Models borrow exact stored bytes, expose decoded bodies,
signatures and canonical hash inputs, and keep RDP scope membership explicit
without authentication claims. Verifiers consume these same parsers and stream
script hash input through generic RustCrypto sinks. WSF XML validation is an
isolated optional `xml` adapter that also builds on `no_std + alloc`; without
that feature WSF fails closed. PowerShell XML comments need no XML library.
Reused committed independent script/RDP fixtures and their narrow mutations,
linked six additional portable cases in the manifest, and added named CLI and
parser-only tests for bytes, BOMs, Unicode, offsets, scope coverage, truncations,
typed errors and XML gating. API tests first failed on missing exports. All
689 previous specification reports compared exactly equal; the suite now has
695 cases. Full locked tests, fmt, Clippy, no-default/xml/std/verify/cli tests,
and no-default bare-metal Clippy with XML pass on macOS. Dependency versions
are unchanged; parser graphs have no verifier/CLI/native-root or native-crypto
dependencies. Linux runtime validation remains in CI.

## LIB-T005 refactor: Extract MSI/MSP and AppX structural state

Added public
`parse::Msi`, `Appx`, ZIP part/component input and lazy block-map views behind
explicit `msi`/`appx` std adapter features, independent of verification and
reports. MSI generic RustCrypto sinks expose canonical metadata/content;
extended-digest checks remain in verification. Immutable AppX structures
never accumulate digest evidence or reports. Added borrowed reusable
`verify_parsed_msi`/`verify_parsed_appx` entry points, retaining extended
metadata, publisher binding, bundle identity/child signer rules, check order,
and catalog `signature_verified: false`. Reused committed fixtures and
provenance, linked four additional portable cases, and added named CLI/domain
and parser-only tests for borrowing, repeated hash input, policy reuse,
malformed/unsupported data, XML/ZIP/DEFLATE, and SHA-256/384/512. API tests
first failed on missing exports; all 695 previous complete specification
reports compare exactly equal (699 cases now). Full locked tests, fmt,
Clippy, minimal/xml/std/msi/appx/verify/cli tests, adapter-only Clippy and
bare-metal minimal/XML Clippy pass on macOS. Dependency versions are unchanged;
adapter normal graphs contain no verifier/CLI/native-root or native-crypto
dependencies. Linux runtime validation remains in CI. See
[library boundaries](../../docs/library.md#msimsp-and-appx-structural-adapters).

## LIB-T006 feat: Make format selection consistent for library callers

Exposed
`format::Format`, filename-only `format::detect`, `verify_with_hint`, and
`verify_as` under the existing verifier feature. The CLI uses the shared
detection table, retaining non-UTF-8 stem handling, binary-magic precedence,
text ambiguity and historical PE fallback. Added CAB/NAVX inspection using
the existing unverified CMS report contract, two portable cases linked to
committed fixtures, named CLI/domain assertions, and public selector tests.
Focused tests first failed on missing APIs and unsupported CLI selectors.
MSI/AppX and text/RDP CLI inspection await format-specific report contracts;
parser-only callers retain explicit constructors. Full locked tests (701 spec
cases), fmt, default Clippy, verifier-only selector tests, and bare-metal
parser Clippy pass on macOS. Linux execution remains in CI. Dependencies are
unchanged. See docs/library.md.

## LIB-T007 feat: Clarify verification policy construction

Added explicit
`VerifyOptions::trusted`, `trusted_with_revocation`, and `integrity_only`
constructors with required caller-supplied time and SHA-1 disabled by default.
Trusted construction requires local CRLs unless `RevocationPolicy::Disabled`
is explicitly selected. Constructors perform no I/O or clock/root loading;
CLI policy construction now uses them. Documented legacy struct literals,
ignored revocation flags without trust, and CLI flag conflicts. Reused committed
fixtures in three portable policy cases, named CLI serialized-field checks,
and API tests for absent CRLs, empty roots, policy flags and legacy behavior.
API tests first failed on missing constructors. Full locked tests (704 spec
cases), formatting, all-target Clippy, verifier-only policy tests and bare-metal
parser Clippy pass on macOS. Dependencies are unchanged; Linux execution remains
in CI. See docs/library.md.

## LIB-T008 refactor: Audit borrowing, errors, and public API stability

Documented
ownership, consuming/reusable parsed entry points, repeated verification after
policy failures, stable parser error kinds, and source-compatible migration.
The dispatcher borrows PE/CAB/NAVX/AppX CMS buffers; measured signature payload
copying drops from 1142/1136/1169/1293 bytes to zero on committed good fixtures.
CMS adapters move decoded certificate storage and signers borrow selected
certificates, guarded by pointer-identity tests. Added optional typed root/CRL/
native-root loading methods without changing policy (the loaders have since
been retyped to `TrustLoadError`; see the docs/library.md migration notes);
remaining copies and loading limits are explicit in docs/library.md.
Reused committed fixtures/provenance, added a repeated-file portable case and
named CLI/domain checks. Signer borrowing first failed its pointer assertion;
loader API tests first failed on missing exports. All 704 prior complete
specification reports compare exactly equal (705 cases now). Full locked
tests, fmt, all-target Clippy, minimal/xml/std/msi/appx/verify/cli tests and
bare-metal minimal/XML Clippy pass on macOS. Dependencies are unchanged;
normal default/parser graphs retain the pure-Rust crypto boundary. Linux
runtime validation remains for CI. See [library notes](../../docs/library.md#ownership-reuse-and-api-stability-lib-t008).

## LIB-T009 feat: Evaluate a `no_std` shared verification core

Added additive
`verify-core` with alloc-only RustCrypto/webpki, CMS/trust/CRLs, timestamps,
reports and PE/CAB/NAVX/script/RDP dispatch. Existing `verify` keeps MSI/AppX
and std; those adapters remain separately gated. CLI path handling stays in
the CLI. Reused committed good/bad fixtures, added a portable policy case,
named CLI check and core tests. Focused test first failed on the absent feature.
Bare-metal Clippy and host core tests exercise more than parser-only support;
full locked tests (706 spec cases), fmt and all-target Clippy pass on macOS.
Linux execution remains in CI; no device execution or Windows policy
equivalence is claimed. See
[inventory and limits](../../docs/library.md#shared-verification-without-std-lib-t009).

## LIB-T010 docs: Reassess shared interfaces and crate extraction after reuse

Reviewed PE/CAB/NAVX, CMS, scripts, RDP and host adapter consumers. Retained
concrete parser APIs, RustCrypto sinks, private container dispatch and the
feature-separated package/facade. Documented parser/verifier/CLI and per-format
crate alternatives, additive feature limits, extraction coupling, packaging,
reconsideration triggers and future source-compatible migration requirements.
No runtime or public API changes. See the
[architecture decision](../../docs/library-architecture.md).

## TEST-T001 test: Maintain a coverage inventory by invariant

Map supported
formats, algorithms, policy modes, trust/timestamp paths, and stable errors to
existing cases. Identify missing good/bad pairs and independent producers;
copied format cases are not new cryptographic evidence. Add meaningful gaps
with exact domain assertions and pinned inputs, time, roots, and CRLs.
Added `tests/coverage-inventory.json`, validated case/error references and
`docs/coverage-inventory.md` with explicit path-check/algorithm/producer gaps.
Closed CRL provider-call coverage gaps with exact portable request traces
and offline/supplied-good/supplied-stale cases using existing fixtures.

## BUILD-T001 test: Add local parser and verifier fuzz targets

Start with DER,
PE/CMS, CAB/NAVX, script blocks, and archive/XML framing; seed with committed
fixtures. Exercise bounded verification with fixed policy where useful.
Minimize failures into committed regression fixtures/spec cases. Keep the
fuzzing toolchain optional and separate from ordinary `cargo test --locked`.
Added ten cargo-fuzz targets in the detached `fuzz/` crate covering every
listed parser, integrity-only verification, and configured-root trust with
fuzzed artifacts and fuzzed roots/CRLs, all at a fixed time. `fuzz/targets.txt`
is the single target list; committed fixtures seed a git-ignored corpus.
`make fuzz` runs locally and in CI (short on pull requests, longer weekly with
a cached corpus); `make lint` checks target/lockfile consistency and lints the
crate. Initial runs found no failures, so no regression fixtures were added.
[Targets, limits, maintenance and recorded runs](../../docs/fuzzing.md).
CRL retrieval is not fuzzed; a differential oracle remains separate work.

## TEST-T004 test: Strengthen fixture-manifest consistency checks

Beyond current
SHA-256 verification, validate byte counts, unique/safe paths, provenance/license
fields, case references, and unlisted or missing artifacts. Define intentional
exceptions for diagnostic JSON and helper data. Maintenance generation remains
explicit and requires review of changed binary artifacts.
Done in `tests/manifest.rs`; rules, exceptions, and what is not enforced are in
[manifest consistency](../../docs/testing.md#manifest-consistency).

## CRL-T030 feat: Add bounded opt-in CRL retrieval

Added certificate CRL
discovery, an injected `CrlSource`, and CLI `--fetch-crls` with bounded HTTP
retrieval. Authenticate signatures and configured-root paths before fetching,
then require full revocation validation with shared work budgets. Offline
defaults remain unchanged; report response provenance without claiming each
artifact verified. Destination checks, redirects, deadlines, response sizes
and aggregate limits are documented in `docs/crl-retrieval.md`. Tests use
committed fixtures and injected responses, never external network services.

## RDP-T001 fix: Keep the outer error's causes on the RDP revocation fallback

When a revocation was another error type's source, the merged usage failure
lost the outer error's cause messages. The fallback in
`choose_usage_failure` (`src/rdp.rs`) now sets `causes` to the whole error
chain, as `VerificationError::from_internal` does. Covered by the unit test
`a_revocation_that_is_another_errors_source_keeps_the_outer_causes`.
