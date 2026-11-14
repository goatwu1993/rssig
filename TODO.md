# Prioritized roadmap

Maintained against the merged [PR #21](https://github.com/goatwu1993/rssig/pull/21)
baseline. **The next scoped implementation is evaluating a `no_std` shared verification
core (LIB-09).** Confirmed correctness regressions take priority over planned
refactoring. New algorithms, formats, and network access require their own
evidence and policy decisions; this list does not promise every Windows behavior.

Unchecked audit items identify work to investigate or validate, not confirmed
vulnerabilities. Inventory existing implementation and tests before adding
coverage. SHA-256/384/512, RSA PKCS#1 v1.5, ECDSA P-256/P-384, nested signatures,
timestamps, and local CRL validation already exist.

## Maintenance and completion rules

- Update this file alongside implementation PRs. Keep task IDs stable, record
  completion evidence or a PR link, and split work that no longer fits one PR.
- Follow [AGENTS.md](AGENTS.md): committed fixture and manifest provenance,
  declarative case, named in-process Rust test, observed intended failure, then
  implementation. Ordinary tests never regenerate fixtures or execute them.
- Preserve configured-root trust, fail-closed revocation, verification order,
  explicit integrity-only policy, and stable typed JSON diagnostics. New schema
  fields require specification cases and serialized-domain assertions first.
- Completion requires focused tests, `cargo test --locked`, formatting, Clippy,
  documentation, and applicable feature/target checks. Record platforms or checks
  not run. Coverage alone is not correctness evidence.
- Keep production cryptography pure Rust. The OS may enumerate roots only;
  implementation references are never build/runtime dependencies. Normal tests
  remain offline and independent of wall time, OS roots, and external verifiers.
- Keep intentionally unsupported behavior documented. Deferred work remains
  deferred until explicitly resumed; passing fixtures is not Windows policy parity.

## P0 — Verification correctness and bounded work

- [x] **SEC-01: Audit arithmetic and structural bounds across every parser.**
  Cover PE/CFB/CAB/NAVX/ZIP offsets, DER lengths, script encodings, RDP framing,
  and XML counts. Exercise truncations, zero/maximum counts, overlapping ranges,
  inconsistent lengths, and 32-bit conversions. Extend PR #18's maximum-offset
  regression; malformed input must return typed errors without panics or
  unchecked allocations. Completed the structural audit and fixes with
  [bounds evidence and limits](docs/parser-bounds.md), a DER regression fixture,
  CAB extreme-offset tests, and cross-format header mutation coverage. Aggregate
  budgets, host reads, fuzzing, and 32-bit execution remain separate tasks.
- [x] **SEC-02: Enforce aggregate verification budgets.** Added one consumable
  per-file budget across certificate-table entries, every signer, nested CMS,
  timestamps, RDP and embedded bundle children. Limits cover decoded/hash bytes,
  certificate candidates and report copies, reports, nesting, path search and
  RustCrypto signature operations; exhaustion returns typed details with no
  partial success. [Inventory, limits and evidence](docs/verification-budgets.md)
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
  Host reads and CLI batch/report buffering are covered by SEC-03.
- [x] **SEC-03: Bound host input and report memory.** Added bounded streaming
  reads for CLI inputs and root/CRL files, per-file and batch byte/report limits,
  path/count limits, and regular-file checks after nonblocking opens. Successful
  reports are counted before retention; bounded failure reserves preserve one
  JSON document and ordered per-file outcomes. [Host limits](docs/host-limits.md)
  document defaults, lowering options, native-root enumeration boundaries and
  conservative failed-read reservations. Portable cases reuse committed fixtures;
  named CLI and unit tests cover oversized sparse files, growing/short streams,
  nonregular inputs, exact EOF, batch exhaustion and oversized failure evidence.
  Full locked tests, fmt, Clippy, CLI-without-system-roots tests and bare-metal
  verify-core Clippy pass on macOS. Dependency review found only a direct optional
  CLI edge to the already-locked libc version for O_NONBLOCK; no native crypto.
  Linux runtime validation remains in CI. Automatic CRL/AIA fetching is FEATURE-01.
- [x] **SEC-04: Audit CMS structure and signature binding.** Checked
  SignedData/SignerInfo versions, supported signer identifiers, canonical
  INTEGER/SET encodings, duplicate/empty attributes, digest-set membership,
  algorithm parameters, and contentType/messageDigest binding. Preserve exact
  signed bytes; never normalize malformed signed encodings into valid ones.
  Keep RDP direct-signature allowances out of Authenticode/countersignatures.
  Added version, signed-value ordering and ECDSA-parameter rejection, paired
  fixtures and signature-math assertions. `docs/cms-security.md` records the
  audit and explicit legacy/opaque-encoding compatibility boundaries.
- [x] **SEC-05: Define ambiguous signer-certificate handling.** Cover duplicate
  certificates, identical issuer/serial identifiers with different keys, missing
  signer certificates, and reordered candidate sets. Ensure candidate selection
  cannot accidentally trust embedded certificates or depend on a permissive
  first match. Identical certificates are accepted as duplicate candidates;
  distinct matches fail with `ambiguous_signer_certificate` before crypto/trust
  selection. Paired/reordered fixtures cover different keys, same-key identity
  conflicts and missing signers. Shared-path tests cover RFC3161, countersigners
  and direct RDP signatures. Policy: `docs/cms-security.md`.
- [ ] **SEC-06: Expand certificate-path policy coverage.** Inventory current
  leaf/intermediate EKU and KeyUsage tests, then cover BasicConstraints, path
  length, name constraints, unknown critical extensions, alternative/cross-signed
  paths, cycles, and same-subject/different-key issuers. Assert selected chains
  and typed failures. Document webpki's applicable profile and trust-anchor
  validity/constraint treatment without claiming complete Windows policy.
- [ ] **SEC-07: Make root/CRL loading diagnostics explicit.** Audit unsupported
  anchors skipped during conversion, mixed valid/invalid PEM bundles, duplicates,
  empty stores, and partial native-root loading failures. Decide whether each
  load is atomic and how exclusions are surfaced. Loading artifacts must never
  imply that a signature or supplied CRL was verified.
- [ ] **SEC-08: Complete timestamp structure and multiplicity tests.** Validate
  the whole supported TSTInfo shape, including version, policy/serial fields,
  optional-field ordering, and unknown fields. Cover duplicate/mixed RFC 3161
  and PKCS#9 timestamps, TSA EKU criticality/exclusivity, KeyUsage, parent-signature
  substitution, and malformed signingTime. Preserve multiple-timestamp rejection
  until an explicit selection policy has its own tests.
- [ ] **SEC-09: Define lifetime-signing and time-boundary policy.** Add an
  expired signer with lifetime-signing EKU and an otherwise valid timestamp;
  enforce supported semantics or reject the unsupported policy. Extend existing
  fractional-time fixtures to selected intermediates, notBefore/notAfter, and
  validation-time boundaries. Keep exact decimal precision and document signer,
  TSA, trust-anchor, and current-CRL time policies separately.
- [ ] **SEC-10: Audit CRL applicability and competing evidence.** Cover absent
  nextUpdate, issuer/AKI mismatch, cRLSign usage, revoked intermediates, incomplete
  issuer coverage, distribution-point scope, unknown critical extensions,
  delta/indirect CRLs, and competing or unrelated supplied CRLs. Specify whether
  an unusable extra CRL rejects a request or is excluded. Never silently treat
  unknown status as good; pin freshness boundaries and unsupported-policy errors.
- [ ] **SEC-11: Report CRL evidence actually used.** Distinguish supplied artifacts
  from CRLs authenticated and used for each selected chain. Include affected
  certificates/CRLs in structured failures. Preserve conservative rejection when
  a current CRL lists a signer even after its signing time; historical good status
  requires separate evidence and policy.
- [ ] **SEC-12: Audit multi-signature and bundle failure semantics.** Pin current
  all-required-signatures policy, primary/nested ordering, first-failure
  precedence, and bundle/child identity and signer binding. Test a valid first
  signature followed by a bad one and the reverse. Later parsing failures must
  not mask earlier cryptographic failures during refactoring.
- [ ] **SEC-13: Complete cryptographic algorithm invariant coverage.** Inventory
  existing SHA-384/512 and P-384 cases before adding missing key/digest/signature
  combinations. Cover malformed RSA/ECDSA encodings, weak and excessive key
  sizes, incompatible OIDs/parameters, and certificate/CRL algorithm mismatches.
  Keep SHA-1 content opt-in separate from unsupported SHA-1 chains; weak RSA must
  remain rejected even with `--allow-sha1`.

## P1 — Clean parse/verify interfaces

- [x] **PE generic digest correctness follow-up (PR #21).** Validate header,
  section, and EOF certificate-table ranges before updating the digest sink.
  Verification now calls the generic function and shares byte selection with
  `Pe::authenticode_chunks`; initial gaps and overlay are hashed once. Covered
  by committed gap/overlay and certificate-range fixtures, portable cases,
  named CLI tests, and external-view bounds/unchanged-sink regressions in
  `tests/parse_core.rs`. Full locked tests, fmt, Clippy, parser-only tests, and
  `thumbv7em-none-eabi` no-default-features check pass on macOS; Linux runs in CI.
  Arbitrary PE layouts remain unsupported.

- [x] **LIB-01: Expose CAB and NAVX parsing on `no_std + alloc` ([PR #23](https://github.com/goatwu1993/rssig/pull/23)).**
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
- [x] **LIB-02: Expose structured CMS signer and attribute inspection ([PR #24](https://github.com/goatwu1993/rssig/pull/24)).**
  Added borrowed `SignerInfo`, `SignerIdentifier`, `Attribute`, `Attributes`, and
  `Content` views, standalone algorithm parsing, and `SignedData::content()`.
  Unknown OIDs/parameters and original DER remain available. Shared algorithm,
  signer framing and attribute helpers run at the existing verification stages;
  algorithm support and trust remain verifier policy. Added committed paired CMS
  fixtures, portable cases, named CLI checks, and parser-only API/bounds tests;
  API tests first failed on missing exports. All 678 previous specification
  reports compared exactly equal; the full suite now covers 682 portable cases.
  Full locked tests, fmt, Clippy, no-default/std/verify/cli feature tests, and
  `thumbv7em-none-eabi` no-default Clippy pass on macOS. Dependencies are unchanged;
  parser-only dependencies exclude verifier/CLI/native roots. Linux runs in CI.
  Self-review added long/short unknown attribute OID preservation independent of
  the fixed-size OID adapter, plus a malformed-encoding counterpart.
  Nested signatures/timestamps remain opaque for LIB-03; CLI schema is unchanged.
- [x] **LIB-03: Add bounded nested-signature and timestamp inspection.** Added
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
- [x] **LIB-04: Extract script and RDP parsing boundaries.** Added public
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
- [x] **LIB-05: Extract MSI/MSP and AppX structural state.** Added public
  `parse::Msi`, `Appx`, ZIP part/component input and lazy block-map views behind
  explicit `msi`/`appx` std adapter features, independent of verification and
  reports. MSI generic RustCrypto sinks expose canonical metadata/content;
  extended-digest checks remain in verification. Immutable AppX structures
  never accumulate digest evidence or reports. Added borrowed reusable
  `verify_parsed_msi`/`verify_parsed_appx` entry points, retaining extended
  metadata, publisher binding, bundle identity/child signer policy, check order,
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
  [library boundaries](docs/library.md#msimsp-and-appx-structural-adapters).
- [x] **LIB-06: Make format selection consistent for library callers.** Exposed
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
- [x] **LIB-07: Clarify verification policy construction.** Added explicit
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
- [x] **LIB-08: Audit borrowing, errors, and public API stability.** Documented
  ownership, consuming/reusable parsed entry points, repeated verification after
  policy failures, stable parser error kinds, and source-compatible migration.
  The dispatcher borrows PE/CAB/NAVX/AppX CMS buffers; measured signature payload
  copying drops from 1142/1136/1169/1293 bytes to zero on committed good fixtures.
  CMS adapters move decoded certificate storage and signers borrow selected
  certificates, guarded by pointer-identity tests. Added optional typed root/CRL/
  native-root loading methods without changing legacy signatures or policy;
  remaining copies and loading-policy limits are explicit in docs/library.md.
  Reused committed fixtures/provenance, added a repeated-file portable case and
  named CLI/domain checks. Signer borrowing first failed its pointer assertion;
  loader API tests first failed on missing exports. All 704 prior complete
  specification reports compare exactly equal (705 cases now). Full locked
  tests, fmt, all-target Clippy, minimal/xml/std/msi/appx/verify/cli tests and
  bare-metal minimal/XML Clippy pass on macOS. Dependencies are unchanged;
  normal default/parser graphs retain the pure-Rust crypto boundary. Linux
  runtime validation remains for CI. See [library notes](docs/library.md#ownership-reuse-and-api-stability-lib-08).
- [x] **LIB-09: Evaluate a `no_std` shared verification core.** Added additive
  `verify-core` with alloc-only RustCrypto/webpki, CMS/trust/CRLs, timestamps,
  reports and PE/CAB/NAVX/script/RDP dispatch. Existing `verify` keeps MSI/AppX
  and std; those adapters remain separately gated. CLI path handling stays in
  the CLI. Reused committed good/bad fixtures, added a portable policy case,
  named CLI check and core tests. Focused test first failed on the absent feature.
  Bare-metal Clippy and host core tests exercise more than parser-only support;
  full locked tests (706 spec cases), fmt and all-target Clippy pass on macOS.
  Linux execution remains in CI; no device execution or Windows policy
  equivalence is claimed. See
  [inventory and limits](docs/library.md#shared-verification-without-std-lib-09).
- [x] **LIB-10: Reassess shared interfaces and crate extraction after reuse.**
  Reviewed PE/CAB/NAVX, CMS, scripts, RDP and host adapter consumers. Retained
  concrete parser APIs, RustCrypto sinks, private container dispatch and the
  feature-separated package/facade. Documented parser/verifier/CLI and per-format
  crate alternatives, additive feature limits, extraction coupling, packaging,
  reconsideration triggers and future source-compatible migration requirements.
  No runtime or public API changes. See the
  [architecture decision](docs/library-architecture.md).

## P1 — Tests, portable specification, and engineering checks

- [x] **TEST-01: Maintain a coverage inventory by invariant.** Map supported
  formats, algorithms, policy modes, trust/timestamp paths, and stable errors to
  existing cases. Identify missing good/bad pairs and independent producers;
  copied format cases are not new cryptographic evidence. Add meaningful gaps
  with exact domain assertions and pinned inputs, time, roots, and CRLs.
  Added `tests/coverage-inventory.json`, validated case/error references and
  `docs/coverage-inventory.md` with explicit path-policy/algorithm/producer gaps.
  Closed CRL provider-call coverage gaps with exact portable request traces
  and offline/supplied-good/supplied-stale cases using existing fixtures.
- [ ] **TEST-02: Add local parser and verifier fuzz targets.** Start with DER,
  PE/CMS, CAB/NAVX, script blocks, and archive/XML framing; seed with committed
  fixtures. Exercise bounded verification with fixed policy where useful.
  Minimize failures into committed regression fixtures/spec cases. Keep the
  fuzzing toolchain optional and separate from ordinary `cargo test --locked`.
- [ ] **TEST-03: Extend invariant and mutation testing.** Verify that excluded
  checksum/signature fields and authenticated payload/metadata mutate as
  documented, and that digest, CMS, timestamp, and trust faults stay isolated.
  Use generated inputs for structural properties, never to regenerate expected
  fixture results during ordinary tests or hide target failures behind setup errors.
- [ ] **TEST-04: Exercise 32-bit behavior and independent consumers.** Current
  bare-metal checks compile the parser but do not execute it there. Add a
  practical 32-bit execution path for bounds regressions and tiny external
  consumer builds that avoid dev-dependency feature unification. Cover minimal,
  `std`, verifier-only, native-root, and CLI feature combinations and doctests.
- [ ] **TEST-05: Validate the specification and schemas together.** Check
  `cases.json` against `cases.schema.json` in the Rust workflow, reconcile schema
  rules with the Serde loader, and detect invalid references or duplicate IDs.
  Audit whether public verification/inspection report schemas suffice for another
  implementation; add missing schema detail before extending output.
- [ ] **TEST-06: Strengthen fixture-manifest consistency checks.** Beyond current
  SHA-256 verification, validate byte counts, unique/safe paths, provenance/license
  fields, case references, and unlisted or missing artifacts. Define intentional
  exceptions for diagnostic JSON and helper data. Maintenance generation remains
  explicit and requires review of changed binary artifacts.
- [ ] **TEST-07: Automate complete-output compatibility comparisons.** Preserve
  PR #18's in-process comparison approach for refactors: exit codes, complete
  JSON, stdout, and stderr. Normalize only unavoidable checkout paths, never
  security-relevant fields. Keep portable partial expectations and add exact
  snapshots/assertions where they protect schema, ordering, or diagnostic causes.
- [ ] **TEST-08: Automate dependency and native-code boundary checks.** Inspect
  resolved normal dependencies/features on Linux/macOS and minimal builds.
  Reject OpenSSL, ring, aws-lc, native validation, and subprocess crypto; examine
  build scripts/linkage as well as package names. Allow native root enumeration
  explicitly. Add dependency advisory/license review without making offline
  fixture tests require network access.
- [ ] **TEST-09: Improve CI evidence and regression visibility.** Keep existing
  Linux/macOS, lint, coverage, and no_std jobs. Surface missing fixture/schema
  checks and relevant uncovered production branches; distinguish the thin
  process adapter from in-process engine coverage. Evaluate a coverage regression
  policy after measuring the baseline, without redundant tests or exclusions
  that hide production code.
- [ ] **TEST-10: Measure performance and allocation budgets.** Benchmark parsing,
  hashing, CMS verification, candidate-chain work, CRLs, and bundles separately
  on representative sizes and adversarial bounded inputs. Track peak memory and
  repeated metadata conversion. Consider streaming/caching or batch parallelism
  with measured benefit, immutable input, bounded work, and deterministic results.

## P1 — CLI, reporting, and distribution

- [ ] **PRODUCT-01: Make remaining failure classifications precise.** Audit
  generic anyhow conversions for unsupported structures, invalid certificates,
  root/CRL loading, timestamps, and exhausted limits. Preserve stable code/stage,
  structured context, and causes. Test conversion from every parser error kind
  and avoid requiring consumers to match prose.
- [ ] **PRODUCT-02: Audit file/stream edge cases.** Cover non-UTF-8 paths, path
  serialization failures, directories/unreadable inputs, repeated files, mixed
  batches, and writer/flush failures through in-process CLI entry points. Prevent
  panic paths while preserving one JSON document where output is writable;
  argument/configuration errors remain plain stderr with exit 2.
- [ ] **PRODUCT-03: Document result and schema evolution.** Define compatibility
  rules for new fields, enum variants, optional values, raw DER, and schema
  versions. Make parse-only, integrity-only, trusted, revocation-disabled, and
  package-hashed-but-not-independently-verified catalog states unambiguous.
  Keep supplied artifacts distinct from selected evidence.
- [ ] **PRODUCT-04: Keep public API and policy documentation current.** Add
  compiling examples for parse-only and explicit trusted verification, feature
  combinations, and error handling. Update stale source paths in the comparison
  document; keep format limits, CLI help, README tables, architecture, and tests
  aligned. External comparisons retain pinned revisions and stated evidence limits.
- [ ] **PRODUCT-05: Define compiler, target, and release support.** Choose and
  test an MSRV; distinguish compiled targets/features from runtime-tested ones.
  Check packaged-crate contents and consumer builds, and document semver/API
  migration before publishing. Prepare reproducible Linux/macOS artifacts and
  checksums when distribution is requested; fixture signing keys and read-only
  reference clones must not enter release artifacts.
- [ ] **PRODUCT-06: Document security review and reporting boundaries.** Provide
  vulnerability-reporting and supported-version policies, and identify areas
  needing independent review before stronger security claims. Keep existing
  AI-assisted-development and Windows-policy limitations visible; passing tests
  or high coverage is not an audit or certification.

## P2 — Interoperability and existing-format coverage

- [ ] **INTEROP-01: Expand independently produced fixtures.** Build on existing
  Jsign MSI/MSP/CAB/NAVX/script/AppX, upstream SignTool, and independent RDP
  artifacts. Prioritize independent PE, nested CMS, timestamps, and trusted
  chain/CRL combinations, including Relic where useful. Record producer/version,
  license, provenance, digest, and narrow bad counterparts. Separate integrity-only
  evidence from trusted verification and keep normal tests offline.
- [ ] **INTEROP-02: Record reproducible cross-tool differences.** Pin tools,
  roots, time, algorithms, revocation/network settings, and each verifier's actual
  checks. Resolve disagreements against format evidence and explicit rssig policy,
  then commit portable expectations. A competitor's success exit is not necessarily
  a trusted verdict; competitors remain maintenance tools.
- [ ] **FORMAT-01: Extend PE layout evidence before broadening support.** Cover
  multiple certificate entries, reordered sections, padding, overlays, PE32/PE32+,
  page sizes, and page hashes. Document deliberately rejected gaps/overlaps and
  certificate placement. Evaluate unsigned-PE inspection separately, with an
  explicit API/CLI contract and unchanged unsigned rejection in verification.
- [ ] **FORMAT-02: Audit MSI/MSP CFB and metadata variants.** Extend independent
  v3/v4, stream-name/order, FAT/miniFAT, metadata, and legacy/extended-signature
  coverage. Pin duplicate/aliased signature-stream handling and file-time details.
  New layouts need bounded traversal and hash evidence; MSP applicability,
  installation semantics, and patch authorization remain outside verification.
- [ ] **FORMAT-03: Expand CAB/NAVX envelope interoperability.** Add independent
  reserve/padding/hash-range and envelope/back-pointer cases. Consider CAB layouts
  with unambiguous hashing policy and producer evidence; multipart handling needs
  a separate design. NAVX payloads remain opaque, and signature success does not
  imply extension validity or installability.
- [ ] **FORMAT-04: Expand text signature encoding evidence.** Cover BOM/newline,
  terminator, comment delimiter, Unicode, and duplicate-block behavior across
  PowerShell/XML and WSH. Pin unsupported legacy encodings and encoded-script
  behavior before adding decoders. No script execution, XMLDSig substitution,
  DTD/entity fetching, or script execution-policy claims.
- [ ] **FORMAT-05: Extend RDP scope mappings only with evidence.** Maintain
  display-name/key/type mappings and canonicalization tests. Unknown signed scope
  entries continue to fail; unscoped properties remain explicitly unsigned.
  More settings/encodings or nested signatures need isolated fixtures and a
  documented policy; never open fixtures in an RDP client.
- [ ] **FORMAT-06: Audit AppX edge cases and policy gaps.** Extend
  ZIP64/descriptors, compression/block boundaries, filename collisions, namespace
  parsing, publisher DN comparison, and bundle child identity/signature cases.
  Evaluate Unicode names and additional manifest/bundle profiles individually
  with producer evidence and aggregate budgets. Keep unsupported external/stub/
  nested bundles explicit; deployment selection and Windows Store acceptance
  are not established by package integrity.

## P3 — Additional capabilities requiring separate design

- [x] **FEATURE-01: Add bounded opt-in CRL retrieval.** Added certificate CRL
  discovery, an injected `CrlSource`, and CLI `--fetch-crls` with bounded HTTP
  retrieval. Authenticate signatures and configured-root paths before fetching,
  then require full revocation validation with shared work budgets. Offline
  defaults remain unchanged; report response provenance without claiming each
  artifact verified. Destination checks, redirects, deadlines, response sizes
  and aggregate limits are documented in `docs/crl-retrieval.md`. Tests use
  committed fixtures and injected responses, never external network services.
- [ ] **FEATURE-01-AIA: Add bounded AIA issuer retrieval.** Extend the retrieval
  boundary to missing intermediate certificates, always as untrusted candidates,
  never new trust anchors. Define pre-trust destination discovery, loop/work
  limits and provenance. HTTPS transport and persistent caching also remain
  separate follow-ups requiring policy and dependency review.
- [ ] **FEATURE-02: Add OCSP with explicit evidence policy.** Require responder
  authorization, signature/freshness checks, issuer/serial binding, and tested
  unknown/revoked/error behavior. Define interaction with CRLs, caches, offline
  operation, and timestamped verification. Network failure must not silently
  become good revocation status.
- [ ] **FEATURE-03: Add RSA-PSS where interoperability justifies it.** Specify
  digest/MGF/salt/trailer parameters and policy for CMS, certificates, CRLs, and
  timestamps independently. Add good/bad parameter and key fixtures and audit
  RustCrypto/webpki support; never reinterpret PSS as v1.5.
- [ ] **FEATURE-04: Add catalog signature and membership verification.** Verify
  trusted catalog signatures and target membership separately. Design standalone
  catalogs first, then explicitly wire AppX CodeIntegrity catalogs into reports
  if supported. Until then retain `signature_verified: false` for package-hashed
  embedded catalogs.
- [ ] **FEATURE-05: Design generic detached signature verification.** Specify
  how a sidecar binds to supplied content, format/SIP selection, CMS profile,
  algorithms, trust, timestamps, and revocation. Reuse the engine while keeping
  RDP canonicalization separate. Parsing a `.p7s` alone must never be presented
  as verification of an unspecified file.

## Deferred and outside the current verification scope

- [ ] **DEFER-01: Windows oracle integration remains deferred at the user's
  request.** Do not add a Windows/SignTool/WinVerifyTrust runner as part of these
  tasks. If explicitly resumed, pin tool/OS versions, roots, time, revocation/
  network configuration, and policy differences; replay captured expectations
  locally without native verification in the engine.
- Signing, installation, execution, patch applicability, device/deployment policy,
  Windows-specific trust/distrust lists, and full Windows policy parity are not
  implied by this roadmap. Add them only through a separately agreed scope.

## Completed baseline

- [x] Pure Rust verification for PE, MSI/MSP, CAB, NAVX, PowerShell/XML, WSH,
  signed RDP settings, and AppX/MSIX packages and embedded bundles, within the
  limits in [README.md](README.md) and the format documents.
- [x] Image/package/script/content binding, supported RustCrypto signatures,
  nested Authenticode signatures, RFC 3161/PKCS#9 timestamps, configured-root
  paths, and supplied local CRLs; explicit reduced-policy reports.
- [x] Serializable verification/inspection types, parsed certificate
  CN/RDNs/EKUs/KeyUsage/validity, selected chains, timestamp signer, CRL artifacts,
  opaque DER preservation, and typed Problem Details errors with causes.
- [x] Committed good/bad fixtures with provenance and SHA-256 manifest checks,
  native in-process CLI tests, and the Serde-loaded portable specification.
  Ordinary tests never spawn the product binary or regenerate expected data.
- [x] Linux/macOS tests, formatting, Clippy, coverage artifacts, and specification
  reports. Optional-feature CI includes a bare-metal parser compile check.
- [x] PE/CMS parser and verification responsibility separation, independent
  inspection CLI, and reusable parsed PE verification
  ([PR #17](https://github.com/goatwu1993/rssig/pull/17)).
- [x] `no_std + alloc` PE/CMS parsing, typed parser errors, borrowed signer/digest
  input, and separate verifier/CLI/native-root features
  ([PR #18](https://github.com/goatwu1993/rssig/pull/18)). Full verification
  still requires `std`; see [library notes](docs/library.md).
- [x] Canonical fractional timestamp and opaque CertificateChoices coverage,
  unsupported algorithm diagnostics, and isolated nonzero certificate payload
  and PE maximum-header-offset regressions.
