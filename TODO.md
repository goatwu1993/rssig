# Prioritized roadmap

One short entry per task (AGENTS.md, "Task tracking"): ID, title, checkbox,
and a link to `docs/tasks/` for anything longer. Finished items keep one line
with their PR; their full records are in [docs/tasks/done.md](docs/tasks/done.md).
Confirmed correctness regressions come before planned refactoring. Unchecked
audit items are work to investigate, not confirmed vulnerabilities. New
algorithms, formats and network access need their own evidence and decision
entries ([docs/decisions.md](docs/decisions.md)); completing a task follows the
TDD workflow and checks in AGENTS.md.

## P0 — Verification correctness and bounded work

- [x] **SEC-01: Audit arithmetic and structural bounds across every parser.** Done; [record](docs/tasks/done.md#sec-01-audit-arithmetic-and-structural-bounds-across-every-parser).
- [x] **SEC-02: Enforce aggregate verification budgets.** Done; [record](docs/tasks/done.md#sec-02-enforce-aggregate-verification-budgets).
- [x] **SEC-03: Bound host input and report memory.** Done; [record](docs/tasks/done.md#sec-03-bound-host-input-and-report-memory).
- [x] **SEC-04: Audit CMS structure and signature binding.** Done; [record](docs/tasks/done.md#sec-04-audit-cms-structure-and-signature-binding).
- [x] **SEC-05: Define ambiguous signer-certificate handling.** Done; [record](docs/tasks/done.md#sec-05-define-ambiguous-signer-certificate-handling).
- [x] **SEC-06: Expand certificate-path rule coverage.** Done; [record](docs/tasks/done.md#sec-06-expand-certificate-path-rule-coverage).
- [x] **SEC-07: Make root/CRL loading diagnostics explicit.** Done; [record](docs/tasks/done.md#sec-07-make-rootcrl-loading-diagnostics-explicit).
- [x] **SEC-08: Complete timestamp structure and multiplicity tests.** Done; [record](docs/tasks/done.md#sec-08-complete-timestamp-structure-and-multiplicity-tests).
- [x] **SEC-09: Define lifetime-signing and time-boundary rules ([PR #43](https://github.com/goatwu1993/rssig/pull/43)).** Done; [record](docs/tasks/done.md#sec-09-define-lifetime-signing-and-time-boundary-rules-pr-43httpsgithubcomgoatwu1993rssigpull43).
- [x] **SEC-10: Audit CRL applicability and competing evidence.** Done; detail in [sec-10-crl-applicability.md](docs/tasks/sec-10-crl-applicability.md).
- [ ] **SEC-11: Report CRL evidence actually used.** Distinguish supplied artifacts from CRLs authenticated and used for each selected chain. Detail in [sec-11.md](docs/tasks/sec-11.md).
- [ ] **SEC-12: Add the signature policy and pin multi-signature semantics.**
  Decided: `--signatures all|any`, default `all`; pin ordering, first-failure
  precedence and bundle/child binding. Detail in
  [sec-12.md](docs/tasks/sec-12.md).
- [ ] **SEC-13: Complete cryptographic algorithm invariant coverage.** Inventory
  existing SHA-384/512 and P-384 cases before adding missing key/digest/signature
  combinations. Cover malformed RSA/ECDSA encodings, weak and excessive key
  sizes, incompatible OIDs/parameters, and certificate/CRL algorithm mismatches.
  Keep SHA-1 content opt-in separate from unsupported SHA-1 chains; weak RSA must
  remain rejected even with `--allow-sha1`.
- [ ] **SEC-14: Lifetime-signing review decisions and deferred follow-ups.**
  Recorded from PR #43 reviews; none permits an invalid signature to verify.
  Kept as decisions (change only with a new decision and paired fixtures):
  - Trust anchors: configured anchors remain keys. Their validity is not checked
    at the validation time or at a lifetime signing time, so a lifetime path
    through a root re-issued after the signing time is accepted.
  - Error precedence: the leaf lifetime notBefore check runs before path
    building (like webpki's leaf validity check), so it precedes
    untrusted_root/unknown-issuer and unknown revocation status of the signer
    path. Store-wide CRL freshness errors are still reported first, by the TSA
    check. A rejected issuer issued after signing ranks as a webpki validity
    error, so it can hide a revoked or wrongly signed issuer on another
    candidate path (pinned by `time-011-lifetime-rollover-revoked-issuer`); the
    signature is still rejected. Equal-rank failures report the first
    encountered.
  - CRL/revocation: revocation is evaluated only at the validation time, and a
    revocation failure on a path is reported before the signing-time check of
    that path. Historical (signing-time) revocation status is not modeled.
  - Diagnostics: `details.certificate` names the chain certificate that failed
    the signing-time or fractional-expiry check (an intermediate when it is the
    cause), matching the existing fractional-expiry convention, not always the
    signer leaf. Errors from webpki's own validity checks instead name the leaf
    in `details.certificate` while `not_before`/`not_after` belong to the
    certificate that failed, lifetime or not. This includes a lifetime
    intermediate issued after a timestamp that equals the validation time.
  - Unsigned timestamps: the signing-time check (and the non-lifetime
    timestamp-before-notBefore rejection) is a consistency check. Removing the
    unsigned timestamp leaves an untimestamped signature validated at the
    validation time only.
  - KeyUsage precedence (pre-existing, SEC-06): the keyCertSign rejection flag
    is shared across candidate paths, so once any candidate lacked keyCertSign a
    final unknown-issuer failure from another path is reported as
    invalid_key_usage. Fails closed; a per-path reason needs separate work.
  - Schema: `TrustReport.lifetime_signing` defaults to `false` when reading
    reports written before SEC-09, so an older report cannot distinguish "not
    lifetime-signed" from "not evaluated". `validation_time` shows which time
    was used; `Option<bool>` would be a schema change.
  - Error details: on "not valid at the signing time", `validation_time` is the
    validation time (when the certificate may be valid) and `signing_time` is
    the instant that failed, unlike other validity errors where
    `validation_time` is the failing instant. CRL presence/freshness errors for
    a lifetime signer carry no `lifetime_signing` detail; per-chain revocation
    evidence is SEC-10/11. Both are schema decisions.
  Open follow-ups:
  - Untested fallback: when the certificate report for a late lifetime
    certificate cannot be built, the error carries a free-text
    `certificate_report_error` detail instead of `certificate`. No fixture
    reaches it; it needs a certificate that parses but cannot be reported, or
    a typed detail.
  - Format coverage: lifetime-signing fixtures cover PE (primary and nested)
    and RDP. MSI, CAB, script and AppX signers use the same trust call without
    a lifetime fixture.
  - Fractional expiry (pre-existing): `check_fractional_validity` runs after
    path selection. With a fractional timestamp and two same-subject/key
    issuers, webpki can select the one whose notAfter equals the timestamp's
    whole second, and the signature is then rejected as certificate_expired
    although the other issuer is valid. Move the check into path building, as
    the lifetime signing-time check does, for every timestamped signer and TSA;
    add a paired rollover fixture.
  - Budget: RDP `verify_trust` repeats the full path search, including the
    lifetime leaf check and a 200,000-unit path-work reservation, for each
    accepted leaf EKU. Stop after an EKU-independent failure without changing
    first-policy-error reporting, and pin the budget effect.
  - Test maintenance: share RFC 3161/PKCS#9 token builders across
    `src/tests.rs`, SEC-08/09 and RDP fixture modules without changing committed
    bytes; keep per-task regeneration commands (as SEC-08 does) consistent with
    `regenerate_cli_fixtures`.
- [x] **SEC-15: Select CRLs against the selected chain, not every candidate.** Done; [record](docs/tasks/done.md#sec-15-select-crls-against-the-selected-chain-not-every-candidate).
- [ ] **SEC-16: Tighten AKI/SKI matching edge cases.** Since PR #60 a CRL is authenticated under the issuer key the path uses. Detail in [sec-16.md](docs/tasks/sec-16.md).
- [ ] **SEC-17: Budget and consolidate CRL applicability work.** Deliberately skipped in PRs #44 and #45. Detail in [sec-17.md](docs/tasks/sec-17.md).
- [ ] **SEC-18: Decide unsupported-but-applicable CRL handling.** Partly decided in PR #60: the best CRL decides, as in OpenSSL and Bouncy Castle, so a stale, delta, indirect, unsupported or out-of-scope CRL is set aside when another CRL of the issuer is usable and authoritative (full-plus-delta and old-beside-current deployments verify). Detail in [sec-18.md](docs/tasks/sec-18.md).
- [ ] **SEC-19: Finish CRL rejection reason coverage.** Deliberately skipped in PR #46. Detail in [sec-19.md](docs/tasks/sec-19.md).
- [x] **SEC-20: Revisit revocation_unknown precedence over path errors.** Done; [record](docs/tasks/done.md#sec-20-revisit-revocation_unknown-precedence-over-path-errors).
- [x] **SEC-21: Bind listed-serial revocation to the verified path.** Done; [record](docs/tasks/done.md#sec-21-bind-listed-serial-revocation-to-the-verified-path).
- [ ] **SEC-22: Pass uncovered certificates to retrieval as typed data.** From the PR #60 review. Detail in [sec-22.md](docs/tasks/sec-22.md).
- [x] **SEC-24: Make rssig the only revocation authority.** Done; detail in [sec-24-single-revocation-authority.md](docs/tasks/sec-24-single-revocation-authority.md).
- [ ] **SEC-23: Follow-ups left open by the PR #60 review.** The review of PR #60 was concluded with these items not changed in that PR. Detail in [sec-23.md](docs/tasks/sec-23.md).
- [x] **SEC-25: Narrow CMS-009 to the attributes RFC 5652 limits.** Done ([PR #73](https://github.com/goatwu1993/rssig/pull/73)); [CMS-009](docs/cms.md#cms-009-single-instance-attributes-occur-at-most-once-in-a-signerinfo).

## P1 — Clean parse/verify interfaces

- [x] **PE generic digest correctness follow-up (PR #21)** Done; [record](docs/tasks/done.md#pe-generic-digest-correctness-follow-up-pr-21).

- [x] **LIB-01: Expose CAB and NAVX parsing on `no_std + alloc` ([PR #23](https://github.com/goatwu1993/rssig/pull/23)).** Done; [record](docs/tasks/done.md#lib-01-expose-cab-and-navx-parsing-on-no_std--alloc-pr-23httpsgithubcomgoatwu1993rssigpull23).
- [x] **LIB-02: Expose structured CMS signer and attribute inspection ([PR #24](https://github.com/goatwu1993/rssig/pull/24)).** Done; [record](docs/tasks/done.md#lib-02-expose-structured-cms-signer-and-attribute-inspection-pr-24httpsgithubcomgoatwu1993rssigpull24).
- [x] **LIB-03: Add bounded nested-signature and timestamp inspection.** Done; [record](docs/tasks/done.md#lib-03-add-bounded-nested-signature-and-timestamp-inspection).
- [x] **LIB-04: Extract script and RDP parsing boundaries.** Done; [record](docs/tasks/done.md#lib-04-extract-script-and-rdp-parsing-boundaries).
- [x] **LIB-05: Extract MSI/MSP and AppX structural state.** Done; [record](docs/tasks/done.md#lib-05-extract-msimsp-and-appx-structural-state).
- [x] **LIB-06: Make format selection consistent for library callers.** Done; [record](docs/tasks/done.md#lib-06-make-format-selection-consistent-for-library-callers).
- [x] **LIB-07: Clarify verification policy construction.** Done; [record](docs/tasks/done.md#lib-07-clarify-verification-policy-construction).
- [x] **LIB-08: Audit borrowing, errors, and public API stability.** Done; [record](docs/tasks/done.md#lib-08-audit-borrowing-errors-and-public-api-stability).
- [x] **LIB-09: Evaluate a `no_std` shared verification core.** Done; [record](docs/tasks/done.md#lib-09-evaluate-a-no_std-shared-verification-core).
- [x] **LIB-10: Reassess shared interfaces and crate extraction after reuse.** Done; [record](docs/tasks/done.md#lib-10-reassess-shared-interfaces-and-crate-extraction-after-reuse).

## P1 — Tests, portable specification, and engineering checks

- [x] **TEST-01: Maintain a coverage inventory by invariant.** Done; [record](docs/tasks/done.md#test-01-maintain-a-coverage-inventory-by-invariant).
- [x] **TEST-02: Add local parser and verifier fuzz targets.** Done; [record](docs/tasks/done.md#test-02-add-local-parser-and-verifier-fuzz-targets).
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
- [x] **TEST-06: Strengthen fixture-manifest consistency checks.** Done; [record](docs/tasks/done.md#test-06-strengthen-fixture-manifest-consistency-checks).
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
- [ ] **TEST-11: Consolidate CRL fixture builders and SEC-10 fixture provenance.** Recorded from PR #44 to #53 reviews; none affects verifier behavior. Detail in [test-11.md](docs/tasks/test-11.md).

- [x] **TEST-12: Index time decisions as `TIME-NNN`.** Done ([PR #68](https://github.com/goatwu1993/rssig/pull/68)); [time decisions](docs/time.md).
- [x] **TEST-13: Index certificate-path decisions as `PATH-NNN`.** Done ([PR #69](https://github.com/goatwu1993/rssig/pull/69)); [certificate-path decisions](docs/path.md).
- [x] **TEST-14: Index timestamp decisions as `TSA-NNN`.** Done ([PR #70](https://github.com/goatwu1993/rssig/pull/70)); [timestamp decisions](docs/tsa.md).
- [x] **TEST-15: Index CMS decisions as `CMS-NNN`.** Done ([PR #72](https://github.com/goatwu1993/rssig/pull/72)); [CMS decisions](docs/cms.md).
- [ ] **TEST-16: Number the `TRUST-` index.** Fill [docs/trust.md](docs/trust.md);
  rename the `sec07-*` cases it claims (the others belong to TEST-17 and TEST-28).
- [ ] **TEST-17: Number the `LIMIT-` index.** Fill [docs/limit.md](docs/limit.md);
  rename the `sec02-*` and `sec03-*` cases.
- [ ] **TEST-18: Number the format indexes, one PR per format.** `PE-`, `MSI-`,
  `CAB-`, `NAVX-`, `PS-`, `WSH-`, `RDP-` and `APPX-`, from their
  `docs/<format>-decisions.md` skeletons. Move an `embedded-signature` case to
  `CMS-` where its rule is shared. `PE-` done ([PR #76](https://github.com/goatwu1993/rssig/pull/76)).
- [ ] **TEST-19: Link CRL retrieval rules to their entries.**
  `docs/crl-retrieval.md` restates rules now in `CRL-026` to `CRL-040`.
- [ ] **TEST-20: Rename task-named library cases.** The `lib04-*` to `lib09-*`
  cases are claimed by the format, `INSPECT-` and `POLICY-` indexes; rename
  them by subject when those are numbered.
- [ ] **TEST-21: Attach the claimed `TIME-` cases.** The cases claimed under
  `TIME` `attach` (the pre-SEC-09 time cases and every format's
  expired-with-timestamp copy) name their TIME entries.
- [x] **TEST-22: Reindex misplaced decisions.** Done ([PR #70](https://github.com/goatwu1993/rssig/pull/70)); mapping in that PR.
- [x] **TEST-23: Scaffold the remaining decision indexes.** Done ([PR #71](https://github.com/goatwu1993/rssig/pull/71)); claims in `tests/decision-claims.json`.
- [ ] **TEST-24: Number the `ALG-` index.** Fill [docs/alg.md](docs/alg.md):
  unsupported algorithms and the SHA-1 opt-in in every format.
- [ ] **TEST-25: Number the `POLICY-` index.** Fill [docs/policy.md](docs/policy.md):
  every format's integrity-only case and the library policy cases.
- [ ] **TEST-26: Number the `CLI-` index.** Fill [docs/cli.md](docs/cli.md).
- [ ] **TEST-27: Number the `INSPECT-` index.** Fill [docs/inspect.md](docs/inspect.md).
- [ ] **TEST-28: Attach the claimed `CRL-`, `PATH-` and `TSA-` cases.** Name
  existing entries for the cases claimed under `attach` (remaining SEC-10
  audit cases, every format's revocation and untrusted-root case), and add a
  PATH entry for `certificate-signature`.
- [x] **TEST-29: Use one meaning per term.** Done ([PR #71](https://github.com/goatwu1993/rssig/pull/71), together with TEST-23 at the owner's request); [glossary](docs/glossary.md).
- [x] **TEST-30: Remove duplicate and overlapping decisions.** Done ([PR #74](https://github.com/goatwu1993/rssig/pull/74)); mapping in that PR.
- [x] **TEST-31: Settle the shared format-skeleton rules.** Done ([PR #75](https://github.com/goatwu1993/rssig/pull/75)); [format indexes](docs/decisions.md#format-indexes).

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
- [ ] **PRODUCT-04: Keep public API and decision documentation current.** Add
  compiling examples for parse-only and explicit trusted verification, feature
  combinations, and error handling. Update stale source paths in the comparison
  document; keep format limits, CLI help, README tables, architecture, and tests
  aligned. External comparisons retain pinned revisions and stated evidence limits.
  CRL applicability, distribution-point and competing-evidence rules live in
  one table cell of `docs/validation-time.md` (the CRL row), which is hard to read
  and to cite. Move it to its own document with one rule per line and its
  pinning cases, and link it from the README and from `AGENTS.md`'s current
  boundaries, which describe CRL handling only in general terms.
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
  checks. Resolve disagreements against format evidence and explicit rssig decisions,
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
  with unambiguous hashing rules and producer evidence; multipart handling needs
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
  documented rules; never open fixtures in an RDP client.
- [ ] **FORMAT-06: Audit AppX edge cases and rule gaps.** Extend
  ZIP64/descriptors, compression/block boundaries, filename collisions, namespace
  parsing, publisher DN comparison, and bundle child identity/signature cases.
  Evaluate Unicode names and additional manifest/bundle profiles individually
  with producer evidence and aggregate budgets. Keep unsupported external/stub/
  nested bundles explicit; deployment selection and Windows Store acceptance
  are not established by package integrity.
- [ ] **FORMAT-07: Decide skipped WIN_CERTIFICATE entries.** PE-004 rejects a
  revision 1.0 entry, an entry of another type and extra bytes in an entry;
  Microsoft's PE Format page allows other types and legacy revision 1.0, and
  Windows rejects extra bytes only with `EnableCertPaddingCheck`. Decide skip,
  verify or reject with fixtures, and settle PE-004's status.

## P3 — Additional capabilities requiring separate design

- [x] **FEATURE-01: Add bounded opt-in CRL retrieval.** Done; [record](docs/tasks/done.md#feature-01-add-bounded-opt-in-crl-retrieval).
- [ ] **FEATURE-01-AIA: Add bounded AIA issuer retrieval.** Extend the retrieval
  boundary to missing intermediate certificates, always as untrusted candidates,
  never new trust anchors. Define pre-trust destination discovery, loop/work
  limits and provenance. HTTPS transport and persistent caching also remain
  separate follow-ups requiring a decision and dependency review.
- [ ] **FEATURE-02: Add OCSP with explicit evidence rules.** Require responder
  authorization, signature/freshness checks, issuer/serial binding, and tested
  unknown/revoked/error behavior. Define interaction with CRLs, caches, offline
  operation, and timestamped verification. Network failure must not silently
  become good revocation status.
- [ ] **FEATURE-03: Add RSA-PSS where interoperability justifies it.** Specify
  digest/MGF/salt/trailer parameters and rules for CMS, certificates, CRLs, and
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
  network configuration, and behavior differences; replay captured expectations
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
  paths, and supplied local CRLs; explicit reduced-verification reports.
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
