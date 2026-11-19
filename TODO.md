# Prioritized roadmap

Maintained alongside implementation and its recorded completion evidence.
Lifetime-signing and time-boundary policy (SEC-09) and CRL applicability and
competing evidence (SEC-10) are complete; the next open security item is reporting
the CRL evidence actually used (SEC-11). The SEC-10 coverage also
supports the separately scoped AIA retrieval work (FEATURE-01-AIA).
Confirmed correctness regressions take priority over planned refactoring.
New algorithms, formats, and network access require their own evidence and
policy decisions; this list does not promise every Windows behavior.

Unchecked audit items identify work to investigate or validate, not confirmed
vulnerabilities. Inventory existing implementation and tests before adding
coverage. SHA-256/384/512, RSA PKCS#1 v1.5, ECDSA P-256/P-384, nested signatures,
timestamps, and local CRL validation already exist.

## Maintenance and completion rules

- Update this file alongside implementation PRs. Keep task IDs stable, record
  completion evidence or a PR link, and split work that no longer fits one PR.
- An item that has outgrown this file moves its detail to a document under
  `docs/tasks/` and keeps its ID, title, checkbox and a link here. Maintain the
  detail there, not in this file.
- Track tasks and their sub-items only in this file and in documents under
  `docs/`. Do not open GitHub issues for them, and do not link an item's open
  work to an issue. A pull request link is allowed only as evidence for work
  already merged.
- Follow [AGENTS.md](AGENTS.md): committed fixture and manifest provenance,
  declarative case, named in-process Rust test, observed intended failure, then
  implementation. Ordinary tests never regenerate fixtures or execute them.
- When a task adds or changes a pinned case, record its ID, rationale, and
  whether it pins acceptance or diagnostics in the task document. Follow the
  [pinned-expectation rules](AGENTS.md#pinned-expectations) for decision metadata
  and changes to decided outcomes.
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
- [x] **SEC-06: Expand certificate-path policy coverage.** Added 38 portable
  cases and named in-process CLI tests for BasicConstraints, path length,
  permitted/excluded DNS constraints, unknown critical extensions, leaf/CA
  EKU and KeyUsage, cross-signing, same-subject/different-key issuers and cycles.
  Exact selected-chain hashes/DER and typed failures are pinned with explicit
  roots, time and local CRLs. Signature-math checks isolate path-policy faults.
  The initial selected-anchor regression reported a same-subject/key root whose
  name constraints rejected the path; reporting now matches name constraints
  too. [Policy inventory and limits](docs/certificate-path-policy.md) document
  webpki's profile and configured-anchor validity/constraint treatment. Full
  locked tests, fmt, Clippy, verify-core and CLI-without-system-roots tests, and
  bare-metal verify-core Clippy pass on macOS. Dependencies are unchanged; Linux
  execution remains in CI. No Windows policy equivalence is claimed.
- [x] **SEC-07: Make root/CRL loading diagnostics explicit.** Atomic DER/PEM
  loading rejects malformed input, unsupported anchors and partial native-root
  enumeration with typed codes, entry positions and causal diagnostics. Exact
  DER duplicates are deduplicated; distinct constrained anchors are retained.
  Fetched bundles enforce the combined 64-CRL limit before final verification.
  Added 18 fixtures and 21 portable cases covering mixed bundles, empty stores,
  duplicates, native loading failures and retrieval limits. Loaded CRLs remain
  supplied artifacts without individual authentication claims. See
  [loading policy, migration and validation evidence](docs/trust-loading.md).
  Full locked tests (799 cases), formatting, Clippy and documented feature/target
  checks pass on macOS. Dependencies are unchanged; Linux runtime validation
  remains in CI. CRL selection/evidence remain SEC-10/SEC-11.
- [x] **SEC-08: Complete timestamp structure and multiplicity tests.** Shared
  TSTInfo parsing now validates mandatory fields, canonical optional ordering and
  accuracy bounds; verification requires version 1 and rejects unsupported tsa
  identity/extensions explicitly. Added 35 committed fixtures/portable cases and
  named CLI tests for structure, duplicate/mixed timestamps, TSA critical and
  exclusive EKU/KeyUsage, parent substitution and malformed signingTime.
  Independent signature-math/image/issuer checks isolate the intended faults;
  parser tests cover accuracy bounds and truncation. Focused tests first accepted
  malformed correctly signed tokens. Multiple timestamps remain unsupported;
  existing CMS duplicate-attribute failure precedence is preserved. See
  [profile, limits and evidence](docs/timestamp-policy.md).
- [x] **SEC-09: Define lifetime-signing and time-boundary policy
  ([PR #43](https://github.com/goatwu1993/rssig/pull/43)).** A leaf with the
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
  are pinned. Signer, TSA, anchor and CRL time policies:
  [time policy](docs/time-policy.md). Full locked tests, fmt, Clippy,
  verify-core/verify/cli feature tests and bare-metal verify-core Clippy pass on
  macOS. Dependencies are unchanged; Linux runtime validation remains in CI.
  Review items decided against or deferred are recorded in SEC-14.
- [x] **SEC-10: Audit CRL applicability and competing evidence.** Detail is in
  [docs/tasks/sec-10-crl-applicability.md](docs/tasks/sec-10-crl-applicability.md):
  the audit checklist (every box checked), decisions, evidence limits and
  pointers to known limitations, which stay open under their own IDs.
- [ ] **SEC-11: Report CRL evidence actually used.** Distinguish supplied artifacts
  from CRLs authenticated and used for each selected chain. Include affected
  certificates/CRLs in structured failures. Preserve conservative rejection when
  a current CRL lists a signer even after its signing time; historical good status
  requires separate evidence and policy.
  Observed today: a CRL excluded as non-applicable still appears in
  `revocation.crls` with role `supplied` beside status `good` (for example
  `sec10-unrelated-expired.crl` with `good.crl`), and nothing marks it unused.
  A `certificate_revoked` result does not identify which supplied CRL listed
  the certificate.
  From the PR #60 review: a retrieved body that is not a CRL (for example an
  HTML error page) is listed in `crl_retrieval.artifacts` as well as reported
  as an `invalid_crl` failure, so counting artifacts overcounts retrieved CRLs.
  Decide whether artifacts mean "bytes received" or "CRLs loaded".
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
- [ ] **SEC-14: Lifetime-signing review decisions and deferred follow-ups.**
  Recorded from PR #43 reviews; none permits an invalid signature to verify.
  Kept as policy (change only with a new policy decision and paired fixtures):
  - Trust anchors: configured anchors remain keys. Their validity is not checked
    at the validation time or at a lifetime signing time, so a lifetime path
    through a root re-issued after the signing time is accepted.
  - Error precedence: the leaf lifetime notBefore check runs before path
    building (like webpki's leaf validity check), so it precedes
    untrusted_root/unknown-issuer and unknown revocation status of the signer
    path. Store-wide CRL freshness errors are still reported first, by the TSA
    check. A rejected issuer issued after signing ranks as a webpki validity
    error, so it can hide a revoked or wrongly signed issuer on another
    candidate path (pinned by `sec09-lifetime-rollover-revoked-issuer`); the
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
- [x] **SEC-15: Select CRLs against the selected chain, not every candidate.**
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
- [ ] **SEC-16: Tighten AKI/SKI matching edge cases.** Since PR #60 a CRL is
  authenticated under the issuer key the path uses. Settled in PR #60 by
  cross-checking OpenSSL, BoringSSL and Bouncy Castle (see "Decisions made"
  in [SEC-10](docs/tasks/sec-10-crl-applicability.md)): on a self-issued
  key-rollover path (two issuers of one name with different keys) CRLs that
  each name their issuer's key verify, as in all three libraries
  (`sec16-self-issued-rollover-with-key-identified-crls-verifies`); webpki
  cannot confirm two issuers of one name, so it confirms the signer only on
  such a path. CRLs without key identifiers are rejected at confirmation, as
  OpenSSL and BoringSSL reject them and unlike Bouncy Castle
  (`sec16-self-issued-rollover-with-both-crls-is-rejected`); the owner chose
  that tiebreaker, so it is Decided.
  Deliberately skipped in
  PR #45. A name-matching candidate without an SKI cannot disprove a CRL's AKI,
  so one SKI-less candidate makes the AKI check vacuous for that name. A
  candidate whose SKI fails to parse is treated as having none. Issuer names
  compare as exact DER, so an issuer encoded differently (PrintableString vs
  UTF8String) is excluded with no diagnostic. Decide whether these should
  exclude, reject or be reported, and pin each with fixtures.
  An AKI that carries only authorityCertIssuer and serial is not compared at
  all; the CRL is matched by issuer name
  (`sec10-root-aki-issuer-serial-crl-name-matched`). That fixture names the
  root's real issuer and serial and is signed by the root, so it cannot tell
  name-only matching from issuer/serial matching; a fixture with a wrong
  serial is needed to pin either behavior.
- [ ] **SEC-17: Budget and consolidate CRL applicability work.** Deliberately
  skipped in PRs #44 and #45. Every verification re-parses all configured
  roots to collect issuer names, outside `budget.decoded_bytes`. The
  mismatched-AKI signature probe runs public-key verifications outside the
  `Budget` and uses its own signature-OID-to-digest table instead of the
  central algorithm mapping. Cache root identities on the `TrustStore`, charge
  probe verifications to the budget, and reuse one algorithm mapping.
  Since PR #46, each applicable CRL is decoded three times per verification
  (x509-cert, webpki borrowed, webpki owned), and the owned form allocates one
  map entry per revoked certificate that is not charged beyond the existing
  8x byte-length reservation. Cache parsed CRLs on the `TrustStore` and pin the
  budget effect for large CRLs.
  `--fetch-crls` asks the source only about the certificates the verifier
  reports without a usable CRL (`details.certificates_without_crl`), as
  OpenSSL's `get_crl` and Bouncy Castle look up CRLs for the certificate being
  checked (PR #60). What remains: a run verifies the input up to once per
  retrieval round, plus once without revocation before the first request (the
  whole-input integrity and trust check), against one budget, and no case
  exhausts it on that path. The per-certificate CRL evaluation decodes
  each loaded CRL once per verification, but verifies CRL signatures with its
  own OID table outside the budgeted algorithm adapter; reuse the adapter.
  Repeated work found in the PR #60 review (results unchanged, bounded by
  existing limits):
  - `LoadedCrl::load` copies each applicable CRL's bytes and tbsCertList and
    builds an owned webpki CRL on every verification and retrieval round; the
    confirmation pass clones it again. Borrow from the store instead.
  - The CRL signature cache key clones the issuer SPKI on every lookup, even
    on a hit; key it by CRL and issuer index.
  - The path callback re-encodes and hashes every certificate on every
    candidate path, uncharged; compute it once per certificate.
  - Every configured root is decoded twice per verification (issuer names
    and anchor certificates); decode it once.
  With revocation on, building the CRL prefilter's issuer names uses `?` on
  each configured root's x509-cert decoding (`src/trust.rs`, as on `main`),
  so one root webpki accepts but x509-cert rejects fails every verification
  with CRLs; skip such a root, as the anchor list already does, with a
  fixture.
  Retrieval skips a certificate whose listed points were all asked and
  whose issuer, authority key and role (CA or end entity) were already asked
  about, so a certificate that an earlier scoped or partial answer did not
  cover can stay `revocation_unknown` without a request of its own; re-ask
  when the earlier answer added no CRL covering it, with a paired fixture.
- [ ] **SEC-18: Decide unsupported-but-applicable CRL handling.** Partly
  decided in PR #60: the best CRL decides, as in OpenSSL and Bouncy Castle, so a
  stale, delta, indirect, unsupported or out-of-scope CRL is set aside when
  another CRL of the issuer is usable and authoritative (full-plus-delta and
  old-beside-current deployments verify). Still open: real delta support, and
  reporting which CRLs were set aside (SEC-11).
  Open from the PR #60 review: a listing counts as a revocation once the CRL
  verifies under the path issuer's key, before delta, indirect or other
  unsupported features are checked, and entry extensions are ignored. A delta
  CRL entry with reason `removeFromCRL` (a hold lifted), or an indirect CRL
  entry whose `certificateIssuer` names another CA with the same serial,
  therefore rejects as `certificate_revoked` a certificate the full CRL
  leaves good. This fails closed. Decide it with real delta support and pin it
  with a full-plus-delta `removeFromCRL` fixture.
  Decided in PR #60 for stale full CRLs: a listing counts only from a CRL
  that is current at the validation time, as in OpenSSL and Bouncy Castle,
  so a released `certificateHold` in an expired CRL no longer revokes
  (`sec10-stale-crl-revocation-beside-fresh-crl-is-ignored`). Still open: a
  current delta or indirect CRL's entries, and the listing in a current CRL
  with a malformed authorityKeyIdentifier
  (`sec10-malformed-aki-crl-revocation-beside-good-crl-revokes`): OpenSSL,
  both Bouncy Castle paths, BoringSSL and relic were compared and do not
  agree (`docs/tasks/sec-10-crl-applicability.md`, "Case reasons"); the owner
  decided to keep counting it, so only delta and indirect entries are open. Original notes follow.
  Deliberately
  kept fail-closed in PR #46. An applicable CRL that webpki cannot use (delta,
  indirect, unknown critical extension) rejects the request even when another
  supplied CRL covers the same issuer, so a normal full-plus-delta CRL
  deployment fails. Options: real delta-CRL support (with FEATURE-level
  evidence) or an explicit, JSON-reported opt-in to skip known-unsupported
  CRLs. Never skip silently.
  Two more cases of the same shape. A CRL naming a distribution point rejects
  the request as `invalid_crl` (`distribution_point_scope`) when the signer
  lists no point, even if a full CRL from the same issuer is also supplied
  (observed with `good-sec06-basic.exe`, `sec06-issuer.crl` and
  `sec10-issuer-idp-match.crl`; no case has the full CRL present). A stale CRL
  from a chain issuer rejects as `crl_expired` even when a fresh CRL from the
  same issuer is supplied (`sec10-root-expired-crl-still-rejected`), so an
  operator who keeps old CRLs beside current ones is rejected. Decide these
  together with the delta case.
- [ ] **SEC-19: Finish CRL rejection reason coverage.** Deliberately skipped
  in PR #46. Only `issuing_distribution_point` and the feature reasons used by
  SEC-10 cases are pinned; `crl_version`, `malformed_extensions`,
  `revocation_reasons_partitioning`, `revocation_reason`, `invalid_crl_number`
  and `unsupported_or_malformed` have no fixture, and other webpki
  rejections fall into the open-ended
  `unsupported_or_malformed` catch-all. The `invalid_crl` message embeds
  webpki's error name, which can change on upgrade (consumers must use
  `details.reason`). A malformed CRL from an unrelated issuer still fails at
  `CertificateList` decoding before the applicability filter, unlike other
  unrelated CRLs. No fixture has a non-canonical TBS encoding to pin that the
  signature probe uses the original TBS bytes.
  For a CRL issuer without cRLSign, `details.certificate` names the leaf being
  checked rather than the issuer whose KeyUsage fails; add the issuer (or a
  `reason`) before consumers depend on the current detail. The same leaf
  report is attached when an intermediate is revoked (`sec10-revoked-issuer`)
  or has unknown status (`sec10-ca-crl-dp-user-scope-excludes-issuer`), so
  the error does not identify the affected certificate; no test asserts it.
  `details.reason` values are string literals in `src/trust.rs`, documented in
  `docs/problems.md` but not a Serde domain enum in `src/domain.rs` and not
  enumerated in `tests/cases.schema.json`. `details.crl` is attached with
  `CrlReport::parse(..).ok()` on the AKI, scope and unsupported-feature paths
  (null if the report parser fails) but with `?` on the nextUpdate and
  freshness paths (a report-parse error replaces the typed error); make them
  consistent.
- [x] **SEC-20: Revisit revocation_unknown precedence over path errors.**
  Done in PR #60: with no applicable CRL the path is still built, so an
  untrusted chain is `untrusted_root` and, with `--fetch-crls`, nothing is
  requested for it (`crl-fetch-untrusted-chain-requests-nothing`). Original
  notes follow.
  Deliberately kept in PR #44. When no supplied CRL applies, revocation_unknown
  is returned before path building, so it hides untrusted_root and other chain
  errors. This extends the existing empty-CRL-set precedence. Revisit together
  with SEC-14's error-precedence notes if consumers need the chain error first.
- [x] **SEC-21: Bind listed-serial revocation to the verified path.**
  Done in PR #60: a listing counts only in a CRL that verifies under the path
  issuer's key, from an issuer with cRLSign (anchors exempt); an unmappable
  signature algorithm is `invalid_crl` (`unsupported_signature_algorithm`), and
  a listing in an authenticated CRL counts even if its authorityKeyIdentifier
  is malformed. Later in PR #60 the listing rule was narrowed to follow
  OpenSSL and Bouncy Castle: it counts only from a current CRL that covers
  the certificate and is at least as new as the deciding CRL (see
  `docs/tasks/sec-10-crl-applicability.md`, "Case reasons"). Original notes follow. From PR
  #48 and #49 reviews. The "revoked in any applicable CRL" check in the path
  callback matches a listing by issuer name and serial only. It accepts a CRL
  whose signature verified under any name-matching candidate key, or whose
  signature algorithm `signed_by` cannot map (`unwrap_or(true)`), and it does
  not require the issuer's cRLSign. With two same-name issuers (key rollover),
  the old key's CRL can therefore reject a signer issued under the new key; a
  valid signature fails closed as `certificate_revoked` on evidence webpki
  would not accept from an authoritative CRL. Count a listing only when the
  CRL verifies under the issuer key the path uses and that issuer may sign
  CRLs (anchors exempt, per SEC-06), and decide whether an applicable CRL with
  an unmappable signature algorithm is `invalid_crl`. With that binding, on
  webpki's unknown status re-run path building without webpki revocation and
  apply the same check to every path certificate, so a signer or intermediate
  listed only by a non-authoritative CRL reports `certificate_revoked`
  (PR #49 tried this for the signer alone by rewriting the final error and
  reverted it). Identify the listing CRL in `details` instead of reusing
  webpki's `CertRevoked` message. Paired fixtures: same-name rollover issuers,
  an issuer without cRLSign, an unmappable algorithm.
- [ ] **SEC-22: Pass uncovered certificates to retrieval as typed data.**
  From the PR #60 review. `--fetch-crls` learns which certificates lack a
  usable CRL by reading `certificates_without_crl` back out of the error's JSON
  `details` and hex-decoding each `der_hex`. If that schema changes and the
  list no longer deserializes, retrieval treats the result as final and
  quietly asks nothing (the same holds for `certificates_with_expired_crl`),
  so `--fetch-crls` stops fetching with no error. Carry the uncovered certificates' DER
  beside the error inside the crate, keep the JSON field for consumers, and
  pin the request sequence with a test.
  Carry the original certificate bytes through that channel too. Today
  `CrlRequest.certificate`, its `issuer`, `certificates_without_crl` and
  `certificate_sha256` all use rssig's re-encoding, which equals the
  original for DER-conformant input. der sorts a SET OF while decoding, so
  a certificate whose name has a multi-valued RDN out of DER order reaches a
  source with an invalid signature and a sorted issuer key, and a portable
  `crl_certificate_responses` implementation hashing the original bytes
  disagrees. Add a fixture with such a name before changing it.
- [ ] **SEC-23: Follow-ups left open by the PR #60 review.** The review of
  PR #60 was concluded with these items not changed in that PR. Reasons and
  references are in
  [SEC-10](docs/tasks/sec-10-crl-applicability.md) ("Case reasons (PR #60)").
  Decided since: a supplied CRL that is not yet valid, scoped elsewhere or
  uses an unsupported feature is refreshed by `--fetch-crls`, as an expired
  one is; one with a bad signature, from an issuer without cRLSign, or
  malformed is not (SEC-10, "Case reasons (refresh of an unusable supplied
  CRL)").
  Owner decision needed:
  - A CRL without nextUpdate that lists a certificate, alone, is
    `invalid_crl` (`missing_next_update`) rather than `certificate_revoked`
    (`sec10-no-next-update-crl-revocation-alone-is-invalid`); both reject.
  Retrieval and the built-in HTTP source:
  - The CLI's fetch limits are per file, so a batch is bounded only by its
    file count (up to 16 requests, 32 MiB and 30 s each). Consider an
    optional batch-wide cap.
  - A DNS timeout closes the built-in source for the rest of the run, even
    when only a short remaining deadline caused it. Reopening once the
    stale resolver finished was reverted (timing-dependent results, and
    `HttpCrlSource` stopped being `Sync`); find a deterministic,
    `Sync`-safe way.
  - `retrieval_trust_bytes` and the other engine limits end the whole
    verification with `resource_limit_exceeded`, rather than recording the
    remaining points and finishing with the evidence gathered.
  - With `fetch_each`, the first over-allowance body of a request is the
    engine's `resource_limit_exceeded` and later ones the source's
    `crl_fetch_failed`; the allowance counts accepted bodies only.
  - A URL-less failure beside an answer by certificate is recorded without
    the points it concerned.
  - The built-in URL check lists reserved labels; other private-use suffixes
    (`.lan`, `.corp`, `.localdomain`) rely on the DNS-answer address check.
  Report shape:
  - `CrlRetrievalArtifact.url`/`final_url` are omitted when absent while
    `CrlRetrievalFailure.url` serializes as `null`; pick one (with
    PRODUCT-03).
  - On the RDP fallback path (a revocation that is another error type's
    source), the merged error loses the outer error's cause messages.
  - Distribution-point URIs are compared byte for byte (webpki's rule), so a
    scheme or host that differs only in case does not match.
  Specification coverage (with TEST-05): the spec's injected CRL source maps
  URLs or certificates to bodies and error kinds, so it cannot express
  URL-less failures, whole-request errors, several entries per request, a
  point shared by certificates of two issuers, or the built-in source's
  deadline and byte-cap behavior. Those are unit-tested only
  (`docs/testing.md`); extend the case format before pinning them
  portably.
  Not from this PR's changes, found during its review:
  - `rssig::cli::command()` is a hidden public function kept for the spec
    runner (#59).
  - `tests/manifest.rs` `fixtures_are_never_indexed_as_sources` creates its
    scratch directory without the drop guard its sibling test uses.
  - The strict root decoding in the CRL prefilter (see SEC-17).

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
- [x] **TEST-02: Add local parser and verifier fuzz targets.** Start with DER,
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
  [Targets, limits, maintenance and recorded runs](docs/fuzzing.md).
  CRL retrieval is not fuzzed; a differential oracle remains separate work.
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
- [x] **TEST-06: Strengthen fixture-manifest consistency checks.** Beyond current
  SHA-256 verification, validate byte counts, unique/safe paths, provenance/license
  fields, case references, and unlisted or missing artifacts. Define intentional
  exceptions for diagnostic JSON and helper data. Maintenance generation remains
  explicit and requires review of changed binary artifacts.
  Done in `tests/manifest.rs`; rules, exceptions, and what is not enforced are in
  [manifest consistency](docs/testing.md#manifest-consistency).
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
- [ ] **TEST-11: Consolidate CRL fixture builders and SEC-10 fixture provenance.**
  Recorded from PR #44 to #53 reviews; none affects verifier behavior. Four
  test builders construct a `TbsCertList` by hand (`src/tests.rs::crl`,
  `time_policy.rs::crls`, `path_policy.rs::write_crl`,
  `crl_applicability.rs::crl_full`). `crl_full` takes seven positional
  arguments and stamps the signature algorithm from the main test identity
  whatever issuer it is given (every test key is P-256 today). The 45 SEC-10
  fixtures come from two generators (`regenerate_sec10_fixtures` for the rssig
  test root's CRLs, `regenerate_sec06_fixtures` for the SEC-06 chain), and the
  names do not say which: `sec10-root-*.crl` is the rssig test root,
  `sec10-sec06-root-*` and `sec10-root-no-crl-sign.der` the SEC-06 root. 57
  SEC-06 manifest entries have no `generator` field, so tests select those
  fixtures by filename. The single-URI distribution-point encoding is written
  by hand in three builders (`path_policy.rs`, `crl_applicability.rs`,
  `crl_fetch_fixtures.rs`), and the `ski` helper in `crl_applicability.rs`
  compares the OID as a string. `sec10-ca-crl-sign-fallback` relies on
  embedded-certificate order to exercise fallback and does not assert that the
  first candidate was tried. Keep committed bytes unchanged when consolidating.

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
  CRL applicability, distribution-point and competing-evidence policy lives in
  one table cell of `docs/time-policy.md` (the CRL row), which is hard to read
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
