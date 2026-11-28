# Prioritized roadmap

One short entry per task (AGENTS.md, "Task tracking"): ID, title, checkbox,
and a link to `docs/tasks/` for anything longer. Finished items keep one line
with their PR; their full records are in [docs/tasks/done.md](docs/tasks/done.md).
Within each priority, tasks are grouped by scope under a `### <SCOPE>` heading,
in the order of the scope's first task. Confirmed correctness regressions come
before planned refactoring. Unchecked
audit items are work to investigate, not confirmed vulnerabilities. New
algorithms, formats and network access need their own evidence and decision
entries ([docs/decisions.md](docs/decisions.md)); completing a task follows the
TDD workflow and checks in AGENTS.md.

### Task IDs

An ID is `<SCOPE>-T<NNN>`, such as `CRL-T012`: the scope, a `T` that
keeps a search for a decision entry (`CRL-012`) from matching a task, and a
three-digit number counted per scope from `001`. A number is never reused;
a finished task stays here as one line. Its document, when it has one, is
`docs/tasks/<scope>-t<nnn>.md` in lowercase. The scope is one of the closed
list in [scopes.yml](scopes.yml): every decision prefix in
[docs/decisions.md](docs/decisions.md), the formats with no decision index
yet (`CAT`, `P7S`), and `TEST`, `LIB`, `DOC` and `BUILD` for work on the
repository itself. The same scope, lowercase, is the scope of the PR title.

A task takes the scope where its change is decided, by the
[Which index](docs/decisions.md#which-index) rule; a task about tests for
one subject belongs to that subject. A task for a format with no scope yet
waits for the owner to add one to `scopes.yml`. An entry starts with its type
(`feat`, `fix`, `refactor`, `test`, `docs` or `build`) and its title; with the
scope and ID they make the PR title, `type(scope): ID title`
(AGENTS.md, "Pull request titles"). An open task that waits on the owner's
decision adds "(owner decision)" after the title.
Fixtures, case IDs and test functions are named after the decision entry
they pin or what they check, never after a task.

## P0 — Verification correctness and bounded work

### LIMIT

- [x] **LIMIT-T001** fix: Audit arithmetic and structural bounds across every parser. Done; [record](docs/tasks/done.md#limit-t001-fix-audit-arithmetic-and-structural-bounds-across-every-parser).
- [x] **LIMIT-T002** fix: Enforce aggregate verification budgets. Done; [record](docs/tasks/done.md#limit-t002-fix-enforce-aggregate-verification-budgets).
- [x] **LIMIT-T003** fix: Bound host input and report memory. Done; [record](docs/tasks/done.md#limit-t003-fix-bound-host-input-and-report-memory).
- [x] **LIMIT-T004** fix: Finish with the gathered evidence when an engine limit is reached. Done; [record](docs/tasks/done.md#limit-t004-fix-finish-with-the-gathered-evidence-when-an-engine-limit-is-reached).
- [ ] **LIMIT-T008** test: Pin in a case that supplied roots and CRLs filling the retained-byte cap leave every certificate unasked (`retrieval_trust_bytes`), the verifier's result standing. Only the unit test `supplied_evidence_over_the_retained_byte_cap_asks_nothing_and_the_result_stands` pins it; the CLI supplies at most the cap (`the_cli_never_supplies_more_than_the_engine_retains`), so a case needs 32 MiB of supplied evidence, as CRL-T050 does for fetched CRLs.
- [ ] **LIMIT-T010** docs: Say that a supplied store may exceed the retained-byte cap.
  The comment in `Retrieval::request` and the "Combined trust evidence" row of
  `docs/crl-retrieval.md` still say the store holds at most 32 MiB; since
  LIMIT-T004 a library store over it is verified as supplied and retrieval adds
  nothing. CRL-039 pins diagnostics but its "Decided by" line states the
  acceptance change: keep that statement in CRL-024 and refer to it. From LIMIT-T004.
- [ ] **LIMIT-T007** fix: Stop the RDP path search after an EKU-independent failure.
  RDP `verify_trust` repeats the full path search, with the lifetime leaf check
  and a 200,000-unit reservation, for each accepted leaf EKU. Stop after a
  failure no other EKU can change, keeping the ranking and merged CRL gaps
  [CRL-027](docs/crl.md#crl-027-which-error-a-rejected-chain-reports) pins;
  pin the budget effect.

### CMS

- [x] **CMS-T001** fix: Audit CMS structure and signature binding. Done; [record](docs/tasks/done.md#cms-t001-fix-audit-cms-structure-and-signature-binding).
- [x] **CMS-T002** fix: Define ambiguous signer-certificate handling. Done; [record](docs/tasks/done.md#cms-t002-fix-define-ambiguous-signer-certificate-handling).
- [x] **CMS-T003** fix: Narrow CMS-009 to the attributes RFC 5652 limits. Done ([PR #73](https://github.com/goatwu1993/rssig/pull/73)); [CMS-009](docs/cms.md#cms-009-single-instance-attributes-occur-at-most-once-in-a-signerinfo).

### PATH

- [x] **PATH-T001** fix: Expand certificate-path rule coverage. Done; [record](docs/tasks/done.md#path-t001-fix-expand-certificate-path-rule-coverage).
- [x] **PATH-T002** fix: Decide whether a malformed extension in a CA certificate fails the path. Done ([PR #97](https://github.com/goatwu1993/rssig/pull/97)); [PATH-013](docs/path.md#path-013-a-path-certificate-whose-extension-does-not-decode-fails-the-path).
- [x] **PATH-T010** fix: Report an embedded certificate whose extension does not decode instead of failing the signature. Done ([PR #108](https://github.com/goatwu1993/rssig/pull/108)); [PATH-013](docs/path.md#path-013-a-path-certificate-whose-extension-does-not-decode-fails-the-path).
- [ ] **PATH-T011** test: Pin how the PATH-013 callback rejection ranks against webpki's errors.
  Detail in [path-t011.md](docs/tasks/path-t011.md).
- [ ] **PATH-T012** fix: Read an x400Address in a certificate's GeneralNames.
  `x509-cert` 0.2 has no x400Address [3] choice, so since PATH-013 a path
  certificate whose subjectAltName (or another GeneralNames) holds one fails
  the path, where OpenSSL reads it (`GEN_X400`; found in PR #97).
- [x] **PATH-T013** fix: Fail the path on a certificate that repeats an extension. Done ([PR #102](https://github.com/goatwu1993/rssig/pull/102)); [PATH-014](docs/path.md#path-014-a-path-certificate-that-repeats-an-extension-fails-the-path).
- [x] **PATH-T014** test: Pin the rest of PATH-014 in `tests/cases.json`. Done ([PR #107](https://github.com/goatwu1993/rssig/pull/107)); [PATH-014](docs/path.md#path-014-a-path-certificate-that-repeats-an-extension-fails-the-path).
- [ ] **PATH-T015** fix: Decide whether an extension OID with a padded arc is rejected.
  `const-oid` 0.9 is reported to accept a base-128 arc with a leading 0x80
  octet, so `55 1D 80 0E` would read as an extension other than 2.5.29.14 and
  PATH-014 would not see it as a repeat; OpenSSL is believed to refuse such an
  encoding. Check both first (from the PR #102 review).
- [ ] **PATH-T016** fix: Decide whether a path may end at a configured root whose basicConstraints, keyUsage or extKeyUsage does not decode (owner decision).
  It fails today, a leftover of the report that could not be built (found in
  PR #108), while a root with a malformed subjectKeyIdentifier verifies.
  Detail in [path-t016.md](docs/tasks/path-t016.md).
- [ ] **PATH-T017** fix: Report `untrusted_root` for an RDP signer with a malformed extKeyUsage when no root is configured.
  `rdp::verify_trust` reads the EKU before `TrustStore::verify` checks for a
  root, so the result is `certificate_chain_invalid` with a decoder message
  where every other format reports `untrusted_root` (found in PR #108).
- [ ] **PATH-T018** test: Pin a timestamp signer whose basicConstraints, keyUsage or extKeyUsage does not decode.
  Since PATH-T010 it verifies under `--integrity-only` with the extension
  marked in `timestamp_verification.certificate`, and PATH-013 rejects it with
  a root; only `tsa-malformed-ski.exe` exists. Add a `tsa-malformed-eku`
  fixture to `regenerate_tsa_fixtures` and both cases (found in PR #108).
- [ ] **PATH-T019** fix: Decide whether an embedded certificate webpki cannot parse is blamed when no path is found.
  It replaces `untrusted_root`, and hides PATH-008's `invalid_key_usage`.
  Detail in [path-t019.md](docs/tasks/path-t019.md).
- [ ] **PATH-T006** fix: Decode certificate names that carry a UniversalString.
  `der` 0.7 has no tag for UniversalString (0x1C), so a certificate or CRL
  whose name carries one does not decode (RFC 5280 section 7.1: optional).
  Check how it is reported and whether to read it.
- [ ] **PATH-T007** fix: Report the keyCertSign rejection per candidate path (owner decision).
  A keyCertSign flag shared across candidate paths reports a later
  unknown-issuer failure as `invalid_key_usage`. This changes a rule kept in
  TIME-T002: PATH-T009 adds its entry first, and the change needs the owner's
  approval.

### TRUST

- [x] **TRUST-T001** fix: Make root/CRL loading diagnostics explicit. Done; [record](docs/tasks/done.md#trust-t001-fix-make-rootcrl-loading-diagnostics-explicit).

### TSA

- [x] **TSA-T001** fix: Complete timestamp structure and multiplicity tests. Done; [record](docs/tasks/done.md#tsa-t001-fix-complete-timestamp-structure-and-multiplicity-tests).

### TIME

- [x] **TIME-T001** fix: Define lifetime-signing and time-boundary rules. Done ([PR #43](https://github.com/goatwu1993/rssig/pull/43)); [record](docs/tasks/done.md#time-t001-fix-define-lifetime-signing-and-time-boundary-rules).
- [x] **TIME-T002** fix: Lifetime-signing review decisions and deferred follow-ups. Done ([PR #96](https://github.com/goatwu1993/rssig/pull/96)); [record](docs/tasks/done.md#time-t002-fix-lifetime-signing-review-decisions-and-deferred-follow-ups).
- [x] **TIME-T005** fix: Check fractional expiry during path building. Done ([PR #109](https://github.com/goatwu1993/rssig/pull/109)). Owner decision (PR #109): check it in path building, for the signer's path and the TSA's.
- [ ] **TIME-T006** fix: Replace the free-text `certificate_report_error` detail with a typed one.
  A late lifetime certificate whose report cannot be built gets prose instead
  of `certificate`, and no fixture reaches it. Since PATH-T010 a report fails
  only for a certificate that does not re-encode, so first show whether any
  certificate can parse and not be reported; if none can, remove the detail.
  Otherwise type it, reach it with a fixture, and extend TIME-013. The
  fractional-expiry error (TIME-005) omits `certificate` in the same
  situation; treat both alike.
- [ ] **TIME-T010** test: Pin the fractional-expiry orderings TIME-014 leaves open.
  Since TIME-T005 the comparison runs inside path building, so three results
  may differ from before and no fixture reaches them: an RDP signer with two
  accepted usages where the other usage fails differently
  (`choose_usage_failure`), a path also rejected for `ambiguous_issuer_keys`
  after selection, and another path that only lacks a CRL (CRL-027). Also
  unpinned: a revocation on another path that fails a path check of its own
  is reported over the expiry, and a webpki search limit reached after a
  fractional rejection is reported instead of it. Add fixtures and cases;
  restore the earlier result where it is the better diagnostic.

### CRL

- [x] **CRL-T001** fix: Audit CRL applicability and competing evidence. Done; detail in [crl-t001.md](docs/tasks/crl-t001.md).
- [ ] **CRL-T002** feat: Report CRL evidence actually used. Distinguish supplied artifacts from CRLs authenticated and used for each selected chain. Detail in [crl-t002.md](docs/tasks/crl-t002.md).
- [x] **CRL-T003** fix: Select CRLs against the selected chain, not every candidate. Done; [record](docs/tasks/done.md#crl-t003-fix-select-crls-against-the-selected-chain-not-every-candidate).
- [x] **CRL-T004** fix: Tighten AKI/SKI matching edge cases. Done ([PR #79](https://github.com/goatwu1993/rssig/pull/79)); [CRL-041](docs/crl.md#crl-041-a-crls-issuer-name-matches-by-rfc-5280-name-comparison) to [CRL-044](docs/crl.md#crl-044-a-crl-that-verifies-is-used-whatever-its-authoritykeyidentifier-names-by-issuer-and-serial).
- [x] **CRL-T005** refactor: Remove repeated CRL name and root work. Done ([PR #80](https://github.com/goatwu1993/rssig/pull/80)); the budgeting and caching it also listed are CRL-T033, and the retrieval re-ask is CRL-T032.
- [ ] **CRL-T006** fix: Decide unsupported-but-applicable CRL handling (owner decision). Partly decided in PR #60: the best CRL decides, as in OpenSSL and Bouncy Castle, so a stale, delta, indirect, unsupported or out-of-scope CRL is set aside when another CRL of the issuer is usable and authoritative (full-plus-delta and old-beside-current deployments verify). Detail in [crl-t006.md](docs/tasks/crl-t006.md).
- [ ] **CRL-T007** test: Finish CRL rejection reason coverage. Deliberately skipped in PR #46. Detail in [crl-t007.md](docs/tasks/crl-t007.md).
- [x] **CRL-T008** fix: Revisit revocation_unknown precedence over path errors. Done; [record](docs/tasks/done.md#crl-t008-fix-revisit-revocation_unknown-precedence-over-path-errors).
- [x] **CRL-T009** fix: Bind listed-serial revocation to the verified path. Done; [record](docs/tasks/done.md#crl-t009-fix-bind-listed-serial-revocation-to-the-verified-path).
- [ ] **CRL-T010** refactor: Pass uncovered certificates to retrieval as typed data. From the PR #60 review. Detail in [crl-t010.md](docs/tasks/crl-t010.md).
- [x] **CRL-T011** refactor: Make rssig the only revocation authority. Done; detail in [crl-t011.md](docs/tasks/crl-t011.md).
- [x] **CRL-T012** fix: Compare more string types in CRL issuer names. Done ([PR #82](https://github.com/goatwu1993/rssig/pull/82)); [CRL-041](docs/crl.md#crl-041-a-crls-issuer-name-matches-by-rfc-5280-name-comparison).
- [ ] **CRL-T013** feat: Identify a CRL's issuer by issuer and serial outside verification.
  Retrieval and CRL-008 read only key identifiers. Detail in
  [crl-t013.md](docs/tasks/crl-t013.md).
- [ ] **CRL-T014** feat: Bound CRL retrieval across a batch. The CLI's fetch
  limits are per file (up to 16 requests, 32 MiB and 30 s each), so a batch
  is bounded only by its file count. Consider an optional batch-wide cap.
- [ ] **CRL-T015** fix: Reopen the built-in CRL source after a DNS timeout. A DNS
  timeout closes `HttpCrlSource` for the rest of the run, even when only a
  short remaining deadline caused it. Reopening once the stale resolver
  finished was reverted in PR #60 (timing-dependent results, and the source
  stopped being `Sync`); find a deterministic, `Sync`-safe way.
- [ ] **CRL-T016** fix: Classify over-allowance CRL bodies consistently. With
  `fetch_each`, a request's first over-allowance body is the engine's
  `resource_limit_exceeded` and later ones the source's `crl_fetch_failed`;
  the allowance counts accepted bodies only.
- [ ] **CRL-T017** fix: Record the points of a URL-less retrieval failure. A
  URL-less failure beside an answer by certificate is recorded without the
  points it concerned.
- [x] **CRL-T018** fix: Refuse more private-use DNS suffixes before resolving. Done ([PR #111](https://github.com/goatwu1993/rssig/pull/111)); [CRL-037](docs/crl.md#crl-037-the-built-in-source-refuses-what-it-does-not-fetch).
- [ ] **CRL-T019** fix: Decide case-insensitive distribution-point matching (owner decision). URIs
  compare byte for byte (webpki's rule), so a scheme or host differing only
  in case does not match; RFC 5280 section 7.4 compares them without regard
  to case. A match can let a CRL decide that is now set aside or replaceable,
  so it may turn a rejection into acceptance: owner's decision.
- [ ] **CRL-T020** fix: Decide which certificates `unknown_status` names (owner decision). When no
  completable path has a gap, it falls back to every path and names
  certificates on stuck paths too (forged or no-cRLSign CRL), so
  `--fetch-crls` asks about them in vain. Pinned on purpose by
  `a_revocation_then_a_missing_crl_then_the_most_specific_failure_decides`;
  covers the expired and replaceable lists too. Owner's decision. Whatever
  is decided, make the stuck-path exclusion part of `unknown_status` (today
  its callers, `completable_first` and `revocation_failure`, must do it).
- [ ] **CRL-T021** fix: Decide whether a newer CRL without nextUpdate clears a listing beside a usable CRL (owner decision).
  It clears an older listing only when no CRL is usable; OpenSSL's newest
  best-scored CRL would give good status. Clearing would loosen an
  acceptance pin: owner's decision. See [CRL-T001](docs/tasks/crl-t001.md), "Recorded, not changed".
- [ ] **CRL-T022** fix: Decide removeFromCRL beside a usable CRL (owner decision). An entry with
  reasonCode removeFromCRL releases the certificate in a CRL without
  nextUpdate standing alone (OpenSSL's `cert_crl`), but beside a usable CRL
  any authenticated listing revokes (PR #60 rule). Releasing it there would
  turn a revocation into acceptance: owner's decision.
- [ ] **CRL-T023** fix: Decide whether a CRL missing only nextUpdate is offered to a source (owner decision).
  It is not (ranked above replaceable), as OpenSSL, BoringSSL and Bouncy
  Castle would use it and not look again; so beside an expired CRL it keeps
  `--fetch-crls` from asking (`crl-035-no-next-update-local-asks-nothing`).
  Offering it would make retrieval fire where the references stay quiet:
  owner's decision.
- [ ] **CRL-T024** feat: Log listings that a newer CRL cleared. Only an accepted
  path's ignored listings reach the logger.
- [ ] **CRL-T032** fix: Re-ask retrieval about a certificate an earlier answer did not cover.
  A certificate whose points, issuer, key and role were already asked about
  stayed `revocation_unknown` even when that answer added no CRL covering it.
  CRL-T041 removed that skip (every such certificate is asked); what remains is
  a paired fixture case pinning it. From CRL-T005.
- [ ] **CRL-T033** refactor: Cache trust inputs and charge the remaining CRL work.
  Results unchanged except where noted. Detail in
  [crl-t033.md](docs/tasks/crl-t033.md).
- [ ] **CRL-T034** fix: Decide whether an answer by certificate matches its issuer by the compared name.
  A fetched CRL counts as an answer by certificate only by exact issuer bytes.
  Retrieval keeps no asked issuers since CRL-T041, so the asking side is gone.
  Detail in [crl-t034.md](docs/tasks/crl-t034.md).
- [ ] **CRL-T035** fix: Decide whether CRL-008 compares issuer names canonically (owner decision).
  It compares the path's issuers by exact bytes, as webpki does; OpenSSL
  compares canonically. Detail in [crl-t035.md](docs/tasks/crl-t035.md).
- [x] **CRL-T036** test: Express a point shared by certificates of two issuers in the case format. Done ([PR #86](https://github.com/goatwu1993/rssig/pull/86); [CRL-050](docs/crl.md#crl-050-each-request-carries-every-point-the-certificate-lists-whatever-was-asked-before), [CRL-051](docs/crl.md#crl-051-each-certificate-records-what-its-own-request-yielded-reuse-is-the-sources)).
- [x] **CRL-T037** test: Pin a spent byte allowance in a case. Done ([PR #98](https://github.com/goatwu1993/rssig/pull/98)); [CRL-046](docs/crl.md#crl-046-a-retrieved-crl-over-the-size-cap-is-reported-with-the-cap-it-hit).
- [x] **CRL-T038** test: Express an answer naming a point by its normalized URL. Done ([PR #106](https://github.com/goatwu1993/rssig/pull/106)).
- [ ] **CRL-T053** refactor: Give the spent-allowance rule an entry that asks its question (owner decision).
  A reindex. CRL-046's title asks how an over-cap body
  is reported, but it also decides that points left once accepted bodies spend
  a request's allowance are not tried, which the two
  `crl-046-a-spent-byte-allowance-` and `-a-byte-short-` cases pin. From CRL-T037.
- [ ] **CRL-T054** fix: Record a refused URL-less body as the answer to the points it left.
  A body naming no URL that is refused (over the byte allowance, not a CRL, or
  past the retained-CRL cap) is not an answer by certificate, so each point
  the source did not name is also recorded as `crl_fetch_failed` "returned
  nothing". Record those points with the refusal instead. From LIMIT-T004.
- [ ] **CRL-T055** test: Pin the refused CRL URL names in the portable specification.
  The names `checked_url` refuses before resolving (CRL-037) are covered only
  by Rust tests; add `tests/cases.json` cases, with fixtures whose
  distribution points use them, so another implementation inherits the list.
  From CRL-T018.
- [ ] **CRL-T056** docs: Decide whether CRL-037's refusals need an acceptance entry.
  CRL-037 pins diagnostics, but a URL it refuses can turn a verified result
  into `revocation_unknown` (its Note, split-horizon names); check the index
  and reindex if the refusal is an acceptance pin. From CRL-T018.
- [ ] **CRL-T057** fix: Record an entry a source names by a withheld spelling of a listed point under the point as listed. A spelling that normalizes to a point but fails screening (a trailing tab or space) answers the point, yet its failure or rejected body is recorded without a URL, so the point has no entry of its own, and a rejected body is counted with the engine's entries about no point (`"about": "no point"`), where one under a URL outside the request is about points since CRL-T049.
- [ ] **CRL-T058** fix: Withhold the `final_url` of a body that names no `url`. `Retrieval::load` records a reported redirect target, any hygienic URL, for a body answering by certificate, so an artifact can carry a URL outside the request without a point.
- [ ] **CRL-T059** test: Let a scripted answer name a URL outside the request, and pin CRL-049's handling of one in `tests/cases.json` with a named test. The runner fails a scripted `url` that is not a listed point (`specification_an_answer_with_a_problem_is_never_sent`), so only unit tests in `engine/src/retrieval.rs` pin it; a case needs an explicit marker that the URL is foreign on purpose.

### POLICY

- [ ] **POLICY-T001** feat: Add the signature policy and pin multi-signature semantics.
  Decided: `--signatures all|any`, default `all`; pin ordering, first-failure
  precedence and bundle/child binding. Detail in
  [policy-t001.md](docs/tasks/policy-t001.md).

### ALG

- [ ] **ALG-T001** test: Complete cryptographic algorithm invariant coverage. Inventory
  existing SHA-384/512 and P-384 cases before adding missing key/digest/signature
  combinations. Cover malformed RSA/ECDSA encodings, weak and excessive key
  sizes, incompatible OIDs/parameters, and certificate/CRL algorithm mismatches.
  Keep SHA-1 content opt-in separate from unsupported SHA-1 chains; weak RSA must
  remain rejected even with `--allow-sha1`.

### RDP

- [x] **RDP-T001** fix: Keep the outer error's causes on the RDP revocation fallback. Done in #89; [record](docs/tasks/done.md#rdp-t001-fix-keep-the-outer-errors-causes-on-the-rdp-revocation-fallback).
- [x] **RDP-T004** test: Cover RDP usage-failure causes through `rssig::cli::run`. Done; [record](docs/tasks/done.md#rdp-t004-test-cover-rdp-usage-failure-causes-through-rssigclirun).
- [x] **RDP-T005** fix: Report `untrusted_root` before reading the signer's EKU. Done in #113; [record](docs/tasks/done.md#rdp-t005-fix-report-untrusted_root-before-reading-the-signers-eku).

## P1 — Clean parse/verify interfaces

### PE

- [x] **PE-T001** fix: Follow up on generic PE digest correctness. Done ([PR #21](https://github.com/goatwu1993/rssig/pull/21)); [record](docs/tasks/done.md#pe-t001-fix-follow-up-on-generic-pe-digest-correctness).

### LIB

- [x] **LIB-T001** feat: Expose CAB and NAVX parsing on `no_std + alloc`. Done ([PR #23](https://github.com/goatwu1993/rssig/pull/23)); [record](docs/tasks/done.md#lib-t001-feat-expose-cab-and-navx-parsing-on-no_std--alloc).
- [x] **LIB-T002** feat: Expose structured CMS signer and attribute inspection. Done ([PR #24](https://github.com/goatwu1993/rssig/pull/24)); [record](docs/tasks/done.md#lib-t002-feat-expose-structured-cms-signer-and-attribute-inspection).
- [x] **LIB-T003** feat: Add bounded nested-signature and timestamp inspection. Done; [record](docs/tasks/done.md#lib-t003-feat-add-bounded-nested-signature-and-timestamp-inspection).
- [x] **LIB-T004** refactor: Extract script and RDP parsing boundaries. Done; [record](docs/tasks/done.md#lib-t004-refactor-extract-script-and-rdp-parsing-boundaries).
- [x] **LIB-T005** refactor: Extract MSI/MSP and AppX structural state. Done; [record](docs/tasks/done.md#lib-t005-refactor-extract-msimsp-and-appx-structural-state).
- [x] **LIB-T006** feat: Make format selection consistent for library callers. Done; [record](docs/tasks/done.md#lib-t006-feat-make-format-selection-consistent-for-library-callers).
- [x] **LIB-T007** feat: Clarify verification policy construction. Done; [record](docs/tasks/done.md#lib-t007-feat-clarify-verification-policy-construction).
- [x] **LIB-T008** refactor: Audit borrowing, errors, and public API stability. Done; [record](docs/tasks/done.md#lib-t008-refactor-audit-borrowing-errors-and-public-api-stability).
- [x] **LIB-T009** feat: Evaluate a `no_std` shared verification core. Done; [record](docs/tasks/done.md#lib-t009-feat-evaluate-a-no_std-shared-verification-core).
- [x] **LIB-T010** docs: Reassess shared interfaces and crate extraction after reuse. Done; [record](docs/tasks/done.md#lib-t010-docs-reassess-shared-interfaces-and-crate-extraction-after-reuse).
- [x] **LIB-T011** refactor: Remove the hidden public `cli::command()`. Done ([PR #115](https://github.com/goatwu1993/rssig/pull/115)).

## P1 — Tests, portable specification, and engineering checks

### TEST

- [x] **TEST-T001** test: Maintain a coverage inventory by invariant. Done; [record](docs/tasks/done.md#test-t001-test-maintain-a-coverage-inventory-by-invariant).
- [ ] **TEST-T002** test: Extend invariant and mutation testing. Verify that excluded
  checksum/signature fields and authenticated payload/metadata mutate as
  documented, and that digest, CMS, timestamp, and trust faults stay isolated.
  Use generated inputs for structural properties, never to regenerate expected
  fixture results during ordinary tests or hide target failures behind setup errors.
- [ ] **TEST-T003** test: Validate the specification and schemas together. Check
  `cases.json` against `cases.schema.json` in the Rust workflow, reconcile schema
  rules with the Serde loader, and detect invalid references or duplicate IDs.
  Audit whether public verification/inspection report schemas suffice for another
  implementation; add missing schema detail before extending output.
- [x] **TEST-T004** test: Strengthen fixture-manifest consistency checks. Done; [record](docs/tasks/done.md#test-t004-test-strengthen-fixture-manifest-consistency-checks).
- [ ] **TEST-T005** test: Automate complete-output compatibility comparisons. Preserve
  PR #18's in-process comparison approach for refactors: exit codes, complete
  JSON, stdout, and stderr. Normalize only unavoidable checkout paths, never
  security-relevant fields. Keep portable partial expectations and add exact
  snapshots/assertions where they protect schema, ordering, or diagnostic causes.
- [ ] **TEST-T006** test: Measure performance and allocation budgets. Benchmark parsing,
  hashing, CMS verification, candidate-chain work, CRLs, and bundles separately
  on representative sizes and adversarial bounded inputs. Track peak memory and
  repeated metadata conversion. Consider streaming/caching or batch parallelism
  with measured benefit, immutable input, bounded work, and deterministic results.
- [x] **TEST-T007** refactor: Rename task-named library cases. Done
  ([PR #81](https://github.com/goatwu1993/rssig/pull/81)), which renamed every
  task-named case, fixture and test by subject.
- [x] **TEST-T008** test: Let a spec case assert that a field is absent. Done ([PR #83](https://github.com/goatwu1993/rssig/pull/83)); `expect.json_absent` in [docs/testing.md](docs/testing.md).
- [x] **TEST-T009** test: Express retrieval edge cases in the case format and reindex the abort cases. Done ([PR #84](https://github.com/goatwu1993/rssig/pull/84), with the CRL-047 reindex at the owner's request); [scripted answers](docs/testing.md).
- [x] **TEST-T010** test: Guard the manifest-sources scratch directory. Done (PR number added when opened).
- [ ] **TEST-T014** test: Remove the duplicated parser-boundary cases. Five
  cases repeat another case's input, command and expectation exactly:
  `powershell-independent-jsign-parser`, `powershell-independent-tampered-parser`,
  `rdp-independent-nfedera-parser`, `psxml-independent-ascii-parser` and
  `appx-publisher-parser` (found in the task reindex). Drop them or make each
  pin what its named test checks.
- [x] **TEST-T015** test: Derive the fixture count from the checked list. Done ([PR #105](https://github.com/goatwu1993/rssig/pull/105)).
- [ ] **TEST-T016** test: Share the RFC 3161/PKCS#9 token builders across test modules.
  Share them across `engine/src/tests.rs` and `engine/src/tests/`
  `timestamp_structure.rs`, `validation_time.rs`, `rdp_fixtures.rs` and
  `cms_audit.rs` without changing committed bytes; keep their regeneration commands consistent with
  `regenerate_cli_fixtures`.
- [x] **TEST-T017** test: Check that committed path fixtures match their generator. Done ([PR #110](https://github.com/goatwu1993/rssig/pull/110)).
- [ ] **TEST-T018** test: State every key the path fixtures use. Their manifest
  provenance names P-256 constants `[40..45; 32]`, but
  `certificate_paths.rs` uses `key(40)` to `key(45)`, `key(47)` and
  `key(48)`: 47 and 48 are missing, and 45 is too if the range is exclusive.
  List the keys exactly, or check the text against the generator. Found in the review of PR #110.
- [ ] **TEST-T019** test: Fail when two fixture generators write one name.
  `regenerate_cli_fixtures` runs several generators into one directory, and a
  later one silently overwrites a file an earlier one wrote. Have them return
  their files and merge them, failing on a repeated name. Found in the review
  of PR #110.
- [ ] **TEST-T020** test: Require each fixture's manifest `cases` to list every
  case that reads it. `tests/manifest.rs` does not check that the lists are
  complete, so a new case on an existing fixture can be left out silently.
  Found in the review of PR #113.

### BUILD

- [x] **BUILD-T001** test: Add local parser and verifier fuzz targets. Done; [record](docs/tasks/done.md#build-t001-test-add-local-parser-and-verifier-fuzz-targets).
- [ ] **BUILD-T002** build: Exercise 32-bit behavior and independent consumers. Current
  bare-metal checks compile the parser but do not execute it there. Add a
  practical 32-bit execution path for bounds regressions and tiny external
  consumer builds that avoid dev-dependency feature unification. Cover minimal,
  `std`, verifier-only, native-root, and CLI feature combinations and doctests.
- [ ] **BUILD-T003** build: Automate dependency and native-code boundary checks. Inspect
  resolved normal dependencies/features on Linux/macOS and minimal builds.
  Reject OpenSSL, ring, aws-lc, native validation, and subprocess crypto; examine
  build scripts/linkage as well as package names. Allow native root enumeration
  explicitly. Add dependency advisory/license review without making offline
  fixture tests require network access.
- [ ] **BUILD-T004** build: Improve CI evidence and regression visibility. Keep existing
  Linux/macOS, lint, coverage, and no_std jobs. Surface missing fixture/schema
  checks and relevant uncovered production branches; distinguish the thin
  process adapter from in-process engine coverage. Evaluate a coverage regression
  policy after measuring the baseline, without redundant tests or exclusions
  that hide production code.
- [ ] **BUILD-T006** build: Keep fixture bytes unchanged on checkout. No
  `.gitattributes` marks `tests/fixtures/` binary, so `core.autocrlf=true`
  rewrites every text fixture (`.pem`, `.rdp`, `.ps1`, `.vbs`, `.json`, ...)
  with CRLF and the manifest SHA-256 check fails, as it already did before
  PR #110 added the generator byte check. Mark them `-text`, with a check that
  fails without it. Found in the review of PR #110.

### CRL

- [ ] **CRL-T025** test: Consolidate CRL fixture builders and CRL-T001 fixture provenance. Recorded from PR #44 to #53 reviews; none affects verifier behavior. Detail in [crl-t025.md](docs/tasks/crl-t025.md).
- [x] **CRL-T026** docs: Link CRL retrieval rules to their entries. Done ([PR #88](https://github.com/goatwu1993/rssig/pull/88)); [CRL retrieval](docs/crl-retrieval.md).
- [ ] **CRL-T027** refactor: Attach the claimed `CRL-` cases. Name existing
  entries for the cases claimed under `attach` (remaining CRL-T001 audit
  cases, every format's revocation case).
- [ ] **CRL-T028** test: Commit fixtures for CRLs without nextUpdate. When such a
  CRL revokes, clears an older listing or is set aside is pinned by unit
  tests on `evaluate_crls` (`engine/src/trust.rs`); the cRLSign, delta,
  removeFromCRL, not-yet-valid, malformed-AKI and unreadable-point variants
  have no fixture or spec case.
- [x] **CRL-T039** refactor: Move the request-count limit from the CRL retrieval engine to the `CrlSource` implementations. Done ([PR #91](https://github.com/goatwu1993/rssig/pull/91)); [CRL-039](docs/crl.md#crl-039-fetch-limits-bound-one-verification), [CRL retrieval](docs/crl-retrieval.md).
- [x] **CRL-T040** refactor: Offer every listed point to the source and cap only the report. Done ([PR #92](https://github.com/goatwu1993/rssig/pull/92)); [CRL-024](docs/crl.md#crl-024-one-certificates-distribution-points-never-end-the-run).
- [x] **CRL-T041** refactor: Move the engine's reuse of earlier answers to the source. Done ([PR #95](https://github.com/goatwu1993/rssig/pull/95)); [CRL-033](docs/crl.md#crl-033-retrieval-asks-per-certificate-only-about-what-lacks-a-crl), [CRL-050](docs/crl.md#crl-050-each-request-carries-every-point-the-certificate-lists-whatever-was-asked-before), [CRL-051](docs/crl.md#crl-051-each-certificate-records-what-its-own-request-yielded-reuse-is-the-sources).
- [ ] **CRL-T042** test: Add a `tests/cases.json` case and CLI test for a certificate listing more than 16 distribution points (CRL-024): all reach the source, and the report keeps 16 entries plus one `details.omitted` entry. Needs a fixture with a many-point certificate.
- [ ] **CRL-T043** refactor: Bound the engine's per-point state for a certificate listing many URIs; measure again after CRL-T041. Detail in [crl-t043.md](docs/tasks/crl-t043.md).
- [x] **CRL-T044** refactor: Give `HttpCrlSource` a per-request point limit. Done in [PR #92](https://github.com/goatwu1993/rssig/pull/92) with CRL-T040; [CRL-039](docs/crl.md#crl-039-fetch-limits-bound-one-verification).
- [ ] **CRL-T045** feat: Decide whether the CLI reuses fetched CRLs across the files of one invocation (owner decision). Detail in [crl-t045.md](docs/tasks/crl-t045.md).
- [ ] **CRL-T046** refactor: Share a cached CRL body, and its digest, between the requests that repeat it. Detail in [crl-t046.md](docs/tasks/crl-t046.md).
- [ ] **CRL-T047** fix: Decide whether a URL the built-in source refuses before any network work uses a distinct-URL slot (owner decision). `HttpCrlSource::fetch_one_keyed` counts it toward `MAX_SOURCE_URLS` before its policy check, as `the_built_in_source_aborts_past_its_distinct_url_cap_until_a_new_verification` pins, so private or local names can spend slots a public point needs.
- [x] **CRL-T048** refactor: Drop the always-false `spent_before` argument of `HttpCrlSource::classify`. Done ([PR #103](https://github.com/goatwu1993/rssig/pull/103)).
- [x] **CRL-T049** fix: Record a response's failure or body naming a URL outside the request without it. Done ([PR #112](https://github.com/goatwu1993/rssig/pull/112)).
- [ ] **CRL-T050** test: Pin in `tests/cases.json` that a certificate reached once retrieved CRLs fill the 32 MiB the store retains is not asked and its points are recorded as not tried (`retrieval_trust_bytes`), the verifier's result standing. Only the unit test `a_certificate_with_no_room_left_is_not_asked_and_the_run_goes_on` pins it: a case needs CRL bodies that load and total near 32 MiB (a large CRL fixture or a generator).
- [ ] **CRL-T051** fix: Decide how the engine offers a listed spelling that normalizes to another listed point (owner decision). It offers each point once by its normalized URL, so a spelling `HttpCrlSource` refuses before parsing (a backslash, over 2,048 bytes) listed first stands in for the clean URL, which is then not offered. Keying offers by raw text keeps both but must still match answers and report entries by the normalized URL.
- [ ] **CRL-T052** fix: Decide whether a request whose byte allowance cannot hold any CRL is made. The engine skips a certificate only when no retained byte is left; with a few left, `HttpCrlSource` still makes HTTP requests that must fail on `crl_response_bytes`, spending its 16-request and 64-URL caps now that every certificate is asked.

### TIME

- [x] **TIME-T003** refactor: Index time decisions as `TIME-NNN`. Done ([PR #68](https://github.com/goatwu1993/rssig/pull/68)); [time decisions](docs/time.md).
- [ ] **TIME-T004** refactor: Attach the claimed `TIME-` cases. The cases claimed under
  `TIME` `attach` (the pre-TIME-T001 time cases and every format's
  expired-with-timestamp copy) name their TIME entries.
- [ ] **TIME-T007** test: Add lifetime-signing fixtures for the formats without one.
  The `*-lifetime-*` cases cover PE (primary and nested) and RDP; MSI, MSP,
  CAB, NAVX, PowerShell, WSH and MSIX/AppX use the same trust call without one.
- [ ] **TIME-T008** docs: Extend and narrow `TIME-` entries for the TIME-T002 rules not yet pinned.
  The [record](docs/tasks/done.md#time-t002-fix-lifetime-signing-review-decisions-and-deferred-follow-ups)
  maps each to its entry: extend TIME-009, TIME-011 and TIME-013 and narrow
  TIME-010 to intermediates where marked; the candidate-path rules are PATH-T009.
- [x] **TIME-T009** fix: Make `TrustReport.lifetime_signing` required. Done ([PR #96](https://github.com/goatwu1993/rssig/pull/96)); owner-approved removal of the pre-TIME-T001 `serde(default)`.

### PATH

- [x] **PATH-T003** refactor: Index certificate-path decisions as `PATH-NNN`. Done ([PR #69](https://github.com/goatwu1993/rssig/pull/69)); [certificate-path decisions](docs/path.md).
- [ ] **PATH-T004** refactor: Attach the claimed `PATH-` cases. Name existing
  entries for the cases claimed under `attach` (every format's untrusted-root
  case), and add a PATH entry for `certificate-signature`.
- [ ] **PATH-T008** test: Pin a root re-issued after a lifetime signing time.
  [PATH-011](docs/path.md#path-011-configured-anchors-are-keys) accepts such a
  path, but its cases pin anchors at the validation time only; add a paired
  fixture.
- [ ] **PATH-T009** docs: Add decision entries for how candidate-path failures are reported.
  Rules kept in TIME-T002: equal-rank failures report the first encountered,
  and once any candidate lacked keyCertSign, a final unknown-issuer failure
  from another path is reported as `invalid_key_usage`.

### TSA

- [x] **TSA-T002** refactor: Index timestamp decisions as `TSA-NNN`. Done ([PR #70](https://github.com/goatwu1993/rssig/pull/70)); [timestamp decisions](docs/tsa.md).
- [ ] **TSA-T003** refactor: Attach the claimed `TSA-` cases. Name existing
  entries for the cases claimed under `attach`.

### CMS

- [x] **CMS-T004** refactor: Index CMS decisions as `CMS-NNN`. Done ([PR #72](https://github.com/goatwu1993/rssig/pull/72)); [CMS decisions](docs/cms.md).

### TRUST

- [ ] **TRUST-T002** refactor: Number the `TRUST-` index. Fill [docs/trust.md](docs/trust.md);
  number the `trust-*` cases it claims (the other cases from the same
  task belong to LIMIT-T005, CRL-T027 and PATH-T004).

### LIMIT

- [ ] **LIMIT-T005** refactor: Number the `LIMIT-` index. Fill [docs/limit.md](docs/limit.md);
  number the `limit-*` cases.
- [ ] **LIMIT-T006** test: Pin the CRL response-entry limit in a case. A
  scripted answer can now carry more than 64 bodies and failures
  (`crl_response_entries`), which only a unit test pins; claim the case under a
  candidate rule until LIMIT-T005 numbers the index. From TEST-T009.

### MSI

- [ ] **MSI-T001** refactor: Number the `MSI-` index. Fill
  [docs/msi-decisions.md](docs/msi-decisions.md) from its skeleton. Move an
  `embedded-signature` case to `CMS-` where its rule is shared.

### CAB

- [ ] **CAB-T001** refactor: Number the `CAB-` index. Fill
  [docs/cab-decisions.md](docs/cab-decisions.md) from its skeleton. Move an
  `embedded-signature` case to `CMS-` where its rule is shared.

### NAVX

- [ ] **NAVX-T001** refactor: Number the `NAVX-` index. Fill
  [docs/navx-decisions.md](docs/navx-decisions.md) from its skeleton. Move an
  `embedded-signature` case to `CMS-` where its rule is shared.

### PS

- [ ] **PS-T001** refactor: Number the `PS-` index. Fill
  [docs/ps-decisions.md](docs/ps-decisions.md) from its skeleton. Move an
  `embedded-signature` case to `CMS-` where its rule is shared.

### WSH

- [ ] **WSH-T001** refactor: Number the `WSH-` index. Fill
  [docs/wsh-decisions.md](docs/wsh-decisions.md) from its skeleton. Move an
  `embedded-signature` case to `CMS-` where its rule is shared.

### RDP

- [ ] **RDP-T002** refactor: Number the `RDP-` index. Fill
  [docs/rdp-decisions.md](docs/rdp-decisions.md) from its skeleton. Move an
  `embedded-signature` case to `CMS-` where its rule is shared.

### APPX

- [ ] **APPX-T001** refactor: Number the `APPX-` index. Fill
  [docs/appx-decisions.md](docs/appx-decisions.md) from its skeleton. Move an
  `embedded-signature` case to `CMS-` where its rule is shared.
- [ ] **APPX-T003** fix: Make `AppxReport.kind` required.
  Its bare `#[serde(default)]` only reads reports written before the field, the
  compatibility shim the release-status rule in AGENTS.md rules out, as
  TIME-T009 removed for `lifetime_signing`; `engine/src/appx.rs` tests reading one.

### DOC

- [x] **DOC-T001** refactor: Reindex misplaced decisions. Done ([PR #70](https://github.com/goatwu1993/rssig/pull/70)); mapping in that PR.
- [x] **DOC-T002** feat: Scaffold the remaining decision indexes. Done ([PR #71](https://github.com/goatwu1993/rssig/pull/71)); claims in `tests/decision-claims.json`.
- [x] **DOC-T003** feat: Use one meaning per term. Done ([PR #71](https://github.com/goatwu1993/rssig/pull/71), together with DOC-T002 at the owner's request); [glossary](docs/glossary.md).
- [x] **DOC-T004** refactor: Remove duplicate and overlapping decisions. Done ([PR #74](https://github.com/goatwu1993/rssig/pull/74)); mapping in that PR.
- [x] **DOC-T005** refactor: Settle the shared format-skeleton rules. Done ([PR #75](https://github.com/goatwu1993/rssig/pull/75)); [format indexes](docs/decisions.md#format-indexes).
- [x] **DOC-T009** docs: Require a guard for review findings judged invalid. Done ([PR #85](https://github.com/goatwu1993/rssig/pull/85)); [Review findings](AGENTS.md#review-findings).
- [ ] **DOC-T010** test: Check `scopes.yml` against its users. Every scope has a
  decision-index row when its kind is `decision` or `format` with an index, every
  `TODO.md` task ID and `### <SCOPE>` heading names a listed scope, and the file
  list in `docs/decisions.md` matches. Adding a YAML parser is a dependency
  decision (fuzz `Cargo.lock` must stay in step): reuse `yaml-rust2`, chosen
  by DOC-T013, in `tests/repository.rs`.
- [x] **DOC-T011** docs: Define the pre-1.0 flow: who decides, how to ask, how a PR is kept. Done ([PR #101](https://github.com/goatwu1993/rssig/pull/101)); [AGENTS.md](AGENTS.md#pre-10-flow).
- [ ] **DOC-T012** docs: Hold the 1.0 gate for decisions (owner decision). Detail in [doc-t012.md](docs/tasks/doc-t012.md).
- [x] **DOC-T013** test: Check the frontmatter of the project skills. Done ([PR #114](https://github.com/goatwu1993/rssig/pull/114)); [Repository checks](docs/testing.md#repository-checks).
- [x] **DOC-T014** docs: Let Claude start `/review-loop` itself, with up to ten rounds. Done ([PR #104](https://github.com/goatwu1993/rssig/pull/104)); [review-loop](.claude/skills/review-loop/SKILL.md).
- [ ] **DOC-T015** test: Check the format of each project skill's `name` and the length of `name` and `description`, against the limits Claude Code documents for skills; `tests/repository.rs` checks only that they are present (DOC-T013).

### ALG

- [ ] **ALG-T002** refactor: Number the `ALG-` index. Fill [docs/alg.md](docs/alg.md):
  unsupported algorithms and the SHA-1 opt-in in every format.

### POLICY

- [ ] **POLICY-T002** refactor: Number the `POLICY-` index. Fill [docs/policy.md](docs/policy.md):
  every format's integrity-only case and the library policy cases.

### CLI

- [ ] **CLI-T001** refactor: Number the `CLI-` index. Fill [docs/cli.md](docs/cli.md).

### INSPECT

- [ ] **INSPECT-T001** refactor: Number the `INSPECT-` index. Fill [docs/inspect.md](docs/inspect.md).

### PE

- [x] **PE-T002** refactor: Number the `PE-` index. Done ([PR #76](https://github.com/goatwu1993/rssig/pull/76)); [PE decisions](docs/pe-decisions.md).

## P1 — CLI, reporting, and distribution

### CLI

- [ ] **CLI-T002** fix: Make remaining failure classifications precise. Audit
  generic anyhow conversions for unsupported structures, invalid certificates,
  root/CRL loading, timestamps, and exhausted limits. Preserve stable code/stage,
  structured context, and causes. Test conversion from every parser error kind
  and avoid requiring consumers to match prose.
- [ ] **CLI-T003** fix: Audit file/stream edge cases. Cover non-UTF-8 paths, path
  serialization failures, directories/unreadable inputs, repeated files, mixed
  batches, and writer/flush failures through in-process CLI entry points. Prevent
  panic paths while preserving one JSON document where output is writable;
  argument/configuration errors remain plain stderr with exit 2.
- [ ] **CLI-T004** fix: Keep the causes an inner conversion already reported.
  `VerificationError::from_internal` rebuilds `causes` from the chain even
  when the typed error on top already carries causes from an earlier
  conversion, so a public `verify_*` boundary reduces them to the message
  (RDP: `at`, then `verify_rdp`). The outer messages RDP-T001 keeps never
  reach the JSON; no case yet pins more than one cause.

### DOC

- [ ] **DOC-T006** docs: Document result and schema evolution. Define compatibility
  rules for new fields, enum variants, optional values, raw DER, and schema
  versions. Make parse-only, integrity-only, trusted, revocation-disabled, and
  package-hashed-but-not-independently-verified catalog states unambiguous.
  Keep supplied artifacts distinct from selected evidence.
- [ ] **DOC-T007** docs: Keep public API and decision documentation current. Add
  compiling examples for parse-only and explicit trusted verification, feature
  combinations, and error handling. Update stale source paths in the comparison
  document; keep format limits, CLI help, README tables, architecture, and tests
  aligned. External comparisons retain pinned revisions and stated evidence limits.
  CRL applicability, distribution-point and competing-evidence rules live in
  one table cell of `docs/validation-time.md` (the CRL row), which is hard to read
  and to cite. Move it to its own document with one rule per line and its
  pinning cases, and link it from the README and from `AGENTS.md`'s current
  boundaries, which describe CRL handling only in general terms.
- [ ] **DOC-T008** docs: Document security review and reporting boundaries. Provide
  vulnerability-reporting and supported-version policies, and identify areas
  needing independent review before stronger security claims. Keep existing
  AI-assisted-development and Windows-policy limitations visible; passing tests
  or high coverage is not an audit or certification.

### CRL

- [ ] **CRL-T029** fix: Serialize absent retrieval URLs one way.
  `CrlRetrievalArtifact.url` and `final_url` are omitted when absent while
  `CrlRetrievalFailure.url` serializes as `null`; pick one under DOC-T006's
  rules.

### BUILD

- [ ] **BUILD-T005** build: Define compiler, target, and release support. Choose and
  test an MSRV; distinguish compiled targets/features from runtime-tested ones.
  Check packaged-crate contents and consumer builds (`make package-check`
  already builds each packaged crate), and document semver/API
  migration before publishing. Prepare reproducible Linux/macOS artifacts and
  checksums when distribution is requested; fixture signing keys and read-only
  reference clones must not enter release artifacts.

## P2 — Interoperability and existing-format coverage

### TEST

- [ ] **TEST-T011** test: Expand independently produced fixtures. Build on existing
  Jsign MSI/MSP/CAB/NAVX/script/AppX, upstream SignTool, and independent RDP
  artifacts. Prioritize independent PE, nested CMS, timestamps, and trusted
  chain/CRL combinations, including Relic where useful. Record producer/version,
  license, provenance, digest, and narrow bad counterparts. Separate integrity-only
  evidence from trusted verification and keep normal tests offline.
- [ ] **TEST-T012** test: Record reproducible cross-tool differences. Pin tools,
  roots, time, algorithms, revocation/network settings, and each verifier's actual
  checks. Resolve disagreements against format evidence and explicit rssig decisions,
  then commit portable expectations. A competitor's success exit is not necessarily
  a trusted verdict; competitors remain maintenance tools.

### PE

- [ ] **PE-T003** test: Extend PE layout evidence before broadening support. Cover
  PE layouts, page sizes and certificate placement, and add a case for each PE
  rule no case pins yet. Detail in [pe-t003.md](docs/tasks/pe-t003.md).
- [ ] **PE-T004** fix: Decide skipped WIN_CERTIFICATE entries. PE-004 rejects
  entries Microsoft's documents allow and osslsigncode and jsign skip. Detail
  in [pe-t004.md](docs/tasks/pe-t004.md).

### MSI

- [ ] **MSI-T002** test: Audit MSI/MSP CFB and metadata variants. Extend independent
  v3/v4, stream-name/order, FAT/miniFAT, metadata, and legacy/extended-signature
  coverage. Pin duplicate/aliased signature-stream handling and file-time details.
  New layouts need bounded traversal and hash evidence; MSP applicability,
  installation semantics, and patch authorization remain outside verification.

### CAB

- [ ] **CAB-T002** test: Expand CAB envelope interoperability. Add independent
  reserve/padding/hash-range cases. Consider CAB layouts with unambiguous
  hashing rules and producer evidence; multipart handling needs a separate
  design.

### NAVX

- [ ] **NAVX-T002** test: Expand NAVX envelope interoperability. Add independent
  envelope/back-pointer cases. NAVX payloads remain opaque, and signature
  success does not imply extension validity or installability.

### PS

- [ ] **PS-T002** test: Expand PowerShell signature encoding evidence. Cover
  BOM/newline, terminator, comment delimiter, Unicode, and duplicate-block
  behavior across PowerShell and PowerShell XML. Pin unsupported legacy
  encodings before adding decoders. No script execution, XMLDSig substitution,
  DTD/entity fetching, or script execution-policy claims.

### WSH

- [ ] **WSH-T002** test: Expand WSH signature encoding evidence. Cover
  BOM/newline, terminator, comment delimiter, Unicode, and duplicate-block
  behavior across WSH scripts. Pin unsupported legacy encodings and
  encoded-script behavior before adding decoders. No script execution,
  DTD/entity fetching, or script execution-policy claims.

### RDP

- [ ] **RDP-T003** test: Extend RDP scope mappings only with evidence. Maintain
  display-name/key/type mappings and canonicalization tests. Unknown signed scope
  entries continue to fail; unscoped properties remain explicitly unsigned.
  More settings/encodings or nested signatures need isolated fixtures and a
  documented rules; never open fixtures in an RDP client.

### APPX

- [ ] **APPX-T002** test: Audit AppX edge cases and rule gaps. Extend
  ZIP64/descriptors, compression/block boundaries, filename collisions, namespace
  parsing, publisher DN comparison, and bundle child identity/signature cases.
  Evaluate Unicode names and additional manifest/bundle profiles individually
  with producer evidence and aggregate budgets. Keep unsupported external/stub/
  nested bundles explicit; deployment selection and Windows Store acceptance
  are not established by package integrity.

## P3 — Additional capabilities requiring separate design

### CRL

- [x] **CRL-T030** feat: Add bounded opt-in CRL retrieval. Done; [record](docs/tasks/done.md#crl-t030-feat-add-bounded-opt-in-crl-retrieval).
- [ ] **CRL-T031** feat: Add OCSP with explicit evidence rules. Require responder
  authorization, signature/freshness checks, issuer/serial binding, and tested
  unknown/revoked/error behavior. Define interaction with CRLs, caches, offline
  operation, and timestamped verification. Network failure must not silently
  become good revocation status.

### PATH

- [ ] **PATH-T005** feat: Add bounded AIA issuer retrieval. Extend the retrieval
  boundary to missing intermediate certificates, always as untrusted candidates,
  never new trust anchors. Define pre-trust destination discovery, loop/work
  limits and provenance. HTTPS transport and persistent caching also remain
  separate follow-ups requiring a decision and dependency review.

### ALG

- [ ] **ALG-T003** feat: Add RSA-PSS where interoperability justifies it. Specify
  digest/MGF/salt/trailer parameters and rules for CMS, certificates, CRLs, and
  timestamps independently. Add good/bad parameter and key fixtures and audit
  RustCrypto/webpki support; never reinterpret PSS as v1.5.

### CAT

- [ ] **CAT-T001** feat: Add catalog signature and membership verification. Verify
  trusted catalog signatures and target membership separately. Design standalone
  catalogs first, then explicitly wire AppX CodeIntegrity catalogs into reports
  if supported. Until then retain `signature_verified: false` for package-hashed
  embedded catalogs.

### P7S

- [ ] **P7S-T001** feat: Design generic detached signature verification. Specify
  how a sidecar binds to supplied content, format/SIP selection, CMS profile,
  algorithms, trust, timestamps, and revocation. Reuse the engine while keeping
  RDP canonicalization separate. Parsing a `.p7s` alone must never be presented
  as verification of an unspecified file.

## Deferred and outside the current verification scope

- [ ] **TEST-T013** test: Add a Windows oracle integration. Deferred at the
  user's request. Do not add a Windows/SignTool/WinVerifyTrust runner as part of these
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
