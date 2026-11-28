# CRL-T001 fix: Audit CRL applicability and competing evidence

Task detail for **CRL-T001** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox. Other IDs below (CRL-T002, CRL-T003 to CRL-T009, CRL-T025,
DOC-T007, TEST-T011, TEST-T013) are items in that file.

The decisions this task made are indexed in [CRL decisions](../crl.md).

**Status:** complete. Every box in the audit checklist is checked, as is the
box in `TODO.md`. The limitations below stay open under their own IDs.

## Scope

Cover absent nextUpdate, issuer/AKI mismatch, cRLSign usage, revoked
intermediates, incomplete issuer coverage, distribution-point scope, unknown
critical extensions, delta/indirect CRLs, and competing or unrelated supplied
CRLs. Specify whether an unusable extra CRL rejects a request or is excluded.
Never silently treat unknown status as good; pin freshness boundaries and
unsupported-feature errors.

The rules are stated in the CRL row of [validation time](../validation-time.md). The
cases named below are in `tests/cases.json`, with named tests in
`tests/cli/crl_applicability.rs` and `tests/cli/crl_fetch.rs`.

## Audit checklist

One box per item in the scope above.

- [x] **Absent nextUpdate.** A chain issuer's CRL without it is `invalid_crl`
  (`missing_next_update`); from an unrelated issuer it is excluded.
  `crl-002-root-crl-no-next-update`,
  `crl-unrelated-no-next-update-crl-excluded`.
- [x] **Issuer/AKI mismatch.** A CRL applies only if its issuer name equals a
  configured root's or embedded candidate's subject and, when it carries an AKI
  keyIdentifier, that matches a name-matching candidate's SKI or the CRL's
  signature verifies under a name-matching candidate key. A malformed AKI on an
  applicable CRL is `invalid_crl`. `crl-root-name-other-aki-crl-excluded`,
  `crl-012-root-aki-crl-still-rejected`,
  `crl-012-root-signed-other-aki-crl-still-rejected`,
  `crl-012-root-crl-malformed-aki`, `crl-unrelated-malformed-aki-crl-excluded`,
  `crl-012-root-aki-issuer-serial-crl-name-matched`. Limits: CRL-T004.
- [x] **cRLSign usage.** An intermediate issuer without cRLSign cannot issue a
  usable CRL (`invalid_key_usage` at `revocation`), and path building falls back
  to a candidate that has it. A configured root is exempt by decision.
  `crl-ca-no-crl-sign`, `crl-ca-crl-sign`, `crl-ca-crl-sign-fallback`,
  `crl-015-root-no-crl-sign-accepted`.
- [x] **Revoked intermediates.** `certificate_revoked` in four `--crl` orders.
  `crl-revoked-issuer`, `crl-revoked-issuer-after-good-root-crl`,
  `crl-revoked-issuer-before-good-root-crl`,
  `crl-revoked-issuer-issuer-crl-first`. Limit: the error details describe the
  signer (CRL-T007).
- [x] **Incomplete issuer coverage.** A chain certificate with no applicable CRL
  is `revocation_unknown`. `time-007-lifetime-rollover-revocation-unknown`,
  `crl-only-unrelated-crl-is-unknown`.
- [x] **Distribution-point scope.** A CRL naming a point is authoritative only
  for a certificate listing the same URI, byte for byte; role flags restrict it
  to end-entity or CA certificates; any matching URI among several names or
  points is enough; non-URI and issuer-relative names never match; a point with
  reasons or cRLIssuer is skipped; a full CRL covers every certificate of its
  issuer. `crl-dp-*` (26 cases), `crl-ca-crl-dp-*`,
  `crl-partition-crl-no-listed-point`,
  `crl-partition-crl-relative-no-listed-point`,
  `crl-012-root-idp-named-point-crl-rejected`,
  `crl-012-root-idp-user-certs-crl-unsupported`,
  `crl-012-root-idp-ca-certs-crl-unsupported`.
- [x] **Unknown critical extensions.** On the CRL or on a revoked entry:
  `invalid_crl` (`unknown_critical_extension`); a non-critical one is ignored.
  `crl-012-root-unknown-critical-extension-crl-unsupported`,
  `crl-012-root-entry-critical-extension-crl-unsupported`,
  `crl-root-unknown-noncritical-extension-crl-accepted`.
- [x] **Delta and indirect CRLs.** `invalid_crl` (`delta_crl`, `indirect_crl`),
  reported before freshness. `crl-012-root-delta-crl-unsupported`,
  `crl-012-root-indirect-crl-unsupported`,
  `crl-012-root-delta-expired-crl-reports-feature`. Limit: CRL-T006.
- [x] **Competing or unrelated supplied CRLs.** Unrelated CRLs are excluded
  whatever their fault; among CRLs that cover the certificate a revocation in
  any one wins in either order. `crl-unrelated-expired-crl-excluded`,
  `crl-unrelated-not-yet-valid-crl-excluded`,
  `crl-competing-crls-good-first-revoked`,
  `crl-competing-crls-revoked-first-revoked`. Since PR #60 a partition for
  another point does not cover the certificate, so its entries are not read
  (`crl-013-dp-other-partition-revocation-is-ignored`,
  `crl-013-dp-other-partition-revocation-is-ignored-first`; see "Case
  reasons"). Limit: CRL-T009.
- [x] **Unusable extra CRL: reject or exclude.** Specified: excluded when it
  does not apply to the chain, otherwise the request fails closed.
  `crl-012-root-expired-crl-still-rejected` against the
  `crl-unrelated-*-excluded` cases. Limit: CRL-T006.
- [x] **Unknown status is never good.** Path validation denies unknown status,
  and a request whose supplied CRLs all fail to apply is `revocation_unknown`.
  `crl-only-unrelated-crl-is-unknown`, `crl-030-dp-other-idp-unknown`,
  `crl-dp-other-idp-revoked-unknown`.
- [x] **Unsupported-feature errors.** Every applicable CRL that cannot be used is
  `invalid_crl` with a `details.reason` listed in [problems](../problems.md).
  Limit: reasons without a fixture are CRL-T007.
- [x] **Freshness boundaries.** A CRL is usable from its thisUpdate (inclusive)
  until one second before its nextUpdate: a validation time one second before
  thisUpdate is `crl_not_yet_valid`, and one equal to nextUpdate is
  `crl_expired`. Pinned on an untimestamped signer.
  `crl-this-update-one-second-ahead`, `crl-this-update-exact`,
  `crl-next-update-one-second-left`, `crl-next-update-exact`. Whole
  seconds only; CRL times carry no fractions.
- [x] **`--fetch-crls` coverage.** Retrieval follows the verifier's result:
  the supplied CRLs are verified first, and the selected certificates' listed
  points are fetched only when that result is `revocation_unknown`. A CRL that
  merely has the issuer's name (another partition, another role, or another
  key of the same name) does not suppress the fetch, and the fetched CRL is
  held to the same verification. `crl-fetch-other-idp-fetches-listed-point`,
  `crl-fetch-other-idp-fetched-revoked`,
  `crl-fetch-other-idp-fetched-other-unknown`,
  `crl-fetch-ca-scope-idp-fetches-listed-point`,
  `crl-fetch-ca-user-scope-idp-fetches-listed-point`,
  `crl-033-fetch-excluded-name-match-fetches-listed-point`,
  `crl-033-fetch-covered-signer-point-not-requested`,
  `crl-033-fetch-asks-each-certificate-without-crl`,
  `crl-033-fetch-covered-signer-is-not-asked`, and the
  `crl-fetch-*-not-fetched` controls; named tests in
  `tests/cli/crl_fetch.rs`.
  A supplied CRL that verification rejects is reported as it is offline and
  nothing is fetched when the certificate lists no point
  (`crl-fetch-no-listed-point-not-fetched`,
  `crl-009-fetch-no-listed-point-role-excluded-scope-rejected`). One that a
  source's CRL could replace is asked about
  (`crl-020-fetch-unusable-scope-supplied-crl-refreshed`; see "Case reasons
  (refresh of an unusable supplied CRL)").
  A listed point that discovery does not support (reasons, cRLIssuer or a
  non-URI name) is not requested and is listed in `crl_retrieval.failures`; the
  result is the verifier's `revocation_unknown`, as without `--fetch-crls`
  (`crl-026-fetch-reasons-point-denied`, `crl-026-fetch-crl-issuer-point-denied`,
  `crl-026-fetch-dns-name-point-denied`).
  History: PR #55 first restated webpki's authority rule for this
  (`has_crl_for`); the follow-up replaced it with the flow above.
  Limits: see evidence limits.

## Decisions made

- The best CRL decides, checked per certificate on each path (PR #60):
  revocation is evaluated by rssig for every certificate on a candidate path,
  as OpenSSL and Bouncy Castle do, and webpki confirmed the accepted path with
  only the chosen CRLs (removed in CRL-T011, see
  [CRL-T011](crl-t011.md); rssig's own evaluation is
  now the only revocation check). An unusable CRL is set aside when another CRL of the
  issuer is usable; the former `root-*` cases (now `crl-012-root-*`) now pin each failure with
  the bad CRL alone and success beside `good.crl`. Changing those earlier
  failure expectations for the bad CRL beside `good.crl` was approved by the
  repository owner as a one-time exception to the AGENTS.md rule; each
  failure is still pinned with the bad CRL alone.

- Compared with OpenSSL and Bouncy Castle (AGENTS.md, "Pinned
  expectations"); source at OpenSSL `crypto/x509/x509_vfy.c` and bc-java
  `prov/.../jce/provider/RFC3280CertPathUtilities.java`,
  `pkix/.../X509RevocationChecker.java`:
  - **Decided, acceptance.** A CA-only CRL (onlyContainsCACerts) that names a
    distribution point, as the only CRL of an end-entity certificate listing
    none, is `invalid_crl` (`distribution_point_scope`), not set aside.
    OpenSSL keeps it as a near match and fails with
    `X509_V_ERR_DIFFERENT_CRL_SCOPE` (`crl_crldp_check`, `check_crl`); Bouncy
    Castle rejects it in processCRLB2 with a distribution-point name mismatch.
    With a full CRL of the issuer present, all three use the full CRL.
    Case: `crl-009-fetch-no-listed-point-role-excluded-scope-rejected`.
  - **Decided, acceptance.** A listing in a CRL whose signature cannot be
    verified (bad or unsupported) never counts as a revocation. OpenSSL fails
    the CRL in `check_crl` before `cert_crl` reads entries; Bouncy Castle
    skips it in processCRLG before processCRLJ reads entries. Here it is
    `invalid_crl` (`unsupported_signature_algorithm`) or
    `invalid_crl_signature`, set aside when another CRL is usable.
  - **Decided, acceptance.** One certificate's distribution points never end
    the run: an over-long URI is skipped; every other URI is offered to the source
    (CRL-T040). OpenSSL's verifier has no such limit
    (an unmatched point means no CRL); Bouncy Castle has none either and
    skips a point that fails. The per-verification limits stay engine limits.
    Unit test `a_certificate_over_the_url_limits_is_skipped_point_by_point`.
  - **Decided by choice, diagnostics only.** Across candidate paths, a CA
    issued after the lifetime signing time on one path outranks a revocation
    on another (`time-011-lifetime-rollover-revoked-issuer`); both reject. The
    libraries do not agree and neither has lifetime signing: OpenSSL builds
    one chain, preferring currently valid issuers, and checks revocation
    before validity on it; Bouncy Castle tries every path and reports the
    last failure, checking validity before revocation per certificate. The
    TIME-T002 precedence is kept.

Change these only with a new decision and paired fixtures.

- A CRL that does not apply to the chain is excluded; one that applies must be
  usable or the request fails closed ([PR
  #44](https://github.com/goatwu1993/rssig/pull/44), #45).
- Unsupported features are reported before freshness, and revoked entries are
  parsed when the CRL is loaded ([PR
  #46](https://github.com/goatwu1993/rssig/pull/46)).
- Configured anchors are keys: a root whose KeyUsage lacks cRLSign still issues
  usable CRLs ([PR #48](https://github.com/goatwu1993/rssig/pull/48); webpki
  0.103 does not track anchor KeyUsage).
- A CRL that names a distribution point is `invalid_crl`
  (`distribution_point_scope`) when a certificate it would cover lists no
  cRLDistributionPoints, because webpki would treat it as authoritative ([PR
  #48](https://github.com/goatwu1993/rssig/pull/48)).
- On a path where every certificate has an authoritative CRL, a listing in any
  other applicable CRL of the issuer's name also rejects, whatever the `--crl`
  order ([PR #48](https://github.com/goatwu1993/rssig/pull/48)). A listing by a
  non-authoritative CRL alone is `revocation_unknown` ([PR
  #49](https://github.com/goatwu1993/rssig/pull/49), until CRL-T009).
- With `--fetch-crls`, retrieval happens only when verification with the
  supplied CRLs is `revocation_unknown`; any other result is returned
  unchanged. This replaces the restated authority rule of PR #55.
- When no supplied CRL applies, `revocation_unknown` is returned before path
  building ([PR #44](https://github.com/goatwu1993/rssig/pull/44); CRL-T008).

## Evidence limits

- Distribution-point matching is rustls-webpki's, observed at 0.103.16, which
  `Cargo.toml` now requires exactly (`=0.103.16`). No other version was
  checked; rerun the `crl-*` cases when changing the pin.
- Not pinned: a certificate mixing a skipped point (reasons or cRLIssuer) with a
  plain URI point.
- Every CRL-T001 CRL is synthetic and signed with ECDSA P-256/SHA-256. There is no
  RSA-signed CRL and no CRL from an independent producer carrying an AKI or
  issuingDistributionPoint (TEST-T011).
- The intended failing run was not observed for `crl-012-root-crl-malformed-aki`
  (fix written before the fixture) or
  `crl-012-root-delta-expired-crl-reports-feature` (case added after the reorder).
  The distribution-point, cRLSign, revoked-intermediate, AKI issuer/serial and
  freshness-boundary cases pinned behavior that already held. The five
  `crl-fetch-*-fetches-*`/`-fetched-*` cases failed before the coverage fix
  (no request was made); the five `-not-fetched` controls already passed. The
  three `-denied` cases were added after the fix and passed at once; before it
  the same inputs were `revocation_unknown`, which was not run.
- The three cases added with the retrieval redesign
  (`crl-033-fetch-excluded-name-match-fetches-listed-point`,
  `crl-009-fetch-no-listed-point-role-excluded-scope-rejected`,
  `fetch-unusable-supplied-crl-not-fetched`, since replaced by
  `crl-020-fetch-unusable-scope-supplied-crl-refreshed` with the opposite
  result) failed before it, for the intended reason each.
- `--fetch-crls` requests points in two steps (certificates whose issuer no
  supplied CRL names, then the rest), pinned on `crl-chain-crl-dp.exe` by
  `crl-033-fetch-covered-signer-point-not-requested`,
  `crl-033-fetch-asks-each-certificate-without-crl`,
  `crl-033-fetch-covered-signer-is-not-asked` and
  `crl-033-fetch-asks-only-the-uncovered-certificate`; the first, third and
  fourth failed
  before the change that introduced them. In the second step a certificate
  that a supplied CRL does cover can still be fetched for; a failed request is
  skipped, but a fetched CRL that is stale or unusable still fails the run
  closed. No fixture has that shape. A certificate mixing a plain URI point
  with an unsupported one has the plain URI requested
  (`crl-033-fetch-mixed-point-requests-plain-uri`, on
  `crl-leaf-crl-dp-mixed.exe`, which failed first).
- Validated on macOS locally and on Linux in CI. No Windows comparison
  (TEST-T013).

## Known limitations tracked elsewhere

The review of PR #60 is concluded; everything it left open is a task in
`TODO.md` (CRL-T014 to CRL-T024, TEST-T010, CRL-T037, CRL-T038, LIMIT-T006, LIB-T011 and CRL-T029),
with CRL-T002, CRL-T006, CRL-T010 and CRL-T033 for the larger items.

- **CRL-T002:** excluded CRLs are still reported as supplied.
- **CRL-T003:** applicability and the scope rule consider every embedded
  candidate.
- **CRL-T004:** AKI/SKI and name-encoding edges.
- **CRL-T033:** unbudgeted and repeated work (what CRL-T005 left).
- **CRL-T006:** an unusable applicable CRL rejects even when another covers the
  issuer.
- **CRL-T007:** reason coverage and error details.
- **CRL-T008:** error precedence.
- **CRL-T009:** listed serials are not bound to the path's issuer key.
- **CRL-T025:** fixture builders and provenance.
- **DOC-T007:** CRL rules document.

## Case reasons (PR #60)

Every case PR #60 added or changed, with why its result is right (AGENTS.md,
"Pinned expectations"). **Decided** cases change only with the owner's
approval; **Observed** ones pin current behavior and may change when a better
result is argued. **Acceptance** pins whether a file verifies or is rejected;
**diagnostics** pins which error, detail or request. The rules and sources
below are now stated once as numbered entries in [CRL decisions](../crl.md)
(`CRL-001` to `CRL-040`), which each case names in its `decision` field; this
section keeps the review history. Line numbers are for OpenSSL 3a3f1356,
bc-java e03fee0b, relic 02c54d58 and BoringSSL `main`.

- **The best CRL decides.** Decided, acceptance; owner-approved exception.
  Bouncy Castle's `checkCRL` skips a CRL that fails a check and goes on to the
  next (`lastException`); OpenSSL's `get_crl_sk` scores CRLs and uses the best
  (`CRL_SCORE_TIME`, `CRL_SCORE_SCOPE`, `CRL_SCORE_NOCRITICAL`). A usable CRL
  beside an unusable one therefore verifies, and the unusable one alone keeps
  its error. Sources: OpenSSL `crypto/x509/x509_vfy.c:1592-1633`
  (`get_crl_sk`), `:1801-1861` (`get_crl_score`), `:2257-2320` (`check_crl`);
  Bouncy Castle
  `prov/src/main/java/org/bouncycastle/jce/provider/RFC3280CertPathUtilities.java:1586-1721`
  (`checkCRL`; `lastException` at `:1718`, thrown at `:1721`). A full CRL (no
  issuingDistributionPoint) is in scope for any certificate: OpenSSL
  `x509_vfy.c:2146-2200` (`crl_crldp_check`), Bouncy Castle
  `RFC3280CertPathUtilities.java:105-195` (`processCRLB2`).
  - Verify beside `good.crl` (added): `crl-012-root-crl-no-next-update-beside-good-crl`,
    `crl-012-root-expired-crl-still-rejected-beside-good-crl`,
    `crl-012-root-aki-crl-still-rejected-beside-good-crl`,
    `crl-012-root-crl-malformed-aki-beside-good-crl`,
    `crl-012-root-signed-other-aki-crl-still-rejected-beside-good-crl`,
    `crl-012-root-unknown-critical-extension-crl-unsupported-beside-good-crl`,
    `crl-012-root-delta-crl-unsupported-beside-good-crl`,
    `crl-012-root-indirect-crl-unsupported-beside-good-crl`,
    `crl-012-root-entry-critical-extension-crl-unsupported-beside-good-crl`,
    `crl-012-root-delta-expired-crl-reports-feature-beside-good-crl`,
    `crl-012-root-idp-user-certs-crl-unsupported-beside-good-crl`,
    `crl-012-root-idp-ca-certs-crl-unsupported-beside-good-crl`,
    `crl-012-root-aki-issuer-serial-crl-name-matched-beside-good-crl`,
    `crl-012-root-idp-named-point-crl-rejected-beside-good-crl`.
  - The same CRLs alone keep their exact error (changed to drop `good.crl`):
    the fourteen `crl-012-root-*` cases of the same names without
    `-beside-good-crl`.
  - Full-CRL controls for the new fixtures (acceptance): `crl-014-chain-crl-dp-full-crls`,
    `crl-014-leaf-crl-dp-mixed-full-crl`, `crl-014-leaf-crl-dp-https-full-crl`.
- **A revocation in a CRL that does not cover the certificate does not
  count.** Decided, acceptance (owner chose to follow the libraries, PR #60).
  OpenSSL's `crl_crldp_check` gives a CRL for another point or role no
  `CRL_SCORE_SCOPE`, so `get_crl_sk` never selects it over the covering CRL
  and `cert_crl` never reads its entries (`crypto/x509/x509_vfy.c`); Bouncy
  Castle's processCRLB2 rejects it before processCRLJ reads entries
  (`RFC3280CertPathUtilities.checkCRL`). On `main` such a listing revoked
  (`crl-dp-other-partition-revoked` and `-first`, expecting
  `certificate_revoked`); they are now
  `crl-013-dp-other-partition-revocation-is-ignored` and `-first` and
  verify. Comparing thisUpdate across partitions would have made the result
  depend on issuance order. The same holds for a CRL whose
  issuingDistributionPoint does not decode: OpenSSL scores it unusable
  (`IDP_INVALID` in `get_crl_score`) and Bouncy Castle skips a CRL whose
  extension does not parse, so its entries are not read here either.
- **A revocation in a role partition without a point name counts.** Decided,
  acceptance. An issuingDistributionPoint with only onlyContainsUserCerts
  (or onlyContainsCACerts) that admits the certificate is in scope in
  OpenSSL (`crl->idp->distpoint == NULL` in `crl_crldp_check`) and Bouncy
  Castle (processCRLB2 compares names only when the IDP has one), so both
  read its entries:
  `crl-006-role-partition-crl-revocation-beside-full-crl-revokes`. Alone it is
  still `invalid_crl`, because webpki cannot use that form
  (`crl-025-role-partition-crl-revocation-alone-is-unsupported`, Observed).
- **A partition for another point is no evidence.** Decided, diagnostics.
  Bouncy Castle's processCRLB2 rejects a CRL whose distribution point does not
  match; OpenSSL gives it no `CRL_SCORE_SCOPE`. The certificate is without a
  CRL, so the status is unknown and retrieval fetches its point:
  `crl-030-expired-partition-for-another-point-leaves-status-unknown`,
  `crl-030-fetch-expired-partition-for-another-point-still-fetches`,
  `crl-030-dp-other-idp-unknown` (details updated).
- **A CA-only CRL naming a point is rejected for an end entity.** Decided,
  acceptance; see the comparison above:
  `crl-009-fetch-no-listed-point-role-excluded-scope-rejected`.
- **A listing counts only from a current CRL.** Decided, acceptance
  (owner delegated the call, PR #60). OpenSSL reads entries only from the
  best-scored, current CRL; Bouncy Castle's `PKIXCRLUtil.findCRLs` drops CRLs
  whose nextUpdate has passed before any entry is read. A revocation in an
  expired CRL beside a fresh CRL that omits the serial therefore verifies
  (`crl-016-stale-crl-revocation-beside-fresh-crl-is-ignored`, formerly
  `-revokes`), and alone it is `crl_expired`
  (`crl-016-stale-crl-revocation-alone-is-expired`). The newest usable CRL
  decides, as OpenSSL's `get_crl_sk` breaks ties by the latest lastUpdate, so
  a listing in an older CRL still within its validity does not count beside
  a newer one (`crl-016-superseded-crl-revocation-beside-newer-crl-is-ignored`)
  and alone it revokes (`crl-016-superseded-crl-revocation-alone-revokes`). A
  CRL without nextUpdate is never current.
  **Corrected after review (the libraries agree):** a CRL without nextUpdate
  claims no expiry, so it *is* current. OpenSSL's `ossl_x509_check_crl_time`
  (`crypto/x509/x509_vfy.c:1555-1587`) checks nextUpdate only when present,
  Bouncy Castle's `PKIXCRLUtil` (`PKIXCRLUtil.java:42-45`) keeps a CRL whose
  nextUpdate is null, and BoringSSL (`x509_vfy.cc:414`) behaves as OpenSSL.
  An authenticated, in-scope CRL without nextUpdate therefore counts for a
  listing, so it revokes beside an older usable CRL
  (`crl-004-no-next-update-crl-revocation-beside-older-crl-revokes`, Decided,
  acceptance; the old
  rule verified a certificate the issuer said was revoked). Such a CRL is
  still unusable as evidence of good status: RFC 5280 requires nextUpdate,
  and alone, without a listing, it is `invalid_crl` / `missing_next_update`
  (`crl-002-root-crl-no-next-update`). Alone with a listing it revokes
  (`crl-028-no-next-update-crl-revocation-alone-revokes`; see "Case reasons (a
  CRL without nextUpdate that lists the certificate)"). On a timestamped
  file the timestamp authority's chain is checked first, and that
  certificate is not listed, so the same CRL alone is `invalid_crl` there
  (`crl-028-no-next-update-crl-revocation-alone-is-invalid`).
- **A listing in a current CRL with a malformed AKI counts.** Decided by the
  owner (PR #60), acceptance (fails closed): a correctly signed CRL of the
  issuer said the certificate is revoked, and a malformed identifier field
  does not make that statement less authentic.
  `crl-005-malformed-aki-crl-revocation-beside-good-crl-revokes`. The
  references do not agree, with a well-formed CRL that omits the serial also
  present:
  - OpenSSL uses the CRL. `crl_cb` (`crypto/x509/x_crl.c:265-269`) leaves
    `akid` NULL and sets `EXFLAG_INVALID`, which `crypto/x509/x509_vfy.c`
    never reads for a CRL; `X509_check_akid` (`crypto/x509/v3_purp.c:1353`)
    treats a NULL akid as a match; `get_crl_sk` (`x509_vfy.c:1603-1633`)
    picks one CRL, the newer on a tie, and `cert_crl` (`x509_vfy.c:2344`)
    reads only that one. Revoked if the malformed CRL has the later
    lastUpdate (or an equal one and comes first), else good.
  - Bouncy Castle's `X509RevocationChecker` (pkix) ignores the CRL's AKI:
    `processCRLF` at
    `pkix/src/main/java/org/bouncycastle/pkix/jcajce/RFC3280CertPathUtilities.java:255-280`
    selects the issuer by name only. Revoked or good by iteration order.
  - Bouncy Castle's provider path throws an uncaught
    `IllegalArgumentException` in `processCRLF`
    (`prov/src/main/java/org/bouncycastle/jce/provider/RFC3280CertPathUtilities.java:379-393`),
    or reports good if the well-formed CRL is iterated first; never revoked.
  - BoringSSL rejects the CRL at parse: `crl_cb` returns 0
    (`crypto/x509/x_crl.cc:157-161`). Never revoked.
  - relic checks no CRLs: chain validation is Go's `x509.VerifyOptions`
    (`lib/pkcs7/verify.go:177`).
  Compared at OpenSSL 3a3f1356, bc-java e03fee0b, relic 02c54d58 and
  BoringSSL `main` (commit not captured).
  rssig: `invalid_crl` alone; beside a usable CRL its listing revokes when
  it is at least as new, which is closest to OpenSSL.
- **Cross-certified paths.** A path that verifies with its CRLs is accepted
  whatever another path does: Decided, acceptance, as Bouncy Castle's builder
  tries every candidate path and accepts one that validates
  (`prov/.../jce/provider/PKIXCertPathBuilderSpi.java:135-270`; a failed
  candidate only sets `certPathException`, `:268`), while OpenSSL builds one
  chain (`x509_vfy.c:3925` `build_chain`) and has no second path to fall
  back on
  (`crl-017-cross-revoked-path-beside-covered-path-verifies`,
  `crl-017-fetch-completes-the-path-without-a-crl-beside-a-revoked-path`,
  `crl-017-fetch-completes-the-path-beside-an-expired-path`). Which error a
  rejected chain reports, and what retrieval is asked: Decided by the written
  argument in `docs/crl-retrieval.md` (only a path that passes every other
  check and lacks CRLs can be completed), diagnostics
  (`crl-027-cross-revoked-path-beside-path-without-crl-names-it`,
  `crl-027-fetch-revocation-stands-when-the-other-path-stays-without-crl`,
  `crl-027-cross-revoked-path-beside-path-failing-key-usage-is-revoked`,
  `crl-027-cross-unusable-crl-decides-beside-path-failing-key-usage`,
  `crl-027-cross-expired-path-beside-path-without-crl-names-the-gap`,
  `crl-027-fetch-path-failing-key-usage-asks-nothing`).
  Changed after review (owner asked for the fix): with `--fetch-crls`, an
  unknown status that names nothing to ask is followed by the check of the
  whole input without revocation, so
  `crl-027-fetch-path-failing-key-usage-asks-nothing` now reports the path's
  own failure (`invalid_key_usage`), as before PR #60, where that check ran
  first; still no request is made. Without `--fetch-crls` the result is
  `revocation_unknown` with an empty list, as before PR #60.
  Only that unknown status, which is no evidence, is followed by the check
  without revocation. A definite CRL failure or revocation on such a chain
  keeps its code with `--fetch-crls`, as without it
  (`crl-029-fetch-path-failing-key-usage-with-unusable-crl-keeps-the-crl-failure`,
  `crl-029-fetch-path-failing-key-usage-with-revoked-issuer-is-revoked`;
  Decided, diagnostics: both reject). So with fetching the code differs from
  the offline one only for an unknown status (including one that also
  carries `unusable_crl` because another certificate on the path lacks a
  CRL), which becomes the path failure; both reject.
- **A revocation on one path names another path's expired-only CRLs.**
  Decided (Bouncy Castle, following the owner's delegated call to refresh
  expired CRLs), acceptance with `--fetch-crls`: a revocation on one
  candidate path also names, in `details.certificates_with_expired_crl`,
  the certificates of another viable path whose only CRLs have expired, so a
  source can refresh them and that path verifies, as Bouncy Castle tries
  every path and fetches past an expired CRL (`PKIXCertPathBuilderSpi.java:135-270`,
  `PKIXCRLUtil.java:42-45`); OpenSSL has no equivalent (one chain, no fetch).
  `crl-031-cross-revoked-path-beside-path-with-expired-crl-names-it`
  (diagnostics), `crl-022-fetch-refreshes-the-path-with-an-expired-crl-beside-a-revoked-path`
  (acceptance). The revoked path's own certificates are not named, and
  neither is anything on a path with a CRL a refresh cannot fix (forged,
  no cRLSign, `invalid_crl`): that path cannot verify, so no source is asked
  (unit test `a_revocation_names_only_paths_a_source_could_complete`; the
  same now holds for `certificates_without_crl`). Named test
  `crl_a_revocation_names_and_fetch_refreshes_another_paths_expired_crl`.
- **A path a source could complete is reported over a stuck path.**
  Decided, diagnostics offline and acceptance with `--fetch-crls`: when no
  path is revoked, a viable path that only lacks or has expired CRLs is
  reported (and its certificates named) ahead of another path whose CRL no
  refresh can fix (forged, no cRLSign, `invalid_crl`, not yet valid), so a
  source can complete it; when every path is stuck, the most specific
  failure decides as before. Unit test
  `a_path_a_source_could_complete_is_reported_over_a_stuck_paths_failure`.
  A by-certificate answer asks for another verification pass only for a
  full CRL that was not already loaded, judged per CRL in a PEM bundle.
- **Declined after review:** setting aside a CRL that names a distribution
  point the certificate does not list, instead of `invalid_crl`
  (`distribution_point_scope`). OpenSSL fails it with
  `X509_V_ERR_DIFFERENT_CRL_SCOPE` and Bouncy Castle rejects it in
  processCRLB2 (see the CA-only comparison above); it stays Decided.
- **With `--fetch-crls`, a definite result is not followed by a check of the
  rest of the input.** Decided, diagnostics. When the first signer's result
  is a definite revocation or CRL failure and nothing is asked, it is the
  result, as without `--fetch-crls`; later nested signatures or bundle
  members are not checked first. Before PR #60 a pass without revocation ran
  first with fetching, so an integrity failure elsewhere could be reported
  instead. Running that pass after a definite result would make the code
  depend on fetching and spend the work budget twice; both results reject.
  The pass still runs before any request (privacy), and after an unknown
  status that names nothing. The same
  holds across an RDP signer's usages. Before, such a certificate was not
  named, and the revocation stood although a refresh could complete the
  other path.
- **Retrieval asks per certificate, only about what lacks a CRL.** Decided,
  diagnostics (which requests are made; the verification result is the same
  either way). OpenSSL's `get_crl`/`lookup_crls` and Bouncy Castle's
  `checkCRLs` look up CRLs for the certificate being checked (OpenSSL
  `x509_vfy.c:2206-2254` `get_crl_delta`, `lookup_crls` at `:2228`, called
  from `check_cert_crl` `:1444-1537`; Bouncy Castle
  `RFC3280CertPathUtilities.java:1754-1880`):
  `crl-033-fetch-covered-signer-point-not-requested`,
  `crl-033-fetch-asks-each-certificate-without-crl`,
  `crl-033-fetch-covered-signer-is-not-asked`,
  `crl-033-fetch-asks-only-the-uncovered-certificate`,
  `crl-033-fetch-excluded-name-match-fetches-listed-point`,
  `crl-033-fetch-mixed-point-requests-plain-uri`,
  `crl-033-fetch-bad-response-is-no-evidence-beside-another-point`.
- **An abort before an expired CRL could be refreshed is marked.** Decided,
  diagnostics: `crl-036-stale-local-source-abort-is-marked` keeps `crl_expired`
  with `retrieval_aborted`.
- **An expired supplied CRL is refreshed.** Decided, acceptance (owner
  delegated the call, PR #60). Bouncy Castle drops CRLs past nextUpdate and,
  with CRL fetching enabled, fetches from the certificate's points; OpenSSL
  does not fetch. `crl-019-stale-local-refreshed-by-provider` (added) verifies
  with the fetched CRL; `crl-019-stale-local-asks-provider` (before PR #60 as
  `crl-stale-local-provider-unused`, which expected no request) now expects
  the request and, without an answer, the same `crl_expired`.
- **A supplied CRL unusable for another reason was not refreshed.**
  Superseded: compared case by case and decided in "Case reasons (refresh of
  an unusable supplied CRL)" below; the Observed case
  `fetch-unusable-supplied-crl-not-fetched` became
  `crl-020-fetch-unusable-scope-supplied-crl-refreshed`.
- **A source answering by certificate leaves no per-point failures.**
  Decided, diagnostics (owner delegated the call): OpenSSL's `lookup_crls`
  and Bouncy Castle's store lookups have no per-point outcome. Only a body
  that loads as a CRL of the certificate's issuer counts, as both look CRLs
  up by issuer name:
  `crl-034-fetch-by-certificate-answer-requests-no-listed-point`. When that
  answer does not settle the certificate's status (for example an expired
  CRL), the listed points the source left unused are recorded as
  `crl_fetch_failed` ("not used"), so that no listed point disappears
  from the report of a failed retrieval (written argument, diagnostics):
  `crl-034-fetch-by-certificate-unusable-answer-records-unused-points`.
- **Missing evidence is `revocation_unknown`; a source has four kinds.**
  Decided by the owner in PR #60's design ("single error code", four kinds
  denied/failed/abort/unknown), diagnostics. The single code matches the
  references: OpenSSL reports `X509_V_ERR_UNABLE_TO_GET_CRL` however the CRL
  could not be obtained (`x509_vfy.c:1489`, `:1527`), and Bouncy Castle one
  "No CRLs found for issuer" error with lookup diagnostics in its message
  (`prov/.../jce/provider/CertPathValidatorUtilities.java:1340`). The four
  kinds have no reference equivalent. Changed:
  `crl-026-fetch-private`, `crl-026-fetch-injected-unavailable`,
  `crl-026-fetch-reasons-point-denied`, `crl-026-fetch-crl-issuer-point-denied`,
  `crl-026-fetch-dns-name-point-denied` (`crl_fetch_denied`/`crl_fetch_failed`
  to `revocation_unknown`, cause in `crl_retrieval.failures`). Added:
  `crl-026-fetch-source-denied-is-no-evidence`,
  `crl-026-fetch-source-failed-is-no-evidence`,
  `crl-026-fetch-source-unknown-is-no-evidence`,
  `crl-047-fetch-source-abort-is-reported`, `crl-047-fetch-source-abort-stops-requests`.
- **The source decides transport.** Decided (owner: the CLI's default HTTP
  source, library users provide their own), acceptance for the injected
  source, diagnostics for the built-in refusal:
  `crl-023-fetch-source-is-asked-for-any-scheme`,
  `crl-037-fetch-builtin-source-denies-https`. Sources under "Who screens a
  distribution-point address" below.
- **An untrusted chain is never fetched for.** Decided, acceptance and
  privacy: path validation fails before any request, as `main`'s preliminary
  pass did, and as OpenSSL's `verify_chain` runs `build_chain` (which needs
  a trust anchor) before `check_revocation` (`x509_vfy.c:266-284`):
  `crl-011-fetch-untrusted-chain-requests-nothing`. Checking the whole input
  first has no reference equivalent (a written privacy argument). The same holds for
  the whole input: before the first request it is verified once without
  revocation, so an invalid nested signature, later signer or bundle member
  is the result and no source is asked
  (`crl-011-fetch-invalid-nested-signature-requests-nothing`).
- **A self-issued key rollover path needs CRLs that name their key.**
  Decided, acceptance, by cross-checking OpenSSL, BoringSSL and Bouncy Castle
  (CRL-T004). `good-path-self-issued-rollover.exe` has two certificates whose
  issuers share one name and have different keys. It verifies without
  revocation (`crl-007-self-issued-rollover-without-revocation-verifies`;
  RFC 5280 section 6.1 allows self-issued certificates for key rollover, and
  OpenSSL 3.0.13 `openssl verify -attime 1800000000` without CRL checks
  reports OK).
  - *CRLs with an authorityKeyIdentifier naming their issuer's key*
    (`path-root-akid.crl`, `path-rollover-akid.crl`): all three libraries
    give each certificate its own key's CRL and accept, in either order.
    OpenSSL `crypto/x509/x509_vfy.c:1869-1889` (`get_crl_score`,
    `crl_akid_check`), BoringSSL `crypto/x509/x509_vfy.cc:490-515`, Bouncy
    Castle `RFC3280CertPathUtilities.java:379-390` (`processCRLF`). Run as a
    maintenance step with OpenSSL 3.0.13 (`openssl verify -crl_check_all
    -attime 1800000000`): OK in both orders. rssig accepts:
    `crl-007-self-issued-rollover-with-key-identified-crls-verifies` and
    `crl-007-self-issued-rollover-with-key-identified-crls-verifies-reversed`.
    webpki 0.103.16 picks a CRL by issuer name and IDP only and cannot
    confirm two issuers of one name, so for such a path (two chosen CRLs of
    one name, every one naming the key it was authenticated under, with
    different keys) webpki confirms the signer with the signer's CRL only,
    and rssig's per-key evaluation decides for the certificates above it.
    That evaluation still rejects a revoked rollover certificate:
    `crl-007-self-issued-rollover-revoked-by-key-identified-crl-is-rejected`
    (`path-root-akid-revoked-rollover.crl`, RFC 5280 section 6.3.3).
    Since CRL-T011, webpki no longer confirms in production: rssig's per-key
    evaluation decides alone, and webpki's signer-only confirmation described
    here runs only in the test-only cross-check
    ([CRL-T011](crl-t011.md)).
  - *CRLs without an authorityKeyIdentifier* (`path-root.crl`,
    `path-rollover.crl`): the libraries differ. OpenSSL keeps one best CRL
    per name and has no fallback after its signature fails
    (`x509_vfy.c:1614-1627`, `:2318-2320`; `v3_purp.c:1353-1354`); the same
    OpenSSL run reports "CRL signature failure" at depth 0 or 1 depending on
    order. BoringSSL's `x509_vfy.cc:665-693`, `:755-760` is the same. Bouncy
    Castle skips a CRL that does not verify and tries the next
    (`RFC3280CertPathUtilities.java:1716-1721`) and accepts. The owner
    chose the tiebreaker (PR #60): the third reference, BoringSSL, rejects,
    so rssig rejects, failing closed, at
    webpki's confirmation (since CRL-T011, at rssig's own accepted-path rule
    `ambiguous_issuer_keys`, which gives the same result)
    (`crl-008-self-issued-rollover-with-both-crls-is-rejected`:
    `certificate_chain_invalid`, reason `ambiguous_issuer_keys`; until CRL-T011 follow-up in PR #64 the
    reason was `confirmation`), in either order.
    An earlier note here said OpenSSL would accept this case; the run shows
    it does not.
- **An RDP signer that only lacks a CRL under one of its usages reports the
  missing CRL.** Decided by written argument; no reference library has an
  equivalent, since accepting an RDP signer under any one of several EKUs is
  an rssig RDP rule (`docs/rdp.md`). The signer of
  `good-rdp-eku-retry-ca.rdp` has codeSigning and serverAuth under a CA
  whose EKU admits serverAuth only: the codeSigning attempt fails on the
  path (`invalid_eku`) and the serverAuth attempt lacks only the CA's CRL.
  Only a failure that names certificates a source could cover counts (an
  empty list names nothing), and a revocation naming another path's gap
  ranks below an unknown status or expired CRL (unit test
  `only_a_named_missing_crl_ranks_a_usage_failure_as_completable`).
  The missing CRL is reported, because a source can supply it
  (`crl-027-rdp-eku-retry-ca-missing-crl-is-unknown`, diagnostics), and
  `--fetch-crls` then verifies the file, as before PR #60, where retrieval
  followed a pass without revocation that succeeded through serverAuth
  (`crl-017-rdp-eku-retry-ca-fetches-the-missing-crl`, acceptance). Control:
  `crl-017-rdp-eku-retry-ca-with-crls-verifies`.
- **A URI that is not an absolute URL is never offered to a source.**
  Decided, diagnostics: OpenSSL's `get_dp_url` returns only `http://` URIs
  (`apps/lib/apps.c:2833`) and Bouncy Castle's `distributionPoint.toURL()`
  fails on a relative one (`CrlCache.java:185`). It is recorded as
  `crl_fetch_denied` with its own message and no `url`. Unit test
  `a_uri_that_is_not_an_absolute_url_is_withheld_with_its_own_reason`.
- **Smaller review fixes (PR #60), unit-tested.** Decided by written
  argument, diagnostics unless noted; no reference library has an equivalent
  (they have no source interface or per-verification URI limit):
  - A source that answers by certificate or issuer leaves points unused that
    later certificates list again; they are offered again, and the engine
    keeps no total of them (CRL-039,
    `a_source_answering_by_certificate_never_exhausts_the_uri_limit`).
  - A whole-request source error naming a URL that is none of the request's
    points is recorded without that URL, so a certificate is never attributed
    a distribution point it did not list
    (`a_whole_request_error_naming_a_foreign_url_is_not_attributed_to_the_certificate`).
  - A full CRL answered by certificate asks for another verification pass
    only when that body itself was newly added, not when another body of the
    response was
    (`a_duplicate_full_crl_by_certificate_beside_a_new_url_body_does_not_ask_for_verification`).
  - Configured roots that are one anchor to webpki (same key, name and
    constraints) may carry different key identifiers; a CRL naming any of
    them is that anchor's, as OpenSSL's `crl_akid_check` compares against the
    chain certificate that matches and Bouncy Castle selects signing keys by
    the CRL's key identifier (`RFC3280CertPathUtilities.java:379-390`). A
    root that names no key cannot disprove a match. Unit test
    `only_a_differing_key_identifier_sets_a_failed_crl_aside`.
  - `CrlSource::begin_verification()` (default: nothing) is called by the
    engine at the start of each verification that may ask the source;
    `HttpCrlSource` renews its allowances there, so a library caller that
    reuses one source across verifications, like the CLI across files, never
    has an earlier verification's allowances charged to a later one. Unit
    tests `a_source_is_told_when_a_verification_begins` and
    `a_new_verification_restores_a_sources_allowances_but_a_dns_timeout_closes_it_for_good`.
  - A source closed by a DNS timeout aborts every later request before any
    work, including a URL its policy would refuse (reported `abort`, not
    `denied`) and across later verifications, so no request is spent and the
    "closed for good" contract holds
    (`a_source_closed_by_a_dns_timeout_aborts_every_request_even_after_a_new_verification`).
  - An RDP signer with several usages: when one usage is revoked, the
    revocation is the result (it is definite), and it names the certificates
    another usage only lacks a CRL for, as a revocation on one candidate path
    names another path's gaps, so `--fetch-crls` can still complete that
    usage. Otherwise a usage that only lacks CRLs is reported first. Unit
    test `a_revoked_usage_is_reported_and_names_another_usages_gaps`.
    Every certificate any other usage reports without a CRL is named once
    (deduplicated by SHA-256), including another revocation's, and so is one
    whose only CRL expired (`certificates_with_expired_crl`), as for
    candidate paths. Spec case
    `crl-027-rdp-eku-retry-ca-revoked-usage-is-revoked` (Decided, diagnostics): the
    serverAuth usage is revoked and codeSigning fails its EKU; the revocation
    is reported, where the first usage's `invalid_eku` was before.
  - A delta CRL answered by certificate is not a full CRL, so it does not ask
    for another verification pass (`a_new_full_crl_by_certificate_asks_for_verification_first`).
  - Re-offered points are not bounded by `crl_source_urls`; the number of
    requests is the source's (CRL-039,
    `re_offered_points_are_not_stopped_by_the_engine_on_request_count`).
  - `check_public_http_url` has a fuzz target, `check_url`.
  - The reserved-name check trims one trailing dot before testing for a
    single-label name too, so `http://intranet./x.crl` is denied like
    `http://intranet/x.crl`. Other private-use DNS suffixes (`.lan`,
    `.corp`, `.localdomain`) were not listed then; CRL-T018 (PR #111)
    added them. The check is of the URL text only: against a private name
    it does not list, the built-in source refuses any DNS answer that is
    not a public address and re-checks every redirect. A custom source
    must do the same in its own client (see `docs/library.md`).
  - The built-in source also denies the RFC 6761 special-use names
    `invalid`, `test` and `example` (as whole labels), and any URL with
    surrounding whitespace, so `check_public_http_url` accepting a string
    means that string is the URL checked.
    `onion` (RFC 7686) and `alt` (RFC 9476) are denied too, whitespace is
    any Unicode whitespace (as the engine's own screening), and a denied
    host, a malformed string and a wrong scheme or port each have their own
    message.
  - A certificate named both without a CRL and with an expired one (on two
    paths) is one retrieval target; a point a certificate left unused is no
    longer reported as not requested once another certificate's request
    offers it (`a_certificate_named_twice_is_one_target`). Since CRL-T041
    such a point is reported for the first certificate as not used, whatever
    a later certificate's request got for it
    (`a_point_one_certificates_answer_left_unused_is_reported_as_not_used`,
    CRL-051). The shared-point variant has no
    spec case: no committed file has two certificates of different issuers
    listing one URI; the unit test checks the serialized failure entries.
    Only a certificate the failed result still names (its status not
    settled) reports the points its source's answer by certificate left
    unused, in request order: with the failure a request for another
    certificate gave the point, nothing if such a request was answered, and
    otherwise as not used (the source did not use it for this certificate).
    A certificate whose status was settled
    leaves no per-point failure (the Decided rule above). A run ended by an
    engine limit or a failed check reports what was recorded until then:
    that error is the result. Codes and URLs are pinned by
    `crl-034-fetch-by-certificate-unusable-answer-records-unused-points`;
    message texts are diagnostics prose, not matched by consumers.
- **Retrieval bookkeeping (unit-tested).** A request marks its points as
  offered only once every engine limit has passed, so a limit that ends the
  run leaves a point another certificate left unused reported as such. The built-in source does no work once spent (no request, DNS
  lookup or connection), and a body that ends exactly at its 32 MiB cap is
  still read to its end (`a_body_ending_exactly_at_the_byte_cap_still_reads_its_end`),
  with the byte limit reported ahead of the deadline. A URL that does not
  parse is reported as not an absolute URL.
- **A DNS timeout still closes the built-in source for the run.** Reopening
  once the stale resolver finished was tried in review and reverted: it made
  a batch's result depend on thread timing and made `HttpCrlSource` stop
  being `Sync`. The close keeps at most one unfinished resolver thread.
- **A URL-less abort marks the points left as not tried.** When a response
  carries an `Abort` without a URL (about the whole request), the points
  left are recorded as `crl_fetch_aborted`, not tried, even beside another
  URL-less failure; an abort naming one point does not relabel the others
  (`points_left_after_an_abort_among_url_less_failures_are_not_tried`).
  A case can now script URL-less failures (TEST-T009:
  `crl-047-url-less-abort-is-reported` pins one abort alone, and
  `crl-047-url-less-abort-beside-another-failure-marks-the-point-not-tried` one beside a URL-less denial).
- **Deadline during I/O.** Each DNS, connect, read and write wait is cut
  to the time left, so an I/O failure once the deadline has passed is
  reported as the deadline (`abort`); a request that completed and failed
  for its own reason (an HTTP status) keeps that reason.
- A delegating source must forward `begin_verification` (documented on the
  trait).
- **Declined after review:** naming the gaps of a path whose other
  certificate has a supplied CRL that is unusable for a reason other than
  expiry. Such a certificate was never asked about, so the path could not
  be completed by retrieval. Since revisited: a certificate whose CRL a
  source could replace is now asked about and its path's gaps are named
  ("Case reasons (refresh of an unusable supplied CRL)").
- **Declined after review (already decided):** confirming intermediates on a
  key-rollover path with webpki (it cannot confirm two same-name issuers;
  rssig's per-key evaluation decides, CRL-T004 above; moot since CRL-T011 removed
  the production confirmation); a batch-wide fetch
  bound (the owner's per-verification choice); one JSON shape for absent
  URLs on artifacts and failures (the artifact change is in the migration
  notes); spreading a URL-less failure beside an answer by certificate over
  the points (it is recorded as it is, decided earlier).
  - Two configured roots with one key and name (one trust anchor to webpki)
    may carry different subjectKeyIdentifiers. A CRL signed by another key
    that names any of them is forged for that anchor
    (`invalid_crl_signature`, recorded as `details.unusable_crl`), whichever
    root is listed first; one naming an identifier no configured root carries
    is another issuer's and is set aside
    (`crl-040-forged-crl-naming-a-same-key-roots-identifier-is-forged`,
    `crl-040-forged-crl-naming-another-key-is-set-aside`; **Observed**,
    diagnostics only, since it changes only which error is reported: both
    reject, and the libraries have no equivalent for two same-key anchors).
    An anchor whose same-key root has no identifier cannot disprove a match.
    Unit test `only_a_differing_key_identifier_sets_a_failed_crl_aside`, named
    test `crl_a_same_key_roots_identifier_makes_a_crl_forged_not_set_aside`.
  - A CRL without nextUpdate alone that lists a certificate left the
    status `invalid_crl` (`missing_next_update`). Since changed to
    `certificate_revoked` with the owner's approval; see "Case reasons (a
    CRL without nextUpdate that lists the certificate)".
  - The built-in source's reserved-name check (then `localhost`, `local`,
    `internal`, `home.arpa`, `invalid`, `test`, `example`, `onion`, `alt`;
    CRL-T018 added the private-use labels) matches whole labels:
    `foo.local` is denied,
    `crl.foolocal` is not (a suffix match denied public names). Unit test
    `denies_nonpublic_ambiguous_or_unsupported_destinations`.
- **Who screens a distribution-point address.** Decided, acceptance for
  library users: the verification core passes every listed URI to the source
  after hygiene screening only, and the source decides what to fetch. None of
  the three libraries screens addresses in its verification core either:
  OpenSSL's core only calls `lookup_crls` (`x509_vfy.c:2228`) and its sample
  callback restricts the scheme to `http://` and nothing else
  (`apps/lib/apps.c:2833`, `:2905-2907`); Bouncy Castle fetches only when
  enabled and leaves the scheme unrestricted unless an allow-list is set
  (`CrlCache.java:136-141`, `:185-188`); BoringSSL never fetches
  (`x509_vfy.cc:697-704`). None refuses private or link-local addresses.
  rssig's built-in `HttpCrlSource` is stricter than all three (public
  addresses, `http` only, no redirects, size and time bounds), and
  `rssig::crl::check_public_http_url` gives a custom source the same check.
  Pinned by `crl-023-fetch-source-is-asked-for-any-scheme` and
  `crl-037-fetch-builtin-source-denies-https`.
- **Fetch limits bound one file.** Decided, diagnostics and availability: in
  OpenSSL the size, timeout and redirect limits are per fetch and nothing is
  cached or accumulated (`apps/lib/apps.c:2866-2867`; `apps/verify.c:220-232`
  loops files with one callback); Bouncy Castle has per-connection timeouts,
  no request or byte counters, and a process-wide cache
  (`CrlCache.java:41-46`). Neither lets what one validation fetched exhaust
  the next, so the engine renews a source's allowances for each verification
  (`CrlSource::begin_verification`), which the CLI relies on. A DNS timeout still closes the source for the
  invocation, to keep at most one unfinished resolver worker. Unit test
  `a_new_verification_restores_a_sources_allowances_but_a_dns_timeout_closes_it_for_good`.
- **Scope of a listing, refined after review.** Decided, acceptance, by the
  same OpenSSL (`crl_crldp_check`) and Bouncy Castle (processCRLB2) rules: a
  named partition's listing counts only on a positive match with a fullName
  URI the certificate lists (an issuer-relative or non-URI name is no
  match); a role-only partition with no name counts for its role; a
  certificate whose own cRLDistributionPoints cannot be read fails closed,
  so the partition is not set aside and its listing counts. Unit tests
  `a_listing_counts_only_on_a_positive_scope_match` and
  `unreadable_certificate_points_never_discard_a_partition` in
  `engine/src/trust.rs`; no committed certificate has an undecodable extension.
- **Other review fixes without a fixture** (unit tests in `engine/src/trust.rs`,
  `engine/src/retrieval.rs` and `src/crl.rs`): a CRL's complete signature
  AlgorithmIdentifier must be one the webpki adapter accepts; rejected paths
  keep CRL indices and the returned error alone carries the CRL report; a
  path needing only a fresh CRL is completable; a full CRL returned by
  certificate triggers verification before further requests; a URL that
  does not parse is withheld; diagnostics for unusable point names are
  bounded per certificate; the request whose DNS lookup times out is the
  abort; a withheld URL is not an answer by certificate. A certificate whose
  own points cannot be read is reported as `certificate_distribution_points`,
  not as a fault of the CRL.

## Case reasons (refresh of an unusable supplied CRL)

Cases from `main` changed by this refresh, checked mechanically against
`origin/main`: only `fetch-unusable-supplied-crl-not-fetched` (Observed,
diagnostics), which is replaced by
`crl-020-fetch-unusable-scope-supplied-crl-refreshed`; its reject became a
verification, with the owner's approval given in the PR #64 discussion. No
Decided case from `main` changed its command or expectation, and
`crl-009-fetch-no-listed-point-role-excluded-scope-rejected` is untouched.

Decided by the repository owner after PR #60, under the standing
rule: follow OpenSSL and Bouncy Castle where they agree, and BoringSSL where
they differ. It replaces the Observed rule that only an expired supplied CRL
is refreshed.

OpenSSL and BoringSSL never download, but both look the issuer's CRLs up in
a second source, the store, which is what `--fetch-crls` and a `CrlSource`
are here. OpenSSL's `get_crl_delta` (`crypto/x509/x509_vfy.c:1564-1590`)
calls `lookup_crls` when the best supplied CRL scores below
`CRL_SCORE_VALID` (`:33-42`): no unhandled critical extension, valid times
and scope. `get_crl_score` (`:1283-1340`) gives a delta CRL, and without
extended support an indirect or reasons-partitioned one, no score at all.
BoringSSL's `get_crl` (`crypto/x509/x509_vfy.cc:697-708`) does the same. The
signature is not scored: it is checked afterwards and its failure is
reported without another lookup (`x509_vfy.c:1664`). Bouncy Castle
(`pkix/.../X509RevocationChecker.java:797-863`, `:468-487`) turns any
`checkCRL` failure but a revocation into "no valid CRL found" and then
fetches from the certificate's distribution points.

| Supplied CRL | OpenSSL, BoringSSL | Bouncy Castle | rssig |
|---|---|---|---|
| expired | second source | fetches | asked about (`certificates_with_expired_crl`) |
| not yet valid | second source | fetches after a failure | asked about |
| an issuingDistributionPoint that cannot be used | second source | fetches | asked about (`certificates_with_replaceable_crl`) |
| another scope that is known (a partition for another point or role) | second source | fetches | set aside; its certificate is listed under `certificates_without_crl` and asked about, as before |
| unknown critical extension, delta, indirect, reasons partition | second source | fetches | asked about |
| bad signature, unsupported signature algorithm | reported, no lookup | fetches | not asked (BoringSSL decides) |
| issuer without cRLSign | reported | fetches | not asked: a fetched CRL has the same issuer |
| malformed (extensions, authorityKeyIdentifier, CRL number, version, entry extensions) | BoringSSL drops it when decoding (`x_crl.cc:122-160`); OpenSSL flags it `EXFLAG_INVALID`, which verification never tests, and an invalid issuingDistributionPoint scores 0 (`x509_vfy.c:1292`): either way the store is still consulted | fetches | asked about: the three agree |
| a point-scoped CRL for a certificate that lists none | no scope score, store lookup | fetches | asked about, by certificate and issuer |
| the certificate's own points unreadable | no equivalent | fetches | not asked: the certificate is at fault |
| no nextUpdate, as the only defect | usable | usable | not asked; a listing in it revokes (see "Case reasons (a CRL without nextUpdate that lists the certificate)") |
| no nextUpdate, with another defect from the rows above | that defect decides | that defect decides | that defect decides, as with nextUpdate present |

A certificate whose only CRLs are unusable for one of the "asked about"
reasons other than expiry is named in `details.certificates_with_replaceable_crl`
on the error that stands (`invalid_crl`, `crl_not_yet_valid`, an unknown
status, or another path's revocation), and a source is asked about it. A
fetched CRL passes the same checks as a supplied one and the best CRL
decides, so the unusable one is set aside beside a usable one, as it already
was between supplied CRLs. Without an answer the original error stands. A
certificate with any CRL that cannot be replaced is not asked about, and its
path is not one a source could complete.

- **Decided, acceptance:**
  `crl-020-fetch-unusable-scope-supplied-crl-refreshed` (was
  `fetch-unusable-supplied-crl-not-fetched`, Observed, which rejected
  with `invalid_crl` and asked nothing; changed with the owner's approval),
  `crl-020-not-yet-valid-local-refreshed-by-provider`,
  `crl-020-unknown-critical-extension-local-refreshed-by-provider`. Each verifies
  with the fetched CRL.
- **Decided, acceptance:** `crl-018-forged-local-asks-nothing`: a supplied CRL
  with a bad signature is `invalid_crl_signature` and nothing is requested,
  although the source holds a good CRL.
- **Decided, diagnostics:**
  `crl-036-fetch-unusable-scope-supplied-crl-stands-without-answer` and
  `crl-036-not-yet-valid-local-asks-provider`: the point is requested, and
  without an answer the original error stands, naming the certificate.
  `crl-035-no-next-update-local-asks-nothing`: `invalid_crl`
  (`missing_next_update`) asks nothing, pending CRL-T023.

- **Decided, acceptance:** a CRL scoped to a distribution point, for a
  certificate that lists none, is replaceable: the certificate is still asked
  about by certificate and issuer, and a full CRL from the source decides
  (`crl-021-fetch-no-listed-point-scope-crl-replaced-by-certificate`). A source
  that answers only by URL has nothing to fetch, so the `invalid_crl` stands
  (`crl-009-fetch-no-listed-point-role-excluded-scope-rejected`).
- **A missing nextUpdate blocks retrieval only as a CRL's sole defect.**
  To OpenSSL, BoringSSL and Bouncy Castle a missing nextUpdate is no defect
  (`x509_vfy.c:1112`, `x509_vfy.cc:414`, `PKIXCRLUtil`), so a CRL's other
  defects decide exactly as they would with nextUpdate present: a point
  scope on a certificate that lists none, a malformed
  authorityKeyIdentifier, a feature webpki rejects (judged on a copy with a
  stand-in nextUpdate) or a thisUpdate in the future is reported and is
  replaceable. Only a CRL with no other defect is `invalid_crl`
  (`missing_next_update`), rssig's stricter rule, and is not asked about:
  the references would use it and not look again. Decided, diagnostics:
  `crl-035-no-next-update-point-scope-crl-is-replaceable`; Decided,
  acceptance: `crl-020-fetch-no-next-update-point-scope-crl-replaced-by-certificate`.
  An earlier revision of this branch checked the missing nextUpdate first,
  which made the same CRL replaceable with nextUpdate and stuck without it.
- **Decided, acceptance:** a malformed CRL does not stop the search for
  another, alone or beside an expired one
  (`crl-020-malformed-aki-local-refreshed-by-provider`,
  `crl-020-malformed-aki-beside-expired-local-refreshed-by-provider`); without
  an answer its failure stands and names the certificate
  (`crl-036-malformed-aki-beside-expired-local-asks-provider`, diagnostics).
- **Decided, diagnostics:** the list's placement beside other evidence,
  on the `path` chain with the root's CRL not yet valid
  (`path-root-not-yet-valid.crl`): a revocation on the cross path names
  the root path's certificate in `certificates_with_replaceable_crl`
  (`crl-031-cross-revoked-path-beside-path-with-not-yet-valid-crl-names-it`),
  and an unknown status names the signer without a CRL in
  `certificates_without_crl` and the issuer with the not-yet-valid CRL in
  `certificates_with_replaceable_crl`
  (`crl-036-chain-unknown-names-missing-and-not-yet-valid-crl`).
- **Decided, acceptance:** with a source, both complete
  (`crl-022-fetch-replaces-the-path-with-a-not-yet-valid-crl-beside-a-revoked-path`,
  `crl-020-fetch-completes-missing-and-not-yet-valid-crl`).
- **Decided, diagnostics:** a source abort is marked
  `retrieval_aborted: true` on `crl_not_yet_valid` and `invalid_crl` as on
  `crl_expired` (`crl-036-not-yet-valid-local-source-abort-is-marked`,
  `crl-036-unknown-critical-extension-local-source-abort-is-marked`), so a consumer
  can tell that the CRL was never refreshed because the source stopped.

Among a certificate's unusable CRLs, the one with the highest rank is
reported, and one that cannot be replaced ranks above one that can, so a
certificate with any such CRL is not asked about. A malformed CRL was first
ranked that way too (a "written choice"); compared with the references it
is replaceable: BoringSSL drops it when decoding, OpenSSL never tests the
invalid flag and still consults the store, and Bouncy Castle fetches. A CRL
scoped to a distribution point, for a certificate that lists none, was also
first ranked unreplaceable, on the mistaken ground that a source is asked
only about listed points; a certificate without points is asked about by
certificate and issuer, so it is replaceable.

## Case reasons (a CRL without nextUpdate that lists the certificate)

Decided by the repository owner after PR #60: the owner asked for
the references to be checked and the call made on them. They agree:

- OpenSSL `crypto/x509/x509_vfy.c:1112` (`ossl_x509_check_crl_time`) and
  BoringSSL `crypto/x509/x509_vfy.cc:414` (`check_crl_time`) check
  nextUpdate only when it is present: the CRL is current, it is used, and a
  listed certificate is `X509_V_ERR_CERT_REVOKED`.
- Bouncy Castle `PKIXCRLUtil.findCRLs` keeps a CRL whose nextUpdate is null,
  so its entry revokes.

A correctly signed, in-scope CRL of the issuer without nextUpdate that lists
the certificate is therefore `certificate_revoked`, alone as beside another
CRL. **Decided, diagnostics:** both results reject; only the code changes.
`crl-028-no-next-update-crl-revocation-alone-revokes` pins it on
`good-pe64.exe`, which has no timestamp, and failed before the change
(`invalid_crl`).

The Decided case `crl-028-no-next-update-crl-revocation-alone-is-invalid`,
which this question was taken from, is unchanged. It uses
`good-countersignature.exe`, whose timestamp authority's chain is checked
first; that certificate is not on the CRL, so the result is the stricter
rule below (`invalid_crl` for the timestamp authority), not the signer's
listing. Its earlier reason in this document described it as the signer's
listing; the reason is now corrected.

Such a listing revokes alone only if webpki would accept the CRL apart
from its missing nextUpdate. webpki cannot parse a CRL without nextUpdate,
so rssig re-encodes it with a stand-in nextUpdate (its thisUpdate) and
parses that with webpki, whose verdict decides: every other webpki rule
applies (version, crlExtensions, cRLNumber, issuingDistributionPoint,
deltas, every entry, the signature AlgorithmIdentifier match). The
signature was already authenticated over the original bytes. A first
version copied those rules by hand and kept missing some; review found
them one by one. In addition, as OpenSSL's `cert_crl` and Bouncy Castle (unlike webpki and BoringSSL), an
entry with reasonCode removeFromCRL does not revoke (any revoking entry for the serial counts). Only a CRL that re-encodes to exactly its original bytes is judged this way; any other is not admitted, which fails closed, and is reported as malformed (`unsupported_or_malformed`, replaceable), as it would be with nextUpdate. References to OpenSSL line numbers in these PR #64 cases are to the 3.3 branch. It does not revoke
either when a newer authenticated full CRL of the issuer
covering the certificate leaves it out, as a listing beside a newer CRL
does not count; and not from an issuer without cRLSign. The missing
nextUpdate must be the CRL's sole defect: the CRL is otherwise one rssig
would use (current, positively in scope, a well-formed
authorityKeyIdentifier, admitted by webpki). With a malformed
authorityKeyIdentifier it does not revoke alone, exactly as the same CRL
with nextUpdate does not; that defect is reported and is replaceable.
(Beside a usable CRL a listing in a CRL with a malformed
authorityKeyIdentifier still counts, as the owner decided in PR #60.) An
earlier revision of this branch let it revoke alone. Unit test `a_crl_without_next_update_revokes_only_under_webpki_rules`.
A newer such CRL that leaves the signer out clears the listing
(`crl-028-no-next-update-crl-revocation-cleared-by-newer-crl`, Decided,
diagnostics: the result is `invalid_crl`, as for the CRL without nextUpdate
alone; both reject), and an older one does not
(`crl-028-no-next-update-crl-revocation-beside-older-clearing-crl-revokes`,
Decided, diagnostics). Only a current, complete, direct CRL clears: an
expired or not-yet-valid one, or a delta, indirect or reason-partitioned
one, would not be preferred by OpenSSL or BoringSSL; nor one whose
scope match cannot be read. The newest such CRL decides even if it lists
the certificate too: a newer entry released by removeFromCRL leaves an
older listing without effect, as OpenSSL reads only the newest
best-scored CRL. A CRL without nextUpdate known to cover another scope is
set aside only if webpki would admit it apart from the missing nextUpdate.
The newest CRL that counts must also be one rssig would otherwise use (a
well-formed authorityKeyIdentifier, and webpki's acceptance apart from a
missing nextUpdate) and must cover the certificate, never a partition for
a point the certificate does not list. Each of these conditions, and each
condition for the revocation itself, has a unit test that fails without it
(`a_crl_without_next_update_is_judged_by_its_other_defects`,
`only_a_usable_covering_crl_clears_a_listing_without_next_update`,
`a_crl_without_next_update_for_another_point_is_set_aside_if_admitted`,
`a_crl_that_does_not_reencode_to_its_bytes_is_not_judged`), checked by
removing each in turn.

The detail was first named `certificates_with_unusable_crl`; it is
`certificates_with_replaceable_crl`, as it names only certificates whose CRL
a source's CRL could replace (forged, no-cRLSign and no-nextUpdate CRLs are
reported through `unusable_crl` only).

The references differ on clearing: OpenSSL and BoringSSL keep only the
newest of equally scored CRLs (`get_crl_sk`, OpenSSL `x509_vfy.c:1150-1164`,
BoringSSL `x509_vfy.cc:675-685`), while Bouncy Castle walks its CRL set in
no fixed order and stops at the first listing or once all reasons are
covered (`RFC3280CertPathUtilities.java:708`), so it may revoke from the
older CRL. BoringSSL decides: the newest CRL decides. OpenSSL and Bouncy
Castle release a removeFromCRL entry (OpenSSL `x509_vfy.c:1686-1689`,
Bouncy Castle `RFC3280CertPathUtilities.java:794`); BoringSSL's `cert_crl`
(`x509_vfy.cc:768-790`) revokes on any entry. The two that agree are
followed.

Beside a usable CRL the PR #60 rule is unchanged: any authenticated,
current, covering listing counts, whatever else is wrong with its CRL, since
counting it rejects. The webpki-rule check applies only to a CRL without
nextUpdate standing alone, where the alternative is a CRL failure that also
rejects, so the check only decides the code and whether a source is asked.
Named test `crl_a_crl_without_next_update_revokes_unless_a_newer_crl_clears_it`.

A missing nextUpdate is checked after the CRL's scope defects, inside the
authority decision, so a CRL whose scope rssig cannot read is reported as
`issuing_distribution_point` (replaceable) with or without nextUpdate. A
CRL without nextUpdate that does not re-encode to its own bytes is reported as
`unsupported_or_malformed` with its own message ("does not re-encode to its
own bytes, so
it cannot be judged").

Recorded, not changed:
- Without `--fetch-crls`, a path whose only gap is a replaceable CRL is
  reported ahead of another path's error that webpki ranks higher (for
  example a certificate not valid at the lifetime signing time), naming its
  certificate in `certificates_with_replaceable_crl`. That is what `main`
  already does for an expired CRL (`completable_path`); the replaceable
  failures follow the same rule.
- Beside a usable CRL, a newer complete CRL without nextUpdate that leaves
  the certificate out does not clear an older listing, though it does when
  no CRL is usable. Clearing it there would turn a revocation into
  acceptance, which needs the owner's decision (CRL-T021).

Kept, stricter than the references: the same CRL without a listing is not
evidence of good status. It stays `invalid_crl` (`missing_next_update`), as
RFC 5280 section 5.1.2.5 requires nextUpdate in conforming CRLs, and a CRL
that never expires cannot show the status is still current; the references
would accept it. That rejection is an acceptance pin
(`crl-002-root-crl-no-next-update`) and is not changed here. Nor is such a CRL
refreshed by `--fetch-crls` (`crl-035-no-next-update-local-asks-nothing`): a
source's CRL would decide only if newer, and the open question was the
wording of a listing, not retrieval.
