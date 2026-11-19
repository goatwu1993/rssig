# SEC-10: Audit CRL applicability and competing evidence

Task detail for **SEC-10** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox. Other IDs below (SEC-11, SEC-15 to SEC-21, TEST-11,
PRODUCT-04, INTEROP-01, DEFER-01) are items in that file.

**Status:** complete. Every box in the audit checklist is checked, as is the
box in `TODO.md`. The limitations below stay open under their own IDs.

## Scope

Cover absent nextUpdate, issuer/AKI mismatch, cRLSign usage, revoked
intermediates, incomplete issuer coverage, distribution-point scope, unknown
critical extensions, delta/indirect CRLs, and competing or unrelated supplied
CRLs. Specify whether an unusable extra CRL rejects a request or is excluded.
Never silently treat unknown status as good; pin freshness boundaries and
unsupported-policy errors.

The rules are stated in the CRL row of [time policy](../time-policy.md). The
cases named below are in `tests/cases.json`, with named tests in
`tests/cli/crl_applicability.rs` and `tests/cli/crl_fetch.rs`.

## Audit checklist

One box per item in the scope above.

- [x] **Absent nextUpdate.** A chain issuer's CRL without it is `invalid_crl`
  (`missing_next_update`); from an unrelated issuer it is excluded.
  `sec10-root-crl-no-next-update`,
  `sec10-unrelated-no-next-update-crl-excluded`.
- [x] **Issuer/AKI mismatch.** A CRL applies only if its issuer name equals a
  configured root's or embedded candidate's subject and, when it carries an AKI
  keyIdentifier, that matches a name-matching candidate's SKI or the CRL's
  signature verifies under a name-matching candidate key. A malformed AKI on an
  applicable CRL is `invalid_crl`. `sec10-root-name-other-aki-crl-excluded`,
  `sec10-root-aki-crl-still-rejected`,
  `sec10-root-signed-other-aki-crl-still-rejected`,
  `sec10-root-crl-malformed-aki`, `sec10-unrelated-malformed-aki-crl-excluded`,
  `sec10-root-aki-issuer-serial-crl-name-matched`. Limits: SEC-16.
- [x] **cRLSign usage.** An intermediate issuer without cRLSign cannot issue a
  usable CRL (`invalid_key_usage` at `revocation`), and path building falls back
  to a candidate that has it. A configured root is exempt by decision.
  `sec10-ca-no-crl-sign`, `sec10-ca-crl-sign`, `sec10-ca-crl-sign-fallback`,
  `sec10-root-no-crl-sign-accepted`.
- [x] **Revoked intermediates.** `certificate_revoked` in four `--crl` orders.
  `sec10-revoked-issuer`, `sec10-revoked-issuer-after-good-root-crl`,
  `sec10-revoked-issuer-before-good-root-crl`,
  `sec10-revoked-issuer-issuer-crl-first`. Limit: the error details describe the
  signer (SEC-19).
- [x] **Incomplete issuer coverage.** A chain certificate with no applicable CRL
  is `revocation_unknown`. `sec09-lifetime-rollover-revocation-unknown`,
  `sec10-only-unrelated-crl-is-unknown`.
- [x] **Distribution-point scope.** A CRL naming a point is authoritative only
  for a certificate listing the same URI, byte for byte; role flags restrict it
  to end-entity or CA certificates; any matching URI among several names or
  points is enough; non-URI and issuer-relative names never match; a point with
  reasons or cRLIssuer is skipped; a full CRL covers every certificate of its
  issuer. `sec10-crl-dp-*` (26 cases), `sec10-ca-crl-dp-*`,
  `sec10-partition-crl-no-listed-point`,
  `sec10-partition-crl-relative-no-listed-point`,
  `sec10-root-idp-named-point-crl-rejected`,
  `sec10-root-idp-user-certs-crl-unsupported`,
  `sec10-root-idp-ca-certs-crl-unsupported`.
- [x] **Unknown critical extensions.** On the CRL or on a revoked entry:
  `invalid_crl` (`unknown_critical_extension`); a non-critical one is ignored.
  `sec10-root-unknown-critical-extension-crl-unsupported`,
  `sec10-root-entry-critical-extension-crl-unsupported`,
  `sec10-root-unknown-noncritical-extension-crl-accepted`.
- [x] **Delta and indirect CRLs.** `invalid_crl` (`delta_crl`, `indirect_crl`),
  reported before freshness. `sec10-root-delta-crl-unsupported`,
  `sec10-root-indirect-crl-unsupported`,
  `sec10-root-delta-expired-crl-reports-feature`. Limit: SEC-18.
- [x] **Competing or unrelated supplied CRLs.** Unrelated CRLs are excluded
  whatever their fault; among CRLs that cover the certificate a revocation in
  any one wins in either order. `sec10-unrelated-expired-crl-excluded`,
  `sec10-unrelated-not-yet-valid-crl-excluded`,
  `sec10-competing-crls-good-first-revoked`,
  `sec10-competing-crls-revoked-first-revoked`. Since PR #60 a partition for
  another point does not cover the certificate, so its entries are not read
  (`sec10-crl-dp-other-partition-revocation-is-ignored`,
  `sec10-crl-dp-other-partition-revocation-is-ignored-first`; see "Case
  reasons"). Limit: SEC-21.
- [x] **Unusable extra CRL: reject or exclude.** Specified: excluded when it
  does not apply to the chain, otherwise the request fails closed.
  `sec10-root-expired-crl-still-rejected` against the
  `sec10-unrelated-*-excluded` cases. Limit: SEC-18.
- [x] **Unknown status is never good.** Path validation denies unknown status,
  and a request whose supplied CRLs all fail to apply is `revocation_unknown`.
  `sec10-only-unrelated-crl-is-unknown`, `sec10-crl-dp-other-idp-unknown`,
  `sec10-crl-dp-other-idp-revoked-unknown`.
- [x] **Unsupported-policy errors.** Every applicable CRL that cannot be used is
  `invalid_crl` with a `details.reason` listed in [problems](../problems.md).
  Limit: reasons without a fixture are SEC-19.
- [x] **Freshness boundaries.** A CRL is usable from its thisUpdate (inclusive)
  until one second before its nextUpdate: a validation time one second before
  thisUpdate is `crl_not_yet_valid`, and one equal to nextUpdate is
  `crl_expired`. Pinned on an untimestamped signer.
  `sec10-crl-this-update-one-second-ahead`, `sec10-crl-this-update-exact`,
  `sec10-crl-next-update-one-second-left`, `sec10-crl-next-update-exact`. Whole
  seconds only; CRL times carry no fractions.
- [x] **`--fetch-crls` coverage.** Retrieval follows the verifier's result:
  the supplied CRLs are verified first, and the selected certificates' listed
  points are fetched only when that result is `revocation_unknown`. A CRL that
  merely has the issuer's name (another partition, another role, or another
  key of the same name) does not suppress the fetch, and the fetched CRL is
  held to the same verification. `sec10-fetch-other-idp-fetches-listed-point`,
  `sec10-fetch-other-idp-fetched-revoked`,
  `sec10-fetch-other-idp-fetched-other-unknown`,
  `sec10-fetch-ca-scope-idp-fetches-listed-point`,
  `sec10-fetch-ca-user-scope-idp-fetches-listed-point`,
  `sec10-fetch-excluded-name-match-fetches-listed-point`,
  `sec10-fetch-covered-signer-point-not-requested`,
  `sec10-fetch-asks-each-certificate-without-crl`,
  `sec10-fetch-covered-signer-is-not-asked`, and the
  `sec10-fetch-*-not-fetched` controls; named tests in
  `tests/cli/crl_fetch.rs`.
  A supplied CRL that verification rejects is reported as it is offline and
  nothing is fetched (`sec10-fetch-no-listed-point-not-fetched`,
  `sec10-fetch-no-listed-point-role-excluded-scope-rejected`,
  `sec10-fetch-unusable-supplied-crl-not-fetched`).
  A listed point that discovery does not support (reasons, cRLIssuer or a
  non-URI name) is not requested and is listed in `crl_retrieval.failures`; the
  result is the verifier's `revocation_unknown`, as without `--fetch-crls`
  (`sec10-fetch-reasons-point-denied`, `sec10-fetch-crl-issuer-point-denied`,
  `sec10-fetch-dns-name-point-denied`).
  History: PR #55 first restated webpki's authority rule for this
  (`has_crl_for`); the follow-up replaced it with the flow above.
  Limits: see evidence limits.

## Decisions made

- The best CRL decides, checked per certificate on each path (PR #60):
  revocation is evaluated by rssig for every certificate on a candidate path,
  as OpenSSL and Bouncy Castle do, and webpki confirms the accepted path with
  only the chosen CRLs. An unusable CRL is set aside when another CRL of the
  issuer is usable; the former `sec10-root-*` cases now pin each failure with
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
    Case: `sec10-fetch-no-listed-point-role-excluded-scope-rejected`.
  - **Decided, acceptance.** A listing in a CRL whose signature cannot be
    verified (bad or unsupported) never counts as a revocation. OpenSSL fails
    the CRL in `check_crl` before `cert_crl` reads entries; Bouncy Castle
    skips it in processCRLG before processCRLJ reads entries. Here it is
    `invalid_crl` (`unsupported_signature_algorithm`) or
    `invalid_crl_signature`, set aside when another CRL is usable.
  - **Decided, acceptance.** One certificate's distribution points never end
    the run: an over-long URI is skipped and the URIs past the first 16 are
    recorded as one `crl_urls` failure. OpenSSL's verifier has no such limit
    (an unmatched point means no CRL); Bouncy Castle has none either and
    skips a point that fails. The per-verification limits stay engine limits.
    Unit test `a_certificate_over_the_url_limits_is_skipped_point_by_point`.
  - **Decided by choice, diagnostics only.** Across candidate paths, a CA
    issued after the lifetime signing time on one path outranks a revocation
    on another (`sec09-lifetime-rollover-revoked-issuer`); both reject. The
    libraries do not agree and neither has lifetime signing: OpenSSL builds
    one chain, preferring currently valid issuers, and checks revocation
    before validity on it; Bouncy Castle tries every path and reports the
    last failure, checking validity before revocation per certificate. The
    SEC-14 precedence is kept.

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
  #49](https://github.com/goatwu1993/rssig/pull/49), until SEC-21).
- With `--fetch-crls`, retrieval happens only when verification with the
  supplied CRLs is `revocation_unknown`; any other result is returned
  unchanged. This replaces the restated authority rule of PR #55.
- When no supplied CRL applies, `revocation_unknown` is returned before path
  building ([PR #44](https://github.com/goatwu1993/rssig/pull/44); SEC-20).

## Evidence limits

- Distribution-point matching is rustls-webpki's, observed at 0.103.16, which
  `Cargo.toml` now requires exactly (`=0.103.16`). No other version was
  checked; rerun the `sec10-*` cases when changing the pin.
- Not pinned: a certificate mixing a skipped point (reasons or cRLIssuer) with a
  plain URI point.
- Every SEC-10 CRL is synthetic and signed with ECDSA P-256/SHA-256. There is no
  RSA-signed CRL and no CRL from an independent producer carrying an AKI or
  issuingDistributionPoint (INTEROP-01).
- The intended failing run was not observed for `sec10-root-crl-malformed-aki`
  (fix written before the fixture) or
  `sec10-root-delta-expired-crl-reports-feature` (case added after the reorder).
  The distribution-point, cRLSign, revoked-intermediate, AKI issuer/serial and
  freshness-boundary cases pinned behavior that already held. The five
  `sec10-fetch-*-fetches-*`/`-fetched-*` cases failed before the coverage fix
  (no request was made); the five `-not-fetched` controls already passed. The
  three `-denied` cases were added after the fix and passed at once; before it
  the same inputs were `revocation_unknown`, which was not run.
- The three cases added with the retrieval redesign
  (`sec10-fetch-excluded-name-match-fetches-listed-point`,
  `sec10-fetch-no-listed-point-role-excluded-scope-rejected`,
  `sec10-fetch-unusable-supplied-crl-not-fetched`) failed before it, for the
  intended reason each.
- `--fetch-crls` requests points in two steps (certificates whose issuer no
  supplied CRL names, then the rest), pinned on `sec10-chain-crl-dp.exe` by
  `sec10-fetch-covered-signer-point-not-requested`,
  `sec10-fetch-asks-each-certificate-without-crl`,
  `sec10-fetch-covered-signer-is-not-asked` and
  `sec10-fetch-asks-only-the-uncovered-certificate`; the first, third and
  fourth failed
  before the change that introduced them. In the second step a certificate
  that a supplied CRL does cover can still be fetched for; a failed request is
  skipped, but a fetched CRL that is stale or unusable still fails the run
  closed. No fixture has that shape. A certificate mixing a plain URI point
  with an unsupported one has the plain URI requested
  (`sec10-fetch-mixed-point-requests-plain-uri`, on
  `sec10-leaf-crl-dp-mixed.exe`, which failed first).
- Validated on macOS locally and on Linux in CI. No Windows comparison
  (DEFER-01).

## Known limitations tracked elsewhere

- **SEC-11:** excluded CRLs are still reported as supplied.
- **SEC-15:** applicability and the scope rule consider every embedded
  candidate.
- **SEC-16:** AKI/SKI and name-encoding edges.
- **SEC-17:** unbudgeted and repeated work.
- **SEC-18:** an unusable applicable CRL rejects even when another covers the
  issuer.
- **SEC-19:** reason coverage and error details.
- **SEC-20:** error precedence.
- **SEC-21:** listed serials are not bound to the path's issuer key.
- **TEST-11:** fixture builders and provenance.
- **PRODUCT-04:** CRL policy document.

## Case reasons (PR #60)

Every case PR #60 added or changed, with why its result is right (AGENTS.md,
"Pinned expectations"). **Decided** cases change only with the owner's
approval; **Observed** ones pin current behavior and may change when a better
result is argued. **Acceptance** pins whether a file verifies or is rejected;
**diagnostics** pins which error, detail or request. Every Decided case also
carries its sources on the case itself, in `decision.references` in
`tests/cases.json`; line numbers are for OpenSSL 3a3f1356, bc-java e03fee0b,
relic 02c54d58 and BoringSSL `main`.

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
  - Verify beside `good.crl` (added): `sec10-root-crl-no-next-update-beside-good-crl`,
    `sec10-root-expired-crl-still-rejected-beside-good-crl`,
    `sec10-root-aki-crl-still-rejected-beside-good-crl`,
    `sec10-root-crl-malformed-aki-beside-good-crl`,
    `sec10-root-signed-other-aki-crl-still-rejected-beside-good-crl`,
    `sec10-root-unknown-critical-extension-crl-unsupported-beside-good-crl`,
    `sec10-root-delta-crl-unsupported-beside-good-crl`,
    `sec10-root-indirect-crl-unsupported-beside-good-crl`,
    `sec10-root-entry-critical-extension-crl-unsupported-beside-good-crl`,
    `sec10-root-delta-expired-crl-reports-feature-beside-good-crl`,
    `sec10-root-idp-user-certs-crl-unsupported-beside-good-crl`,
    `sec10-root-idp-ca-certs-crl-unsupported-beside-good-crl`,
    `sec10-root-aki-issuer-serial-crl-name-matched-beside-good-crl`,
    `sec10-root-idp-named-point-crl-rejected-beside-good-crl`.
  - The same CRLs alone keep their exact error (changed to drop `good.crl`):
    the fourteen `sec10-root-*` cases of the same names without
    `-beside-good-crl`.
  - Full-CRL controls for the new fixtures (acceptance): `sec10-chain-crl-dp-full-crls`,
    `sec10-leaf-crl-dp-mixed-full-crl`, `sec10-leaf-crl-dp-https-full-crl`.
- **A revocation in a CRL that does not cover the certificate does not
  count.** Decided, acceptance (owner chose to follow the libraries, PR #60).
  OpenSSL's `crl_crldp_check` gives a CRL for another point or role no
  `CRL_SCORE_SCOPE`, so `get_crl_sk` never selects it over the covering CRL
  and `cert_crl` never reads its entries (`crypto/x509/x509_vfy.c`); Bouncy
  Castle's processCRLB2 rejects it before processCRLJ reads entries
  (`RFC3280CertPathUtilities.checkCRL`). On `main` such a listing revoked
  (`sec10-crl-dp-other-partition-revoked` and `-first`, expecting
  `certificate_revoked`); they are now
  `sec10-crl-dp-other-partition-revocation-is-ignored` and `-first` and
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
  `sec10-role-partition-crl-revocation-beside-full-crl-revokes`. Alone it is
  still `invalid_crl`, because webpki cannot use that form
  (`sec10-role-partition-crl-revocation-alone-is-unsupported`, Observed).
- **A partition for another point is no evidence.** Decided, diagnostics.
  Bouncy Castle's processCRLB2 rejects a CRL whose distribution point does not
  match; OpenSSL gives it no `CRL_SCORE_SCOPE`. The certificate is without a
  CRL, so the status is unknown and retrieval fetches its point:
  `sec10-expired-partition-for-another-point-leaves-status-unknown`,
  `sec10-fetch-expired-partition-for-another-point-still-fetches`,
  `sec10-crl-dp-other-idp-unknown` (details updated).
- **A CA-only CRL naming a point is rejected for an end entity.** Decided,
  acceptance; see the comparison above:
  `sec10-fetch-no-listed-point-role-excluded-scope-rejected`.
- **A listing counts only from a current CRL.** Decided, acceptance
  (owner delegated the call, PR #60). OpenSSL reads entries only from the
  best-scored, current CRL; Bouncy Castle's `PKIXCRLUtil.findCRLs` drops CRLs
  whose nextUpdate has passed before any entry is read. A revocation in an
  expired CRL beside a fresh CRL that omits the serial therefore verifies
  (`sec10-stale-crl-revocation-beside-fresh-crl-is-ignored`, formerly
  `-revokes`), and alone it is `crl_expired`
  (`sec10-stale-crl-revocation-alone-is-expired`). The newest usable CRL
  decides, as OpenSSL's `get_crl_sk` breaks ties by the latest lastUpdate, so
  a listing in an older CRL still within its validity does not count beside
  a newer one (`sec10-superseded-crl-revocation-beside-newer-crl-is-ignored`)
  and alone it revokes (`sec10-superseded-crl-revocation-alone-revokes`). A
  CRL without nextUpdate is never current.
  **Corrected after review (the libraries agree):** a CRL without nextUpdate
  claims no expiry, so it *is* current. OpenSSL's `ossl_x509_check_crl_time`
  (`crypto/x509/x509_vfy.c:1555-1587`) checks nextUpdate only when present,
  Bouncy Castle's `PKIXCRLUtil` (`PKIXCRLUtil.java:42-45`) keeps a CRL whose
  nextUpdate is null, and BoringSSL (`x509_vfy.cc:414`) behaves as OpenSSL.
  An authenticated, in-scope CRL without nextUpdate therefore counts for a
  listing, so it revokes beside an older usable CRL
  (`sec10-no-next-update-crl-revocation-beside-older-crl-revokes`, Decided,
  acceptance; the old
  rule verified a certificate the issuer said was revoked). Such a CRL is
  still unusable as evidence of good status: RFC 5280 requires nextUpdate,
  and alone it is `invalid_crl` / `missing_next_update`
  (`sec10-no-next-update-crl-revocation-alone-is-invalid`, diagnostics).
- **A listing in a current CRL with a malformed AKI counts.** Decided by the
  owner (PR #60), acceptance (fails closed): a correctly signed CRL of the
  issuer said the certificate is revoked, and a malformed identifier field
  does not make that statement less authentic.
  `sec10-malformed-aki-crl-revocation-beside-good-crl-revokes`. The
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
  (`sec10-cross-revoked-path-beside-covered-path-verifies`,
  `sec10-fetch-completes-the-path-without-a-crl-beside-a-revoked-path`,
  `sec10-fetch-completes-the-path-beside-an-expired-path`). Which error a
  rejected chain reports, and what retrieval is asked: Decided by the written
  argument in `docs/crl-retrieval.md` (only a path that passes every other
  check and lacks CRLs can be completed), diagnostics
  (`sec10-cross-revoked-path-beside-path-without-crl-names-it`,
  `sec10-fetch-revocation-stands-when-the-other-path-stays-without-crl`,
  `sec10-cross-revoked-path-beside-path-failing-key-usage-is-revoked`,
  `sec10-cross-unusable-crl-decides-beside-path-failing-key-usage`,
  `sec10-cross-expired-path-beside-path-without-crl-names-the-gap`,
  `sec10-fetch-path-failing-key-usage-asks-nothing`).
  Changed after review (owner asked for the fix): with `--fetch-crls`, an
  unknown status that names nothing to ask is followed by the check of the
  whole input without revocation, so
  `sec10-fetch-path-failing-key-usage-asks-nothing` now reports the path's
  own failure (`invalid_key_usage`), as before PR #60, where that check ran
  first; still no request is made. Without `--fetch-crls` the result is
  `revocation_unknown` with an empty list, as before PR #60.
  Only that unknown status, which is no evidence, is followed by the check
  without revocation. A definite CRL failure or revocation on such a chain
  keeps its code with `--fetch-crls`, as without it
  (`sec10-fetch-path-failing-key-usage-with-unusable-crl-keeps-the-crl-failure`,
  `sec10-fetch-path-failing-key-usage-with-revoked-issuer-is-revoked`;
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
  `sec10-cross-revoked-path-beside-path-with-expired-crl-names-it`
  (diagnostics), `sec10-fetch-refreshes-the-path-with-an-expired-crl-beside-a-revoked-path`
  (acceptance). The revoked path's own certificates are not named, and
  neither is anything on a path with a CRL a refresh cannot fix (forged,
  no cRLSign, `invalid_crl`): that path cannot verify, so no source is asked
  (unit test `a_revocation_names_only_paths_a_source_could_complete`; the
  same now holds for `certificates_without_crl`). Named test
  `sec10_a_revocation_names_and_fetch_refreshes_another_paths_expired_crl`.
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
  `sec10-fetch-covered-signer-point-not-requested`,
  `sec10-fetch-asks-each-certificate-without-crl`,
  `sec10-fetch-covered-signer-is-not-asked`,
  `sec10-fetch-asks-only-the-uncovered-certificate`,
  `sec10-fetch-excluded-name-match-fetches-listed-point`,
  `sec10-fetch-mixed-point-requests-plain-uri`,
  `sec10-fetch-bad-response-is-no-evidence-beside-another-point`.
- **An abort before an expired CRL could be refreshed is marked.** Decided,
  diagnostics: `crl-stale-local-source-abort-is-marked` keeps `crl_expired`
  with `retrieval_aborted`.
- **An expired supplied CRL is refreshed.** Decided, acceptance (owner
  delegated the call, PR #60). Bouncy Castle drops CRLs past nextUpdate and,
  with CRL fetching enabled, fetches from the certificate's points; OpenSSL
  does not fetch. `crl-stale-local-refreshed-by-provider` (added) verifies
  with the fetched CRL; `crl-stale-local-asks-provider` (before PR #60 as
  `crl-stale-local-provider-unused`, which expected no request) now expects
  the request and, without an answer, the same `crl_expired`.
- **A supplied CRL unusable for another reason is not refreshed.** Observed,
  diagnostics: `sec10-fetch-unusable-supplied-crl-not-fetched`. Bouncy Castle
  would fetch here too; kept narrow until compared case by case.
- **A source answering by certificate leaves no per-point failures.**
  Decided, diagnostics (owner delegated the call): OpenSSL's `lookup_crls`
  and Bouncy Castle's store lookups have no per-point outcome. Only a body
  that loads as a CRL of the certificate's issuer counts, as both look CRLs
  up by issuer name:
  `sec10-fetch-by-certificate-answer-requests-no-listed-point`. When that
  answer does not settle the certificate's status (for example an expired
  CRL), the listed points the source left unused are recorded as
  `crl_fetch_failed` ("not requested"), so that no listed point disappears
  from the report of a failed retrieval (written argument, diagnostics):
  `sec10-fetch-by-certificate-unusable-answer-records-unused-points`.
- **Missing evidence is `revocation_unknown`; a source has four kinds.**
  Decided by the owner in PR #60's design ("single error code", four kinds
  denied/failed/abort/unknown), diagnostics. The single code matches the
  references: OpenSSL reports `X509_V_ERR_UNABLE_TO_GET_CRL` however the CRL
  could not be obtained (`x509_vfy.c:1489`, `:1527`), and Bouncy Castle one
  "No CRLs found for issuer" error with lookup diagnostics in its message
  (`prov/.../jce/provider/CertPathValidatorUtilities.java:1340`). The four
  kinds have no reference equivalent. Changed:
  `crl-fetch-private`, `crl-fetch-injected-unavailable`,
  `sec10-fetch-reasons-point-denied`, `sec10-fetch-crl-issuer-point-denied`,
  `sec10-fetch-dns-name-point-denied` (`crl_fetch_denied`/`crl_fetch_failed`
  to `revocation_unknown`, cause in `crl_retrieval.failures`). Added:
  `crl-fetch-source-denied-is-no-evidence`,
  `crl-fetch-source-failed-is-no-evidence`,
  `crl-fetch-source-unknown-is-no-evidence`,
  `crl-fetch-source-abort-is-reported`, `sec10-fetch-source-abort-stops-requests`.
- **The source decides transport.** Decided (owner: the CLI's default HTTP
  source, library users provide their own), acceptance for the injected
  source, diagnostics for the built-in refusal:
  `sec10-fetch-source-is-asked-for-any-scheme`,
  `sec10-fetch-builtin-source-denies-https`. Sources under "Who screens a
  distribution-point address" below.
- **An untrusted chain is never fetched for.** Decided, acceptance and
  privacy: path validation fails before any request, as `main`'s preliminary
  pass did, and as OpenSSL's `verify_chain` runs `build_chain` (which needs
  a trust anchor) before `check_revocation` (`x509_vfy.c:266-284`):
  `crl-fetch-untrusted-chain-requests-nothing`. Checking the whole input
  first has no reference equivalent (a written privacy argument). The same holds for
  the whole input: before the first request it is verified once without
  revocation, so an invalid nested signature, later signer or bundle member
  is the result and no source is asked
  (`crl-fetch-invalid-nested-signature-requests-nothing`).
- **A self-issued key rollover path needs CRLs that name their key.**
  Decided, acceptance, by cross-checking OpenSSL, BoringSSL and Bouncy Castle
  (SEC-16). `good-sec06-self-issued-rollover.exe` has two certificates whose
  issuers share one name and have different keys. It verifies without
  revocation (`sec16-self-issued-rollover-without-revocation-verifies`;
  RFC 5280 section 6.1 allows self-issued certificates for key rollover, and
  OpenSSL 3.0.13 `openssl verify -attime 1800000000` without CRL checks
  reports OK).
  - *CRLs with an authorityKeyIdentifier naming their issuer's key*
    (`sec06-root-akid.crl`, `sec06-rollover-akid.crl`): all three libraries
    give each certificate its own key's CRL and accept, in either order.
    OpenSSL `crypto/x509/x509_vfy.c:1869-1889` (`get_crl_score`,
    `crl_akid_check`), BoringSSL `crypto/x509/x509_vfy.cc:490-515`, Bouncy
    Castle `RFC3280CertPathUtilities.java:379-390` (`processCRLF`). Run as a
    maintenance step with OpenSSL 3.0.13 (`openssl verify -crl_check_all
    -attime 1800000000`): OK in both orders. rssig accepts:
    `sec16-self-issued-rollover-with-key-identified-crls-verifies` and
    `sec16-self-issued-rollover-with-key-identified-crls-verifies-reversed`.
    webpki 0.103.16 picks a CRL by issuer name and IDP only and cannot
    confirm two issuers of one name, so for such a path (two chosen CRLs of
    one name, every one naming the key it was authenticated under, with
    different keys) webpki confirms the signer with the signer's CRL only,
    and rssig's per-key evaluation decides for the certificates above it.
    That evaluation still rejects a revoked rollover certificate:
    `sec16-self-issued-rollover-revoked-by-key-identified-crl-is-rejected`
    (`sec06-root-akid-revoked-rollover.crl`, RFC 5280 section 6.3.3).
  - *CRLs without an authorityKeyIdentifier* (`sec06-root.crl`,
    `sec06-rollover.crl`): the libraries differ. OpenSSL keeps one best CRL
    per name and has no fallback after its signature fails
    (`x509_vfy.c:1614-1627`, `:2318-2320`; `v3_purp.c:1353-1354`); the same
    OpenSSL run reports "CRL signature failure" at depth 0 or 1 depending on
    order. BoringSSL's `x509_vfy.cc:665-693`, `:755-760` is the same. Bouncy
    Castle skips a CRL that does not verify and tries the next
    (`RFC3280CertPathUtilities.java:1716-1721`) and accepts. The owner
    chose the tiebreaker (PR #60): the third reference, BoringSSL, rejects,
    so rssig rejects, failing closed, at
    webpki's confirmation
    (`sec16-self-issued-rollover-with-both-crls-is-rejected`:
    `certificate_chain_invalid`, reason `confirmation`), in either order.
    An earlier note here said OpenSSL would accept this case; the run shows
    it does not.
- **An RDP signer that only lacks a CRL under one of its usages reports the
  missing CRL.** Decided by written argument; no reference library has an
  equivalent, since accepting an RDP signer under any one of several EKUs is
  rssig's RDP policy (`docs/rdp.md`). The signer of
  `good-rdp-eku-retry-ca.rdp` has codeSigning and serverAuth under a CA
  whose EKU admits serverAuth only: the codeSigning attempt fails on the
  path (`invalid_eku`) and the serverAuth attempt lacks only the CA's CRL.
  Only a failure that names certificates a source could cover counts (an
  empty list names nothing), and a revocation naming another path's gap
  ranks below an unknown status or expired CRL (unit test
  `only_a_named_missing_crl_ranks_a_usage_failure_as_completable`).
  The missing CRL is reported, because a source can supply it
  (`rdp-eku-retry-ca-missing-crl-is-unknown`, diagnostics), and
  `--fetch-crls` then verifies the file, as before PR #60, where retrieval
  followed a pass without revocation that succeeded through serverAuth
  (`rdp-eku-retry-ca-fetches-the-missing-crl`, acceptance). Control:
  `rdp-eku-retry-ca-with-crls-verifies`.
- **A URI that is not an absolute URL is never offered to a source.**
  Decided, diagnostics: OpenSSL's `get_dp_url` returns only `http://` URIs
  (`apps/lib/apps.c:2833`) and Bouncy Castle's `distributionPoint.toURL()`
  fails on a relative one (`CrlCache.java:185`). It is recorded as
  `crl_fetch_denied` with its own message and no `url`. Unit test
  `a_uri_that_is_not_an_absolute_url_is_withheld_with_its_own_reason`.
- **Smaller review fixes (PR #60), unit-tested.** Decided by written
  argument, diagnostics unless noted; no reference library has an equivalent
  (they have no source interface or per-verification URI limit):
  - The `crl_source_urls` limit counts each distinct normalized URI once, so
    a source that answers by certificate or issuer, and so leaves points
    unused that later certificates list again, cannot exhaust it; five
    certificates listing the same 16 points use 16, not 80
    (`a_source_answering_by_certificate_never_exhausts_the_uri_limit`).
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
    `rdp-eku-retry-ca-revoked-usage-is-revoked` (Decided, diagnostics): the
    serverAuth usage is revoked and codeSigning fails its EKU; the revocation
    is reported, where the first usage's `invalid_eku` was before.
  - A delta CRL answered by certificate is not a full CRL, so it does not ask
    for another verification pass (`a_new_full_crl_by_certificate_asks_for_verification_first`).
  - Re-offered points are bounded by `crl_requests` (64 source requests per
    verification), not by `crl_source_urls`
    (`re_offered_points_are_bounded_by_the_request_limit`).
  - `check_public_http_url` has a fuzz target, `check_url`.
  - The reserved-name check trims one trailing dot before testing for a
    single-label name too, so `http://intranet./x.crl` is denied like
    `http://intranet/x.crl`. Other private-use DNS suffixes (`.lan`,
    `.corp`, `.localdomain`) are not listed: the check is of the URL text
    only; the built-in source refuses any DNS answer that is not a public
    address and re-checks every redirect, which is what protects against
    them. A custom source must do the same in its own client (see
    `docs/library.md`).
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
    offers it (`a_certificate_named_twice_is_one_target`,
    `a_point_requested_later_is_not_reported_as_not_requested`). Such a
    point is reported for the first certificate with the outcome its later
    request got (its failure, or nothing if it was answered), and as not
    requested only if no request carried it. The shared-point variant has no
    spec case: no committed file has two certificates of different issuers
    listing one URI; the unit test checks the serialized failure entries.
    Only a certificate the failed result still names (its status not
    settled) reports the points its source's answer by certificate left
    unused, in request order: with the failure a request for another
    certificate gave the point, nothing if such a request was answered, and
    otherwise as not requested. A certificate whose status was settled
    leaves no per-point failure (the Decided rule above). A run ended by an
    engine limit or a failed check reports what was recorded until then:
    that error is the result. Codes and URLs are pinned by
    `sec10-fetch-by-certificate-unusable-answer-records-unused-points`;
    message texts are diagnostics prose, not matched by consumers.
- **Retrieval bookkeeping (unit-tested).** A request marks its points as
  offered only once every engine limit has passed, so a limit that ends the
  run leaves a point another certificate left unused reported as such. The built-in source does no work once spent (no request, DNS
  lookup or connection), and a body that ends exactly at its 32 MiB cap is
  still read to its end (`a_body_ending_exactly_at_the_byte_cap_still_reads_its_end`),
  with the byte limit reported ahead of the deadline. A URL that does not
  parse is reported as not an absolute URL.
- **Deadline during I/O.** Each DNS, connect, read and write wait is cut
  to the time left, so an I/O failure once the deadline has passed is
  reported as the deadline (`abort`), not as the request's own failure.
- **Declined after review:** not closing the built-in source after a DNS
  timeout caused only by a short remaining deadline. The close is what
  keeps at most one unfinished resolver thread per source (std has no
  cancellable DNS); reopening would allow one per file. A delegating source
  must forward `begin_verification` (documented on the trait).
- **Declined after review:** naming the gaps of a path whose other
  certificate has a supplied CRL that is unusable for a reason other than
  expiry. Such a certificate is never asked about (Observed,
  `sec10-fetch-unusable-supplied-crl-not-fetched`), so the path cannot be
  completed by retrieval; changing that is revisiting the Observed rule
  (Bouncy Castle would fetch), not this one.
- **Declined after review (already decided):** confirming intermediates on a
  key-rollover path with webpki (it cannot confirm two same-name issuers;
  rssig's per-key evaluation decides, SEC-16 above); a batch-wide fetch
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
    (`sec10-forged-crl-naming-a-same-key-roots-identifier-is-forged`,
    `sec10-forged-crl-naming-another-key-is-set-aside`; **Observed**,
    diagnostics only, since it changes only which error is reported: both
    reject, and the libraries have no equivalent for two same-key anchors).
    An anchor whose same-key root has no identifier cannot disprove a match.
    Unit test `only_a_differing_key_identifier_sets_a_failed_crl_aside`, named
    test `sec10_a_same_key_roots_identifier_makes_a_crl_forged_not_set_aside`.
  - A CRL without nextUpdate alone that lists a certificate leaves the
    status `invalid_crl` (`missing_next_update`), not `certificate_revoked`:
    it is unusable evidence (RFC 5280 requires nextUpdate), and the
    certificate is rejected either way
    (`sec10-no-next-update-crl-revocation-alone-is-invalid`, Decided,
    diagnostics).
  - The built-in source's reserved-name check (now `localhost`, `local`,
    `internal`, `home.arpa`, `invalid`, `test`, `example`, `onion`, `alt`) matches whole labels: `foo.local` is denied,
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
  `retrieval::check_public_http_url` gives a custom source the same check.
  Pinned by `sec10-fetch-source-is-asked-for-any-scheme` and
  `sec10-fetch-builtin-source-denies-https`.
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
  `src/trust.rs`; no committed certificate has an undecodable extension.
- **Other review fixes without a fixture** (unit tests in `src/trust.rs`,
  `src/retrieval.rs` and `src/retrieval/http.rs`): a CRL's complete signature
  AlgorithmIdentifier must be one the webpki adapter accepts; rejected paths
  keep CRL indices and the returned error alone carries the CRL report; a
  path needing only a fresh CRL is completable; a full CRL returned by
  certificate triggers verification before further requests; a URL that
  does not parse is withheld; diagnostics for unusable point names are
  bounded per certificate; the request whose DNS lookup times out is the
  abort; a withheld URL is not an answer by certificate. A certificate whose
  own points cannot be read is reported as `certificate_distribution_points`,
  not as a fault of the CRL.
