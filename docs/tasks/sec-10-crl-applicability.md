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
**diagnostics** pins which error, detail or request.

- **The best CRL decides.** Decided, acceptance; owner-approved exception.
  Bouncy Castle's `checkCRL` skips a CRL that fails a check and goes on to the
  next (`lastException`); OpenSSL's `get_crl_sk` scores CRLs and uses the best
  (`CRL_SCORE_TIME`, `CRL_SCORE_SCOPE`, `CRL_SCORE_NOCRITICAL`). A usable CRL
  beside an unusable one therefore verifies, and the unusable one alone keeps
  its error.
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
  issuingDistributionPoint cannot be read: OpenSSL scores it unusable
  (`IDP_INVALID` in `get_crl_score`) and Bouncy Castle skips a CRL whose
  extension does not parse, so its entries are not read here either.
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
- **A listing in a current CRL with a malformed AKI counts.** Observed,
  acceptance (fails closed); not yet compared with either library:
  `sec10-malformed-aki-crl-revocation-beside-good-crl-revokes`.
- **Cross-certified paths.** A path that verifies with its CRLs is accepted
  whatever another path does: Decided, acceptance, as Bouncy Castle's builder
  tries every candidate path and accepts one that validates
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
- **Retrieval asks per certificate, only about what lacks a CRL.** Decided,
  diagnostics (which requests are made; the verification result is the same
  either way). OpenSSL's `get_crl`/`lookup_crls` and Bouncy Castle's
  `checkCRLs` look up CRLs for the certificate being checked:
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
  with the fetched CRL; `crl-stale-local-asks-provider` (on `main` as
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
  `sec10-fetch-by-certificate-answer-requests-no-listed-point`.
- **Missing evidence is `revocation_unknown`; a source has four kinds.**
  Decided by the owner in PR #60's design ("single error code", four kinds
  denied/failed/abort/unknown), diagnostics. Changed:
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
  `sec10-fetch-builtin-source-denies-https`.
- **An untrusted chain is never fetched for.** Decided, acceptance and
  privacy: path validation fails before any request, as `main`'s preliminary
  pass did: `crl-fetch-untrusted-chain-requests-nothing`.
