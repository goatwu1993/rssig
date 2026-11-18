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
  whatever their fault; among applicable CRLs a revocation in any one wins in
  either order. `sec10-unrelated-expired-crl-excluded`,
  `sec10-unrelated-not-yet-valid-crl-excluded`,
  `sec10-competing-crls-good-first-revoked`,
  `sec10-competing-crls-revoked-first-revoked`,
  `sec10-crl-dp-other-partition-revoked`,
  `sec10-crl-dp-other-partition-revoked-first`. Limit: SEC-21.
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
  `sec10-fetch-name-matched-signer-point-requested-second`,
  `sec10-fetch-covered-point-failure-skipped`, and the
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
  `sec10-fetch-name-matched-signer-point-requested-second` and
  `sec10-fetch-covered-point-failure-skipped`; the first and last failed
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
