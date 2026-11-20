# Lifetime signing and time boundaries (SEC-09)

The verifier never reads the clock. `VerifyOptions.now` (the CLI's `--time`, or
the host clock when `--time` is omitted) is the single whole-second validation
time for one verification. Each kind of certificate or artifact is checked at a
documented time:

| Subject | Time used | Notes |
| --- | --- | --- |
| Signer chain, timestamped | Timestamp `signing_time` | A valid timestamp lets an expired signer remain trusted. `TrustReport.validation_time` records the time used. |
| Signer chain, untimestamped | Validation time | notBefore and notAfter are inclusive at whole seconds. |
| Signer chain, lifetime-signing EKU | Validation time, and notBefore at the signing time | See below. `TrustReport.lifetime_signing` is `true`. |
| TSA chain | Timestamp `signing_time` | The TSA EKU must be exclusively timeStamping, so lifetime signing never applies to it. |
| Timestamp itself | Validation time | `signing_time` equal to the validation time is accepted; any nonzero fraction in that second, or a later second, is `timestamp_in_future`. |
| Configured trust anchors | Not checked | webpki treats configured anchors as keys; see [path policy](certificate-path-policy.md). Checking them at a lifetime signing time is SEC-14. |
| CRLs | Validation time | Revocation is checked per certificate on each candidate path, as OpenSSL's `check_cert_crl` and Bouncy Castle's `X509RevocationChecker` do. A certificate's candidate CRLs are those with its issuer's name. Each is authenticated under the issuer key that path uses (the next certificate, or the configured root behind the anchor); one that does not verify is set aside silently if its authorityKeyIdentifier names another key, and otherwise is `invalid_crl_signature`. An intermediate issuer must have cRLSign (`invalid_key_usage`); configured anchors are keys and are exempt. A CRL is usable when, in this order: its issuer has cRLSign; its authorityKeyIdentifier is well formed; its issuingDistributionPoint does not name a point the certificate lacks (`invalid_crl`, `distribution_point_scope`, when the certificate lists no CRL distribution points); webpki can use it (`invalid_crl` with a stable `details.reason` for an unknown critical extension, a delta or indirect CRL, or an unsupported issuing distribution point or version; a CRL without nextUpdate, which webpki cannot parse, is judged on a copy with a stand-in nextUpdate); the validation time is not before thisUpdate (`crl_not_yet_valid`); it has nextUpdate (`invalid_crl`, `missing_next_update`); and the validation time is before nextUpdate (`crl_expired`; `sec10-crl-this-update-*`, `sec10-crl-next-update-*`). The missing nextUpdate is checked after every other defect because OpenSSL, BoringSSL and Bouncy Castle do not treat it as one: a CRL's other defects decide as they would with nextUpdate present (`sec10-no-next-update-point-scope-crl-is-replaceable`). A usable CRL decides only if it is authoritative for the certificate: no issuingDistributionPoint, or one whose onlyContainsUserCerts/onlyContainsCACerts flags admit it and whose fullName URIs include one the certificate lists, byte for byte (only fullName URIs compare; a point with reasons or a cRLIssuer is skipped); this is webpki 0.103's rule. **The best CRL decides:** an unusable CRL is set aside when another CRL of the issuer is usable and authoritative (`sec10-root-*-beside-good-crl`); only when none is does the most specific failure decide, ranked forged signature, missing cRLSign, `invalid_crl` that a fetched CRL cannot replace (no nextUpdate, unsupported signature algorithm, unreadable certificate points), `invalid_crl` that one could (a distribution-point scope on a certificate that lists none, malformed, an unsupported feature, an unusable issuingDistributionPoint), not yet valid, expired. With none at all the status is `revocation_unknown`, and `details.certificates_without_crl` names every certificate on the path that lacked one. Only paths that pass every other path policy (keyCertSign, issued after a lifetime signing time) decide a revocation failure, and a revocation on another path does not hide theirs, unless none passes; then revocation is still reported first but names no certificate (`sec10-cross-unusable-crl-decides-beside-path-failing-key-usage`). A revocation on one candidate path decides; when another such path has certificates with no CRL at all, the revocation also names them in `details.certificates_without_crl`, and those whose only CRLs have expired in `details.certificates_with_expired_crl`, and those whose only CRLs a source's CRL could replace (not yet valid, malformed, an unusable or point-scoped issuingDistributionPoint, an unsupported feature) in `details.certificates_with_replaceable_crl`, so that `--fetch-crls` can complete that path (`sec10-cross-revoked-path-beside-path-without-crl-names-it`, `sec10-cross-revoked-path-beside-path-with-expired-crl-names-it`). A certificate with a usable authoritative CRL is `certificate_revoked` if any current CRL authenticated under its issuer's key lists it, and covers the certificate lists it, whatever the `--crl` order; without usable evidence such a listing leaves the status unknown, except in a CRL whose only defect is a missing nextUpdate: OpenSSL, BoringSSL and Bouncy Castle use such a CRL, so its listing revokes alone too, provided the missing nextUpdate is its sole defect (it is otherwise current, in scope, well formed and one webpki would accept), its entry is not removeFromCRL, and no newer such CRL of the issuer leaves the certificate out (`sec10-no-next-update-crl-revocation-alone-revokes`). A CRL that does not cover the certificate (a partition for another point or role) is not read for entries, as in OpenSSL and Bouncy Castle (`sec10-crl-dp-other-partition-revocation-is-ignored`). A named partition counts only on a positive match with a fullName URI the certificate lists; a role-only partition with no name counts for its role; and if the certificate's own points cannot be read, the match is unknown, so the partition is neither set aside nor are its listings dropped. A CRL whose complete signature AlgorithmIdentifier (parameters included) the webpki adapter does not accept is `invalid_crl` (`unsupported_signature_algorithm`) and never displaces a usable CRL. A listing that does not count is logged at `Warn` through an injected logger. A listing in a current CRL whose authorityKeyIdentifier is malformed still counts, by the owner's decision: the reference implementations disagree, and the CRL is correctly signed by the issuer (`sec10-malformed-aki-crl-revocation-beside-good-crl-revokes`; references in `docs/tasks/sec-10-crl-applicability.md`). The newest usable CRL (latest thisUpdate) decides, as OpenSSL prefers the latest lastUpdate. A listing in a CRL that is not current (expired or not yet valid), or that is older than the deciding CRL, does not count, as in OpenSSL and Bouncy Castle: it may be a hold that was since released (`sec10-stale-crl-revocation-beside-fresh-crl-is-ignored`, `sec10-superseded-crl-revocation-beside-newer-crl-is-ignored`). With `--fetch-crls`, a certificate whose only CRLs have expired, are not yet valid, have an unusable issuingDistributionPoint, are malformed or use an unsupported feature is offered to the source for a replacement (`docs/crl-retrieval.md`); a bad signature, an unsupported signature algorithm, a missing cRLSign or a missing nextUpdate is not. A current CRL listing a certificate rejects it even after a valid timestamp. The per-certificate check above is the only revocation decision; webpki builds paths without revocation options (SEC-24). On a self-issued key-rollover path (two issuers of one name with different keys) whose chosen CRLs each name their issuer's key in an authorityKeyIdentifier, each certificate gets its own key's CRL, and OpenSSL, BoringSSL and Bouncy Castle accept such a path (`sec16-self-issued-rollover-with-key-identified-crls-verifies`); without key identifiers rssig rejects it by the accepted-path rule `ambiguous_issuer_keys` (`sec16-self-issued-rollover-with-both-crls-is-rejected`). With `--fetch-crls`, the CRL source is asked only about the certificates the verifier reports without a usable CRL: none, only expired ones, or only ones it could replace. A CRL's currency is judged at the validation time (the time now, or a lifetime-signing signer's), while the test-only webpki cross-check (SEC-24) runs at the signing time of a timestamped signer; the two cannot disagree on expiry, because nextUpdate after now is also after the earlier signing time, and webpki does not test thisUpdate. |

## Lifetime signing

A signer certificate whose ExtendedKeyUsage contains Microsoft lifetime signing
(`1.3.6.1.4.1.311.10.3.13`) is supported with these semantics:

- The signer's selected path (leaf and intermediates) is validated at the
  validation time, not at the timestamp time. A valid RFC 3161 or PKCS#9
  timestamp therefore does not extend an expired lifetime-signing signer.
  Failures are the usual `certificate_expired` / `certificate_not_yet_valid` at
  `certificate_chain`, with `lifetime_signing: true` added to the webpki
  validation/notAfter/notBefore details. A `signing_time` detail is added only
  when a timestamp established one.
- When a timestamp is present, the leaf and every intermediate in the selected
  path must also have notBefore at or before the signing time. This is stricter
  than validating only at the validation time: rssig does not accept a
  timestamp claiming a signature predates its leaf or intermediate certificate.
  The comparison is inclusive at whole seconds: notBefore equal to the signing
  time is valid, one second later is not. Configured anchors are not checked
  (see the table above and SEC-14 in the roadmap). notAfter needs no separate
  signing-time check, because the timestamp cannot follow the validation time.
- This is a consistency check on the timestamp's claim, not a trust boundary.
  Timestamps are unsigned attributes: removing one leaves an ordinary
  untimestamped signature, which is validated at the validation time only.
  The same holds for a non-lifetime signer whose timestamp precedes its
  notBefore.
- The leaf is checked before path building, like webpki's own leaf validity
  check, so it precedes unknown-issuer (`untrusted_root`) and unknown
  revocation status of the signer path. An empty root store is still reported
  first. The check needs a timestamp, and the TSA chain is verified before the
  signer against the same store-wide CRLs, so an expired or not-yet-valid CRL
  is reported first, with or without the lifetime EKU.
  The intermediate check runs inside path building, so a candidate issued
  after signing (for example, a rolled-over CA with the same subject and key)
  is rejected and webpki continues with other candidates.
- When the leaf fails, or no candidate path is accepted, the result is
  `certificate_not_yet_valid` with message "lifetime-signing certificate was
  not valid at the signing time". Details name the offending `certificate`, its
  `not_before`, the `signing_time` that failed, the `validation_time` and
  `required_eku`. If the certificate report cannot be built,
  `certificate_report_error` replaces `certificate` so the signing-time reason
  is still reported.
- Candidate rejection follows webpki's error ranking: the signing-time
  rejection ranks as a certificate-validity error, above an intermediate
  lacking keyCertSign and unknown issuers. Within one candidate path every
  intermediate is checked for signing time before a missing keyCertSign is
  reported, so the result does not depend on where each defect sits in the
  path. Among equally ranked failures the first encountered is reported. The
  check runs after webpki's own checks of a candidate path, so a revocation or
  signature failure on that same path is reported instead.
- The signing-time message and offending certificate are attached only when
  the surviving webpki error carries that certificate's notBefore at the
  signing time. Otherwise the generic `certificate_not_yet_valid` chain error
  is reported with webpki's own `not_before`, so a change in webpki's search
  order cannot name the wrong certificate.
- The timestamp is still fully verified (imprint, TSA signature, TSA chain at
  the signing time, future-time check), and is reported.
- Only the leaf's EKU is consulted. The EKU on an intermediate does not enable
  lifetime semantics. The rule is applied in the shared trust path, so it
  covers primary and nested Authenticode signatures, every format, and RDP
  signers. Fixtures pin PE primary and nested signatures and RDP signers.
- Successful reports set `TrustReport.lifetime_signing` to `true` and
  `validation_time` to the validation time. The field is `false` for every
  other signer and every TSA report, and defaults to `false` when reading
  older reports.

This conservative policy does not claim Windows equivalence, including
WinVerifyTrust flags that change timestamp or lifetime-signing treatment.

## Fractional time boundaries

webpki compares validity at whole seconds. A fractional timestamp is checked at
its whole second, then the selected leaf and intermediates must have
`notAfter > signing_time`. This second step runs after path selection, so it
does not consider an alternative issuer with a later notAfter (SEC-14).
Consequences pinned by fixtures:

- `signing_time == notAfter` is valid; `notAfter + .5` is `certificate_expired`
  with "fractional timestamp exceeds certificate validity", for both the leaf
  and an intermediate. One whole second later fails in webpki.
- `notBefore + .5` is valid; `notBefore - 1 + .5` is `certificate_not_yet_valid`.
  This holds for both the leaf and an intermediate.
- Exact decimal digits are preserved in `fractional_seconds`; no floating
  point rounding is used.

## Evidence and maintenance

32 committed deterministic test-only signed fixtures (28 single-signature PE
files, 2 PE files with a nested signature and 2 inert RDP files) and 3 CRLs
(`sec09-*`) back 47 portable cases and 37 named in-process CLI tests in
`tests/cli/time_policy.rs`. Paired cases isolate:

- the lifetime-signing EKU: the same expired signer and valid RFC 3161 or
  PKCS#9 timestamp, with and without the EKU, as a PE signer, as a nested PE
  signature and as an RDP signer;
- issuer selection among rolled-over intermediates, and signing-time versus
  keyCertSign precedence in both embedded orders and in both positions on one
  path;
- notAfter and notBefore at, and one second past, the validation time, and the
  leaf and intermediate boundaries described above;
- the lifetime signing-time boundary: leaf and intermediate notBefore equal to
  the timestamp (accepted) and one second after it (rejected);
- revocation for a lifetime signer issued by an intermediate: good status with
  CRLs from the root and the intermediate, unknown status without the
  intermediate's CRL, a revoked leaf reported before the signing-time check on
  the same path, the signing-time rejection outranking a revoked issuer on
  another path, and CRL freshness reported first with or without the EKU.

Whole-second and fractional boundary cases through an intermediate disable
revocation explicitly; they predate the intermediate CRL fixtures. A native
test checks every fixture's image digest (PE) or canonical settings signature
(RDP), signer/TSA/certificate signatures, leaf and intermediate validity
windows, issuer links, EKU, intermediate keyCertSign, the RFC 3161 or PKCS#9
time and the timestamp's binding to the signer's signature. Another checks
each CRL's issuer, signature and revoked serials. Other formats (MSI, CAB,
scripts, AppX) share the same trust call but have no lifetime-signing fixture.

Before the production change, the lifetime-signing fixtures were accepted at
the timestamp time (`lifetime-expired`, `lifetime-counter-expired`, and
`lifetime-valid` one second past notAfter). Every non-lifetime boundary case
already matched and is pinned as a regression guard. Review follow-up: the
first post-selection signing-time check rejected `lifetime-intermediate-rollover`
although a valid issuer was embedded, and an untimestamped lifetime failure
reported the validation time as `signing_time`; both cases now pin the fix.
A second review moved candidate rejection to the validity rank and out of
unbudgeted report construction; the keyCertSign precedence fixtures already
produced the documented result before that change and guard it. A later review
found that within one path the first defect encountered won:
`lifetime-chain-ca-usage-late` returned `invalid_key_usage` while its swapped
counterpart returned `certificate_not_yet_valid`. Both now report the late
intermediate. The RDP, nested and revocation cases were added afterwards and
passed on first run; they pin behavior rather than reproduce a failure. The
signing-time boundary pairs were added after a review showed that changing the
comparison to `>=` passed the suite; both that mutation and `> at + 1` now
fail `tests/cli/time_policy.rs`.

Maintenance: `cargo test --locked regenerate_sec09_fixtures -- --ignored`
(also run by `regenerate_cli_fixtures`). Ordinary tests consume committed bytes.
