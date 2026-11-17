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
| CRLs | Validation time | thisUpdate must not follow it; nextUpdate must follow it. A current CRL listing a certificate rejects it even after a valid timestamp. A CRL whose issuer names no configured root or embedded candidate certificate, or whose authorityKeyIdentifier keyIdentifier differs from that of every name-matching candidate with a subject key identifier and whose signature does not verify under any name-matching candidate key, is excluded before these checks; a stale CRL from a chain issuer rejects the request (`crl_not_yet_valid`, `crl_expired`), and one without nextUpdate is `invalid_crl`. An applicable CRL that webpki cannot use (unknown critical extension, delta CRL, indirect CRL, unsupported issuing distribution point or version) is `invalid_crl` with a stable `details.reason`, never silently skipped. Remaining applicability work is SEC-10. |

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
