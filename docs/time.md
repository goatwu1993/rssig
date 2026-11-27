# Validation-time decisions

Numbered decisions that answer one question: **at which instant are
certificates checked?** The validation time, a timestamp's signing time,
lifetime signing and the validity boundaries, and how a failure at that
instant ranks against other failures. Whether a timestamp token can be trusted
at all is a [timestamp token decision](tsa.md); see [which
index](decisions.md#which-index). The entry format is defined in [Decision
indexes](decisions.md); the rules are explained in [validation
time](validation-time.md), and the review history is in
[TIME-T001](tasks/done.md#time-t001-fix-define-lifetime-signing-and-time-boundary-rules)
and
[TIME-T002](tasks/done.md#time-t002-fix-lifetime-signing-review-decisions-and-deferred-follow-ups).

TIME-003 and TIME-004 check a timestamp's time, but against certificate
validity and the validation time, so they belong here rather than to the
token decisions.

## Order

Entries are numbered from most to least important, in the tiers used by
[CRL decisions](crl.md#order); within a tier, Decided entries come before
Observed ones. A new entry takes the next free number.

1. **Fail-open:** a broken rule could accept a certificate outside its
   validity at the time that matters.
2. **Availability:** a broken rule would reject a valid file.
3. **Result diagnostics:** which error code or details are reported; both
   outcomes reject.

## Index

| ID | Decision | Status | Pins |
|---|---|---|---|
| [TIME-001](#time-001-a-lifetime-signing-signer-is-validated-at-the-validation-time) | A lifetime-signing signer is validated at the validation time | Decided | acceptance |
| [TIME-002](#time-002-a-lifetime-signers-chain-must-be-valid-at-the-signing-time) | A lifetime signer's chain must be valid at the signing time | Decided | acceptance |
| [TIME-003](#time-003-a-timestamped-signers-chain-is-validated-at-the-signing-time) | A timestamped signer's chain is validated at the signing time | Decided | acceptance |
| [TIME-004](#time-004-a-timestamp-after-the-validation-time-is-rejected) | A timestamp after the validation time is rejected | Decided | acceptance |
| [TIME-005](#time-005-a-fractional-timestamp-is-compared-exactly-with-validity) | A fractional timestamp is compared exactly with validity | Decided | acceptance |
| [TIME-006](#time-006-an-untimestamped-signer-is-validated-at-the-validation-time-inclusive-at-whole-seconds) | An untimestamped signer is validated at the validation time, inclusive at whole seconds | Decided | acceptance |
| [TIME-007](#time-007-a-lifetime-path-is-still-revocation-checked-at-the-validation-time) | A lifetime path is still revocation-checked at the validation time | Decided | acceptance |
| [TIME-008](#time-008-path-building-skips-an-intermediate-issued-after-the-signing-time) | Path building skips an intermediate issued after the signing time | Decided | acceptance |
| [TIME-009](#time-009-the-signing-time-rejection-ranks-as-a-validity-error) | The signing-time rejection ranks as a validity error | Decided | diagnostics |
| [TIME-010](#time-010-a-revocation-on-the-same-path-is-reported-before-the-signing-time-check) | A revocation on the same path is reported before the signing-time check | Decided | diagnostics |
| [TIME-011](#time-011-lifetime-signing-validity-outranks-revocation-on-another-path) | Lifetime-signing validity outranks revocation on another path | Decided | diagnostics |
| [TIME-012](#time-012-crl-freshness-is-reported-before-the-signing-time-check) | CRL freshness is reported before the signing-time check | Decided | diagnostics |
| [TIME-013](#time-013-failure-details-name-the-chain-certificate-that-failed) | Failure details name the chain certificate that failed | Decided | diagnostics |
| [TIME-014](#time-014-the-fractional-expiry-rejection-is-reported-last-on-its-path) | The fractional-expiry rejection is reported last on its path | Observed | diagnostics |

## Tier 1: fail-open

### TIME-001: A lifetime-signing signer is validated at the validation time

A signer whose ExtendedKeyUsage contains lifetime signing
(`1.3.6.1.4.1.311.10.3.13`) has its selected path validated at the validation
time, not at the timestamp time, so a valid RFC 3161 or PKCS#9 timestamp does
not extend an expired lifetime signer. Only the leaf's EKU counts. The rule
applies in the shared trust path: primary and nested signatures, every
format, and RDP signers.

- **Status:** Decided
- **Decided by:** written choice, PR #43 (TIME-T001)
- **Pins:** acceptance
- **Sources:**
  - The purpose of the lifetime-signing EKU: a signature it marks does not
    outlive the signer certificate, whatever its timestamp.
  - Written argument in [validation
    time](validation-time.md#lifetime-signing); no Windows equivalence is
    claimed.

### TIME-002: A lifetime signer's chain must be valid at the signing time

When a timestamp is present, the lifetime signer's leaf and every
intermediate on the selected path must also have notBefore at or before the
signing time (the inclusive boundary of TIME-006). The result is
`certificate_not_yet_valid` ("lifetime-signing certificate was not valid at
the signing time").

- **Status:** Decided
- **Decided by:** written choice, PR #43 (TIME-T001); the boundary pairs were
  added in review after a `>=` mutation passed the suite
- **Pins:** acceptance
- **Sources:**
  - Written argument: a timestamp must not claim a signature predates its
    certificate. This is a consistency check on an unsigned attribute, not a
    trust boundary: removing the timestamp leaves an untimestamped signature
    (TIME-001).

### TIME-003: A timestamped signer's chain is validated at the signing time

For a signer without the lifetime EKU, a valid timestamp moves chain
validation to its `signing_time`: an expired signer remains trusted, and a
certificate that was not valid at that time is rejected. The TSA chain is
validated at the signing time too. A timestamp whose signing time is before
the signer's notBefore is `certificate_not_yet_valid`, the same consistency
check as for a lifetime signer (TIME-002).

- **Status:** Decided
- **Decided by:** written argument (Authenticode timestamp semantics); the
  notBefore check is a written choice, PR #43 (TIME-T001), kept as a decision in
  TIME-T002
- **Pins:** acceptance
- **Sources:**
  - RFC 3161 sections 1 and 2: a time-stamp token proves that a datum existed
    at a particular time.
  - [validation time](validation-time.md) table, "Signer chain, timestamped".
  - Written argument: the notBefore check is the same consistency check as
    TIME-002.

### TIME-004: A timestamp after the validation time is rejected

A `signing_time` equal to the validation time is accepted; any nonzero
fraction in that second, or a later second, is `timestamp_in_future`.

- **Status:** Decided
- **Decided by:** written argument
- **Pins:** acceptance
- **Sources:**
  - A timestamp from the future cannot be evidence of when the signature
    existed; the validation time is the latest instant rssig can vouch for.

### TIME-005: A fractional timestamp is compared exactly with validity

A fractional signing time is compared exactly with the inclusive validity of
TIME-006: the leaf and intermediates of the path that verifies must have
notBefore at or before it and notAfter at or after it. So `notAfter` itself is valid and
`notAfter + .5` is `certificate_expired`; `notBefore + .5` is valid and
`notBefore - 1 + .5` is `certificate_not_yet_valid`. Exact decimal digits are
kept; no floating point is used. The comparison runs inside path building,
for the signer's path and the TSA's: an issuer that expires within the
timestamp's whole second is rejected as a candidate and another issuer with
the same subject and key that is valid at the fractional time is used,
wherever each is embedded. The anchor a path ends at is not compared with
the fraction; an embedded certificate used as an intermediate is.

- **Status:** Decided
- **Decided by:** written choice, PR #43 (TIME-T001); checked in path
  building by owner, PR #109 (TIME-T005)
- **Pins:** acceptance
- **Sources:**
  - RFC 5280 section 4.1.2.5 (validity is inclusive of notBefore and
    notAfter), applied to RFC 3161 `genTime` fractions.
  - Validity counts while an issuer is chosen. OpenSSL
    `crypto/x509/x509_vfy.c:411-415` (`get0_best_issuer_sk`: "Prefer the
    first match with suitable validity period or latest expiration"), at
    whole seconds only (`ossl_x509_check_cert_time`, `x509_vfy.c:2503-2540`):
    it has no fractional verification time. Bouncy Castle
    `PKIXCertPathBuilderSpi.java:209` validates each candidate path and
    `:253-262` tries the next issuer when it fails; `cert.checkValidity`
    (`RFC3280CertPathUtilities.java:1292`) compares a `Date`, which carries
    milliseconds. Read at the pinned commits; neither library was run.
- **Unit tests:** `fractional_expiry::the_signer_and_every_intermediate_are_compared_with_the_fraction`
  (`engine/src/trust.rs`); `time-005-root-not-after-fraction` pins that the
  path's anchor is left out.
- **Note:** before PR #109 the comparison ran after path selection, so a
  file whose first embedded issuer expired within the timestamp's second was
  rejected although a valid same-key issuer was embedded, and verified with
  the two in the other order. Which failure is reported when a path fails
  this comparison and something else is TIME-014.

### TIME-006: An untimestamped signer is validated at the validation time, inclusive at whole seconds

A signer without a timestamp has its chain validated at the validation time. A
certificate is valid from notBefore to notAfter, both inclusive at whole
seconds.

- **Status:** Decided
- **Decided by:** written argument
- **Pins:** acceptance
- **Sources:**
  - RFC 5280 section 4.1.2.5: notBefore and notAfter are inclusive.

### TIME-007: A lifetime path is still revocation-checked at the validation time

Lifetime signing changes only the validity time. A path through an
intermediate needs that intermediate's CRL (otherwise `revocation_unknown`),
and a revoked leaf is rejected even when another path would verify. Historical
(signing-time) revocation status is not modeled.

- **Status:** Decided
- **Decided by:** written choice, PR #43; kept as a decision in TIME-T002
- **Pins:** acceptance
- **Sources:**
  - AGENTS.md, "Fail closed" for unknown revocation status; CRL-001.

## Tier 2: availability

### TIME-008: Path building skips an intermediate issued after the signing time

The signing-time check of intermediates runs inside path building, so a
rolled-over intermediate with the same subject and key that was issued after
signing is rejected as a candidate and another valid issuer is used. A
candidate rejected by a path rule instead is PATH-009.

- **Status:** Decided
- **Decided by:** review fix, PR #43 (the first post-selection check rejected
  `time-008-lifetime-intermediate-rollover`)
- **Pins:** acceptance
- **Sources:**
  - Written argument: a valid embedded issuer must not be lost because
    another candidate was tried first.

## Tier 3: result diagnostics

### TIME-009: The signing-time rejection ranks as a validity error

Candidate rejection follows webpki's error ranking: the signing-time
rejection ranks above an intermediate lacking keyCertSign and above unknown
issuers. Within one path every intermediate is checked for signing time
before a missing keyCertSign is reported, so the result does not depend on
where each defect sits. Both outcomes reject.

- **Status:** Decided
- **Decided by:** review fix, PR #43
- **Pins:** diagnostics
- **Sources:**
  - Written argument: the reported defect must not depend on embedding order.

### TIME-010: A revocation on the same path is reported before the signing-time check

The signing-time check runs after webpki's own checks of a candidate path, so
a revocation on that path is reported instead. Both outcomes reject.

- **Status:** Decided
- **Decided by:** written choice, kept as a decision in TIME-T002
- **Pins:** diagnostics
- **Sources:**
  - Written argument in [validation time](validation-time.md#lifetime-signing).

### TIME-011: Lifetime-signing validity outranks revocation on another path

Across candidate paths, a CA issued after the lifetime signing time on one
path outranks a revocation on another; both reject.

- **Status:** Decided
- **Decided by:** written choice (the references disagree and neither has
  lifetime signing); kept as a decision in TIME-T002
- **Pins:** diagnostics
- **Sources:**
  - OpenSSL builds one chain and checks revocation before validity.
  - Bouncy Castle tries every path and checks validity before revocation per
    certificate.

### TIME-012: CRL freshness is reported before the signing-time check

The TSA chain is verified before the signer against the same store-wide CRLs,
so an expired or not-yet-valid CRL is reported first, with or without the
lifetime EKU. Both outcomes reject.

- **Status:** Decided
- **Decided by:** written choice, kept as a decision in TIME-T002
- **Pins:** diagnostics
- **Sources:**
  - Written argument in [validation time](validation-time.md#lifetime-signing).

### TIME-013: Failure details name the chain certificate that failed

`details.certificate` names the certificate that failed the signing-time or
fractional-expiry check, an intermediate when it is the cause. A signing-time
message and certificate are attached only when the surviving webpki error
carries that certificate's notBefore at the signing time; otherwise the
generic chain error is reported. Successful reports set
`TrustReport.lifetime_signing` and `validation_time`, and a report without
`lifetime_signing` does not deserialize.

- **Status:** Decided
- **Decided by:** written choice, kept as a decision in TIME-T002; the field
  made required with the owner's approval in PR #96 (TIME-T009)
- **Pins:** diagnostics
- **Sources:**
  - Written argument: a change in webpki's search order must not name the
    wrong certificate.
  - AGENTS.md, "Release status": no compatibility shims for earlier shapes.
- **Note:** pinned by named tests in `tests/cli/validation_time.rs`, and the
  required field by `core_checks_trust_revocation_and_integrity` in
  `engine/tests/verification_core.rs`; no spec case names this entry yet.
  Webpki validity errors naming the leaf, the signing-time error details and
  store-wide CRL presence and freshness errors carrying no `lifetime_signing`
  detail are not pinned here yet (TIME-T008).

### TIME-014: The fractional-expiry rejection is reported last on its path

On one candidate path the fractional comparison of TIME-005 is judged after
every other path check and applied after revocation, as the signing-time
check is (TIME-010). A path that also has an intermediate lacking keyCertSign
is `invalid_key_usage`, wherever each defect sits; a revoked certificate on
it is `certificate_revoked`; a certificate on it with no CRL is
`revocation_unknown` that names nothing, since no CRL completes the path
(CRL-027). A path that fails only this comparison passed everything else, so
its expiry is reported over another candidate's validity failure: an issuer
already expired at the whole second, in either embedded order. CRL-027 still
decides across paths: a revocation on another path is reported over it, and
so is a path that only lacks a CRL. All outcomes reject.

- **Status:** Observed
- **Decided by:** —
- **Pins:** diagnostics
- **Sources:**
  - Written argument: moving the comparison into path building (TIME-T005)
    is meant to change which issuer is chosen, not which failure is
    reported. Within a path it keeps the order it had after path selection;
    across paths it follows CRL-027, which now applies because the failure
    is known while paths are built.
- **Note:** named tests `time_fraction_expiry_is_reported_after_a_missing_key_cert_sign`,
  `time_fraction_expiry_is_reported_after_revocation_on_the_same_path`,
  `time_a_revoked_issuer_on_another_path_is_reported_over_fraction_expiry`
  and `time_fraction_expiry_is_reported_over_an_issuer_expired_earlier` in
  `tests/cli/validation_time.rs`. Two results differ from before PR #109:
  the missing-CRL result named the certificate, and a revoked issuer on the
  other path was reported as the fractional expiry. Not pinned (TIME-T010):
  an RDP signer with two accepted usages whose other usage fails
  differently, a path that would also be rejected for ambiguous issuer keys
  after selection, and another path that only lacks a CRL.

## Candidate rules

Unnumbered. `tests/decision-claims.json` assigns these cases here until they
name an entry.

- `attach`: cases that pin an existing TIME entry but do not name it yet: the
  pre-TIME-T001 time cases (TIME-T004) and every format's expired-with-timestamp
  and validity cases.
