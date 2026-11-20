# Validation-time decisions

Numbered decisions that answer one question: **at which instant are
certificates checked?** The validation time, a timestamp's signing time,
lifetime signing and the validity boundaries, and how a failure at that
instant ranks against other failures. Whether a timestamp token can be trusted
at all is a [timestamp token decision](tsa.md); see
[which index](decisions.md#which-index). The entry format is defined in
[Decision indexes](decisions.md); the policy is explained in
[time policy](time-policy.md), and the review history is in SEC-09 and SEC-14
([done](tasks/done.md), [TODO.md](../TODO.md)).

TIME-004 and TIME-005 check a timestamp's time, but against certificate
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
| [TIME-004](#time-004-a-timestamp-before-the-signers-notbefore-is-rejected) | A timestamp before the signer's notBefore is rejected | Decided | acceptance |
| [TIME-005](#time-005-a-timestamp-after-the-validation-time-is-rejected) | A timestamp after the validation time is rejected | Decided | acceptance |
| [TIME-006](#time-006-a-fractional-timestamp-is-compared-exactly-with-validity) | A fractional timestamp is compared exactly with validity | Decided | acceptance |
| [TIME-007](#time-007-an-untimestamped-signer-is-validated-at-the-validation-time-inclusive-at-whole-seconds) | An untimestamped signer is validated at the validation time, inclusive at whole seconds | Decided | acceptance |
| [TIME-008](#time-008-a-lifetime-path-is-still-revocation-checked-at-the-validation-time) | A lifetime path is still revocation-checked at the validation time | Decided | acceptance |
| [TIME-009](#time-009-path-building-skips-an-intermediate-issued-after-the-signing-time) | Path building skips an intermediate issued after the signing time | Decided | acceptance |
| [TIME-010](#time-010-the-signing-time-rejection-ranks-as-a-validity-error) | The signing-time rejection ranks as a validity error | Decided | diagnostics |
| [TIME-011](#time-011-a-revocation-on-the-same-path-is-reported-before-the-signing-time-check) | A revocation on the same path is reported before the signing-time check | Decided | diagnostics |
| [TIME-012](#time-012-lifetime-signing-validity-outranks-revocation-on-another-path) | Lifetime-signing validity outranks revocation on another path | Decided | diagnostics |
| [TIME-013](#time-013-crl-freshness-is-reported-before-the-signing-time-check) | CRL freshness is reported before the signing-time check | Decided | diagnostics |
| [TIME-014](#time-014-failure-details-name-the-chain-certificate-that-failed) | Failure details name the chain certificate that failed | Decided | diagnostics |

## Tier 1: fail-open

### TIME-001: A lifetime-signing signer is validated at the validation time

A signer whose ExtendedKeyUsage contains lifetime signing
(`1.3.6.1.4.1.311.10.3.13`) has its selected path validated at the validation
time, not at the timestamp time, so a valid RFC 3161 or PKCS#9 timestamp does
not extend an expired lifetime signer. Only the leaf's EKU counts. The rule
applies in the shared trust path: primary and nested signatures, every
format, and RDP signers.

- **Status:** Decided
- **Decided by:** written choice, PR #43 (SEC-09)
- **Pins:** acceptance
- **Sources:**
  - The purpose of the lifetime-signing EKU: a signature it marks does not
    outlive the signer certificate, whatever its timestamp.
  - Written argument in [time policy](time-policy.md#lifetime-signing); no
    Windows equivalence is claimed.

### TIME-002: A lifetime signer's chain must be valid at the signing time

When a timestamp is present, the lifetime signer's leaf and every
intermediate on the selected path must also have notBefore at or before the
signing time, inclusive at whole seconds. The result is
`certificate_not_yet_valid` ("lifetime-signing certificate was not valid at
the signing time").

- **Status:** Decided
- **Decided by:** written choice, PR #43 (SEC-09); the boundary pairs were
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
validated at the signing time too.

- **Status:** Decided
- **Decided by:** written argument (Authenticode timestamp semantics)
- **Pins:** acceptance
- **Sources:**
  - RFC 3161 section 4 (a timestamp proves the datum existed at that time).
  - [time policy](time-policy.md) table, "Signer chain, timestamped".

### TIME-004: A timestamp before the signer's notBefore is rejected

A timestamp claiming a signing time before a non-lifetime signer's notBefore
is `certificate_not_yet_valid`, as for a lifetime signer (TIME-002).

- **Status:** Decided
- **Decided by:** written choice, PR #43 (SEC-09); kept as policy in SEC-14
- **Pins:** acceptance
- **Sources:**
  - Written argument: the same consistency check as TIME-002.

### TIME-005: A timestamp after the validation time is rejected

A `signing_time` equal to the validation time is accepted; any nonzero
fraction in that second, or a later second, is `timestamp_in_future`.

- **Status:** Decided
- **Decided by:** written argument
- **Pins:** acceptance
- **Sources:**
  - A timestamp from the future cannot be evidence of when the signature
    existed; the validation time is the latest instant rssig can vouch for.

### TIME-006: A fractional timestamp is compared exactly with validity

A fractional timestamp is checked at its whole second, then the selected leaf
and intermediates must have `notAfter > signing_time`: `notAfter` itself is
valid and `notAfter + .5` is `certificate_expired`; `notBefore + .5` is valid
and `notBefore - 1 + .5` is `certificate_not_yet_valid`. Exact decimal digits
are kept; no floating point is used.

- **Status:** Decided
- **Decided by:** written choice, PR #43 (SEC-09)
- **Pins:** acceptance
- **Sources:**
  - RFC 5280 section 4.1.2.5 (validity is inclusive of notBefore and
    notAfter), applied to RFC 3161 `genTime` fractions.
- **Note:** the check runs after path selection, so it does not consider an
  alternative issuer with a later notAfter (open in SEC-14).

### TIME-007: An untimestamped signer is validated at the validation time, inclusive at whole seconds

- **Status:** Decided
- **Decided by:** written argument
- **Pins:** acceptance
- **Sources:**
  - RFC 5280 section 4.1.2.5: notBefore and notAfter are inclusive.

### TIME-008: A lifetime path is still revocation-checked at the validation time

Lifetime signing changes only the validity time. A path through an
intermediate needs that intermediate's CRL (otherwise `revocation_unknown`),
and a revoked leaf is rejected even when another path would verify. Historical
(signing-time) revocation status is not modeled.

- **Status:** Decided
- **Decided by:** written choice, PR #43; kept as policy in SEC-14
- **Pins:** acceptance
- **Sources:**
  - AGENTS.md, "Fail closed" for unknown revocation status; CRL-001.

## Tier 2: availability

### TIME-009: Path building skips an intermediate issued after the signing time

The signing-time check of intermediates runs inside path building, so a
rolled-over intermediate with the same subject and key that was issued after
signing is rejected as a candidate and another valid issuer is used.

- **Status:** Decided
- **Decided by:** review fix, PR #43 (the first post-selection check rejected
  `time-009-lifetime-intermediate-rollover`)
- **Pins:** acceptance
- **Sources:**
  - Written argument: a valid embedded issuer must not be lost because
    another candidate was tried first.

## Tier 3: result diagnostics

### TIME-010: The signing-time rejection ranks as a validity error

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

### TIME-011: A revocation on the same path is reported before the signing-time check

The signing-time check runs after webpki's own checks of a candidate path, so
a revocation on that path is reported instead. Both outcomes reject.

- **Status:** Decided
- **Decided by:** written choice, kept as policy in SEC-14
- **Pins:** diagnostics
- **Sources:**
  - Written argument in [time policy](time-policy.md#lifetime-signing).

### TIME-012: Lifetime-signing validity outranks revocation on another path

Across candidate paths, a CA issued after the lifetime signing time on one path outranks a revocation on another; both reject.

- **Status:** Decided
- **Decided by:** written choice (the references disagree and neither has lifetime signing); kept as policy in SEC-14
- **Pins:** diagnostics
- **Sources:**
  - OpenSSL builds one chain and checks revocation before validity.
  - Bouncy Castle tries every path and checks validity before revocation per certificate.

### TIME-013: CRL freshness is reported before the signing-time check

The TSA chain is verified before the signer against the same store-wide CRLs,
so an expired or not-yet-valid CRL is reported first, with or without the
lifetime EKU. Both outcomes reject.

- **Status:** Decided
- **Decided by:** written choice, kept as policy in SEC-14
- **Pins:** diagnostics
- **Sources:**
  - Written argument in [time policy](time-policy.md#lifetime-signing).

### TIME-014: Failure details name the chain certificate that failed

`details.certificate` names the certificate that failed the signing-time or
fractional-expiry check, an intermediate when it is the cause. A signing-time
message and certificate are attached only when the surviving webpki error
carries that certificate's notBefore at the signing time; otherwise the
generic chain error is reported. Successful reports set
`TrustReport.lifetime_signing` and `validation_time`.

- **Status:** Decided
- **Decided by:** written choice, kept as policy in SEC-14
- **Pins:** diagnostics
- **Sources:**
  - Written argument: a change in webpki's search order must not name the
    wrong certificate.
- **Note:** pinned by named tests in `tests/cli/time_policy.rs`; no spec case
  names this entry yet.

## Candidate rules

Unnumbered. `tests/decision-claims.json` assigns these cases here until they name an entry.

- `attach`: cases that pin an existing TIME entry but do not name it yet: the pre-SEC-09 time cases (TEST-21) and every format's expired-with-timestamp and validity cases.
