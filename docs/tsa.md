# Timestamp decisions

Numbered decisions behind rssig's timestamp handling: what an RFC 3161 token
or PKCS#9 countersignature must contain, bind and be signed by. The entry
format is defined in [Decision indexes](decisions.md); the profile and its
limits are explained in [timestamp policy](timestamp-policy.md), and the
history in SEC-08 ([done](tasks/done.md), PR #42). When a timestamp's time is
used, and how it meets certificate validity, are [time decisions](time.md).

## Order

Entries are numbered from most to least important, in the tiers used by
[CRL decisions](crl.md#order); within a tier, Decided entries come before
Observed ones. A new entry takes the next free number.

1. **Fail-open:** a broken rule could let a timestamp vouch for a signature
   it does not cover, or accept a token outside the supported profile.
2. **Availability:** a broken rule would reject a valid timestamp.

## Index

| ID | Decision | Status | Pins |
|---|---|---|---|
| [TSA-001](#tsa-001-a-timestamp-must-bind-the-parents-exact-signature) | A timestamp must bind the parent's exact signature | Decided | acceptance |
| [TSA-002](#tsa-002-the-tsas-signature-must-verify) | The TSA's signature must verify | Decided | acceptance |
| [TSA-003](#tsa-003-the-tsa-certificate-needs-a-critical-exclusive-timestamping-eku) | The TSA certificate needs a critical, exclusive timeStamping EKU | Decided | acceptance |
| [TSA-004](#tsa-004-a-signer-has-at-most-one-timestamp) | A signer has at most one timestamp | Decided | acceptance |
| [TSA-005](#tsa-005-tstinfo-must-follow-the-rfc-3161-profile-exactly) | TSTInfo must follow the RFC 3161 profile exactly | Decided | acceptance |
| [TSA-006](#tsa-006-tsa-identity-and-tstinfo-extensions-are-rejected) | TSA identity and TSTInfo extensions are rejected | Decided | acceptance |
| [TSA-007](#tsa-007-a-well-formed-timestamp-within-the-profile-verifies) | A well-formed timestamp within the profile verifies | Decided | acceptance |

## Tier 1: fail-open

### TSA-001: A timestamp must bind the parent's exact signature

An RFC 3161 token's messageImprint must be the digest of the parent signer's
exact signature bytes (`timestamp_imprint_mismatch` at `timestamp`), and a
PKCS#9 countersignature's message digest must match them
(`content_digest_mismatch` at `cms`). The binding is checked independently of
the image or content hashes, in every format.

- **Status:** Decided
- **Decided by:** written argument, PR #42 (SEC-08)
- **Pins:** acceptance
- **Sources:**
  - RFC 3161 section 2.4.2 (messageImprint) and the Authenticode convention
    of timestamping the signature value.
  - RFC 5652 section 11.4: a countersignature's message-digest covers the
    signature value of the signerInfo it countersigns.

### TSA-002: The TSA's signature must verify

A token or countersignature whose TSA signature does not verify is
`invalid_timestamp` at `timestamp`.

- **Status:** Decided
- **Decided by:** written argument
- **Pins:** acceptance
- **Sources:**
  - RFC 5652 section 5.6 (signature verification) and RFC 3161 section 2.4.2.

### TSA-003: The TSA certificate needs a critical, exclusive timeStamping EKU

In trusted verification the TSA certificate's ExtendedKeyUsage must be
critical and contain only timeStamping (`invalid_eku` at `timestamp`), and a
present KeyUsage must include digitalSignature (`invalid_key_usage`). This
applies to RFC 3161 tokens and countersignatures alike; integrity-only mode
omits it explicitly.

- **Status:** Decided
- **Decided by:** written argument (RFC 3161), PR #42 (SEC-08)
- **Pins:** acceptance
- **Sources:**
  - RFC 3161 section 2.3: the TSA's certificate must contain exactly one
    extended key usage, id-kp-timeStamping, and that extension must be
    critical.
  - RFC 5280 section 4.2.1.3 for digitalSignature.

### TSA-004: A signer has at most one timestamp

Multiple attribute values, an RFC 3161 token beside a countersignature in
either order, and the two RFC 3161 attribute aliases together are
`invalid_timestamp`. A duplicated attribute OID is rejected earlier by CMS
attribute validation (`invalid_signature` at `cms`). There is no selection
policy.

- **Status:** Decided
- **Decided by:** written choice, PR #42 (SEC-08): failing closed instead of
  choosing a timestamp
- **Pins:** acceptance
- **Sources:**
  - Written argument: with more than one candidate time, any selection rule
    lets an attacker who can add an unsigned attribute pick the time used.

### TSA-005: TSTInfo must follow the RFC 3161 profile exactly

Verification requires version 1, a DER policy OID, canonical nonnegative
serial and nonce, GeneralizedTime with strict calendar, UTC and exact
fractional digits (PKCS#9 signingTime also allows canonical UTCTime),
optional fields in RFC order without duplicates or unknown tags, accuracy
millis and micros from 1 through 999 in order, and ordering omitted or DER
TRUE. Anything else is `invalid_timestamp` at `timestamp`.

- **Status:** Decided
- **Decided by:** written argument, PR #42 (SEC-08); before it, such tokens
  were accepted
- **Pins:** acceptance
- **Sources:**
  - RFC 3161 section 2.4.2 (TSTInfo fields and accuracy bounds).
  - X.690 DER rules for canonical encodings.

### TSA-006: TSA identity and TSTInfo extensions are rejected

The optional `tsa` field and `extensions`, even noncritical ones, are
`invalid_timestamp` in verification instead of being ignored. Inspection keeps
their framed DER without authenticating or interpreting it.

- **Status:** Decided
- **Decided by:** written choice, PR #42 (SEC-08)
- **Pins:** acceptance
- **Sources:**
  - Written argument: identity matching and extension policy are not
    implemented, so accepting these fields would vouch for content rssig has
    not evaluated.

## Tier 2: availability

### TSA-007: A well-formed timestamp within the profile verifies

Trusted RFC 3161 tokens and countersignatures verify, including tokens with
every optional field the profile allows. Unknown policy OIDs are accepted as
identifiers; no policy allowlist is applied.

- **Status:** Decided
- **Decided by:** written argument, PR #42 (SEC-08)
- **Pins:** acceptance
- **Sources:**
  - RFC 3161 section 2.4.2; TSA policy documents are out of scope (see
    [timestamp policy](timestamp-policy.md)).
