# CMS structure decisions

Numbered decisions that answer one question: **is the CMS SignedData and its
signer binding acceptable?** SignedData and SignerInfo structure, signer
identification, the signer's signature, content and attribute binding,
CertificateChoices and nested signatures. The entry format is defined in
[Decision indexes](decisions.md); the profile and its limits are explained in
[CMS structure and signature binding](cms-security.md), and the history is in
SEC-04 (PR #37) and SEC-05 (PR #38) ([done](tasks/done.md)).

## Boundaries

- Algorithm acceptance is `ALG-`; where an algorithm identifier sits in CMS
  and whether it agrees with the signer key is here (CMS-002).
- Timestamp tokens are `TSA-`, except CMS structure inside a token, such as
  CertificateChoices (CMS-012) and duplicated unsigned attributes (CMS-009),
  which is here.
- Nesting depth limits are `LIMIT-`.
- A format's own embedding of the CMS blob is that format's index.
- Whether every signature of a file must verify, and which failure is
  reported first, is the open task SEC-12; CMS-013 pins only that a nested
  signature is checked like the primary one.

## Order

Entries are numbered from most to least important, in the tiers used by
[CRL decisions](crl.md#order); within a tier, Decided entries come before
Observed ones. A new entry takes the next free number.

1. **Fail-open:** a broken rule could accept a signature that does not bind
   the signer's key to the signed content, or accept a structure outside the
   supported profile.
2. **Availability:** a broken rule would reject a well-formed signature.
3. **Result diagnostics:** the error code, stage or details a consumer
   matches; both outcomes reject.

## Index

| ID | Decision | Status | Pins |
|---|---|---|---|
| [CMS-001](#cms-001-the-signers-signature-must-verify-with-the-signer-certificates-key) | The signer's signature must verify with the signer certificate's key | Decided | acceptance |
| [CMS-002](#cms-002-the-signature-algorithm-must-agree-with-the-signer-key-and-take-no-forbidden-parameters) | The signature algorithm must agree with the signer key and take no forbidden parameters | Decided | acceptance |
| [CMS-003](#cms-003-the-signer-certificate-is-matched-by-exact-issuer-and-serial) | The signer certificate is matched by exact issuer and serial | Decided | acceptance |
| [CMS-004](#cms-004-distinct-certificates-matching-the-signer-identifier-are-rejected) | Distinct certificates matching the signer identifier are rejected | Decided | acceptance |
| [CMS-005](#cms-005-the-messagedigest-attribute-must-match-the-content) | The messageDigest attribute must match the content | Decided | acceptance |
| [CMS-006](#cms-006-the-signed-contenttype-must-match-the-encapsulated-content) | The signed contentType must match the encapsulated content | Decided | acceptance |
| [CMS-007](#cms-007-the-signers-digest-algorithm-must-be-listed-in-digestalgorithms) | The signer's digest algorithm must be listed in digestAlgorithms | Decided | acceptance |
| [CMS-008](#cms-008-signed-attributes-are-verified-exactly-as-encoded-in-canonical-order) | Signed attributes are verified exactly as encoded, in canonical order | Decided | acceptance |
| [CMS-009](#cms-009-an-attribute-oid-appears-at-most-once-in-a-signerinfo) | An attribute OID appears at most once in a SignerInfo | Decided | acceptance |
| [CMS-010](#cms-010-signeddata-and-signerinfo-must-be-well-formed-with-supported-versions) | SignedData and SignerInfo must be well-formed with supported versions | Decided | acceptance |
| [CMS-011](#cms-011-unknown-attributes-stay-opaque-and-their-oids-must-be-minimally-encoded) | Unknown attributes stay opaque, and their OIDs must be minimally encoded | Decided | acceptance |
| [CMS-012](#cms-012-non-x509-certificatechoices-stay-opaque-and-cannot-supply-a-signer) | Non-X.509 CertificateChoices stay opaque and cannot supply a signer | Decided | acceptance |
| [CMS-013](#cms-013-a-nested-signature-is-verified-like-the-primary-one) | A nested signature is verified like the primary one | Observed | acceptance |
| [CMS-014](#cms-014-legacy-version-1-signeddata-and-signerinfo-verify) | Legacy version 1 SignedData and SignerInfo verify | Decided | acceptance |
| [CMS-015](#cms-015-an-ambiguous-signer-reports-the-number-of-matching-certificates) | An ambiguous signer reports the number of matching certificates | Decided | diagnostics |
| [CMS-016](#cms-016-envelope-defects-are-malformed_cms-signerinfo-defects-invalid_signature) | Envelope defects are malformed_cms, SignerInfo defects invalid_signature | Observed | diagnostics |

## Tier 1: fail-open

### CMS-001: The signer's signature must verify with the signer certificate's key

The SignerInfo signature must verify, under the declared algorithm, with the
public key of the selected signer certificate over the exact signed bytes
(the signed attributes with only their implicit tag replaced by SET). A
corrupted signature, or a signer certificate carrying a different key, is
`invalid_signature` at `cms`, in every format: PE, MSI and MSP, CAB, NAVX,
PowerShell and PowerShell XML, WSH, RDP, and MSIX/AppX packages and bundle
members.

- **Status:** Decided
- **Decided by:** written argument, PR #37 (SEC-04)
- **Pins:** acceptance
- **Sources:**
  - RFC 5652 sections 5.4 and 5.6: the signature is computed over the DER
    SET encoding of signedAttrs and verified with the signer's public key.
  - [cms-security.md](cms-security.md), rows "Signed bytes" and "Signature
    parameters".
  - relic `lib/pkcs7/verify.go:116-161` (`SignerInfo.Verify`) and jsign 7.6
    (cf5d2ce) `verify/SignatureIntegrityRule.java:38-46` (Bouncy Castle
    `SignerInformation.verify`) reject the same faults.
- **Unit tests:** `cms_structure_fixtures_preserve_signature_math` in
  `src/tests/cms_audit.rs` proves each CMS structure fixture is signed
  correctly, so its failure comes from the targeted check.

### CMS-002: The signature algorithm must agree with the signer key and take no forbidden parameters

The SignerInfo signature algorithm must match the signer certificate's key
type and the signer's digest algorithm. Supported RSA identifiers accept
absent or NULL parameters; supported ECDSA identifiers require absent
parameters. A mathematically valid signature under a mismatched or wrongly
parameterized identifier is `invalid_signature` at `cms`.

- **Status:** Decided
- **Decided by:** written choice, PR #37 (SEC-04)
- **Pins:** acceptance
- **Sources:**
  - RFC 5758 section 3.2: the ECDSA with SHA-2 identifiers MUST omit the
    parameters field; RFC 5753 for ECDSA in CMS.
  - [cms-security.md](cms-security.md), row "Signature parameters".

### CMS-003: The signer certificate is matched by exact issuer and serial

The signer is identified by IssuerAndSerialNumber (SignerInfo version 1),
compared with the embedded candidates by canonical DER issuer and serial. A
SignerInfo whose issuer or serial matches no embedded certificate, or a
SignedData without the signer certificate, is `invalid_signature` at `cms`.
A subjectKeyIdentifier identity is inspectable but not supported for
verification. The same rule applies to RFC 3161 tokens, PKCS#9
countersignatures and RDP signatures.

- **Status:** Decided
- **Decided by:** written choice, PR #37 (SEC-04) and PR #38 (SEC-05)
- **Pins:** acceptance
- **Sources:**
  - RFC 5652 section 5.3: `sid` identifies the signer's certificate.
  - [cms-security.md](cms-security.md), row "SignerInfo version and
    identity" and "Signer certificate selection".
  - relic `lib/pkcs7/verify.go:94-103` (`FindCertificate`) and jsign 7.6
    `verify/SignatureVerifier.java:97-101` fail when no certificate matches.

### CMS-004: Distinct certificates matching the signer identifier are rejected

When more than one distinct embedded certificate matches the signer's issuer
and serial, verification fails with `ambiguous_signer_certificate` at `cms`
before the signature or any path is checked, in either order and even when
the candidates share the public key or one of them is trusted. Byte-identical
duplicates are one candidate, and certificate order never changes the result
or the selected signer. Embedded duplicates do not supply trust.

- **Status:** Decided
- **Decided by:** written choice, PR #38 (SEC-05)
- **Pins:** acceptance
- **Sources:**
  - [cms-security.md](cms-security.md#signer-certificate-selection-sec-05).
  - relic `lib/pkcs7/verify.go:94-103` and jsign 7.6
    `verify/SignatureVerifier.java:98-105` take the first match; rssig
    deliberately does not, so that certificate order cannot select a
    different signer.
- **Unit tests:** `cms_signer_selection_shared_timestamp_and_detached` and
  `cms_signer_embedded_duplicates_do_not_supply_trust` in
  `src/tests/signer_selection.rs` cover RFC 3161, countersignature and RDP
  selection.

### CMS-005: The messageDigest attribute must match the content

Exactly one signed messageDigest value is required and must equal the
computed digest of the encapsulated content; otherwise the result is
`content_digest_mismatch` at `cms`. A countersignature's digest of the
parent signature is TSA-001.

- **Status:** Decided
- **Decided by:** written argument, PR #37 (SEC-04)
- **Pins:** acceptance
- **Sources:**
  - RFC 5652 sections 5.4 and 11.2.
  - [cms-security.md](cms-security.md), row "Content binding".
  - relic `lib/pkcs7/verify.go:128-134`.

### CMS-006: The signed contentType must match the encapsulated content

The signed contentType attribute must equal the encapsulated content type
(`invalid_signature` at `cms`); a countersignature must omit it.

- **Status:** Decided
- **Decided by:** written argument, PR #37 (SEC-04)
- **Pins:** acceptance
- **Sources:**
  - RFC 5652 sections 5.3 and 11.1: contentType must be present in signed
    attributes and match eContentType; countersignatures carry none.
  - [cms-security.md](cms-security.md), row "Content binding".

### CMS-007: The signer's digest algorithm must be listed in digestAlgorithms

For attached and detached signatures, the SignerInfo digest algorithm must
appear in SignedData.digestAlgorithms (`invalid_signature` at `cms`).
Countersignatures have no enclosing set to check.

- **Status:** Decided
- **Decided by:** written choice, PR #37 (SEC-04)
- **Pins:** acceptance
- **Sources:**
  - RFC 5652 section 5.1: digestAlgorithms lists the digest algorithms of all
    signers; RFC 5652 does not require a verifier to check it, so this is a
    written choice to reject an inconsistent envelope.
  - [cms-security.md](cms-security.md), row "Digest algorithms".

### CMS-008: Signed attributes are verified exactly as encoded, in canonical order

Signed attributes and each attribute's value SET must be in DER
(lexicographic) order as signed. Verification never sorts or re-encodes them,
so a correctly signed but non-canonical set is `invalid_signature` at `cms`.

- **Status:** Decided
- **Decided by:** written choice, PR #37 (SEC-04)
- **Pins:** acceptance
- **Sources:**
  - RFC 5652 section 5.3: SignedAttributes MUST be DER encoded; X.690
    section 11.6 orders SET OF components.
  - [cms-security.md](cms-security.md), rows "Signed attribute sets" and
    "Signed bytes".

### CMS-009: An attribute OID appears at most once in a SignerInfo

A duplicated attribute OID, in signed or unsigned attributes, and an
attribute with an empty value SET are `invalid_signature` at `cms`. This
includes two RFC 3161 timestamp attributes or two countersignature
attributes on one signer, which are rejected here before the timestamp
multiplicity rule (TSA-004) is reached.

- **Status:** Decided
- **Decided by:** owner, PR #72 (moved from TSA-004); first a written
  choice in PR #37 (SEC-04) for signed attributes, extended to unsigned
  timestamp attributes in PR #42 (SEC-08)
- **Pins:** acceptance
- **Sources:**
  - RFC 5652 sections 11.1 to 11.3: contentType, messageDigest and
    signingTime must not appear more than once; extending this to every
    attribute OID is a written choice.
  - Written argument (as TSA-004): if an unsigned attribute may repeat, an
    attacker who can add one chooses which copy is used.
  - [cms-security.md](cms-security.md), row "Signed attribute sets";
    [timestamp profile](timestamp-profile.md).
  - relic `lib/pkcs7/attributes.go:58-73` (`GetOne`) rejects multiple values
    for one attribute but takes the first of duplicated OIDs.
- **Unit tests:** `cms_attribute_and_integer_boundaries` in
  `src/tests/cms_audit.rs`.

### CMS-010: SignedData and SignerInfo must be well-formed with supported versions

SignedData and SignerInfo must use bounded, definite, minimal DER lengths,
consume their input completely, use the supported tags and canonical
INTEGER encodings, and carry a supported version: SignedData version 1, or 3,
4 or 5 as the envelope indicates (version 1 for detached RDP), and
SignerInfo version 1. A SignedData needs at least one and at most 64
SignerInfos. Anything else fails closed in every format: `malformed_cms` at
`cms` for the envelope (truncated or trailing data, an unsupported SignedData
version, an empty or oversized signer set), and `invalid_signature` at `cms`
for a SignerInfo field such as its version (CMS-016).

- **Status:** Decided
- **Decided by:** written choice, PR #37 (SEC-04)
- **Pins:** acceptance
- **Sources:**
  - RFC 5652 sections 5.1 and 5.3 (versions) and X.690 section 10 (DER).
  - [cms-security.md](cms-security.md), rows "SignedData version",
    "SignerInfo version and identity" and "DER framing".
  - relic `lib/pkcs7/verify.go:66-68` and jsign 7.6
    `verify/SignatureVerifier.java:90-93` reject an empty signer set.
- **Note:** the 64-signer bound is a parser bound reported as
  `malformed_cms`; budgets in general are `LIMIT-`.

### CMS-011: Unknown attributes stay opaque, and their OIDs must be minimally encoded

An unknown attribute's value is kept as opaque DER and does not affect
verification, whatever the length of its OID. Its OID must still be a valid,
minimally encoded OBJECT IDENTIFIER: a subidentifier starting with 0x80 is
`invalid_signature` at `cms`, signed or unsigned.

- **Status:** Decided
- **Decided by:** written choice, PR #24 (LIB-02) and PR #37 (SEC-04)
- **Pins:** acceptance
- **Sources:**
  - X.690 section 8.19.2: a subidentifier is encoded in the fewest octets.
  - [cms-security.md](cms-security.md), rows "Signed attribute sets" and
    "DER framing"; LIB-02 in [done](tasks/done.md).

### CMS-012: Non-X.509 CertificateChoices stay opaque and cannot supply a signer

RFC 5652 CertificateChoices other than an X.509 certificate are kept as
opaque DER in the publisher CMS and in an RFC 3161 token and never become a
signer certificate, a chain candidate or a trust anchor. A malformed choice or
an unknown choice tag fails, and an attribute certificate cannot replace a
missing signer certificate; inside a timestamp token these are
`invalid_timestamp` at `timestamp`.

- **Status:** Decided
- **Decided by:** written choice, PR #37 (SEC-04)
- **Pins:** acceptance
- **Sources:**
  - RFC 5652 section 10.2.2 (CertificateChoices).
  - [cms-security.md](cms-security.md): opaque certificate and revocation
    choices do not become trust anchors or CRL evidence.

### CMS-013: A nested signature is verified like the primary one

Every nested Authenticode signature (SpcNestedSignature) is verified with the
same CMS, signer, timestamp, path and revocation rules as the primary
signature, in every format that carries one; a nested signature that fails is
the file's result (`invalid_signature` at `cms` for a corrupted nested
signature), even when the primary one verifies.

- **Status:** Observed
- **Decided by:** —
- **Pins:** acceptance
- **Sources:**
  - Microsoft Authenticode PE format (SpcNestedSignature, OID
    1.3.6.1.4.1.311.2.4.1).
  - jsign 7.6 `SignatureUtils.java:91-112` (`getSignatures`) and
    `verify/SignatureVerifier.java:89-125` verify each nested signature
    separately.
- **Note:** SEC-12 is to decide the multi-signature semantics (all
  signatures required, ordering, first-failure precedence).

## Tier 2: availability

### CMS-014: Legacy version 1 SignedData and SignerInfo verify

A well-formed SignedData with legacy version 1, a version 1 SignerInfo and
correctly ordered unknown signed attributes verifies; rssig does not enforce
RFC 5652's version-selection algorithm on it.

- **Status:** Decided
- **Decided by:** written choice, PR #37 (SEC-04)
- **Pins:** acceptance
- **Sources:**
  - [cms-security.md](cms-security.md): legacy version 1 is retained for
    the Authenticode and historical timestamp corpus; this is a
    compatibility profile.
  - RFC 5652 section 5.1 (version selection) and RFC 2315 (PKCS#7 version 1).

## Tier 3: result diagnostics

### CMS-015: An ambiguous signer reports the number of matching certificates

The CMS-004 rejection is `ambiguous_signer_certificate` at `cms`, with
`details.matching_certificates` counting every matching entry, exact
duplicates included.

- **Status:** Decided
- **Decided by:** written choice, PR #38 (SEC-05)
- **Pins:** diagnostics
- **Sources:**
  - [cms-security.md](cms-security.md#signer-certificate-selection-sec-05).
- **Unit tests:** `cms_signer_selection_is_independent_of_certificate_order`
  in `tests/cli/signer_selection.rs`.

### CMS-016: Envelope defects are malformed_cms, SignerInfo defects invalid_signature

A defect in the SignedData envelope is `malformed_cms` at `cms`; a defect in
a SignerInfo field or its attributes (version, attribute order, duplicate or
malformed attribute OID) is `invalid_signature` at `cms`, although the
library's standalone `Attributes::parse` reports the same attribute defects
as `MalformedCms`.

- **Status:** Observed
- **Decided by:** —
- **Pins:** diagnostics
- **Sources:**
  - Current behavior; no reference library distinguishes these codes.
