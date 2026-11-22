# Timestamp structure and multiplicity (TSA-T001)

The shared Authenticode/RDP verifier accepts one timestamp per signer: either
RFC 3161 (Microsoft or CMS timestamp attribute OID) or a PKCS#9 countersignature.
Multiple attribute values, mixed types, and the two RFC 3161 aliases together
are rejected, as are two attributes with the same timestamp OID (the CMS layer
accepts repeated attributes other than those of
[CMS-009](cms.md#cms-009-single-instance-attributes-occur-at-most-once-in-a-signerinfo)). All multiplicity failures use
`invalid_timestamp`, `timestamp`. There is no timestamp selection rule.
The numbered decisions behind this page, with their status and sources, are
[Timestamp token decisions](tsa.md) (`TSA-001` to `TSA-007`).

## Supported TSTInfo profile

The verifier uses the same borrowed TSTInfo structural parser as inspection:

- Version must be the canonical INTEGER 1 in verification. Inspection preserves
  other well-formed unsigned versions without claiming support or trust.
- Policy must be a DER OBJECT IDENTIFIER. Unknown policies are accepted as
  identifiers; rssig does not evaluate TSA policy documents or require a policy
  allowlist.
- Serial and nonce are canonical nonnegative DER INTEGERs. Their original DER
  is preserved by inspection. No global serial-uniqueness or request/nonce
  matching claim is made for embedded timestamps.
- MessageImprint has exactly an AlgorithmIdentifier and OCTET STRING. Existing
  digest, parameter and SHA-1 rules apply; its digest must bind the parent's exact
  signature bytes, independently of image/CMS content hashes.
- genTime is GeneralizedTime, with the existing strict calendar, UTC and exact
  fractional-decimal checks. PKCS#9 signingTime also permits canonical UTCTime.
- Optional fields have unique tags in RFC order: accuracy, ordering, nonce,
  tsa, extensions. Unknown fields and trailing fields fail closed.
- Accuracy seconds is a canonical nonnegative INTEGER; implicitly tagged
  millis/micros are canonical integers from 1 through 999, in order. Empty
  accuracy is allowed by the ASN.1 shape. Accuracy is authenticated metadata;
  it does not widen certificate validity or future-time checks. Ordering may be
  omitted (default false) or encoded as DER TRUE; explicit FALSE is noncanonical.
- Optional tsa identity and extensions are currently unsupported in verification,
  including noncritical extensions. They fail with `invalid_timestamp` at
  `timestamp` rather than being ignored. Inspection retains their framed DER
  without authenticating or interpreting it. Identity matching and extension
  rules require separately scoped work.

The field layout and accuracy bounds follow
[RFC 3161 section 2.4.2](https://www.rfc-editor.org/rfc/rfc3161.html#section-2.4.2).
This is an embedded-signature profile, not a complete RFC 3161 request/response
client: ESS signing-certificate attributes and TSA policy semantics are not
validated. It does not establish Windows policy equivalence.

## TSA and trust

Trusted verification requires a critical, exclusively timeStamping EKU and,
when KeyUsage is present, digitalSignature. These checks already existed and
apply to both timestamp kinds. Integrity-only mode authenticates the signature
and parent binding but explicitly omits certificate-path, EKU/KeyUsage and
revocation policy. Embedded TSA certificates remain untrusted candidates;
configured roots and current local CRLs determine trust. Certificate/time
boundaries and lifetime signing are documented in [validation time](validation-time.md).

## Evidence and maintenance

35 committed deterministic test-only PE fixtures have portable specification
cases and individually named in-process CLI tests. They include trusted good
RFC 3161/countersignature controls and a good optional-field control; malformed
structure, unsupported fields, duplicate/mixed timestamps, parent substitution,
malformed signingTime, and TSA EKU/KeyUsage faults have isolated counterparts.
Native assertions independently verify every parent/TSA signature and issuer
signature and the unchanged PE image hash, including malformed TSTInfo cases.
Parser tests cover accuracy integer boundaries and every truncated prefix.

Before the production change, the focused CLI suite accepted malformed version,
policy, serial, optional ordering, accuracy and unknown-field tokens, as well
as the now explicitly unsupported tsa/extensions fields. Duplicate attribute
and countersignature digest expectations were aligned with their existing typed
CMS rejection, preserving failure precedence. A corrected UTCTime-tag mutation
also pins the GeneralizedTime requirement.

Maintenance: `cargo test --locked regenerate_tsa_fixtures -- --ignored`.
Ordinary tests consume committed bytes. These synthetic fixtures extend security
invariant coverage; independent timestamp producer diversity remains TEST-T011.
