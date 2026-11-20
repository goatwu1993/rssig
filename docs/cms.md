# CMS structure decisions

**Skeleton.** This index is not numbered yet. It answers one question: **Is the CMS SignedData and its signer binding acceptable?** Its format and the rule for placing a decision are in [Decision indexes](decisions.md#which-index).

## Scope

SignedData and SignerInfo structure, signer identification and selection, signer signature, content and attribute digests, CertificateChoices, nested signatures.

## Boundaries

- Algorithm acceptance is `ALG-`.
- Timestamp tokens are `TSA-`, except CMS structure inside a token, such as CertificateChoices, which is here; TSA-004's duplicated-attribute clause moves here (TEST-15).
- Nesting depth limits are `LIMIT-`.
- A format's own embedding of the CMS blob is that format's index.

## Sources

- [cms-security.md](cms-security.md) (SEC-04, SEC-05)

## Order

When numbered, entries follow the tiers of [CRL decisions](crl.md#order): fail-open, availability, result diagnostics.

## Candidate rules

Unnumbered. `tests/decision-claims.json` assigns every unindexed case to one of these keys; numbering them is the task for this index in `TODO.md`.

- `structure`: SignedData and SignerInfo must have the canonical structure and versions, with no trailing data; anything else fails closed (`malformed_cms`, or `invalid_signature` for a SignerInfo field such as its version), in every format.
- `signer-signature`: the signer's signature must verify with the signer certificate's key and declared algorithm (`invalid_signature` at `cms`), in every format.
- `signer-identification`: the signer certificate is identified by issuer and serial (SignerInfo version 1); a subjectKeyIdentifier identity is inspectable but unsupported for verification, and an ambiguous or missing match fails.
- `content-digest`: the message digest attribute must match the content.
- `nested`: nested signatures are verified like the primary one, in every format.
- `content-binding`: the encapsulated content type and the digest-algorithm set must match the signer (`invalid_signature`).
- `attributes`: signed attributes must be DER-ordered as signed, and an attribute OID of any length is decoded without bypassing the signature check (including unsigned attributes).
- `certificate-choices`: RFC 5652 CertificateChoices are handled without bypassing signature checks.
- `support`: a well-formed SignedData verifies.
