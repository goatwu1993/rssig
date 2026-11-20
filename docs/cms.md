# CMS structure decisions

**Skeleton.** This index is not numbered yet. It answers one question: **Is the CMS SignedData and its signer binding acceptable?** Its format and the rule for placing a decision are in [Decision indexes](decisions.md#which-index).

## Scope

SignedData and SignerInfo structure, signer identification and selection, signer signature, content and attribute digests, CertificateChoices, nested signatures.

## Boundaries

- Algorithm acceptance is `ALG-`.
- Timestamp tokens are `TSA-`; TSA-004's duplicated-attribute clause moves here (TEST-15).
- Nesting depth limits are `LIMIT-`.
- A format's own embedding of the CMS blob is that format's index.

## Sources

- [cms-security.md](cms-security.md) (SEC-04, SEC-05)

## Order

When numbered, entries follow the tiers of [CRL decisions](crl.md#order): fail-open, availability, result diagnostics.

## Candidate rules

Unnumbered. `tests/decision-claims.json` assigns every unindexed case to one of these keys; numbering them is the task for this index in `TODO.md`.

- `structure`: SignedData and SignerInfo must have the canonical structure and versions, with no trailing data; anything else fails closed (`malformed_cms`), in every format.
- `signer-signature`: the signer's signature must verify with the signer certificate's key and declared algorithm (`invalid_signature` at `cms`), in every format.
- `signer-identification`: the signer certificate is identified by issuer and serial (SignerInfo version 1); a subjectKeyIdentifier identity is inspectable but unsupported for verification, and an ambiguous or missing match fails.
- `content-digest`: the message digest attribute must match the content.
- `nested`: nested signatures are verified like the primary one, in every format.
- `attributes`: signed attributes must be well formed (long OIDs and encodings).
- `certificate-choices`: RFC 5652 CertificateChoices are handled without bypassing signature checks.
- `support`: a well-formed SignedData verifies.
