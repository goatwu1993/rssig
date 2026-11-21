# PE format decisions

**Skeleton.** This index is not numbered yet. It answers one question: **How is a PE file parsed and hashed for signing?** Its format and the rule for placing a decision are in [Decision indexes](decisions.md#which-index).

## Scope

PE images: image hash, page hashes, checksum, certificate table.

## Boundaries

- A rule that is the same in every format stays in its subject index (`CMS-`, `ALG-`, `TSA-`, `TIME-`, `CRL-`, `PATH-`, `POLICY-`); this index links to it.

## Sources

- [boundaries.md](boundaries.md)

## Order

When numbered, entries follow the tiers of [CRL decisions](crl.md#order): fail-open, availability, result diagnostics.

## Candidate rules

Unnumbered. `tests/decision-claims.json` assigns every unindexed case to one of these keys; numbering them is the task for this index in `TODO.md`. What each key means, and which part of it another index owns, is in [Format indexes](decisions.md#format-indexes).

- `hash`: the Authenticode image digest (checksum and certificate table excluded) and any page hashes must match what was signed (`image_digest_mismatch`, `page_hash_mismatch`).
- `structure`: a malformed or unsupported image or certificate table fails closed (`invalid_pe`, `invalid_certificate_table`).
- `support`: supported PE32 and PE32+ layouts, page hashes and checksum exclusion verify; timestamp controls are TSA-007.
- `unsigned`: an image whose certificate-table directory entry is empty is reported as `unsigned` at `pe`.
