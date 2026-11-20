# NAVX format decisions

**Skeleton.** This index is not numbered yet. It answers one question: **How is a NAVX file parsed and hashed for signing?** Its format and the rule for placing a decision are in [Decision indexes](decisions.md#which-index).

## Scope

NAVX packages: envelope and hash.

## Boundaries

- A rule that is the same in every format stays in its subject index (`CMS-`, `ALG-`, `TSA-`, `TIME-`, `CRL-`, `PATH-`, `POLICY-`); this index links to it.

## Sources

- [navx.md](navx.md)

## Order

When numbered, entries follow the tiers of [CRL decisions](crl.md#order): fail-open, availability, result diagnostics.

## Candidate rules

Unnumbered. `tests/decision-claims.json` assigns every unindexed case to one of these keys; numbering them is the task for this index in `TODO.md`.

- `embedded-signature`: how the signature is embedded and extracted; a broken embedding is `malformed_cms` or `invalid_signature` (may move to `CMS-` where the rule is shared).
- `hash`: the format's content hash must match what was signed.
- `structure`: a malformed or unsupported container fails closed with the format's `invalid_*` code.
- `support`: supported layouts and signers verify (trusted, independent producers, timestamps kept by the format).
- `unsigned`: a file without a signature is reported as `unsigned`.
