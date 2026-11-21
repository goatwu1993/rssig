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

Unnumbered. `tests/decision-claims.json` assigns every unindexed case to one of these keys; numbering them is the task for this index in `TODO.md`. What each key means, and which part of it another index owns, is in [Format indexes](decisions.md#format-indexes).

- `hash`: the NAVX content hash must match what was signed (`navx_digest_mismatch`).
- `structure`: a malformed or unsupported envelope fails closed (`invalid_navx`).
- `support`: supported layouts and signers verify, including signatures from independent producers (jsign, nfedera); timestamp controls are TSA-007.
- `unsigned`: a file whose content runs to its end, with no signature after it, is reported as `unsigned` at `navx`.
- `sip`: the signed content's SIP identity (type, UUID, version, reserved fields) and framing must be this format's; anything else is `malformed_cms`.
