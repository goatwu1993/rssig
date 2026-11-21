# WSH format decisions

**Skeleton.** This index is not numbered yet. It answers one question: **How is a WSH file parsed and hashed for signing?** Its format and the rule for placing a decision are in [Decision indexes](decisions.md#which-index).

## Scope

Windows Script Host scripts: comment styles, encodings, blocks, script hash.

## Boundaries

- A rule that is the same in every format stays in its subject index (`CMS-`, `ALG-`, `TSA-`, `TIME-`, `CRL-`, `PATH-`, `POLICY-`); this index links to it.

## Sources

- [wsh.md](wsh.md)

## Order

When numbered, entries follow the tiers of [CRL decisions](crl.md#order): fail-open, availability, result diagnostics.

## Candidate rules

Unnumbered. `tests/decision-claims.json` assigns every unindexed case to one of these keys; numbering them is the task for this index in `TODO.md`. What each key means, and which part of it another index owns, is in [Format indexes](decisions.md#format-indexes).

- `hash`: the script hash must match what was signed (`script_digest_mismatch`).
- `structure`: a malformed or unsupported script or signature block, including mixed signature styles, fails closed (`invalid_wsh`).
- `support`: supported layouts and signers verify, including signatures from independent producers (jsign, nfedera); timestamp controls are TSA-007.
- `unsigned`: a script without a signature block is reported as `unsigned` at `wsh`.
- `sip`: the signed content's SIP identity (type, UUID, version, reserved fields) and framing must be this format's; anything else is `malformed_cms`.
