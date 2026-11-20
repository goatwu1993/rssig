# RDP format decisions

**Skeleton.** This index is not numbered yet. It answers one question: **How is a RDP file parsed and hashed for signing?** Its format and the rule for placing a decision are in [Decision indexes](decisions.md#which-index).

## Scope

RDP signed settings: canonical settings, scope, EKU rule.

## Boundaries

- A rule that is the same in every format stays in its subject index (`CMS-`, `ALG-`, `TSA-`, `TIME-`, `CRL-`, `PATH-`, `POLICY-`); this index links to it.

## Sources

- [rdp.md](rdp.md)

## Order

When numbered, entries follow the tiers of [CRL decisions](crl.md#order): fail-open, availability, result diagnostics.

## Candidate rules

Unnumbered. `tests/decision-claims.json` assigns every unindexed case to one of these keys; numbering them is the task for this index in `TODO.md`.

- `eku`: the format's signer EKU rule.
- `hash`: the format's content hash must match what was signed.
- `structure`: a malformed or unsupported container fails closed with the format's `invalid_*` code.
- `support`: supported layouts and signers verify, including signatures from independent producers (jsign, nfedera); timestamp controls are TSA-007.
- `unsigned`: a file without a signature is reported as `unsigned`.
- `unsupported`: explicitly unsupported features are rejected, not ignored.
- `embedded-signature`: how the format embeds the CMS blob (an empty signature stream, an attached instead of detached CMS, required signed attributes).
