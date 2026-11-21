# PowerShell format decisions

**Skeleton.** This index is not numbered yet. It answers one question: **How is a PowerShell file parsed and hashed for signing?** Its format and the rule for placing a decision are in [Decision indexes](decisions.md#which-index).

## Scope

PowerShell hash-comment and XML-comment scripts: encodings, signature block, script hash.

## Boundaries

- A rule that is the same in every format stays in its subject index (`CMS-`, `ALG-`, `TSA-`, `TIME-`, `CRL-`, `PATH-`, `POLICY-`); this index links to it.

## Sources

- [powershell.md](powershell.md), [powershell-xml.md](powershell-xml.md)

## Order

When numbered, entries follow the tiers of [CRL decisions](crl.md#order): fail-open, availability, result diagnostics.

## Candidate rules

Unnumbered. `tests/decision-claims.json` assigns every unindexed case to one of these keys; numbering them is the task for this index in `TODO.md`. What each key means, and which part of it another index owns, is in [Format indexes](decisions.md#format-indexes).

- `hash`: the script hash must match what was signed (`script_digest_mismatch`).
- `structure`: a malformed or unsupported script or signature block fails closed (`invalid_powershell`).
- `support`: supported layouts and signers verify, including signatures from independent producers (jsign, nfedera); timestamp controls are TSA-007.
- `unsigned`: a script without a signature block is reported as `unsigned` at `powershell`.
- `sip`: the signed content's SIP identity (type, UUID, version, reserved fields) and framing must be this format's; anything else is `malformed_cms`.
