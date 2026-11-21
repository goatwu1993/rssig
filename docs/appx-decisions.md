# MSIX/AppX format decisions

**Skeleton.** This index is not numbered yet. It answers one question: **How is a MSIX/AppX file parsed and hashed for signing?** Its format and the rule for placing a decision are in [Decision indexes](decisions.md#which-index).

## Scope

MSIX/AppX packages and bundles: ZIP, block map, Publisher, bundle members.

## Boundaries

- A rule that is the same in every format stays in its subject index (`CMS-`, `ALG-`, `TSA-`, `TIME-`, `CRL-`, `PATH-`, `POLICY-`); this index links to it.

## Sources

- [appx.md](appx.md)

## Order

When numbered, entries follow the tiers of [CRL decisions](crl.md#order): fail-open, availability, result diagnostics.

## Candidate rules

Unnumbered. `tests/decision-claims.json` assigns every unindexed case to one of these keys; numbering them is the task for this index in `TODO.md`. What each key means, and which part of it another index owns, is in [Format indexes](decisions.md#format-indexes).

- `hash`: the package digests and block-map hashes must match what was signed (`appx_digest_mismatch`, `block_hash_mismatch`).
- `publisher`: the package Publisher must match the signer.
- `structure`: a malformed or unsupported package, bundle or block map fails closed (`invalid_appx`).
- `support`: supported layouts and signers verify, including signatures from independent producers (jsign, nfedera); timestamp controls are TSA-007.
- `unsigned`: a package without `AppxSignature.p7x` is reported as `unsigned` at `appx`.
- `unsupported`: explicitly unsupported features are rejected, not ignored.
- `sip`: the signed content's SIP identity (type, UUID, version, reserved fields) and framing must be this format's; anything else is `malformed_cms`.
