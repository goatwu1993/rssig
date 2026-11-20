# MSI and MSP format decisions

**Skeleton.** This index is not numbered yet. It answers one question: **How is a MSI and MSP file parsed and hashed for signing?** Its format and the rule for placing a decision are in [Decision indexes](decisions.md#which-index).

## Scope

MSI and MSP packages: CFB streams, package and extended hashes.

## Boundaries

- A rule that is the same in every format stays in its subject index (`CMS-`, `ALG-`, `TSA-`, `TIME-`, `CRL-`, `PATH-`, `POLICY-`); this index links to it.

## Sources

- [msi.md](msi.md)

## Order

When numbered, entries follow the tiers of [CRL decisions](crl.md#order): fail-open, availability, result diagnostics.

## Candidate rules

Unnumbered. `tests/decision-claims.json` assigns every unindexed case to one of these keys; numbering them is the task for this index in `TODO.md`.

- `extended`: the extended hash over storage and stream metadata (names, sizes, times, flags, CLSIDs) must match (`extended_digest_mismatch`).
- `hash`: the package hash over streams and storages must match what was signed (`package_digest_mismatch`).
- `structure`: a malformed or unsupported container fails closed with the format's `invalid_*` code.
- `support`: supported layouts and signers verify, including signatures from independent producers (jsign, nfedera); timestamp controls are TSA-007.
- `unsigned`: a file without a signature is reported as `unsigned`.
- `sip`: the signed content's SIP identity (type, UUID, version, reserved fields) and framing must be this format's; anything else is `malformed_cms`.
- `embedded-signature`: how the format embeds the CMS blob (an empty signature stream, an attached instead of detached CMS, required signed attributes).
