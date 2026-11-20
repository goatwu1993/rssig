# Trust-loading decisions

**Skeleton.** This index is not numbered yet. It answers one question: **What becomes a configured root or CRL?** Its format and the rule for placing a decision are in [Decision indexes](decisions.md#which-index).

## Scope

Loading roots and CRLs from files and the system store: accepted encodings, duplicates, empty and malformed input, atomic failure.

## Boundaries

- How a loaded root is used is `PATH-`; how a loaded CRL is used is `CRL-`.
- Counts of loaded CRLs are `LIMIT-`.

## Sources

- [trust-loading.md](trust-loading.md) (SEC-07)

## Order

When numbered, entries follow the tiers of [CRL decisions](crl.md#order): fail-open, availability, result diagnostics.

## Candidate rules

Unnumbered. `tests/decision-claims.json` assigns every unindexed case to one of these keys; numbering them is the task for this index in `TODO.md`.

- `loading`: malformed, truncated, unsupported or mismatched root and CRL files are configuration errors (exit 2), atomically.
- `accepted-input`: PEM and DER bundles, duplicates and whitespace are accepted.
- `empty-store`: an empty trust store is reported before path building.
