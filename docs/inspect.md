# Inspection decisions

**Skeleton.** This index is not numbered yet. It answers one question: **What does `parse` report about a file?** Its format and the rule for placing a decision are in [Decision indexes](decisions.md#which-index).

## Scope

Inspection output: views of PE and CMS structures, preserved DER for unfamiliar values, recursion into nested signatures and timestamps.

## Boundaries

- Verification results are other indexes; inspection never claims trust.
- The nesting depth limit is `LIMIT-`, shared with verification.

## Sources

- [library.md](library.md)

## Order

When numbered, entries follow the tiers of [CRL decisions](crl.md#order): fail-open, availability, result diagnostics.

## Candidate rules

Unnumbered. `tests/decision-claims.json` assigns every unindexed case to one of these keys; numbering them is the task for this index in `TODO.md`.

- `views`: inspection reports structure and preserves unfamiliar DER without verifying it.
- `malformed`: malformed input is reported with a typed error.
- `recursion`: inspection recurses into nested signatures, timestamps and countersignatures and reports each; how deep it may go is `LIMIT-` `budgets`.
