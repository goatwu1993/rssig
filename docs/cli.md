# CLI decisions

**Skeleton.** This index is not numbered yet. It answers one question: **What does the command line accept and report?** Its format and the rule for placing a decision are in [Decision indexes](decisions.md#which-index).

## Scope

Subcommands, argument and verification-option conflicts, help and version, exit codes, read errors, problem-details output.

## Boundaries

- Trust-input errors are `TRUST-`; what `parse` reports is `INSPECT-`.

## Sources

- [library.md](library.md)
- [problems.md](problems.md)

## Order

When numbered, entries follow the tiers of [CRL decisions](crl.md#order): fail-open, availability, result diagnostics.

## Candidate rules

Unnumbered. `tests/decision-claims.json` assigns every unindexed case to one of these keys; numbering them is the task for this index in `TODO.md`.

- `arguments`: unknown subcommands, retired commands and conflicting verification options are argument errors (exit 2).
- `help-version`: help and version print plain text on stdout (exit 0).
- `exit-codes`: mixed per-file results give exit 1 with one JSON document.
- `read-errors`: a missing input is reported as plain text or per-file `read_failed`.
