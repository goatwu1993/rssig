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

- `arguments`: unknown subcommands, retired commands, usage errors such as a missing FILES argument, and conflicting or missing required verification options (such as no revocation choice) are argument errors (exit 2).
- `help-version`: help and version print plain text on stdout (exit 0).
- `exit-codes`: mixed per-file results give exit 1 with one JSON document.
- `read-errors`: an input file that cannot be read is reported as plain text or per-file `read_failed`.
- `causes`: a per-file verification error's `causes` are the messages of every context the error passed through, outermost first, then the causes an earlier conversion gave the typed error, or its own message when none did. Converting the error again at a public `verify_*` boundary keeps those causes instead of reducing them to the message. `message` stays the typed error's own, so `causes` may begin with contexts it does not contain. A parser error reports its own causes without the contexts above it (CLI-T005). With no typed error in the chain, `causes` are every message in the chain and `message` joins them with `: `. An error built directly rather than converted, such as `read_failed` or a `crl_retrieval.failures` entry for a denied request or an undecodable body, has no causes.
