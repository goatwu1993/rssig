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
- `causes`: a per-file verification error's `causes` are the messages of every context the error passed through, outermost first, then the causes an earlier conversion gave the typed error, or its own message when none did. Converting the error again at a public `verify_*` boundary keeps those causes instead of reducing them to the message. `message` stays the typed error's own, so `causes` may begin with contexts it does not contain. The contexts above a parser error come first in the same way, then the parser error's own causes; the summary of the parser error that decides, such as `invalid PE`, is not a cause. With no typed error in the chain, `causes` are every message in the chain and `message` joins them with `: `. An error built directly rather than converted, such as `read_failed` or a `crl_retrieval.failures` entry for a denied request or an undecodable body, has no causes.
- `typed-layer`: a per-file verification error takes its code, stage, message and details from the outermost typed layer of its error chain, the error itself or another error's source: a `VerificationError` as it is, a parser error with the code and stage of its kind and, for an unsupported RDP signscope entry, `details.scope` (as [RDP decisions](rdp.md) report it). A parser error's kind is the default for its own chain: a typed layer in that chain decides instead, as `parse::Error::new` already lets a nested parser error's kind stand. The code and stage of the step that failed apply only to a chain with no typed layer. A typed value attached as an anyhow context or message is not a chain entry, so this rule does not see it; every one the engine and the CLI attach is text, which the [repository check](testing.md#repository-checks) `no_code_attaches_a_typed_error_as_an_anyhow_context` keeps true. Reporting the more specific code is a diagnostics choice, Observed until this index is numbered. No committed fixture reaches a parser error that is another error's source, so the unit tests `a_parser_error_that_is_another_errors_source_keeps_its_code_and_scope` and `a_typed_layer_inside_a_parser_errors_chain_decides` in `engine/src/domain.rs` pin it.
