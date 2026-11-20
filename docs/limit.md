# Limit decisions

**Skeleton.** This index is not numbered yet. It answers one question: **When does rssig stop work?** Its format and the rule for placing a decision are in [Decision indexes](decisions.md#which-index).

## Scope

Aggregate verification budgets, nesting depth, host input and report size, batch counts, the number of CRLs.

## Boundaries

- Retrieval limits (URIs per certificate, the built-in source's bounds) stay `CRL-`; the count of loaded CRLs, supplied and fetched together, is here.

## Sources

- [verification-budgets.md](verification-budgets.md) (SEC-02)
- [host-limits.md](host-limits.md) (SEC-03)

## Order

When numbered, entries follow the tiers of [CRL decisions](crl.md#order): fail-open, availability, result diagnostics.

## Candidate rules

Unnumbered. `tests/decision-claims.json` assigns every unindexed case to one of these keys; numbering them is the task for this index in `TODO.md`.

- `budgets`: per-file budgets bound entries, width and nesting depth (eight, for verification and `parse` alike); exceeding one is `resource_limit_exceeded` or a fail-closed parse error.
- `host-input`: input, report and batch sizes are bounded by the host.
- `crl-count`: the number of supplied and fetched CRLs is bounded.
