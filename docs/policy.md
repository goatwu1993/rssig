# Verification-mode decisions

**Skeleton.** This index is not numbered yet. It answers one question: **Which checks does this verification mode run?** Its format and the rule for placing a decision are in [Decision indexes](decisions.md#which-index).

## Scope

Trusted, integrity-only and revocation-disabled modes, and their reflection in JSON; repeatable verification.

## Boundaries

- What each check decides is its own index.

## Sources

- [library.md](library.md)

## Order

When numbered, entries follow the tiers of [CRL decisions](crl.md#order): fail-open, availability, result diagnostics.

## Candidate rules

Unnumbered. `tests/decision-claims.json` assigns every unindexed case to one of these keys; numbering them is the task for this index in `TODO.md`.

- `modes`: integrity-only and no-revocation modes are explicit and reflected in JSON, in every format.
- `repeatable`: verifying again, or through another entry point, gives the same result.
