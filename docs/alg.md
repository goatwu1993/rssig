# Algorithm decisions

**Skeleton.** This index is not numbered yet. It answers one question: **Is this algorithm acceptable here?** Its format and the rule for placing a decision are in [Decision indexes](decisions.md#which-index).

## Scope

Digest and signature algorithms, SHA-1 and its explicit opt-in, key types and sizes.

## Boundaries

- Where an algorithm sits in CMS is `CMS-`; whether a certificate path is valid is `PATH-`.
- Which algorithms are supported is decided here; what an unusable CRL signature means for revocation is CRL-003.

## Sources

- [boundaries.md](boundaries.md)
- [cms-security.md](cms-security.md)

## Order

When numbered, entries follow the tiers of [CRL decisions](crl.md#order): fail-open, availability, result diagnostics.

## Candidate rules

Unnumbered. `tests/decision-claims.json` assigns every unindexed case to one of these keys; numbering them is the task for this index in `TODO.md`.

- `unsupported`: an unsupported digest or signature algorithm is `unsupported_algorithm`.
- `sha1`: SHA-1 digests are `weak_algorithm` unless `--allow-sha1` is given, in every format.
- `key-size`: an RSA key below 2048 bits is `weak_algorithm`, even with `--allow-sha1`.
