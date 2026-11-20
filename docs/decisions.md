# Decision indexes

A spec case pins what the verifier does, not proof that it is right. Every
pinned result is backed by a numbered **decision entry** that says why it is
right. This page defines the format of every decision index; each index
holds only its entries.

| Prefix | Index | Subject |
|---|---|---|
| `CRL-` | [crl.md](crl.md) | CRL selection, scope, issuer keys, candidate paths and CRL retrieval |
| `TIME-` | [time.md](time.md) | Validation time: at which instant certificates are checked |
| `PATH-` | [path.md](path.md) | Certificate-path policy: anchors, issuer identity, constraints, EKU and KeyUsage, path building |
| `TSA-` | [tsa.md](tsa.md) | Timestamp tokens: whether an RFC 3161 token or countersignature can be trusted at all |

A new subject gets its own prefix and index file directly under `docs/`, and
a row here.

## Which index

Each index answers one question; an entry goes where its question is asked.
The usual error codes are a hint, not the rule.

| Question | Index | Typical codes |
|---|---|---|
| Which CRL decides, does it apply, is a certificate revoked, and how is a missing CRL fetched? | `CRL-` | `invalid_crl`, `certificate_revoked`, `revocation_unknown`, `crl_expired` |
| At which instant are certificates checked: validation time, signing time, lifetime signing, validity boundaries? | `TIME-` | `certificate_expired`, `certificate_not_yet_valid`, `timestamp_in_future` |
| Can this timestamp token be trusted at all: binding, TSA signature and EKU, multiplicity, TSTInfo profile? | `TSA-` | `invalid_timestamp`, `timestamp_imprint_mismatch`, `invalid_eku` at `timestamp` |
| Is this certificate path acceptable: anchors, issuer identity, constraints, EKU and KeyUsage, path building? | `PATH-` | `untrusted_root`, `certificate_chain_invalid`, `invalid_eku`, `invalid_key_usage` |

A rule that touches two questions goes where its decision is made: the
precedence between a lifetime-signing failure and a revocation is set by the
lifetime-signing policy, so it is a `TIME-` entry (TIME-012); whether a root
or an intermediate may sign CRLs without cRLSign is a CRL-issuer rule, so it
is a `CRL-` entry (CRL-015), separate from the general anchor rule PATH-011.

## Entry format

An entry is a level-three heading `### PREFIX-NNN: Title`, a short statement
of the rule, and these fields as list items:

- **Status:** exactly one of
  - `Decided`: argued right; changes only with the repository owner's
    approval, recorded in the PR and in "Decided by".
  - `Observed`: current behavior, pinned so that a change is visible; may
    change when a better result is argued.
  - `Retired`: no longer in force; one line says why.
  - `Superseded by PREFIX-NNN`: replaced by the named entry.
- **Decided by:** who or what settled it, with the PR where it applies:
  `owner, PR #N` (the owner decided or delegated the call),
  `references agree` (OpenSSL and Bouncy Castle, and BoringSSL where named),
  `<library> followed` (one reference, the other having no equivalent),
  `written argument` or `written choice` (no reference equivalent), or `—`
  for an Observed entry.
- **Pins:** exactly one of `acceptance` (verifies or rejects: security) or
  `diagnostics` (which code, stage, detail or request). A rule with both
  sides is two entries. An acceptance pin is never loosened without a Decided
  entry.
- **Sources:** reference locations, RFC sections or the written argument.
  Unless stated, line numbers are for OpenSSL 3a3f1356 (3.3 where a source
  says so), bc-java e03fee0b, relic 02c54d58, BoringSSL `main` (commit not
  captured) and webpki 0.103.16.
- **Unit tests** and **Note**, where an entry has them.

An entry does not list its cases. For a disputed revocation, path or CRL
result, Sources compare OpenSSL (`crypto/x509/x509_vfy.c`, `openssl verify
-crl_check_all`) and Bouncy Castle (`RFC3280CertPathUtilities`,
`X509RevocationChecker`): where they agree, follow them; where they differ or
have no equivalent, write down the choice. Run such comparisons as a separate
maintenance step, never inside `cargo test` or the product.

## Cases

A case in `tests/cases.json` names the entry it pins with
`"decision": "PREFIX-NNN"`, and its ID starts with the lowercase prefix and
number (`crl-001-…`). The case's Status and Pins are its entry's; a case
without `decision` counts as Observed. To list an entry's cases:

```sh
jq -r '.cases[] | select(.decision == "CRL-001") | .id' tests/cases.json
```

`tests/spec.rs` reads every entry in `docs/*.md`, checks its fields and that
IDs are unique, and checks that every case's `decision` names an entry that
is `Decided` or `Observed`.

## IDs

An ID is a prefix and a three-digit number. Each index orders its entries by
importance when it is first numbered and says how; a later entry takes the
next free number. A changed rule keeps its ID while git history keeps the
earlier text. An ID is not renumbered except in a reindex the repository
owner approves: a PR whose title and description say so, which moves
misplaced entries to the right index, renumbers every affected index to keep
its order, updates every case ID, decision and reference in the same change,
and adds its old-to-new mapping below. Outside a reindex, a dropped entry keeps
its ID with Status `Retired` or `Superseded by`.

## Reindex history

Older PRs, reviews and commit messages cite IDs as they were then. Map them
with this table; an ID not listed kept its number.

| Reindex | Old ID | New ID |
|---|---|---|
| PR #70 | CRL-032 | TIME-012 |
| PR #70 | CRL-033 to CRL-048 | CRL-032 to CRL-047 (each one lower) |
| PR #70 | TIME-010 | merged into PATH-011 |
| PR #70 | TIME-011, TIME-012 | TIME-010, TIME-011 |

## Task documents

A task document under `docs/tasks/` links to the entries its work adds or
changes instead of restating them.
