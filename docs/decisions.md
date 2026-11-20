# Decision indexes

A spec case pins what the verifier does, not proof that it is right. Every
pinned result is backed by a numbered **decision entry** that says why it is
right. This page defines the format of every decision index; each index
holds only its entries.

| Prefix | Index | Subject |
|---|---|---|
| `CRL-` | [crl.md](crl.md) | CRL selection, scope, issuer keys, candidate paths and CRL retrieval |

A new subject gets its own prefix and index file directly under `docs/`, and
a row here.

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
next free number. An ID is never reused or renumbered once it is on `main`: a
dropped entry keeps it with Status `Retired` or `Superseded by`, and a changed
rule keeps it while git history keeps the earlier text.

## Task documents

A task document under `docs/tasks/` links to the entries its work adds or
changes instead of restating them.
