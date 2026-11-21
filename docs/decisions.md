# Decision indexes

A spec case pins what the verifier does, not proof that it is right. Every
pinned result is backed by a numbered **decision entry** that says why it is
right. Terms are defined in the [glossary](glossary.md). This page defines
the format of every decision index. An index holds
its entries and, until every case it claims names one, a "Candidate rules"
section; a skeleton index has only the latter.

| Prefix | Index | Subject |
|---|---|---|
| `CRL-` | [crl.md](crl.md) | CRL selection, scope, issuer keys, candidate paths and CRL retrieval |
| `TIME-` | [time.md](time.md) | Validation time: at which instant certificates are checked |
| `PATH-` | [path.md](path.md) | Certificate-path rules: anchors, issuer identity, constraints, EKU and KeyUsage, path building |
| `TSA-` | [tsa.md](tsa.md) | Timestamp tokens: whether an RFC 3161 token or countersignature can be trusted at all |
| `CMS-` | [cms.md](cms.md) | CMS SignedData structure, signer identification and signature, nested signatures |
| `ALG-` | [alg.md](alg.md) (skeleton) | Algorithm acceptance, SHA-1 opt-in |
| `TRUST-` | [trust.md](trust.md) (skeleton) | Loading roots and CRLs |
| `LIMIT-` | [limit.md](limit.md) (skeleton) | Verification budgets, nesting depth, host input limits |
| `POLICY-` | [policy.md](policy.md) (skeleton) | Verification modes: trusted, integrity-only, no revocation |
| `CLI-` | [cli.md](cli.md) (skeleton) | Command-line arguments, help, exit codes, read errors |
| `INSPECT-` | [inspect.md](inspect.md) (skeleton) | What `parse` reports |
| `PE-` | [pe-decisions.md](pe-decisions.md) (skeleton) | PE parsing and hashing |
| `MSI-` | [msi-decisions.md](msi-decisions.md) (skeleton) | MSI and MSP parsing and hashing |
| `CAB-` | [cab-decisions.md](cab-decisions.md) (skeleton) | CAB parsing and hashing |
| `NAVX-` | [navx-decisions.md](navx-decisions.md) (skeleton) | NAVX parsing and hashing |
| `PS-` | [ps-decisions.md](ps-decisions.md) (skeleton) | PowerShell and PowerShell XML scripts |
| `WSH-` | [wsh-decisions.md](wsh-decisions.md) (skeleton) | Windows Script Host scripts |
| `RDP-` | [rdp-decisions.md](rdp-decisions.md) (skeleton) | RDP signed settings |
| `APPX-` | [appx-decisions.md](appx-decisions.md) (skeleton) | MSIX/AppX packages and bundles |

A new subject gets its own prefix and index file directly under `docs/`, and
a row here. Format indexes are named `<format>-decisions.md` because the
format's own document already has the plain name.

Every case in `tests/cases.json` without a `decision` is claimed by exactly
one index and one of its candidate rules in `tests/decision-claims.json`;
`tests/spec.rs` checks this, and that each candidate key is listed in its
index's "Candidate rules". Filling an index moves its cases from the claims
file to their entries.

## Which index

Each index answers one question; an entry goes where its question is asked.
The usual error codes are a hint, not the rule.

| Question | Index | Typical codes |
|---|---|---|
| Which CRL decides, does it apply, is a certificate revoked, and how is a missing CRL fetched? | `CRL-` | `invalid_crl`, `certificate_revoked`, `revocation_unknown`, `crl_expired` |
| At which instant are certificates checked: validation time, signing time, lifetime signing, validity boundaries? | `TIME-` | `certificate_expired`, `certificate_not_yet_valid`, `timestamp_in_future` |
| Can this timestamp token be trusted at all: binding, TSA signature and EKU, multiplicity, TSTInfo profile? | `TSA-` | `invalid_timestamp`, `timestamp_imprint_mismatch`, `invalid_eku` at `timestamp` |
| Is this certificate path acceptable: anchors, issuer identity, constraints, EKU and KeyUsage, path building? | `PATH-` | `untrusted_root`, `certificate_chain_invalid`, `invalid_eku`, `invalid_key_usage` |
| Is the CMS SignedData and its signer binding acceptable? | `CMS-` | `malformed_cms`, `invalid_signature`, `ambiguous_signer_certificate`, `content_digest_mismatch` at `cms` |
| Is this algorithm acceptable here? | `ALG-` | `unsupported_algorithm`, `weak_algorithm` |
| What becomes a configured root or CRL? | `TRUST-` | configuration errors (exit 2) for trust inputs |
| When does rssig stop work? | `LIMIT-` | `resource_limit_exceeded` |
| Which checks does this verification mode run? | `POLICY-` | results of integrity-only and no-revocation runs |
| What does the command line accept and report? | `CLI-` | exit codes, `read_failed`, argument errors |
| What does `parse` report about a file? | `INSPECT-` | `parse` output |
| How is a file of this format parsed and hashed for signing? | `PE-`, `MSI-`, `CAB-`, `NAVX-`, `PS-`, `WSH-`, `RDP-`, `APPX-` | the format's `invalid_*`, digest-mismatch and `unsigned` codes |

A rule that touches two questions goes where its decision is made: the
precedence between a lifetime-signing failure and a revocation is set by the
lifetime-signing rules, so it is a `TIME-` entry (TIME-011); whether a root
or an intermediate may sign CRLs without cRLSign is a CRL-issuer rule, so it
is a `CRL-` entry (CRL-015), separate from the general anchor rule PATH-011. A rule
that is the same in every format stays in its subject index, and the format
index links to it: every format's SHA-1, integrity-only, nested-signature,
revocation and expired-with-timestamp cases name `ALG-`, `POLICY-`, `CMS-`,
`CRL-` and `TIME-` entries. Limits on CRL retrieval (URIs per certificate, the
built-in source's size, time and request bounds) stay `CRL-`; engine budgets
are `LIMIT-`, including the count of loaded CRLs (at most 64, supplied and
fetched together). How a loaded root is
used is `PATH-`; how it is loaded is `TRUST-`.

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
  says so), bc-java e03fee0b, BoringSSL `main` (commit not captured) and
  webpki 0.103.16; for Windows-format entries only, osslsigncode 2.16
  (04c9aa7e), jsign 7.6 (cf5d2ce) and relic 02c54d58 (see AGENTS.md).
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

| Reindex | Old ID (on `main` before) | New ID |
|---|---|---|
| PR #70 | CRL-021 | merged into CRL-020 |
| PR #70 | CRL-022 to CRL-031 | CRL-021 to CRL-030 (each one lower) |
| PR #70 | CRL-032 | TIME-012 |
| PR #70 | CRL-033 to CRL-043 | CRL-031 to CRL-041 (each two lower) |
| PR #70 | CRL-044 | merged into CRL-041 |
| PR #70 | CRL-045 to CRL-048 | CRL-042 to CRL-045 (each three lower) |
| PR #70 | TIME-010 | merged into PATH-011 |
| PR #70 | TIME-011, TIME-012 | TIME-010, TIME-011 |
| PR #72 | TSA-004, duplicated attribute OID clause (cases `tsa-004-duplicate-rfc`, `tsa-004-duplicate-counter`) | CMS-009 (cases `cms-009-duplicate-rfc`, `cms-009-duplicate-counter`); TSA-004 keeps its number |
| PR #73 | CMS-009 cases `cms-009-duplicate-rfc`, `cms-009-duplicate-counter` | back to TSA-004 as `tsa-004-duplicate-rfc`, `tsa-004-duplicate-counter`, now `invalid_timestamp` at `timestamp` (SEC-25 narrowed CMS-009) |
| PR #74 | CRL-021 | merged into CRL-020 |
| PR #74 | CRL-022 to CRL-039 | CRL-021 to CRL-038 (each one lower) |
| PR #74 | CRL-040 | CRL-039 (also takes CRL-041) |
| PR #74 | CRL-041 | merged into CRL-039 |
| PR #74 | CRL-042 to CRL-045 | CRL-040 to CRL-043 (each two lower) |
| PR #74 | TIME-004 | merged into TIME-003 |
| PR #74 | TIME-005 to TIME-014 | TIME-004 to TIME-013 (each one lower) |
| PR #74 | CMS-014 | merged into CMS-010 |
| PR #74 | CMS-015, CMS-016 | CMS-014, CMS-015 |

In PR #74 every case was renamed with its entry, including the cases of a
merged entry (for example `crl-041-…` is now `crl-039-…`).

## Task documents

A task document under `docs/tasks/` links to the entries its work adds or
changes instead of restating them.
