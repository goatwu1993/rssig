# Glossary

The words below have one meaning each across the code, the docs, `TODO.md` and
`AGENTS.md`. Use them this way; when a new term is needed, add it here in the
same change.

## Behavior

| Term | Meaning | Not to be confused with |
|---|---|---|
| **policy** | A behavior the caller **selects**: `VerifyOptions` and its `RevocationPolicy`, integrity-only mode, `--no-revocation`, the `--allow-sha1` opt-in, a `CrlSource`'s own URL policy. The `POLICY-` index records these modes. | Fixed behavior, which is a rule. |
| **rule** | Fixed verifier behavior that no option turns off, stated in prose ("the best usable CRL decides"). A decision entry states one rule. | A policy, which is selectable. |
| **check** | The code or verification step that enforces a rule ("path checks", "signature checks"). | |
| **profile** | The supported subset of an external format or standard, for example the [timestamp profile](timestamp-profile.md) of RFC 3161. | |
| **verification mode** | One of the selectable policies above: trusted, integrity-only or revocation disabled. | |

External policies keep their own names: Windows trust and code-integrity
policy, Group Policy, PowerShell execution policy, the RFC 3161 TSA policy OID,
X.509 `certificatePolicies`, and other tools' policies.

## Decisions

| Term | Meaning |
|---|---|
| **decision** (entry) | A numbered statement of one rule with its reason, `PREFIX-NNN` ([format](decisions.md#entry-format)). |
| **decision index** | The file holding one prefix's entries, such as [crl.md](crl.md); listed in [decision indexes](decisions.md). |
| **skeleton index** | An index with candidate rules but no numbered entries yet. |
| **Status** | `Decided` (argued right; changes only with the owner's approval), `Observed` (current behavior, kept visible), `Retired` or `Superseded by`. |
| **Decided by** | Who or what settled a Decided entry: the owner, the references, or a written argument. |
| **Pins** | Whether an entry pins **acceptance** (verifies or rejects) or **diagnostics** (which code, stage, detail or request). |
| **candidate rule** | An unnumbered rule in an index's "Candidate rules" section, waiting to become an entry. |
| **claim** | The assignment of a case without a decision to one index and candidate rule, in `tests/decision-claims.json`. |
| **reindex** | An owner-approved change that moves, merges or renumbers entries and renames their cases, recorded in [reindex history](decisions.md#reindex-history). |

## Specification and tests

| Term | Meaning |
|---|---|
| **spec** (specification) | `tests/cases.json`, its schema, the fixtures and `tests/fixtures/manifest.json`: what any implementation of the CLI must do. |
| **case** | One entry in `tests/cases.json`: a command, its inputs and the expected result. |
| **fixture** | A committed input file under `tests/fixtures/`, with provenance in the manifest. |
| **named test** | A Rust test under `tests/cli/` that checks one fixture in-process. |
| **pinned result** | A case's expected result; every one needs a decision ([AGENTS.md](../AGENTS.md#pinned-expectations)). |

## Work

| Term | Meaning |
|---|---|
| **task** | An item in `TODO.md` with an ID such as `SEC-10` or `TEST-23` (two digits; decision IDs have three). One task is the scope of one PR. |
| **task document** | Detail for a task under `docs/tasks/`. |

## Time and trust

| Term | Meaning |
|---|---|
| **validation time** | The single instant one verification judges at (`--time`, or the host clock); see [validation time](validation-time.md). |
| **signing time** | The time a timestamp attests. |
| **lifetime signing** | The EKU that keeps a signer from being extended by a timestamp. |
| **configured root** (anchor) | A trust anchor from `--roots` or the system store; embedded certificates are only candidates. |
| **supplied CRL** / **fetched CRL** | A CRL given locally with `--crl`, or one a `CrlSource` returned. |
