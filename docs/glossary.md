# Glossary

The words below have one meaning each across the code, the docs, `TODO.md` and
`AGENTS.md`. Use them this way; when a new term is needed, add it here in the
same change.

## Behavior

| Term | Meaning | Not to be confused with |
|---|---|---|
| **policy** | A behavior the caller **selects**: `VerifyOptions` and its `RevocationPolicy`, integrity-only mode, `--no-revocation`, the `--allow-sha1` opt-in, a `CrlSource`'s own URL policy. The `POLICY-` index records the verification modes; the SHA-1 opt-in is `ALG-` and a source's URL policy is `CRL-`. | Fixed behavior, which is a rule. |
| **rule** | Fixed verifier behavior that no option turns off, stated in prose ("the best usable CRL decides"). A decision entry states one rule, or what one policy does. | A policy, which is selectable. |
| **engine** | The `rssig-engine` package (`engine/`): parsing, inspection, verification and CRL retrieval (`Retrieval` in `engine/src/retrieval.rs`). It judges evidence over what its caller supplies and bounds what it records and accepts back. It reads no files, clock or network, enumerates no OS roots, and makes no fetch policy ([where the engine ends](crl-retrieval.md#where-the-engine-ends-and-the-application-begins)). | The **application**, or a `CrlSource`. |
| **application** | The `rssig` package (repository root): the CLI and the defaults the engine leaves to its caller, namely `HttpCrlSource` (`src/crl.rs`), OS roots (`src/roots.rs`), host limits and the default policy the CLI builds from its flags. | The engine. |
| **collaborator** | Something the engine's caller injects for the engine to call, behind an interface the engine defines: a `CrlSource` for CRLs, a `Logger` for diagnostics. A collaborator supplies or observes; it never decides a verification result. The application's `HttpCrlSource` is its default CRL collaborator, and `rssig::cli::Host` carries the ones an embedder of the CLI injects. | A **policy**, which the caller selects as data (`VerifyOptions`). |
| **source** | A `CrlSource`: what the engine asks for CRLs. It decides what to fetch, from where, and how often and how much (requests, URLs, time, bytes on the wire); the application's `HttpCrlSource` is the default one. | The engine, or the CLI that builds one. |
| **fetch policy** | The source's decisions on what to fetch and how much: schemes, destinations, redirects, and the totals of requests, URLs, time and wire bytes (CRL-023, CRL-039). A new one goes in `HttpCrlSource`, not `Retrieval`. | A **policy**, which the caller selects; a source's URL policy is one kind of fetch policy. |
| **check** | The code or verification step that enforces a rule ("path checks", "signature checks"). | |
| **profile** | The supported subset of an external format or standard, for example the [timestamp profile](timestamp-profile.md) of RFC 3161. | |
| **verification mode** | One of the selectable policies above: trusted, integrity-only or revocation disabled. | |

External policies keep their own names: Windows trust and code-integrity
policy, Group Policy, PowerShell execution policy, the RFC 3161 TSA policy OID,
X.509 `certificatePolicies`, and other tools' policies.

## Decisions

| Term | Meaning |
|---|---|
| **decision** (entry) | A numbered statement of one rule, or of what one policy does, with its reason, `PREFIX-NNN` ([format](decisions.md#entry-format)). |
| **decision index** | The file holding one prefix's entries, such as [crl.md](crl.md); listed in [decision indexes](decisions.md). |
| **skeleton index** | An index with candidate rules but no numbered entries yet. |
| **Status** | `Decided` (argued right; changes only with the owner's approval), or `Observed` (current behavior, kept visible). |
| **Decided by** | Who or what settled a Decided entry: the owner, Microsoft's documentation (Windows formats), the references, or a written argument. |
| **reference** (implementation) | A read-only implementation cited as evidence: OpenSSL and Bouncy Castle for the underlying crypto; osslsigncode, jsign and relic for Windows formats where Microsoft documents nothing or contradicts itself ([AGENTS.md](../AGENTS.md)). |
| **tiebreaker** | Another implementation, named with its commit in the entry that uses it, that settles a Windows-format point on which osslsigncode, jsign and relic disagree. |
| **Pins** | Whether an entry pins **acceptance** (verifies or rejects) or **diagnostics** (which code, stage, detail or request). |
| **candidate rule** | An unnumbered rule in an index's "Candidate rules" section, waiting to become an entry. |
| **claim** | The assignment of a case without a decision to one index and candidate rule, in `tests/decision-claims.json`. |
| **reindex** | An owner-approved change that moves, merges or renumbers entries and renames their cases; its PR description lists the old-to-new mapping ([IDs](decisions.md#ids)). |

## Specification and tests

| Term | Meaning |
|---|---|
| **spec** (specification) | `tests/cases.json`, its schema, the fixtures and `tests/fixtures/manifest.json`: what any implementation of the CLI must do. |
| **case** | One entry in `tests/cases.json`: a command, its inputs and the expected result. |
| **fixture** | A committed input file under `tests/fixtures/`, with provenance in the manifest. |
| **injected answer** | What a case's injected CRL source returns for one certificate it is asked about (`crl_certificate_responses`): a fixture file name, or a scripted answer. Not an *answer by certificate* (CRL-034), which is a body that loads as a CRL of the certificate's issuer; an injected answer may hold none. |
| **scripted answer** | An injected answer written out in a case: the response's bodies and failures, or the error the source fails the whole request with ([testing.md](testing.md)). |
| **named test** | A Rust test under `tests/cli/` that checks one fixture in-process. |
| **pinned result** | A case's expected result; every one needs a decision ([AGENTS.md](../AGENTS.md#pinned-expectations)). |

## Work

| Term | Meaning |
|---|---|
| **task** | An item in `TODO.md` with an ID `<SCOPE>-T<NNN>` such as `CRL-T012` ([task IDs](../TODO.md#task-ids)); the `T` keeps it apart from a decision entry such as `CRL-012`. One task is the scope of one PR. |
| **task document** | Detail for a task under `docs/tasks/`. |

## Time and trust

| Term | Meaning |
|---|---|
| **validation time** | The single instant one verification judges at (`--time`, or the host clock); see [validation time](validation-time.md). |
| **signing time** | The time a timestamp attests. |
| **lifetime signing** | The EKU that keeps a signer from being extended by a timestamp. |
| **configured root** (anchor) | A trust anchor from `--roots` or the system store; embedded certificates are only candidates. |
| **supplied CRL** / **fetched CRL** | A CRL given locally with `--crl`, or one a `CrlSource` returned. |
