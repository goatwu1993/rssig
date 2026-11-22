# rssig

rssig is a Rust CLI and library for verifying embedded Windows PE/MSI/MSP/CAB/NAVX/PowerShell/WSH/MSIX/AppX Authenticode
signatures and RDP signed settings on **macOS and Linux**.

Reference implementations are read-only sources to read and cite, never
dependencies; do not require any of them at build or runtime.

- **Windows formats only** (how PE, MSI/MSP, CAB, NAVX, PowerShell, WSH,
  RDP and MSIX/AppX files are parsed, hashed and embed their signature):
  Microsoft's documentation comes first: its format specifications, the
  learn.microsoft.com pages, and its security bulletins and advisories, which
  record what Windows enforces. Cite each by title, URL and date, and quote
  it; do not commit a copy whose licence forbids it. Where Microsoft documents
  nothing, or its documents conflict, use osslsigncode, jsign and relic
  together (local `osslsigncode/`, `jsign/` and `relic/` clones). Where those
  disagree, another implementation may break the tie, named with its commit
  in the entry that uses it. A rule that departs from what Microsoft
  documents says so and why.
- **Never for the underlying crypto.** CMS/PKCS#7, signatures, timestamps,
  certificates, certificate paths, CRLs and revocation use OpenSSL and Bouncy
  Castle, at the commits in [docs/decisions.md](docs/decisions.md#entry-format).
  Do not cite osslsigncode, jsign or relic as evidence there, even where they
  wrap one of those libraries.

Terms such as policy, rule, decision and spec have one meaning each, defined
in [docs/glossary.md](docs/glossary.md); use them consistently and add new
terms there.

## Release status

rssig is pre-release (0.x, unpublished). Its public interfaces and contracts
may change without notice: the library API, CLI arguments and exit codes, the
JSON result schema and error codes, `tests/cases.json` and its schema, and the
fixture manifest. Do not add compatibility shims, deprecation periods or
migration layers for earlier shapes; change the contract directly and update
the specification, documentation and migration notes in the same change. This
does not relax the "Pinned expectations" rules below: a pinned result still
changes only for a stated reason.

## Pull request titles

PR titles must use Conventional Commit format: `feat: Add xxx`,
`fix: Correct xxx`, or `refactor: Simplify xxx`. Choose the appropriate lowercase
type and capitalize the first word after the colon and space.

## Task tracking

Tasks live in `TODO.md`, one short entry each: ID, title, checkbox and at most
a few lines. An ID is `<SCOPE>-T<NNNNN>` (`CRL-T00012`), from the closed scope
list and rules in [TODO.md](TODO.md#task-ids); the title is the PR title.
Detail longer than that goes in `docs/tasks/<id>.md` (`docs/tasks/crl-t00012.md`),
linked from the entry. A finished item becomes one line with its PR; its evidence lives in
the PR and git history. A task is the scope of one PR: work found along the
way becomes a new task, not a larger branch. Do not create or reference
GitHub issues to track tasks or sub-items.

## Architecture and constraints

- Use pure Rust for PE/MSI/CAB/NAVX/PowerShell/MSIX/AppX parsing/hashing, CMS/PKCS#7, signature verification,
  certificate path validation, timestamps, and revocation validation.
- The OS may supply root certificates only. `rustls-native-certs` is the current
  adapter. macOS framework calls are allowed for root enumeration, never for
  signature, chain, timestamp, or revocation verification.
- Do not introduce OpenSSL (system or vendored), ring, aws-lc, WinVerifyTrust,
  native certificate validation, or subprocess crypto tools into the engine.
- RustCrypto implements the cryptographic primitives. webpki path validation
  uses our RustCrypto algorithm adapter with native crypto features disabled.
  rssig alone decides revocation, in the path callback; webpki builds paths
  without revocation options. Review the resolved dependency graph when
  changing dependencies.
- `anyhow` is internal error plumbing only and must not leak into the public
  API. Public signatures, fields, and trait bounds name rssig's own error types
  (`parse::Error`, `TrustLoadError`, `domain::VerificationError`) or `std`/`core`
  ones; convert at the public boundary.
- Trust anchors must come from the configured root store. Embedded certificates
  are untrusted chain candidates. A mathematically valid signature alone is not
  a trusted signature.
- Fail closed for malformed/unsupported data and unknown revocation status.
  Any integrity-only or revocation-disabled mode must be explicit and reflected
  in JSON. Unsupported policies must be documented; do not claim Windows policy
  equivalence.
- Verification emits exactly one JSON document on stdout, including per-file
  failures. Argument/configuration errors use plain text on stderr (exit 2);
  help/version use plain text on stdout (exit 0). Keep logs off stdout.
- Public verification results are Serde domain types in `src/domain.rs`.
  Successful bundles include parsed certificate names (CN and all RDNs), EKUs,
  key usage, validity, the selected trust chain, timestamp signer, and supplied
  CRL artifacts. Preserve DER encodings for unfamiliar values. A supplied CRL
  must not be labeled individually verified merely because it was loaded.
- Errors carry a typed stable `code`, verification `stage`, readable `message`,
  structured `details`, and causal diagnostics. Consumers match enum codes,
  never prose. Add declarative spec cases and Rust assertions for serialized domain fields before extending the schema.

## Required TDD workflow

1. Before changing behavior, commit or add the smallest fixture reproducing it
   under `tests/fixtures/`. Pair a good artifact with a narrowly changed bad
   artifact when possible. Never execute PE/MSI/CAB or script fixtures, open RDP fixtures in a client, or install MSIX/AppX fixtures.
2. Add a case to `tests/cases.json` first; it and the fixtures/manifest are the
   language-independent specification. Add a named Rust test under `tests/cli/`
   for implementation-specific checks of the fixture, CLI argv, exit
   code, and serialized domain result. Invoke the Clap-based `rssig::cli::run`
   directly with an argument array and captured writer; never spawn the binary.
   Pin `--time`, use `--no-system-roots` with explicit test roots, and provide
   local CRLs so tests are independent of wall time, network, OS roots, and paths.
3. Run the focused Cargo test and observe the intended **failure**. A parser or
   setup failure is not evidence of the target cryptographic failure.
4. Make the smallest production change that passes the testcase. Preserve all
   existing good and bad expectations; never relax expected failures to hide a
   verifier regression. Changing a pinned expectation on purpose follows
   "Pinned expectations" below.
5. Run `cargo test --locked` for the complete suite. Add focused unit tests
   for parser bounds and cryptographic invariants where black-box cases cannot
   isolate the issue. Refactor only while the suite stays green.
6. Run `cargo fmt --check` and `cargo clippy --all-targets --locked -- -D warnings`.
   Record any validation that could not run, including missing target platforms.

## Pinned expectations

A case pins what the verifier does, not proof that it is right.

1. **Every pinned result needs a reason:** a numbered decision entry (format
   and the index for each prefix, such as `CRL-`, `TIME-` and `PATH-`, in
   [docs/decisions.md](docs/decisions.md)) that the case names in
   `"decision"`. "The code did this" is not a reason. Until it names one, a
   case is claimed by an index and candidate rule in
   `tests/decision-claims.json`.
2. **Decided or observed:** a Decided entry changes only with the repository
   owner's approval, recorded in the PR; an Observed one may change when a
   better result is argued.
3. **Safety or wording:** an entry pins acceptance or diagnostics. A wording
   disagreement never blocks a correct fix; an acceptance pin is never
   loosened without a Decided reason.
4. **Conflicts go to the owner:** judge a review finding that contradicts a
   pinned case on its merits; if it may be right, ask the owner and name the
   case in the PR.
5. **Only `main` is existing:** a case added earlier in the same branch or PR
   is no reason to decline a fix.
6. **Compare with a second implementation** for a disputed revocation, path
   or CRL result, as [docs/decisions.md](docs/decisions.md) describes.
7. **Audit before adding:** before adding or changing an entry, check it
   against every index ([which index](docs/decisions.md#which-index)): it must
   not duplicate, contradict or overlap another entry, and it must sit in the
   index that asks its question.
8. **Reindex on a real conflict:** when an entry turns out to duplicate,
   contradict or sit in the wrong index, record it as a task and fix it in a
   reindex PR: merge or move the entry, renumber and reorder the affected
   indexes, and rename its cases and fixtures, in one owner-approved PR that
   says so and lists the old-to-new mapping in its description; the
   repository keeps no tombstones or mapping tables. Doing it in the PR that
   found it also needs the owner's approval.

## Native Rust tests and coverage

`cargo test --locked` is the single entry point for every test. Tests call
`rssig::cli::run` or `run_with_writers` in-process with an argument array and
captured writers, never a child process, with absolute fixture paths.
`tests/cases.json`, its schema, the fixtures and the manifest are the portable
specification another language could implement the CLI from; do not add test
commands to the product CLI. Prefer stable codes, stages and serialized
fields over prose. Commands, layout, coverage and CI are in
[docs/testing.md](docs/testing.md).

## Fuzzing

Fuzz targets live in the detached `fuzz/` crate and need nightly; see
`docs/fuzzing.md`. They are never part of `cargo test --locked`.

- Adding a parser or public parse/verify entry point: add a fuzz target in the
  same change (source file, `[[bin]]`, and a `fuzz/targets.txt` line).
- Changing the root `Cargo.lock`: resynchronize `fuzz/Cargo.lock` as
  `docs/fuzzing.md` describes. `make lint` runs `fuzz/check.sh` and fails on drift.
- Fixing a fuzz finding: commit the minimized input as a fixture with a spec
  case and named test, per the TDD workflow. Never weaken a target to pass.

## Fixtures

Commit binary fixtures with provenance, SHA-256 digests and intended outcomes
in `tests/fixtures/manifest.json`. Ordinary tests never regenerate or
overwrite fixtures; regeneration is the explicit maintenance command in
[docs/testing.md](docs/testing.md#fixtures), followed by a review of every
binary change. Use public, deterministic test-only keys and a fixed
validation time; never commit real private keys or proprietary binaries.

## Current boundaries

Supported formats, algorithms, CRL handling and what is not implemented are
listed in [docs/boundaries.md](docs/boundaries.md); keep it current with each
change. Never describe passing fixtures as Windows policy parity.
