# Tests and coverage

## Formatting and lint rules

Rust uses [Clippy](https://doc.rust-lang.org/clippy/) for linting and
[rustfmt](https://github.com/rust-lang/rustfmt) for formatting. Together they
serve the role of a lint/style toolchain such as golangci-lint and gofmt.
Install the development components for a rustup-managed toolchain:

```sh
rustup component add rustfmt clippy
```

Run the same formatting and lint checks used by CI:

```sh
make lint
```

The phony `lint` target runs `cargo fmt --check` followed by
`cargo clippy --all-targets --locked -- -D warnings`. It checks every Rust
target, including tests, without rewriting files. Run `cargo fmt` to apply
formatting using the standard defaults for the package's Rust 2024 edition.

`Cargo.toml` defines the package-wide lint policy:

- Forbid unsafe Rust in this package and reject ignored `must_use` values.
- Enable Clippy's default correctness, suspicious, style, complexity, and
  performance checks, retaining errors for correctness lints.
- Reject `dbg!`, `todo!`, and `unimplemented!` macros.
- Treat every warning as an error in `make lint` and CI.

Add stricter pedantic or restriction lints individually when they fit the
project. If a lint needs an exception, keep it local and explain the reason
with the lint attribute's `reason` field. Dependencies keep their own lint
policies; these settings apply to rssig's code.

## Running tests

Run the complete native and specification suite with:

```sh
cargo test --locked
```

Feature-boundary checks run separately in CI:

```sh
rustup target add thumbv7em-none-eabi
cargo clippy --locked --lib --no-default-features --target thumbv7em-none-eabi -- -D warnings
cargo test --locked --no-default-features
cargo test --locked --no-default-features --features xml
cargo clippy --locked --lib --no-default-features --features xml --target thumbv7em-none-eabi -- -D warnings
cargo test --locked --no-default-features --features std
cargo test --locked --no-default-features --features msi
cargo test --locked --no-default-features --features appx
cargo clippy --all-targets --locked --no-default-features --features msi,appx -- -D warnings
cargo test --locked --no-default-features --features verify
cargo test --locked --no-default-features --features cli
```

The bare-metal check compiles the library and its production dependencies on a
target without `std`; it does not execute fixtures on that target. Host tests in
`tests/parse_core.rs` exercise the same parser API, typed errors, borrowed signer
encodings, and known PE digests in parser-only builds. The maximum `e_lfanew`
fixture pins rejection of malformed offsets without 32-bit arithmetic overflow.
`tests/parse_text.rs` checks script/RDP canonical bytes, encoding/BOM behavior,
WSH insertion positions, untrusted RDP coverage, truncations, and XML gating
in both parser-only and XML-enabled builds. The default suite continues to run every CLI, domain, crypto, and spec test.

Every fixture regression is an individually named Rust test. `tests/cli/pe.rs`
and `tests/cli/msi.rs` contain the 142 migrated cases, with their exit codes,
error identities, diagnostics, exact array lengths, and serialized domain fields
preserved. Rust/Cargo reports each named test directly. Separately, `tests/spec.rs` uses
Serde to load `tests/cases.json` and invokes the same CLI library for every
declarative case. Neither path spawns a child process.

`tests/cli/parse.rs` and the `parse-*` specification cases cover the inspection
contract: good/tampered PE pairs, unknown envelope algorithms, opaque certificate
choices, standalone/truncated CMS, ordered failures, and command diagnostics.
The standalone CMS pair is extracted from `good-pe64.exe`; its bad counterpart
loses only the final byte. `parse-unknown-digest.exe` changes only the outer
SignedData digest OID, unlike the existing signer-algorithm fault fixture.
Tests consume these committed artifacts and never regenerate them. Parse tests
need no roots, CRLs, or validation time because they perform no authentication;
paired verification assertions use explicit options and a pinned time.

The binary passes process arguments, stdout, and stderr to the public
Clap-based `rssig::cli::run_with_writers` entry point. That function takes argv
including the program name and separate writers, returns an exit code, and never
calls `process::exit`. `rssig::cli::run` remains a convenience entry point that
captures both streams in one writer.
Tests exercise the actual parser and command implementation in-process:

```rust
let mut stdout = Vec::new();
let mut stderr = Vec::new();
let exit_code = rssig::cli::run_with_writers(
    ["rssig", "--help"], &mut stdout, &mut stderr,
).unwrap();
assert_eq!(exit_code, 0);
assert!(stderr.is_empty());
assert!(String::from_utf8(stdout).unwrap().contains("Usage:"));
```

`tests/cli_interface.rs` tests help/version, invalid arguments, conflicting verification options,
configuration errors, multiple inputs, and writer failures. Fixture tests use
absolute paths and pinned validation times without changing process-global cwd
or environment. The committed PE/MSI artifacts are data, never executed. The
public domain types must deserialize captured verification reports.

The `rssig test --cases ...` product subcommand is removed. The JSON suite and
its schema remain the portable specification. Use
Cargo filters to run one regression or group:

```sh
cargo test --locked --test cli pe::tampered_image -- --exact
cargo test --locked --test cli msi::
cargo test --locked --test cli_interface
```


## Test layout

`rssig::cli::run` captures combined output;
`run_with_writers` takes separate stdout/stderr sinks and is used by the
process adapter and stream-contract tests. Neither exits the calling process.
Tests do not change the working directory and must not require another
language or runtime.

Example fixture-first regression:

```rust
#[test]
fn rejects_modified_image() {
    let input = format!("{}/tests/fixtures/bad-image-digest.exe", env!("CARGO_MANIFEST_DIR"));
    let mut stdout = Vec::new();
    let code = rssig::cli::run(
        ["rssig", "verify", "--integrity-only", "--time", "1800000000", &input],
        &mut stdout,
    ).unwrap();
    let report: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
    assert_eq!(code, 1);
    assert_eq!(report["results"][0]["error"]["code"], "image_digest_mismatch");
}
```

## Coverage reports

Install the optional development tool and matching LLVM tools. For Homebrew Rust:

```sh
brew install cargo-llvm-cov llvm
```

For a rustup-managed toolchain:

```sh
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --version 0.9.1 --locked
```

Run the same Cargo tests, including the Serde-loaded JSON specification, with
instrumentation and render both formats:

```sh
make coverage
```

This invokes cargo-llvm-cov, not an external test runner. It also saves per-case
JSON results to `target/coverage/conformance.json`; ordinary `cargo test` does not
write that report. To run only the JSON specification through the CLI library:

```sh
cargo test --locked --test spec cli_conforms_to_committed_json_specification -- --exact
```

Open `target/coverage/html/index.html` directly in a browser. Cobertura consumers
can read `target/coverage/cobertura.xml`. Both reports use the same recorded run;
rendering a second format does not rerun tests. No coverage service or token is
required. Coverage and test tooling are not runtime dependencies.

With Homebrew Rust, `make coverage` automatically locates the installed Homebrew
LLVM tools. Explicit `LLVM_COV` and `LLVM_PROFDATA` overrides are preserved.
Their LLVM major version must be compatible with `rustc -vV`. With rustup,
matching tools come from the `llvm-tools-preview` component.

Reports exclude integration-test files and fixture builders under `src/tests.rs`
and `src/tests/`. Production source remains included, including the thin binary
adapter even though fixture and specification tests invoke the CLI library directly. A coverage
percentage is an execution measure, not a claim that every possible invalid
input or Windows policy has been tested.

## CI

GitHub Actions runs `make lint` in a dedicated Ubuntu lint job and
`cargo test --locked` in separate verification jobs on Linux and macOS.
A separate Linux coverage job runs `make coverage` and uploads
the `coverage` artifact. Download and extract it,
then open `html/index.html`; `cobertura.xml` is alongside the HTML directory.
The coverage job also uses the
[Cobertura coverage action](https://github.com/goatwu1993/actions/tree/main/coverage-action)
on pull request and push events to post a report and a neutral coverage check.
The report step is skipped for fork PRs because their token cannot write PR
comments or checks. It does not enforce a coverage threshold.
The ordinary test jobs require no coverage tool. No job regenerates fixtures or
needs Java, Go, external signing tools, system trust contents, or network CRLs.

## Fixtures

Commit binary fixtures and their provenance, SHA-256 digests, and intended
outcomes in `tests/fixtures/manifest.json`. Ordinary tests consume committed
fixtures; they must never regenerate expected data or overwrite fixtures.
Generated fixtures use public, deterministic **test-only** keys and a fixed
validation time. Synthetic fixtures are PE/CFB/CAB containers and inert comment-only scripts; externally signed artifacts have per-artifact provenance.
Do not put real private keys or proprietary binaries in the repository.

The explicit maintenance command is:

```sh
cargo test --locked regenerate_cli_fixtures -- --ignored
```

After intentional regeneration, review all binary changes and update the
manifest. Add independent jsign/relic-produced or publicly redistributable
fixtures with source/version/license information when extending interoperability.
The existing synthetic corpus alone is not evidence of full interoperability.

Windows-oracle integration is deferred. The current development loop runs the
committed fixtures and JSON expectations locally; it requires no Windows
environment or external verifier. Passing these expectations must not be
described as Windows compatibility validation.

## Portable CLI specification

`tests/cases.json`, `tests/cases.schema.json`, `tests/fixtures/manifest.json`, and
the committed fixture files define the CLI conformance specification. Keep these
files even if every Rust source file is deleted: a clean-room implementation in
any language can use the same argv, artifacts, exit codes, and JSON assertions.
The Rust runner is an adapter for this implementation, not the specification.

Suite version 1 uses:

- `id`: unique case identity, independent of Rust test names.
- `command`: argv after the program name; never a shell command.
- `input`: optional fixture filename, appended as one argument.
- `inputs`: optional ordered array of fixture filenames; mutually exclusive
  with `input`. Omit both for help/version/argument-only cases.
- `expect.exit_code`: exact expected exit code.
- `expect.json`: recursive object subsets, exact array lengths/order, and exact
  scalar values/types for verification results on stdout.
- `expect.contains`: string fragments at RFC 6901 JSON Pointers in the output.
- `expect.stdout` / `expect.stderr`: exact stream contents, including an empty
  string to assert that nothing was emitted.
- `expect.stdout_contains` / `expect.stderr_contains`: nonempty arrays of plain
  text fragments. Exactly one of `json`, `stdout_contains`, or `stderr_contains`
  selects the output mode. Text cases reject JSON output; JSON cases require
  exactly one JSON document. Stderr must be empty unless explicitly expected.
- `expect.stderr_once`: optional with `stderr_contains`; nonempty array of plain
  text fragments that must each occur exactly once in stderr, so a diagnostic
  states each cause once.

Inputs are relative to the suite's fixtures directory. Root/CRL argument paths
are relative to the suite file, as are explicit `fixtures/...` argv paths. The
Rust adapter resolves them to absolute paths without changing global cwd. Each
verification invocation returns exactly one JSON document on stdout. Command
errors are plain text on stderr; help/version are plain text on stdout. Keep validation times, explicit
roots, and local CRLs pinned so expected results are portable and offline.

The manifest pins the bytes, SHA-256, provenance, and intended outcomes of the
fixtures. `cases` links identify declarative cases; optional `tests` links point
to additional native regressions. Neither fixture generation nor expected-output
regeneration is part of ordinary tests or coverage.

### Manifest consistency

`tests/manifest.rs` checks the manifest against the committed fixtures, the case
specification, and the tests and generators it names. It runs in
`cargo test --locked` and never regenerates or modifies a fixture. Rust sources
under `src/` and `tests/` (never `tests/fixtures/`) are parsed with `syn`, so comments and string literals never count as code; a
file `syn` cannot parse or that is not UTF-8 is recorded and reported by
`committed_sources_index_without_errors` rather than silently ignored or
panicking. One
test of the directory scan creates and removes a scratch directory under
Cargo's `CARGO_TARGET_TMPDIR`, named per process so concurrent runs cannot collide.

| Rule | Requirement |
| --- | --- |
| Schema | Only known fields with the expected types; `schema_version` is 1. A misspelled field fails instead of being ignored. |
| Paths | `file` is one plain name directly in `tests/fixtures/`: it starts with an ASCII letter or digit and contains only those, `.`, `_`, and `-`, and is not `manifest.json` in any letter case. It is listed once, compared case-insensitively because macOS checkouts are case-insensitive. |
| Presence | Every listed file exists; every file in the directory is listed; the directory has no subdirectories. By-product files matching `.gitignore` (`.DS_Store`, `._name`, `.name.swp`, `name~`) are skipped: no artifact can have such a name. Any other hidden file, and every directory, is reported. |
| Content | `bytes` equals the file length and `sha256` is the lowercase hexadecimal digest. |
| Description | Nonblank. |
| Provenance | The manifest-level default is complete. An artifact with a `provenance` object records a `license` and a `source`, `generator`, or `command`. An artifact produced outside the repository (a `signer`, `signer_jar_sha256`, `upstream_revision`, or URL `source`) states its own `license`, and so does anything derived, through any chain of `source` links, from such an artifact or one with a `provenance` object. A URL is any `scheme://` text, in both the manifest and case arguments. No recorded provenance or license value is blank. |
| Generators | Each `generator` names a Rust source file under `src/` or `tests/` (or `build.rs`), optionally followed by `::function` naming a free function declared in it (`inner::function` inside an inline `mod inner`), then optionally whitespace and a note. Methods and anything inside a block (function bodies, closures, const initializers) cannot be named. |
| Case links | Each ID in `cases` is defined in `tests/cases.json` (`UnknownCase`) and listed once (`DuplicateCase`). |
| Case inputs | Every file a case reads is a listed artifact. `tests/common/spec_suite.rs` defines the case types and `Case::files_read`, shared with `tests/spec.rs`: `input`, `inputs`, CRL response bodies, `fixtures/...` arguments, `--roots`/`--crl` values in both forms, and plain arguments containing a path separator. It destructures every case and expectation field, so a new field does not compile until it is classified. As in Clap, a value starting with `-` directly after a path option is another flag (the option's value is missing), except a lone `-`. Arguments after `--` are positional files read relative to the CLI's working directory, so they always fail; in `--flag=value`, only the value is checked for a path or URL. CRL response bodies must be listed plain names, never intentionally absent ones, since the runner reads them whenever the CLI requests their URL. A path option without the `fixtures/` prefix (even a listed name), a path leaving the fixture directory, a trailing separator or `.` segment, or an exempt file such as `manifest.json` fails. A bare positional argument without a separator is not treated as a file: the existing ones only appear in argument-error cases the CLI rejects before reading anything. |
| Path options | `PATH_OPTIONS` equals every long name, alias, and short form of the options whose value Clap parses as a `PathBuf`, read from the real parser through the hidden `rssig::cli::command()` (test `path_options_match_the_cli_definition` in `tests/spec.rs`). A new file-valued option, alias, or short form fails until the runner and this check know about it. |
| Fixture directory | `cases.json` names `fixtures`, the directory this manifest describes. Otherwise that single problem is reported and case inputs are not checked. |
| Case IDs | Case IDs in `cases.json` are unique; the runner's own validation also rejects duplicates. Case `input`/`inputs` and CRL response bodies are plain fixture names in the schema (`$defs/fixtureName`), the runner, and this check (`spec_suite::is_fixture_name`). |
| Test links | Each `tests` entry is `module::function`: a top-level function marked `#[test]` in `tests/cli/<module>.rs`, a module that a test target under `tests/` includes. |
| Pairs | `paired_good` names another listed artifact. |
| Derived sources | A top-level `source` that is not a URL (`scheme://...`) names another listed artifact. A `source` inside a `provenance` object is free text and is not resolved. |

Intentional exceptions are constants in that file:

- `manifest.json` is the only unlisted file. Diagnostic JSON and helper data
  such as `cli-missing-files.json` are ordinary listed artifacts.
- `missing.exe`, `missing-root.der`, `missing.crl`, and
  `missing-parse-input.exe` are inputs that cases name because they do not
  exist. Each must stay absent (`PresentAbsentInput`) and remain used by a case
  (`UnusedException`).

Artifacts without provenance of their own inherit the manifest-level default
(repository-generated, Apache-2.0). Two relationships are deliberately not
enforced: an artifact may list a case that reaches it only indirectly (for
example an issuer certificate embedded in the signed input), and an artifact
need not list every case that reads it. Each rule has a test that breaks a copy
of the committed data and requires exactly the expected problems, and no
others. An entry with an unsafe or duplicate name still has its other fields
checked, so one run reports all of its problems.

## Invariant inventory

See [coverage by invariant](coverage-inventory.md) and the maintained
`tests/coverage-inventory.json` case/error/producer index. Cargo tests validate
its references; it records open gaps separately from existing evidence.

Retrieval cases can provide `crl_responses` (URL to fixture filename),
`crl_errors` (URL to the fetch-error kind the injected source returns instead:
`denied`, `failed`, `abort` or `unknown`; it reads no file and requires
`crl_responses`; an unmapped URL is `failed`) and `expect.crl_requests`
(exact ordered URL array, including failed requests).
An empty request array asserts no calls. The request expectation requires an
injected response map and never triggers real network requests itself.
`crl_certificate_responses` (lowercase SHA-256 of a certificate's DER, as
rssig re-encodes it, which equals the original for every committed fixture, to a
fixture filename; requires `crl_responses`) makes the injected source
answer a request for that certificate with that CRL alone, without a URL, as
a source keyed by certificate or issuer does; none of that certificate's
listed URLs is requested. Such answers are not listed in
`expect.crl_requests`, which holds URLs only
(`crl-017-fetch-completes-the-path-without-a-crl-beside-a-revoked-path`,
`crl-034-fetch-by-certificate-answer-requests-no-listed-point`). Expectations
match listed fields only, so the absence of `crl_retrieval.failures` is
asserted by the named test
`crl_fetch_by_certificate_answer_leaves_no_point_failures`.

A case may carry a `decision` (not used to run it): the ID of the entry it
pins in a decision index under `docs/`, such as `"decision": "CRL-001"` for
[CRL decisions](crl.md). The entry states the rule once, with its Status
(`Decided` or `Observed`), who decided it, whether it pins `acceptance` or
`diagnostics`, and its sources; a case without `decision` counts as observed.
`tests/spec.rs` reads every `### PREFIX-NNN: title` entry in `docs/*.md`,
checks its fields, and checks that each case's `decision` names an entry. See
AGENTS.md, "Pinned expectations".

Every test build enables the internal `revocation-crosscheck` feature through
a self dev-dependency in `Cargo.toml`. After rssig accepts a path's
revocation status, it re-runs webpki's own revocation check with the CRLs
rssig chose and panics on disagreement, so every fixture case with CRLs also
checks that rssig and webpki agree. Product builds never enable it, and it is
also compiled out without `debug_assertions`, so release test runs skip it; see
[CRL-T00011](tasks/crl-t00011.md).

Five retrieval behaviors have unit tests only, because no committed input can
reach them through the CLI:

- An error with `details.reason` `ambiguous_issuer_keys` is final for retrieval. Since
  CRL-T00011 it is produced only by the accepted-path rule for same-name issuers
  with different keys whose CRLs do not name those keys
  (`crl-008-self-issued-rollover-with-both-crls-is-rejected`). Its code is
  `certificate_chain_invalid`, which retrieval never treats as missing CRLs,
  so the `revocation_unknown` branch is unreachable through the CLI.
  `retrieval::tests::a_confirmation_disagreement_is_final_for_retrieval` pins
  the decision.
- A certificate whose issuer name cannot be read is recorded as
  `invalid_certificate` for each listed point, and the source is not asked.
  Every certificate reaching retrieval has already been decoded from DER, and
  a decoded name always re-encodes, so no fixture reaches this branch.
- At most 64 CRL bodies and failures in one source response
  (`crl_response_entries`). The spec's injected source answers one body per
  listed URL, and a certificate lists at most 16, so a case cannot exceed the
  limit; `retrieval::tests::a_response_with_too_many_entries_ends_the_run`
  covers it.
- Points recorded as not tried once a request's byte allowance is spent. The
  allowance is up to 32 MiB and fixtures are a few hundred bytes, so no case
  spends it;
  `retrieval::tests::points_left_when_the_byte_allowance_is_spent_are_not_tried`
  covers it.
- The built-in HTTP source's kinds (a last request keeping its own failure,
  aborts when spent). Tests never use the network, so these are unit tests
  in `src/retrieval/http.rs`.
