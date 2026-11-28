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

The workspace's `default-members` are both packages, so this runs the engine's
(`engine/`, `rssig-engine`) and the application's (`./`, `rssig`) tests. For
one of them, use `-p rssig` or `-p rssig-engine --features retrieval`: the
engine's CRL retrieval module and its tests are behind the `retrieval`
feature, which is not an engine default and is built in the workspace run only
because the application enables it. Plain `-p rssig-engine` leaves them out.

Feature-boundary checks run separately in CI, one package at a time so that
the application's feature requests never unify into the engine's:

```sh
rustup target add thumbv7em-none-eabi
cargo clippy --locked -p rssig-engine --lib --no-default-features --target thumbv7em-none-eabi -- -D warnings
cargo clippy --locked -p rssig-engine --lib --no-default-features --features xml --target thumbv7em-none-eabi -- -D warnings
cargo clippy --locked -p rssig-engine --lib --no-default-features --features verify-core --target thumbv7em-none-eabi -- -D warnings
cargo test --locked -p rssig-engine --no-default-features --features verify-core
cargo test --locked -p rssig-engine --no-default-features
cargo test --locked -p rssig-engine --no-default-features --features xml
cargo test --locked -p rssig-engine --no-default-features --features std
cargo test --locked -p rssig-engine --no-default-features --features msi
cargo test --locked -p rssig-engine --no-default-features --features appx
cargo clippy -p rssig-engine --all-targets --locked --no-default-features --features msi,appx -- -D warnings
cargo test --locked -p rssig-engine --no-default-features --features verify
cargo test --locked -p rssig-engine --no-default-features --features retrieval
cargo test --locked -p rssig --no-default-features --features crl-fetch
cargo test --locked -p rssig --no-default-features --features system-roots
cargo test --locked -p rssig --no-default-features --features cli
```

The bare-metal check compiles the library and its production dependencies on a
target without `std`; it does not execute fixtures on that target. Host tests in
`engine/tests/parse_core.rs` exercise the same parser API, typed errors, borrowed signer
encodings, and known PE digests in parser-only builds. The maximum `e_lfanew`
fixture pins rejection of malformed offsets without 32-bit arithmetic overflow.
`engine/tests/parse_text.rs` checks script/RDP canonical bytes, encoding/BOM behavior,
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

| Where | Package | What |
| --- | --- | --- |
| `tests/fixtures/`, `tests/cases.json`, `tests/fixtures/manifest.json` | shared | The portable specification and its fixtures, read by both packages; the engine reads the fixtures as `../tests/fixtures/`. |
| `tests/cli.rs`, `tests/cli/`, `tests/cli_interface.rs`, `tests/spec.rs`, `tests/manifest.rs` | `rssig` | CLI behavior, the JSON specification runner and manifest consistency, through `rssig::cli`. |
| `tests/repository.rs` | `rssig` | [Repository checks](#repository-checks): committed files no product code reads, such as the project skills' frontmatter. |
| `src/crl.rs`, `src/roots.rs`, `src/cli.rs`, `src/cli/` unit tests | `rssig` | The default HTTP CRL source, OS root adapter, CLI internals, and the agreement of the runner's `PATH_OPTIONS` with the private Clap definition. |
| `engine/tests/*.rs` | `rssig-engine` | The library API without the CLI: parsing, inspection, verification, policy, logging and trust loading. |
| `engine/src/tests.rs`, `engine/src/tests/`, module unit tests | `rssig-engine` | Engine internals and the ignored fixture generators. |

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

## Packaged crates

Tests run from the repository, not from a packaged crate. There is one fixture
directory, `tests/fixtures/`; the application's tests read it as
`tests/fixtures/...` and the engine's as `../tests/fixtures/...` (the layout
of [authenticode-rs](https://github.com/google/authenticode-rs), whose tool
reads its library's test data the same way and whose library package excludes
it). Each package lists what it publishes (`include` in its `Cargo.toml`):
its sources and licence files, without tests, the engine's `src/tests` tree,
documentation or repository housekeeping.

`make package-check` runs `cargo package --workspace --locked`, which builds
each packaged crate's library and binary from its own files. CI runs it in the
`package` job. It fails when library or binary source reads a file outside its
package. It builds no tests or doc examples: the engine's doc examples read
the shared fixtures too, so like the tests they run from the repository
(`cargo test --locked` runs them).

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

Reports exclude integration-test files and fixture builders under `engine/src/tests.rs`
and `engine/src/tests/`. Production source remains included, including the thin binary
adapter even though fixture and specification tests invoke the CLI library directly. A coverage
percentage is an execution measure, not a claim that every possible invalid
input or Windows policy has been tested.

## CI

GitHub Actions runs `make lint` in a dedicated Ubuntu lint job and
`cargo test --locked` in separate verification jobs on Linux and macOS.
A `package` job runs `make package-check` (see [Packaged crates](#packaged-crates)).
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
- `expect.json_absent`: optional with `json` (a JSON-mode case); a nonempty
  array of RFC 6901 JSON Pointers to members that must **not** be in the
  output, since `json` checks a subset and cannot say that a field is missing
  (a forged CRL is reported with `unusable_crl`, a set-aside one without it).
  - Each pointer names a member of an object, never an array element; it has no
    empty token and uses only the escapes `~0` and `~1`; none repeats.
  - The pointer's parent must exist in the output and be an object, so a
    mistyped pointer fails instead of passing. A member whose value is `null`
    is present.
  - A pointer may not name a member that `json` expects, nor a member of
    something `json` shows is not an object. This validation is best effort: a
    mistyped ancestor that `json` does not mention fails when the case runs.
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
regeneration is part of ordinary tests or coverage, with one exception that
writes nothing:
`certificate_paths_fixtures_preserve_image_cms_and_certificate_signatures`
runs the path fixture generator in memory and requires that the files it
generates are exactly those the manifest attributes to
`regenerate_path_fixtures` and that each committed file holds the generated
bytes. The generator is deterministic (fixed keys, RFC 6979 ECDSA), so a change
to it fails this test until the fixtures are regenerated and reviewed.

### Manifest consistency

`tests/manifest.rs` checks the manifest against the committed fixtures, the case
specification, and the tests and generators it names. It runs in
`cargo test --locked` and never regenerates or modifies a fixture. Rust sources
under each package's `src/` and `tests/` (`src/`, `tests/`, `engine/src/`,
`engine/tests/`; never `tests/fixtures/`) are parsed with `syn`, so comments and string literals never count as code; a
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
| Generators | Each `generator` names a Rust source file under a package's `src/` or `tests/` (or `build.rs`), by repository-relative path such as `engine/src/tests.rs`, optionally followed by `::function` naming a free function declared in it (`inner::function` inside an inline `mod inner`), then optionally whitespace and a note. Methods and anything inside a block (function bodies, closures, const initializers) cannot be named. |
| Case links | Each ID in `cases` is defined in `tests/cases.json` (`UnknownCase`) and listed once (`DuplicateCase`). |
| Case inputs | Every file a case reads is a listed artifact. `tests/common/spec_suite.rs` defines the case types and `Case::files_read`, shared with `tests/spec.rs`: `input`, `inputs`, CRL response bodies, `fixtures/...` arguments, `--roots`/`--crl` values in both forms, and plain arguments containing a path separator. It destructures every case and expectation field, so a new field does not compile until it is classified. As in Clap, a value starting with `-` directly after a path option is another flag (the option's value is missing), except a lone `-`. Arguments after `--` are positional files read relative to the CLI's working directory, so they always fail; in `--flag=value`, only the value is checked for a path or URL. CRL response bodies must be listed plain names, never intentionally absent ones, since the runner reads them whenever the CLI requests their URL. A path option without the `fixtures/` prefix (even a listed name), a path leaving the fixture directory, a trailing separator or `.` segment, or an exempt file such as `manifest.json` fails. A bare positional argument without a separator is not treated as a file: the existing ones only appear in argument-error cases the CLI rejects before reading anything. |
| Path options | `PATH_OPTIONS` equals every long name, alias, and short form of the options whose value Clap parses as a `PathBuf`, read from the real parser by the unit test `path_options_match_the_cli_definition` in `src/cli.rs`, which `include!`s the list from `src/cli/path_options.rs` (shared with `tests/common/spec_suite.rs`) so the parser stays private. Subcommands are walked at every depth. A new file-valued option, alias, or short form fails until the runner and this check know about it. |
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

## Repository checks

`tests/repository.rs` checks committed files that no product code reads, so a
malformed one fails `cargo test --locked` instead of passing unnoticed. YAML is
parsed with [`yaml-rust2`](https://crates.io/crates/yaml-rust2), a pure-Rust
YAML 1.2 parser and a dev-dependency of the root package only, never matched
with a pattern.

| Check | Requirement |
| --- | --- |
| Project skills | Every entry of `.claude/skills/` is a directory holding a `SKILL.md` whose first line is `---` and whose frontmatter, up to the next `---` line, is one valid YAML document (no duplicate keys): a mapping with a string `name` equal to the directory's name and a nonblank string `description`. The closing line may end the file and a CRLF line ending (a Windows checkout) is read as LF; a byte order mark is no `---` line, and a delimiter with trailing whitespace or a stray `\r` is reported as such. By-product regular files are skipped by the same rule as in [Manifest consistency](#manifest-consistency) (`tests/common/by_product.rs`: `.DS_Store`, `._name`, `.name.swp`, `name~`); a directory is always checked. `SKILL.md` is found by its exact name, even on a case-insensitive file system. A symbolic link, as `.claude`, `.claude/skills`, an entry or `SKILL.md`, is never followed and is reported as one, and so is a name that is not UTF-8. Every skill AGENTS.md names, as a backticked word (or a list of them joined by `,`, `and` or `or`) followed by the word `skill` or `skills` in any case, or as `/name` with any arguments (which AGENTS.md uses only for project skills), must be among those checked, and so must the three it names today; a code fence, double or escaped backtick, or unbalanced backtick in AGENTS.md fails the check. Name format and length limits are not checked (DOC-T015). |

Each rule has a test that feeds a broken copy and requires the expected
problem, including a description with an unquoted `: `, which makes the
frontmatter invalid YAML. The tests of the directory scan
(`committed_skills_*`) each create and remove a scratch directory under
Cargo's `CARGO_TARGET_TMPDIR`, named per test and process; the symbolic-link
cases run on Unix and the non-UTF-8 name case on Linux.

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
rssig re-encodes it, which equals the original for every committed fixture, to
an injected answer; requires `crl_responses`) makes the injected source
respond to a request for that certificate with that alone, as
a source keyed by certificate or issuer does; none of that certificate's
listed URLs is requested. Such answers are not listed in
`expect.crl_requests`, which holds URLs only
(`crl-017-fetch-completes-the-path-without-a-crl-beside-a-revoked-path`,
`crl-034-fetch-by-certificate-answer-requests-no-listed-point`). Expectations
match listed fields only, so the absence of `crl_retrieval.failures` is
asserted with `expect.json_absent`
(`crl-034-an-answer-with-several-bodies-settles-the-status`) and by the named
test `crl_fetch_by_certificate_answer_leaves_no_point_failures`.

An injected answer is either that fixture filename or a scripted object, for what a
source can return and a URL-to-file map cannot say:
- `crls`: the bodies of the response, in order, each `{"file", "url"?, "pad_to"?}`;
  a body without a `url` is offered by certificate or issuer (whether it counts as
  an answer by certificate is CRL-034's). `pad_to` zero-pads
  the body to that many bytes (at least the file's size, at most 16777216, and the
  `pad_to` values of a case add up to at most 67108864), so that a source can
  return a body over a size cap without a large fixture. A `pad_to` of the
  file's own size pads nothing, so that body is held to the caps as an
  unpadded one is; the case total still counts every `pad_to` value, so it
  is the stricter bound.
- `failures`: the failures of the response, in order, each `{"kind", "url"?}`
  with `kind` one of `denied`, `failed`, `abort` and `unknown`. When some
  listed point is left that no body or failure named, the first one without a
  `url` answers those points, unless a body answered by certificate while
  retrieval had not aborted (an abort anywhere in this response cancels this,
  one naming a URL included:
  `an_abort_naming_one_point_does_not_relabel_the_others`) and it is no abort,
  or another failure without a `url` is an abort and this one is not
  (`the_first_of_two_aborts_without_a_url_answers_the_points`). Otherwise, with no point
  left (`a_failure_without_a_url_is_recorded_as_it_is_when_every_point_was_named`),
  and for every later one without a `url`, it is recorded as it is, for no
  point (`engine/src/retrieval.rs`, around the `whole_request` handling, and its unit
  tests). Nothing is asked after an abort, so no earlier response can hold one
  (`abort_stops_every_further_request`).
- `error`: one `{"kind", "url"?}`, the source failing the whole request
  instead of returning a response. It excludes `crls` and `failures`, and an
  answer holds at least one of the three.

The runner does not check a padded scripted body against the request's byte
allowance: a source that returns more than it may is a case (`pad_to`), and the
engine judges the size. Any other answer over the allowance, plain or a
scripted body without `pad_to`, fails the case instead, so an oversized body is
always given on purpose. A scripted body is judged by what the bodies before it
left of the allowance, counted as the engine counts it: a body within the caps
spends it, one over them does not.

The cases pin the code and the cause of each failure, not that a failure naming
no URL is recorded once per listed point; the unit test
`a_failure_without_a_url_in_a_response_answers_every_point` in
`engine/src/retrieval.rs` pins that.

A scripted `url` must be one of the points this request carries, spelled as
listed or in its normalized form: the two are equal once each is parsed and
serialized as the WHATWG URL Standard does (the `url` crate's `Url`), which
lower-cases the scheme and host and drops a default port. The engine matches a
source's URL to a listed point the same way, and the report keeps the
source's spelling
(`crl-026-a-failure-naming-the-point-by-its-normalized-url-is-recorded-for-it`,
guarded by `specification_a_point_named_by_its_normalized_url_is_spelled_otherwise`).
The runner fails a case whose URL is not one of them, and its message
prints the listed points. A point shared by two certificates is carried by
each request (CRL-050), so a scripted `url` answers it for every certificate
asked by URL, and the runner's source, which keeps no cache, is asked for it
each time:
- a point that fails is requested and recorded for each certificate
  (`crl-051-a-failed-point-is-asked-and-recorded-for-each-certificate`);
- a scripted answer for a later certificate may name a point an earlier
  certificate's request used, because the later request carries it too
  (`crl-050-a-certificate-whose-point-another-used-is-still-asked`; the runner
  fails the case if the request leaves the point out);
- a certificate given an injected answer by certificate requests none of its
  own points, and a point its answer leaves unused is still carried by a later
  certificate, whose URL answer then requests it
  (`crl-050-a-point-left-unused-is-offered-for-a-certificate-of-another-issuer`:
  the signer is answered by certificate, and the issuer's certificate is the
  one the URL answers).

All of these run on `crl-chain-shared-crl-dp.exe`. A
URL that went stale or was mistyped therefore cannot turn a case about the point
into one about a URL outside the request; the engine's handling of one outside it
is unit-tested
(`a_whole_request_error_naming_a_foreign_url_is_not_attributed_to_the_certificate`
and, for one inside a response, the tests CRL-049 lists; a case that names one
on purpose is CRL-T059).

The runner also fails a case whose `pad_to` would cut its file, and a case with an
injected answer, plain or scripted, that nobody requested (a stale certificate
hash, or an engine that stopped asking; a case does not carry one for a
certificate it never asks about). A response keyed by URL (`crl_responses`) may go
unrequested: a
case maps one to show that nothing is asked
(`crl-018-forged-local-asks-nothing`, `crl-035-no-next-update-local-asks-nothing`),
and `expect.crl_requests` is what fails it if the engine starts asking. The schema
cannot express these run-time rules; an implementation enforces them itself.
A scripted answer with any problem is never sent: the runner names every
problem of the answer first, then the source aborts, so the engine never runs a
response other than the one the case scripts
(`specification_an_answer_with_a_problem_is_never_sent`).
They hold for every case with an injected answer, plain or scripted, including
older ones such as the `crl-034-fetch-by-certificate-` cases.

The cases with a scripted answer, and those of CRL-045, CRL-048 and CRL-049, are
listed below.
Some cases run the same input under different entries, since a case names one:
`crl-048-a-body-that-is-not-a-crl-is-never-evidence` and
`crl-049-a-body-that-is-not-a-crl-is-reported-before-the-point-it-left`, and
`crl-045-body-over-the-size-cap-is-no-answer`,
`crl-046-an-over-cap-body-reports-the-cap-it-hit` and
`crl-049-an-over-cap-body-is-reported-before-the-point-it-left`; beside the
shared result code, each pins its own entry's part:
- `crl-026-url-less-denial-answers-the-listed-point`
- `crl-026-whole-request-failure-answers-the-listed-point`
- `crl-047-url-less-abort-is-reported`
- `crl-047-url-less-abort-beside-another-failure-marks-the-point-not-tried`
- `crl-026-url-less-unknown-failure-answers-the-listed-point`
- `crl-026-url-less-failed-failure-answers-the-listed-point`,
  `crl-026-whole-request-denial-answers-the-listed-point` and
  `crl-026-whole-request-unknown-failure-answers-the-listed-point`
- `crl-047-whole-request-abort-is-reported` and
  `crl-047-an-abort-beside-a-revoking-crl-leaves-the-result-unmarked` (a
  definite result after an abort keeps its code, unmarked)
- `crl-026-a-failure-naming-the-point-is-recorded-for-it` and
  `crl-026-a-failure-naming-the-point-by-its-normalized-url-is-recorded-for-it`
- `crl-034-an-answer-with-several-bodies-settles-the-status`
- `crl-049-a-body-that-is-not-a-crl-is-reported-before-the-point-it-left` and
  `crl-049-an-over-cap-body-is-reported-before-the-point-it-left` (CRL-049: a
  body rejected on load comes before the point it left)
- `crl-048-a-body-that-is-not-a-crl-is-never-evidence`
- `crl-048-a-crl-of-another-issuer-is-never-evidence`
- `crl-048-a-crl-signed-by-another-key-is-never-evidence` and
  `crl-048-an-authentic-crl-from-a-source-revokes` (CRL-048: a source is never
  trusted; its CRL is authenticated like a supplied one)
- `crl-045-body-over-the-size-cap-is-no-answer` (a body over
  the 8 MiB cap is no answer, so the result is `revocation_unknown` with no
  artifact; `crl-049-an-over-cap-body-is-reported-before-the-point-it-left`
  pins its failures in CRL-049's order)
- `crl-046-an-over-cap-body-reports-the-cap-it-hit` (CRL-046: the cap it hit,
  `limit`, `requested` and `used`, then the point it left)
- `crl-046-a-spent-byte-allowance-leaves-the-point-not-tried` and
  `crl-046-a-byte-short-of-the-allowance-leaves-the-point-failed` (CRL-046: four
  bodies within 8 MiB, none a CRL, that add up to exactly the request's
  allowance leave the point not tried, `resource_limit_exceeded` with `limit`
  and `used` both the allowance; one byte less leaves it `crl_fetch_failed`.
  Either way the result is `revocation_unknown`. The input lists one point,
  so the spent case pins the unanswered point, not several left over; that is
  `points_left_when_the_byte_allowance_is_spent_are_not_tried`)
- `crl-045-oversized-body-does-not-count-against-the-next` (two rejected 16 MiB
  bodies would reach the allowance if they counted)
- `crl-045-over-allowance-body-does-not-count-against-the-next` (bodies under
  8 MiB that together pass the 32 MiB allowance; they pad a certificate, never a
  CRL, so only the last body can answer whatever the CRL decoder accepts, and the
  artifacts show the fifth was not taken)

The cases on `crl-chain-shared-crl-dp.exe` (CRL-050 and CRL-051), which answer
by certificate, fail a point or deny it:
- `crl-050-a-point-left-unused-is-offered-for-a-certificate-of-another-issuer`
  (the signer's answer by certificate leaves the point unused, so the issuer's
  certificate carries it and the URL answers it)
- `crl-050-a-certificate-whose-point-another-used-is-still-asked` (the URL
  answers the signer, and the issuer's certificate is asked carrying the same
  point: its scripted answer names it, which the runner accepts only for a
  point the request carries)
- `crl-051-a-failed-point-is-asked-and-recorded-for-each-certificate` and
  `crl-051-a-denied-point-is-recorded-for-each-certificate` (the point is
  requested for each certificate, fails or is denied each time, and each
  certificate's report records it)

The `crl-045-` cases pin CRL-045. The two `does-not-count-against-the-next`
cases each fail if a rejected body counted against the bodies after it, which
was checked by changing the engine; the single-body case pins only that an
over-cap body is no answer. Their sizes are chosen against the engine's caps,
and `specification_the_crl_045_cases_rest_on_the_engines_caps` fails if a cap
moves so that a case would pass without testing what it says.
`specification_the_crl_046_allowance_cases_rest_on_the_engines_caps` does the
same for the two allowance cases of CRL-046, whose bodies must add up to the
allowance and to one byte less. The first case fails if the engine took an
allowance as spent only once passed, the second if it took one as spent a byte
early; both were checked by changing the engine.

Named tests in `tests/cli/crl_fetch.rs` check what the cases leave out:
- `crl_fetch_by_certificate_failures_are_serialized_for_the_listed_point`: the
  stage, problem type and title of each source failure, beside what the cases
  pin.
- `crl_fetch_by_certificate_a_body_that_is_not_a_crl_leaves_the_point_unanswered`:
  both failures, the body first, from a source written in Rust.
- `crl_fetch_by_certificate_a_body_over_the_size_cap_is_rejected_and_leaves_the_point_unanswered`:
  the same failures as `crl-046-an-over-cap-body-reports-the-cap-it-hit`,
  from a source written in Rust, with the cap read from
  `rssig_engine::retrieval::MAX_CRL_BYTES` rather than written out.

The failures of those two bodies come in CRL-049's order (a body rejected on
load before a point left unanswered), so the
cases `crl-049-a-body-that-is-not-a-crl-is-reported-before-the-point-it-left`
and `crl-049-an-over-cap-body-is-reported-before-the-point-it-left` pin them.

A point shared by certificates of two issuers is expressible: the
`crl-050-` and `crl-051-` cases run `crl-chain-shared-crl-dp.exe`, whose signer
and issuer certificate list one point. The built-in source's deadline and
byte cap are not expressible in a case, because they need real HTTP, which a
case never makes. The built-in source's are
unit-tested without a network in `src/crl.rs`, which stays their
place.

A case may carry a `decision` (not used to run it): the ID of the entry it
pins in a decision index under `docs/`, such as `"decision": "CRL-001"` for
[CRL decisions](crl.md). The entry states the rule once, with its Status
(`Decided` or `Observed`), who decided it, whether it pins `acceptance` or
`diagnostics`, and its sources; a case without `decision` counts as observed.
`tests/spec.rs` reads every `### PREFIX-NNN: title` entry in `docs/*.md`,
checks its fields, and checks that each case's `decision` names an entry. See
AGENTS.md, "Pinned expectations".

Every test build in the repository enables the engine's internal
`revocation-crosscheck` feature: the engine's tests through its self
dev-dependency in `engine/Cargo.toml`, the application's through its
dev-dependency on `rssig-engine` in the root `Cargo.toml`. Each test crate
includes a guard that fails the build without it. After rssig accepts a path's
revocation status, it re-runs webpki's own revocation check with the CRLs
rssig chose and panics on disagreement, so every fixture case with CRLs also
checks that rssig and webpki agree. Product builds never enable it, and it is
also compiled out without `debug_assertions`, so release test runs skip it; see
[CRL-T011](tasks/crl-t011.md).

These retrieval behaviors have unit tests only: no committed input can reach
them through the CLI, or, where noted, no case pins them yet:

- An error with `details.reason` `ambiguous_issuer_keys` is final for retrieval. Since
  CRL-T011 it is produced only by the accepted-path rule for same-name issuers
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
- At most 64 CRL bodies, and bodies and failures together at most 64 plus one per point offered, in one source response
  (`crl_response_entries`). A scripted answer can now reach it, and no case
  pins it yet (LIMIT-T006);
  `retrieval::tests::a_response_with_too_many_entries_is_not_used_and_the_run_goes_on` covers it,
  and `retrieval::tests::an_abort_in_a_response_past_the_entry_bound_still_stops_retrieval`
  an abort inside such a response.
- Supplied roots and CRLs over the retained-byte cap, which leave every
  certificate unasked (`retrieval_trust_bytes`): only the library can supply
  them, since the CLI loads at most the cap
  (`the_cli_never_supplies_more_than_the_engine_retains`), and no case pins the
  store at the cap yet (LIMIT-T008);
  `retrieval::tests::supplied_evidence_over_the_retained_byte_cap_asks_nothing_and_the_result_stands`
  covers it.
- Several points left once a request's byte allowance is spent: no case pins
  them, since the input of the CRL-046 allowance cases lists one point;
  `retrieval::tests::points_left_when_the_byte_allowance_is_spent_are_not_tried`
  covers several.
- The built-in HTTP source's kinds (a last request keeping its own failure,
  aborts when spent). Tests never use the network, so these are unit tests
  in `src/crl.rs`.
