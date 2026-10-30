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

Every fixture regression is an individually named Rust test. `tests/cli/pe.rs`
and `tests/cli/msi.rs` contain the 142 migrated cases, with their exit codes,
error identities, diagnostics, exact array lengths, and serialized domain fields
preserved. Rust/Cargo reports each named test directly. Separately, `tests/spec.rs` uses
Serde to load `tests/cases.json` and invokes the same CLI library for every
declarative case. Neither path spawns a child process.

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

`tests/cli_interface.rs` tests help/version, invalid arguments, policy conflicts,
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
