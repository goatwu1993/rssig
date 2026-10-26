# Tests and coverage

Run the complete suite with:

```sh
cargo test --locked
```

Every fixture regression is an individually named Rust test. `tests/cli/pe.rs`
and `tests/cli/msi.rs` contain the 142 migrated cases, with their exit codes,
error identities, diagnostics, exact array lengths, and serialized domain fields
preserved. Rust/Cargo reports each case directly; no JSON case file, custom
runner, or subprocess is involved.

The binary's only job is to pass process arguments and stdout to the public
Clap-based `rssig::cli::run` entry point. That function takes argv including the
program name and a writer, returns an exit code, and never calls `process::exit`.
Tests exercise the actual parser and command implementation in-process:

```rust
let mut stdout = Vec::new();
let exit_code = rssig::cli::run(["rssig", "--help"], &mut stdout).unwrap();
let report: serde_json::Value = serde_json::from_slice(&stdout).unwrap();
assert_eq!(exit_code, 0);
assert_eq!(report["command"], "help");
```

`tests/cli_interface.rs` tests help/version, invalid arguments, policy conflicts,
configuration errors, multiple inputs, and writer failures. Fixture tests use
absolute paths and pinned validation times without changing process-global cwd
or environment. The committed PE/MSI artifacts are data, never executed. The
public domain types must deserialize captured verification reports.

The `rssig test --cases ...` subcommand and its suite schema were removed. Use
Cargo filters to run one regression or group:

```sh
cargo test --locked --test cli pe::tampered_image -- --exact
cargo test --locked --test cli msi::
cargo test --locked --test cli_interface
```

## Coverage reports

Install the optional development tool and matching LLVM tools:

```sh
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --version 0.9.1 --locked
```

Run all native tests with instrumentation once, then render both formats:

```sh
cargo llvm-cov clean --workspace
cargo llvm-cov --locked --all-targets --no-report
cargo llvm-cov report --ignore-filename-regex '(^|/)tests(/|\.rs$)' --html --output-dir target/coverage
cargo llvm-cov report --ignore-filename-regex '(^|/)tests(/|\.rs$)' --cobertura --output-path target/coverage/cobertura.xml
```

Open `target/coverage/html/index.html` directly in a browser. Cobertura consumers
can read `target/coverage/cobertura.xml`. Both reports use the same recorded run;
rendering a second format does not rerun tests. No coverage service or token is
required. Coverage and test tooling are not runtime dependencies.

With a Homebrew Rust installation, set `LLVM_COV` and `LLVM_PROFDATA` to matching
LLVM binaries instead of installing a rustup component. Their LLVM major version
must be compatible with `rustc -vV` (for example, Homebrew LLVM tools under
`/opt/homebrew/opt/llvm/bin/`).

Reports exclude integration-test files and fixture builders under `src/tests.rs`
and `src/tests/`. Production source remains included, including the thin binary
adapter even though fixture tests invoke the CLI library directly. A coverage
percentage is an execution measure, not a claim that every possible invalid
input or Windows policy has been tested.

## CI

GitHub Actions runs `cargo fmt --check`, Clippy, and `cargo test --locked` on
Linux and macOS. A separate Linux coverage job runs the same Cargo suite with
instrumentation and uploads the `coverage` artifact. Download and extract it,
then open `html/index.html`; `cobertura.xml` is alongside the HTML directory.
The ordinary test jobs require no coverage tool. No job regenerates fixtures or
needs Java, Go, external signing tools, system trust contents, or network CRLs.
