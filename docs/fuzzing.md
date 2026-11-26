# Fuzzing

Coverage-guided fuzz targets live in the detached `fuzz/` crate. They target
the engine package (`rssig-engine`), and the application package (`rssig`)
only for the default CRL source's URL policy (`check_url`). They need a
nightly toolchain and [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz), so
they are optional: `cargo test --locked`, `make lint`, and the stable build
never compile or run them. `fuzz/` has its own `[workspace]` and lockfile.

## Property

Every target asserts the same thing: **any byte string returns a value or a
typed error.** A panic, an arithmetic or slice-bounds abort, a hang beyond the
per-input timeout, or memory growth beyond the limit is a bug. The targets do
not assert verdicts; accepting a forged signature is not something a fuzzer can
detect without an oracle. Differential testing against another verifier remains
separate work.

## Targets

| Target | Entry points | Seeds (by fixture extension) |
| --- | --- | --- |
| `parse_cms` | `SignedData::parse`/`inspect`, `SignerInfo`, `Attributes`, `AlgorithmIdentifier`, `TstInfo`, `ParsedTime` | `der`, `crl` |
| `parse_pe` | `Pe::parse`, `signatures`, `authenticode_digest`, then CMS on each blob | `exe` |
| `parse_cab_navx` | `Cab::parse`, `Navx::parse` and their digest ranges | `cab`, `navx` |
| `inspect` | The engine's `inspect::pe`, `cms`, `cab` and `navx` reports | `exe`, `der`, `cab`, `navx` |
| `parse_msi` | `Msi::parse`, metadata and content digest streaming | `msi`, `msp` |
| `parse_appx` | `Appx::parse`, ZIP parts, content types, identities, `BlockMap` | `msix`, `appx`, bundles |
| `parse_text` | `Powershell::parse`/`parse_xml`, `Wsh::parse` for each kind, `Rdp::parse` | script and `rdp` fixtures |
| `verify_binary` | `verify_as` for PE, MSI, AppX, CAB and NAVX | all binary container fixtures |
| `verify_text` | `verify_as` for each text format, plus `verify` detection | script and `rdp` fixtures |
| `verify_trusted` | `verify` against the committed test root and CRLs, with revocation required and disabled | container, script and `rdp` fixtures |
| `verify_logged` | `Verifier::verify` with an injected logger that formats every record, compared with `verify` | container, script and `rdp` fixtures |
| `trust_loading` | `TrustStore::add_roots`/`add_crl`/`from_system_roots`, then `verify_pe` of one fixed valid image | `der`, `crl`, `pem` |

`verify_binary` and `verify_text` use `VerifyOptions::integrity_only`.
`verify_binary` repeats every format, including CAB and NAVX, with `allow_sha1`
to reach the legacy digest branch.

`verify_trusted` and `trust_loading` cover configured-root trust from both
sides. `verify_trusted` fixes the store (`root.der`, `good.crl`,
`good-intermediate.crl`) and mutates the artifact and its embedded, untrusted
certificates, reaching path building, EKU and time checks, and CRL
applicability. `trust_loading` fixes one valid image (`good-pe64.exe`) and
mutates the roots or CRLs it is verified against.

All four use a fixed validation time and perform no clock, system-root,
network, or filesystem access, so runs are reproducible. `verify_retrieval`
drives the engine's retrieval through an in-memory source; the application's
HTTP transport (`rssig::crl::HttpCrlSource`) is **not** fuzzed beyond its URL
check (`check_url`).

`fuzz/targets.txt` is the single list of targets and their seed extensions.
The seeding script, the Makefile, and CI all read it.

## Running

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --version 0.13.2 --locked

make fuzz                         # seed, then 30 seconds per target
make fuzz FUZZ_SECONDS=3600       # longer local run
make fuzz FUZZ_TARGETS=parse_pe   # one target
make fuzz-cmin                    # shrink local corpora to inputs that add coverage
cargo +nightly fuzz run parse_pe -- -max_len=131072 -timeout=10
```

`make fuzz` invokes cargo through `rustup run nightly`, so it works when a
Homebrew `cargo` is first on `PATH`, and passes the host `--target` explicitly:
a prebuilt (musl) cargo-fuzz binary otherwise selects a musl target that the
address sanitizer cannot use. Add `--target <host triple>` when calling
`cargo fuzz` directly with such a binary. Every target runs even after one
fails; the failures are listed at the end.

`make fuzz-seed` (or `fuzz/seed-corpus.sh`) copies committed fixtures into
`fuzz/corpus/<target>/`. The corpus, `fuzz/artifacts/`, and `fuzz/target/` are
git-ignored; fixtures remain the single committed source of seeds. Seeding only
copies files: it never executes, opens, or installs a fixture.

Default limits are a 128 KiB maximum input, a 10 second per-input timeout, and
a 2 GiB memory limit. The largest committed seed is under 80 KiB.

## Continuous integration

`.github/workflows/fuzz.yml` runs `make fuzz` in one job, so all targets share
one build:

| Trigger | Per target | Corpus cache |
| --- | --- | --- |
| Pull request | 60 seconds | Restored, never saved |
| Push to `main` | 60 seconds | Restored, minimized, saved |
| Weekly schedule | 900 seconds | Restored, minimized, saved |
| Manual dispatch | `seconds` input, at most 16,200 divided by the number of targets (1,157 for 14): 270 minutes of fuzzing, leaving 75 of the 345-minute job for the build, cache and minimization | Restored, minimized, saved |

The scheduled and push durations shrink to 16,200 seconds divided by the
number of targets when they would exceed it, so adding targets never fails
those runs; a larger manual `seconds` input is refused.

The cached corpus accumulates inputs across runs, so each run starts from what
earlier runs discovered instead of from the fixtures alone. Crashing inputs are
uploaded as a workflow artifact. Pull-request runs are a regression smoke
test; the weekly run is the one expected to find new behavior. The nightly
toolchain is not pinned, so a toolchain regression can fail this workflow
independently of a change.

`make lint` (and therefore the stable Lint job) runs `make fuzz-lint`:
`fuzz/check.sh`, then rustfmt and Clippy on the fuzz crate. Clippy compiles the
targets, so an `rssig-engine` or `rssig` API change that breaks one fails Lint without nightly.

## Maintenance

`fuzz/check.sh` needs no fuzzing toolchain and fails when:

- `fuzz/targets.txt`, `fuzz/fuzz_targets/*.rs`, and the `[[bin]]` entries in
  `fuzz/Cargo.toml` name different targets; or
- a package shared with the root `Cargo.lock` has no version in common with
  it, meaning fuzzing would exercise dependencies that do not ship.

After changing the root `Cargo.lock`, resynchronize the fuzz lockfile:

```sh
cp Cargo.lock fuzz/Cargo.lock
cargo metadata --manifest-path fuzz/Cargo.toml --format-version 1 >/dev/null
```

Cargo keeps the copied versions and only adds the fuzz-only packages.

When adding a parser or public entry point, add a target (source file,
`[[bin]]`, and a `targets.txt` line) in the same change. Every few months, run
`cargo +nightly fuzz coverage <target>` and check that the parser and verifier
modules a target is meant to reach are actually covered; a passing run only
shows that nothing crashed.

## Handling a finding

1. Reproduce: `cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>`.
2. Minimize: `cargo +nightly fuzz tmin <target> <file>`.
3. Follow the [AGENTS.md](../AGENTS.md) TDD workflow: commit the minimized
   input under `tests/fixtures/` with manifest provenance, add a case to
   `tests/cases.json` and a named Rust test, observe the failure, then fix.
4. Never commit a crashing input only to the fuzz corpus; ordinary tests must
   cover the regression without the fuzzing toolchain.

## Recorded runs

| Date | Duration | Result |
| --- | --- | --- |
| 2026-11-18 | 7 minutes per target (the first eight targets), 4 cores, Linux x86-64, about 9.9 million executions in total | No panics, timeouts, or memory-limit failures in any target. |
| 2026-11-18 | 6 minutes each for `verify_trusted`, `trust_loading`, and the revised `verify_binary`, same host, about 0.8 million executions in total | No panics, timeouts, or memory-limit failures. |

Short runs find shallow bugs only. An absence of findings here is not evidence
that deeper states are safe.
