# Fuzzing

Coverage-guided fuzz targets live in the detached `fuzz/` crate. They need a
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
| `parse_cms` | `SignedData::parse`/`inspect`, `SignerInfo`, `Attributes`, `AlgorithmIdentifier`, `TstInfo`, `ParsedTime` | `der`, `bin`, `crl` |
| `parse_pe` | `Pe::parse`, `signatures`, `authenticode_digest`, then CMS on each blob | `exe` |
| `parse_cab_navx` | `Cab::parse`, `Navx::parse` and their digest ranges | `cab`, `navx` |
| `parse_msi` | `Msi::parse`, metadata and content digest streaming | `msi`, `msp` |
| `parse_appx` | `Appx::parse`, ZIP parts, content types, identities, `BlockMap` | `msix`, `appx`, bundles |
| `parse_text` | `Powershell::parse`/`parse_xml`, `Wsh::parse` for each kind, `Rdp::parse` | script and `rdp` fixtures |
| `verify_binary` | `verify_as` for PE, MSI, AppX, CAB and NAVX | all binary container fixtures |
| `verify_text` | `verify_as` for each text format, plus `verify` detection | script and `rdp` fixtures |

The two `verify_*` targets use `VerifyOptions::integrity_only` with a fixed
validation time. They load no roots or CRLs, read no clock, and perform no
network or filesystem access, so runs are reproducible. `verify_binary` also
repeats each input with `allow_sha1` to reach the legacy digest branch.
Configured-root trust, revocation, and CRL retrieval are **not** fuzzed.

## Running

```sh
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --version 0.13.2 --locked

make fuzz                    # seed, then 30 seconds per target
make fuzz FUZZ_SECONDS=3600  # longer local run
cargo +nightly fuzz run parse_pe -- -max_len=131072 -timeout=10
```

`make fuzz-seed` (or `fuzz/seed-corpus.sh`) copies committed fixtures into
`fuzz/corpus/<target>/`. The corpus, `fuzz/artifacts/`, and `fuzz/target/` are
git-ignored; fixtures remain the single committed source of seeds. Seeding only
copies files: it never executes, opens, or installs a fixture.

Default limits are a 128 KiB maximum input, a 10 second per-input timeout, and
a 2 GiB memory limit. The largest committed seed is under 80 KiB.

## Continuous integration

`.github/workflows/fuzz.yml` runs each target for 60 seconds on pull requests
and pushes to `main`, one matrix job per target, and uploads any crashing input
as a workflow artifact. A manual dispatch accepts a longer duration. This is a
regression smoke test, not a substitute for long local or scheduled runs.

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
| 2026-11-18 | 7 minutes per target, 4 cores, Linux x86-64, about 9.9 million executions in total | No panics, timeouts, or memory-limit failures in any target. |

Short runs find shallow bugs only. An absence of findings here is not evidence
that deeper states are safe.
