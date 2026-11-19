# Injected diagnostic logging

rssig has no global logger and no logging dependency. The engine writes to no
stream and emits nothing unless the caller supplies a `rssig::log::Logger`.
Logging is available with `verify-core`, including `no_std + alloc` builds.

```rust
use rssig::{log::{Level, Logger, Record}, verify::{Verifier, VerifyOptions}};
use std::sync::Mutex;

struct Lines(Mutex<Vec<String>>);
impl Logger for Lines {
    fn enabled(&self, level: Level) -> bool { level >= Level::Info }
    fn log(&self, record: &Record<'_>) {
        self.0.lock().unwrap().push(format!("{:?} {:?} {}", record.level, record.stage, record.message));
    }
}

// `bytes` holds the file to verify.
let lines = Lines(Mutex::new(Vec::new()));
let options = VerifyOptions::integrity_only(1800000000);
let report = Verifier::new(&options).with_logger(&lines).verify(bytes)?;
```

## Interface

- `Logger::log(&self, &Record)` receives each record. `Logger::enabled(level)`
  defaults to `true`; return `false` to skip a level before its record is built.
  `Logger` requires `Sync`, so a `Verifier` with a logger can still be shared
  across threads. Keep interior state in atomics or a lock.
- `Record` has a `level`, the verification `stage` (the same `domain::Stage` that
  errors carry), and a lazily formatted `message`. `Level` is ordered
  `Debug < Info < Warn`. Both types are non-exhaustive.
- `verify::Verifier::new(&options).with_logger(&logger)` offers `verify`,
  `verify_with_hint`, `verify_as` and, with `crl-fetch`, `verify_with_crl_source`.
  Without a logger each behaves exactly like the free function of the same name.
- `cli::run_with_host(argv, stdout, stderr, Host::new().with_logger(&logger))`
  injects a logger into the in-process CLI. `Host` also carries the optional
  `CrlSource`, so both can be supplied together.

`VerifyOptions` is unchanged: its public fields and struct literals stay
source-compatible, and every existing free function keeps its signature and
logs nothing.

## What is logged

| Level | Stage | Event |
| --- | --- | --- |
| `Warn` | `configuration` | Integrity-only policy, disabled revocation, or permitted SHA-1 content digests; once per verification |
| `Warn` | the error's stage | The typed failure that ended verification, with its code and message |
| `Warn` | `revocation` | A certificate with good status is listed by an authenticated CRL that did not count (not current, older than the deciding CRL, or not covering it) |
| `Info` | `cms` | Each verified signer: subject and certificate SHA-256 |
| `Info` | `revocation` | Each CRL request made through a `CrlSource` |
| `Debug` | `input`, `cms`, `timestamp`, `certificate_chain`, `revocation` | Detected format and size, CMS signer/certificate counts, digest match, timestamp, validated path length and revocation status, retrieval passes and response sizes |

The CLI adds one `Debug`/`input` record naming each file before it is verified.

## Limits

- A record is a diagnostic, not a verdict. A "signer verified" record can be
  followed by a failure of a later signer, nested signature or bundle child.
  Only the returned `VerificationBundle` or `VerificationError` states the
  outcome. A logger cannot change it: reports and errors are identical with
  and without one.
- Messages are unstable prose. Match error codes, stages and report fields,
  never message text.
- Messages can quote text derived from untrusted input, such as certificate
  subjects and CRL URLs. That text is Rust-debug-escaped, but a sink must still
  treat every message as untrusted data.
- Logging is not charged to [verification budgets](verification-budgets.md). A
  sink bounds its own retention and I/O, and must not panic or block.
- `verify_parsed_*` entry points and the `parse` command do not log.
- The `rssig` binary has no logging flag and injects no logger, so its stdout
  and stderr contract is unchanged.
