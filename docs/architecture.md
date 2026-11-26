# Code responsibilities

rssig is a Cargo workspace of two packages, one per layer. The engine decides;
the application supplies what the engine leaves to its caller.

| Package | Path | Owns | Never does |
| --- | --- | --- | --- |
| `rssig-engine` | `engine/` | Parsing, hashing, CMS, certificate paths, timestamps, revocation, reports and error codes; the policy options (`VerifyOptions`, `RevocationPolicy`) and the collaborator interfaces (`retrieval::CrlSource`, `log::Logger`) | Read files, the clock, the environment or the network; enumerate OS roots; choose a default policy or host limit |
| `rssig` | `./` | The CLI (argv, files, clock, streams, exit codes), host input and report limits, the default policy the CLI builds from its flags, and the default collaborators: `crl::HttpCrlSource` and `roots::system_roots` | Parse, hash or verify anything itself |

The dependency is one-way: `rssig` depends on `rssig-engine`, never the
reverse, so nothing in the engine can reach an application default. The
application re-exports the engine as `rssig::engine` so an embedder of the CLI
can name the types it injects. A library that brings its own roots, CRLs and
clock depends on `rssig-engine` alone.

## Engine modules (`engine/src/`)

| Module | Responsibility |
| --- | --- |
| `format` | Public verifier-feature selector and filename-hint detection without filesystem access. Input classification: binary magic, then optional filename hints, then text signature markers. Unknown input retains the historical PE fallback. |
| `parse` | `no_std + alloc` PE/CAB/NAVX/CMS/script/RDP structures, typed parsing errors, and borrowed container digest chunks; no signature verification, trust, clocks, or file I/O. |
| `parse/msi.rs` | Optional `msi`/`std` CFB structure, extracted signature streams, and generic canonical metadata/content input; no digest comparison or reports. |
| `parse/appx.rs` / `parse/appx/zip.rs` | Optional `appx`/`std` ZIP/DEFLATE/XML structures, parts, component inputs, identities, bundle entries and lazy block-map views. |
| `parse/signer.rs` | Borrowed untrusted CMS signer, identifier, attribute and content views; shared structural helpers preserve verification check order. |
| `inspect` | Public, unverified inspection reports (`pe`, `cms`, `cab`, `navx`) projected from parser values, preserving raw DER. Never calls the verifier. |
| `pe` / `cab` / `navx` / `powershell` / `wsh` / `rdp` | Verifier-side adapters over the parsers: digests, framing and, for RDP, the detached-content pipeline. |
| `msi` / `appx` | Package integrity checks, digest comparisons and report construction over shared structural parsers. |
| `verify/mod.rs` | Public verification entry points, explicit options, the `Verifier` with its injected logger, and container construction. |
| `verify/container.rs` | Embedded CMS extraction and each container's padding/framing rules. |
| `verify/integrity.rs` | SIP/content binding, algorithm checks, image/package/script digests, and PE page hashes. Returns digest evidence to the signer pipeline. |
| `verify/authenticode.rs` | Ordered signer pipeline: integrity, CMS authentication, publisher binding, timestamp, configured trust, report, nested signatures. |
| `verify/appx.rs` | Embedded bundle package verification and package identity/signer binding. |
| `verify/timestamp.rs` | RFC 3161/PKCS#9 binding, TSA validation, canonical time decoding, and fractional expiry checks. Shared with RDP verification. |
| `verify/budget.rs` | Aggregate per-verification work budgets. |
| `cms` / `crypto` | Authenticode/CMS interpretation and signature verification using RustCrypto primitives. |
| `trust` | Configured trust anchors (explicit DER/PEM, or roots an OS adapter hands to `TrustStore::from_system_roots`), webpki path building, rssig's per-certificate CRL evaluation (the only revocation check); `trust/error.rs` maps adapter errors. |
| `retrieval` | Optional (`retrieval` feature): the `CrlSource` interface, distribution-point discovery and the retrieval loop that asks the injected source and verifies again. No transport. |
| `log` | The injected `Logger` interface and its per-verification sink. |
| `domain` | Public Serde result/error declarations and stable diagnostics. |
| `report` | Conversion from decoded certificate/CRL metadata to domain reports, preserving unfamiliar values. |

## Application modules (`src/`)

| Module | Responsibility |
| --- | --- |
| `cli` | Top-level command dispatch, stdout/stderr, exit codes, and `Host`, the collaborators an embedder injects in place of the defaults. |
| `cli/batch.rs` | Shared file reads, ordered results, first-failure Problem Details, and JSON envelopes. |
| `cli/verify.rs` | Verification arguments and the default policy: roots (OS store unless `--no-system-roots`), CRLs, the validation clock, revocation and the default CRL source. |
| `cli/parse.rs` | Inspection arguments and explicit PE/CMS/CAB/NAVX selection, calling `engine::inspect`, with no verification setup. |
| `cli/limits.rs` | Host limits: input, report and trust-file sizes, path counts, and the size of the loaded trust store. |
| `crl` | `HttpCrlSource`, the default `CrlSource`: bounded public HTTP, its URL policy (`check_public_http_url`) and its own request, URL, byte and time limits (CRL-039). |
| `roots` | `system_roots`, the default root source: OS enumeration through `rustls-native-certs`, validated by the engine. |
| `main.rs` | The binary: `cli::run_with_writers` on the process streams. |

Parsing is not an authenticated result. The verifier consumes immutable input and
explicit policy, and embedded certificates remain untrusted chain candidates.
Inspection has separate domain types and never calls the verifier. Both CLI
commands share file/stream handling while keeping verification setup out of the
parse path. The parser builds without `std`, and depends only on `anyhow`, `der`,
`digest`, `base64ct`, and `x509-cert`, all with their default features disabled. The optional `msi` and `appx` adapters
add CFB/DEFLATE/CRC/XML dependencies, independently of verification. The domain layer
converts parser errors to the existing verification/CLI diagnostics.
Format classification does not make an input valid: the selected parser enforces
its structure. Filename hints never override recognized binary magic.

Verification order is part of the observable error contract. For example, each
CMS frame is checked immediately before authenticating that signature; checking
all frames first could allow a later malformed entry to mask an earlier digest
or signature failure. The refactor preserves the existing order and diagnostics.

## Remaining boundaries

PE, CAB, and NAVX parsing lives under `parse`, with optional verification-side
hashing adapters consuming the shared borrowed digest input. PowerShell/XML, WSH, and RDP decoding, block framing, and canonical input also
live under `parse`; the optional `parse/wsf_xml.rs` adapter validates WSF XML.
MSI/MSP and AppX structural parsing lives under `parse` through explicit
`std` adapters. AppX objects hold immutable structural state; hashing returns
component evidence and integrity validation returns reports, without mutating
those objects. Parsed MSI/MSP objects change only their CFB read cursor. RDP verification retains its detached-content pipeline, trust checks, and
coverage-report projection; its parser has no hashes or verification state.
Full verification still requires `std`, including the CFB reader and AppX compression/XML stack. There is no format plugin trait;
the engine is one package, not a crate per format.

## Feature boundary

Engine (`rssig-engine`) features:

| Feature | Responsibility |
| --- | --- |
| No features | Signed containers, CMS, PowerShell/XML comments, VBScript/JScript and RDP parsing; `core + alloc`. |
| `xml` | Bounded WSF XML adapter using roxmltree; `core + alloc`, no verifier dependency. |
| `std` | Standard-library support in parser dependencies only. |
| `msi` | MSI/MSP structural parser and generic canonical hash input; enables `std` and CFB. |
| `appx` | AppX structural ZIP/DEFLATE/XML parser and canonical component input; enables `std` and `xml`. |
| `verify-core` | The shared verifier, inspection reports and domain types on `core + alloc`. |
| `verify` (default) | All supported format verifiers, domain reports, RustCrypto/webpki, explicit roots/CRLs; enables `msi` and `appx`. |
| `retrieval` | CRL retrieval through an injected `CrlSource`; enables `verify`. No transport. |

Application (`rssig`) features; the application always uses the engine's `verify`:

| Feature | Responsibility |
| --- | --- |
| `crl-fetch` | `crl::HttpCrlSource`, the default CRL source; enables the engine's `retrieval`. |
| `system-roots` | `roots::system_roots`, native root enumeration only. |
| `cli` | Clap, filesystem/clock/stream adapters, and the binary; enables `crl-fetch`. |

The application's defaults enable `cli` and `system-roots`. A CLI built without
`system-roots` requires explicit `--no-system-roots` or `--integrity-only`; it
never silently downgrades trust. Tests and CI build the engine's parser and
shared verifier for `thumbv7em-none-eabi`, where `std` is unavailable, with
`-p rssig-engine` so the application's feature requests do not unify into it.

The design reference is Google's
[`authenticode-rs` at 2538267](https://github.com/google/authenticode-rs/tree/25382676bbf4594b5bd69c2c55a5d88932aa27b7).
Its borrowed structures and independent digest interface informed this boundary.
rssig retains its own bounded PE layout rules, parser implementation, and full
trust/revocation verifier; the reference is not a build or runtime dependency.

`retrieval` is an optional std module above the shared verifier. It takes
untrusted CRL bytes from the injected `CrlSource`; URL/HTTP transport and
bounded DNS/socket I/O are the application's (`rssig::crl`), outside the engine. Two verification passes share the engine budget,
and only the final revocation-checked result is returned. See [CRL retrieval](crl-retrieval.md).

`log` defines the caller-injected `Logger`. The sink travels beside the
per-verification work budget, so the engine has no global logger and writes to
no stream. See [injected logging](logging.md).
