# Code responsibilities

The crate keeps its verification entry points and JSON contracts. Internal
modules are organized around the work they own, rather than a new crate hierarchy.

| Module | Responsibility |
| --- | --- |
| `cli` | Top-level command dispatch, stdout/stderr, and exit codes. |
| `cli/batch.rs` | Shared file reads, ordered results, first-failure Problem Details, and JSON envelopes. |
| `cli/verify.rs` | Verification arguments and configuration: roots, CRLs, validation clock, and explicit policy. |
| `cli/parse.rs` | Inspection arguments and explicit PE/CMS selection, with no verification setup. |
| `inspection` | Converts untrusted parser values into inspection reports, preserving raw DER. |
| `format` | Input classification: binary magic, then optional filename hints, then text signature markers. Unknown input retains the historical PE fallback. |
| `parse` | `no_std + alloc` PE/CAB/NAVX/CMS/script/RDP structures, typed parsing errors, and borrowed container digest chunks; no signature verification, trust, clocks, or file I/O. |
| `parse/signer.rs` | Borrowed untrusted CMS signer, identifier, attribute and content views; shared structural helpers preserve verification check order. |
| `verify/mod.rs` | Public verification entry points, explicit options, and container construction. |
| `verify/container.rs` | Embedded CMS extraction and each container's padding/framing rules. |
| `verify/integrity.rs` | SIP/content binding, algorithm policy, image/package/script digests, and PE page hashes. Returns digest evidence to the signer pipeline. |
| `verify/authenticode.rs` | Ordered signer pipeline: integrity, CMS authentication, publisher binding, timestamp, configured trust, report, nested signatures. |
| `verify/appx.rs` | Embedded bundle package verification and package identity/signer binding. |
| `verify/timestamp.rs` | RFC 3161/PKCS#9 binding, TSA validation, canonical time decoding, and fractional expiry checks. Shared with RDP verification. |
| `cms` / `crypto` | Authenticode/CMS interpretation and signature verification using RustCrypto primitives. |
| `trust` | Configured trust anchors, native-root enumeration, webpki path/CRL validation; `trust/error.rs` maps adapter errors. |
| `domain` | Public Serde result/error declarations and stable diagnostics. |
| `report` | Conversion from decoded certificate/CRL metadata to domain reports, preserving unfamiliar values. |

Parsing is not an authenticated result. The verifier consumes immutable input and
explicit policy, and embedded certificates remain untrusted chain candidates.
Inspection has separate domain types and never calls the verifier. Both CLI
commands share file/stream handling while keeping verification setup out of the
parse path. The parser builds without `std`, and depends only on `anyhow`, `der`,
`digest`, `base64ct`, and `x509-cert`, all with their default features disabled. The domain layer
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
MSI and AppX structural parsing remain internal. AppX's internal package object still
accumulates component/report state during integrity
validation. RDP verification retains its detached-content pipeline, trust policy, and
coverage-report projection; its parser has no hashes or verification state.
Full verification still requires `std`, including the CFB reader and AppX compression/XML stack. There is no format plugin trait or
separate workspace crate hierarchy.

## Feature boundary

| Feature | Responsibility |
| --- | --- |
| No features | Signed containers, CMS, PowerShell/XML comments, VBScript/JScript and RDP parsing; `core + alloc`. |
| `xml` | Bounded WSF XML adapter using roxmltree; `core + alloc`, no verifier dependency. |
| `std` | Standard-library support in parser dependencies only. |
| `verify` | All supported format verifiers, domain reports, RustCrypto/webpki, explicit roots/CRLs; enables `std` and `xml`. |
| `system-roots` | Native root enumeration only; enables `verify`. |
| `cli` | Clap, filesystem/clock/stream adapters, and the binary; enables `verify`. |

Defaults enable `cli` and `system-roots`. A CLI built without `system-roots`
requires explicit `--no-system-roots` or `--integrity-only`; it never silently
downgrades trust. Tests and CI build the parser for `thumbv7em-none-eabi`, where
`std` is unavailable, and exercise verification with host integrations disabled.

The design reference is Google's
[`authenticode-rs` at 2538267](https://github.com/google/authenticode-rs/tree/25382676bbf4594b5bd69c2c55a5d88932aa27b7).
Its borrowed structures and independent digest interface informed this boundary.
rssig retains its own bounded PE layout rules, parser implementation, and full
trust/revocation verifier; the reference is not a build or runtime dependency.
