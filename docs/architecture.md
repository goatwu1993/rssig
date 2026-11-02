# Code responsibilities

The crate keeps its existing public entry points and JSON contracts. Internal
modules are organized around the work they own, rather than a new crate hierarchy.

| Module | Responsibility |
| --- | --- |
| `cli` | Arguments, file/configuration I/O, clock/root loading for verification, stdout/stderr and exit codes. |
| `format` | Input classification: binary magic, then optional filename hints, then text signature markers. Unknown input retains the historical PE fallback. |
| `parse` | Borrowed, untrusted PE/CMS structures; no hashing, signature verification, trust, clocks, or file I/O. |
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
Format classification does not make an input valid: the selected parser enforces
its structure. Filename hints never override recognized binary magic.

Verification order is part of the observable error contract. For example, each
CMS frame is checked immediately before authenticating that signature; checking
all frames first could allow a later malformed entry to mask an earlier digest
or signature failure. The refactor preserves the existing order and diagnostics.

## Remaining boundaries

Container-specific parsing and hashing still live together outside PE. AppX's
internal package object still accumulates component/report state during integrity
validation. RDP retains its detached-content pipeline and scope policy. These
are candidates for subsequent extractions, with their format-specific fixtures
protecting behavior. This change does not introduce a format plugin trait,
separate workspace crates, dependency changes, or `no_std` support.
