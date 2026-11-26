# Shared interfaces and package boundaries

## Engine and application packages

rssig is a Cargo workspace of two packages, which replaces LIB-T010's
single-package decision below:

- `rssig-engine` (`engine/`): pure logic, policy options and the
  collaborator interfaces. Parser, inspection, verifier, trust, timestamps, revocation, CRL
  retrieval through an injected `CrlSource`, the `Logger` interface, reports
  and error codes.
- `rssig` (root): the application. The CLI and the defaults the engine leaves
  to its caller: `crl::HttpCrlSource`, `roots::system_roots`, host limits and
  the default policy built from CLI flags.

The cut is at the host boundary, not between parser and verifier: they stay in
one engine package, so the extraction work listed below for a
parser/verifier/CLI split (inherent methods on parser types, PE page-hash
ranges, shared DER helpers) was not needed. Five seams were opened instead,
each the smallest public interface the application needs:

| Engine interface | Was | For |
| --- | --- | --- |
| `TrustStore::from_system_roots` | `TrustStore::from_system` read the OS store inside the engine | `rssig::roots::system_roots` enumerates and hands over the roots and the enumeration errors; the engine still rejects a partial enumeration, validates each anchor and reports its position |
| `TrustStore::root_count`, `crl_count`, `encoded_len` | the CLI's store-size check lived in the engine (`check_host_limits`) | the CLI's host limits (`cli/limits.rs`) |
| `retrieval::limit` | crate-private; `HttpCrlSource` used it from inside the engine | `HttpCrlSource`'s own request and URL caps report the same `resource_limit_exceeded` details as the engine's limits |
| `log::Record::new` | the CLI built a non-exhaustive `Record` in-crate | the CLI's own debug record through the injected logger |
| `inspect::{pe, cms, cab, navx}` | crate-private `inspection`, compiled only with `cli` | the CLI's `parse` command |

`HttpCrlSource` (with its own caps `MAX_SOURCE_REQUESTS`, `MAX_SOURCE_URLS`,
`MAX_HTTP_REQUESTS` and `MAX_NETWORK_BYTES`, and
`check_public_http_url`) moved from `retrieval` to `rssig::crl`; it uses only
the engine's public `retrieval` interface. Public paths change accordingly
(pre-release, no compatibility layer): engine items are `rssig_engine::...`,
re-exported by the application as `rssig::engine`. The behavior, JSON
contracts, exit codes, fixtures and existing cases are unchanged. Two cases
were added, `limit-supplied-64-crls` and `limit-supplied-65-crls`, to put the
CLI's bound on supplied CRLs (now in `cli/limits.rs`) into the specification. Tests run from the repository, where both packages read the one
`tests/fixtures/` directory; the published crates exclude their tests, and
`make package-check` (CI's `package` job) checks that each packaged crate
builds.

The rest of this document is LIB-T010's assessment, kept for its interface
analysis; its packaging decision is superseded above.

## LIB-T010 assessment

Decision (superseded for packaging by the engine and application packages above): retain one `rssig` package and its existing public facade. Keep the
feature-separated parser, verification core, host format adapters and CLI as
modules. Do not introduce a public all-format container trait or split crates
at this stage. Crate extraction is not required for `no_std` verification.

This reassessment follows reuse by PE, CAB, NAVX, scripts, RDP, MSI/MSP and AppX
through LIB-T001 to LIB-T009. It is based on the repository's implementations and committed
consumer tests, not independent downstream adoption or Windows policy testing.
See [library usage and migration](library.md) for the supported API contracts.

### Interfaces justified by reuse

| Consumers | Shared interface in use | Boundary to retain |
| --- | --- | --- |
| PE and external PE layout views | `parse::PeTrait`, `PeOffsets`, `authenticode_digest` with a RustCrypto `digest::Update` sink | Validate all supplied ranges before hashing; supplied offsets do not validate actual PE header encoding. PE page hashes remain a distinct operation. |
| CAB and NAVX | Borrowed `as_bytes()`, `signature()`, and fixed-size `authenticode_chunks()` arrays | Digest order is format-specific. CAB permits bounded zero CMS padding; NAVX requires exact DER termination. |
| CMS and signers across formats | `parse::SignedData`, `SignerInfo`, algorithm/attribute views and bounded recursive inspection | Preserve unfamiliar DER without interpreting parsing as authentication. CMS framing is checked at the format's verification boundary. |
| PowerShell and WSH | Shared text decoding and comment-block parsing internals; format-specific public views | Canonical signed text and decoded CMS need owned storage. WSF XML and comment-style rules cannot be represented as raw file chunks alone. |
| MSI/MSP and AppX | Explicit structural adapters and parsed verification entry points | MSI streams through a mutable CFB cursor; AppX has immutable ZIP parts, multiple digest components, block maps, Publisher and bundle binding. |
| Authenticode formats | Private `verify::container::Container`, integrity dispatch and common signer/timestamp/trust pipeline | Keep SIP identities, error stages, digest evidence and failure order format-specific. |
| RDP | Shared CMS/trust machinery with a separate scoped-settings verifier | Detached CMS over canonical selected settings must retain signed/unsigned-setting evidence; it is not an Authenticode image digest. |
| Library and CLI | `format::Format`, byte/filename selection, explicit `VerifyOptions`, owned domain reports | Filesystem access, clocks, argument diagnostics and writer handling belong to the CLI. |

`digest::Update` already provides the useful algorithm-independent sink. Another
hash trait would duplicate it. CAB and NAVX chunk loops are small and infallible
after structural parsing; PE range validation and MSI cursor errors have different
contracts. A generic `SignedContainer` trait would need to model one/many
signatures, borrowed/decoded buffers, mutable streaming, component digests and
format rules. No current consumer needs that extension point. Keep concrete
parsers and the private enum rather than freezing those differences into public
associated types or callbacks. Future external format support needs its own
decision and security review; opaque CMS bytes plus a computed hash are insufficient.

Existing evidence includes `engine/tests/parse_core.rs`, `engine/tests/parse.rs`,
`engine/tests/library_stability.rs`, and `engine/tests/verification_core.rs`, plus the portable
cases and format-specific CLI tests. These cover structural inspection versus
verification, borrowing and repeated policy use, typed errors and explicit trust.
They justify retaining these interfaces; they do not measure independent consumer
maintenance cost or constrained-device resource use.

### Packaging alternatives

| Option | Feature isolation | Public API and packaging | Maintenance cost / decision |
| --- | --- | --- | --- |
| One package with optional features (LIB-T010; replaced by the two packages) | Base parser uses alloc; `verify-core` adds crypto/reports; `msi`/`appx` add std; `cli` and `system-roots` add host integration | One version, lockfile and facade; parser users must disable defaults | Superseded by the two packages. CI already checks host feature combinations and bare-metal parser/XML/verifier builds. |
| Parser + verifier + CLI crates, with `rssig` facade | Separate package dependency graphs make boundaries more explicit; additive Cargo features still unify for a shared package | Requires new package manifests, publish order, inter-package version requirements and facade re-exports | Defer until independent consumers or release cadence justify the extra boundaries. Requires resolving the concrete coupling below. |
| Separate crate per format or host adapter | Could narrow format dependencies further | Many package/version combinations and cross-format CMS/report dependencies | Defer. MSI/AppX already have independent feature gates; no demonstrated need for separate releases. |

Cargo features are additive. Disabling defaults in one dependency does not stop
another dependency from enabling `cli`, `std` or native roots on the same package.
A crate split could improve dependency ownership, but cannot by itself guarantee
that an application's entire graph is `no_std`. The existing bare-metal
production-library checks avoid host dev-dependency feature unification. Native
root enumeration remains an optional root source, never a verifier backend.
At the time, `system-roots` enabled full `verify`, including std format
adapters; it was not an alloc-only core feature. (In the two-package layout it
is an application feature that adds only `rustls-native-certs`.)

#### Concrete extraction work, if justified later

- Verifier adapters currently add private inherent methods to parser types
  (`engine/src/pe.rs`, `engine/src/cab.rs`, `engine/src/navx.rs`). An external verifier crate cannot
  add inherent implementations to foreign types. Move these to verifier-owned
  functions/newtypes or private extension traits before moving modules.
- PE page hashing currently reads crate-private validated ranges. Define a
  narrowly scoped validated view or relocate that calculation; do not expose
  unchecked mutable layout fields merely to make a split compile.
- DER helpers and CMS interpretation cross module boundaries. Assign structural
  DER decoding to the parser and algorithm/content checks to verification, with
  a one-way parser dependency. Keep domain error conversion on the verifier side
  to avoid a parser-to-verifier dependency cycle.
- Keep reports, trust and timestamp checks together initially. Moving public
  types into separate crates requires re-exporting the same definitions, not
  duplicating them into conversion layers. Preserve `?` conversions and error
  sources as well as serialized code/stage/details.
- Host adapters need independent feature forwarding. CLI inspection also uses
  parser views; the CLI package must depend on both public boundaries without
  reaching into private modules. Keep native roots separately optional.
- Verify package contents and out-of-workspace builds before publishing. Use
  compatible registry versions plus local paths for internal dependencies and
  publish in dependency order. Repository-relative fixture includes and local
  jsign/relic references must never become runtime dependencies.

### Compatibility and reconsideration

No caller migration was required by this decision at the time. The engine and
application split later moved those paths; see the [migration
table](library.md#engine-and-application-packages). CLI argv and JSON contracts
remain intact. Concrete parsed verification ownership remains
as documented in [LIB-T008](library.md#ownership-reuse-and-api-stability-lib-t008).
There are no new fixtures or failing behavior tests for this documentation-only
reassessment because it changes no parsing, hashing, verification or report behavior.

Reconsider extraction when a real downstream consumer needs a separately
versioned parser/verifier, when feature isolation demonstrably cannot express a
required graph, or when independent ownership/release cadence offsets coordinated
package maintenance. First record that consumer and its required feature/type
surface. A future split must preserve the `rssig` facade through feature forwarding
and re-exports, document any unavoidable breaking signatures, and demonstrate old
import paths against the same fixtures, cases and serialized domain assertions.

Before accepting such a split, run the full locked suite, formatting and Clippy,
the existing feature matrix and bare-metal checks, inspect resolved normal
production dependency graphs, and check packaged external consumers. Preserve
RustCrypto-only verification, configured-root trust, explicit integrity-only and
revocation policy, and current failure ordering. External consumer packaging and
32-bit execution remain BUILD-T002 work; this reassessment does not claim those
checks have been implemented.

Validation for this decision on macOS: `cargo test --locked`,
`cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`, and
`cargo clippy --locked --lib --no-default-features --features verify-core --target
thumbv7em-none-eabi -- -D warnings` passed. Normal parser and `verify-core`
dependency trees were reviewed: the parser excludes verifier crypto, Clap and
native roots; the core excludes Clap, native roots and prohibited crypto backends.
Dependencies and lockfile are unchanged. Linux execution remains for CI.
