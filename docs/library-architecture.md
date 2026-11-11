# Shared interfaces and crate boundaries (LIB-10)

Decision: retain one `rssig` package and its existing public facade. Keep the
feature-separated parser, verification core, host format adapters and CLI as
modules. Do not introduce a public all-format container trait or split crates
at this stage. Crate extraction is not required for `no_std` verification.

This reassessment follows reuse by PE, CAB, NAVX, scripts, RDP, MSI/MSP and AppX
through LIB-01–09. It is based on the repository's implementations and committed
consumer tests, not independent downstream adoption or Windows policy testing.
See [library usage and migration](library.md) for the supported API contracts.

## Interfaces justified by reuse

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
format policy. No current consumer needs that extension point. Keep concrete
parsers and the private enum rather than freezing those differences into public
associated types or callbacks. Future external format support needs its own
policy/security review; opaque CMS bytes plus a computed hash are insufficient.

Existing evidence includes `tests/parse_core.rs`, `tests/parse.rs`,
`tests/library_stability.rs`, and `tests/verification_core.rs`, plus the portable
cases and format-specific CLI tests. These cover structural inspection versus
verification, borrowing and repeated policy use, typed errors and explicit trust.
They justify retaining these interfaces; they do not measure independent consumer
maintenance cost or constrained-device resource use.

## Packaging alternatives

| Option | Feature isolation | Public API and packaging | Maintenance cost / decision |
| --- | --- | --- | --- |
| One package with optional features (current) | Base parser uses alloc; `verify-core` adds crypto/reports; `msi`/`appx` add std; `cli` and `system-roots` add host integration | One version, lockfile and facade; parser users must disable defaults | Retain. CI already checks host feature combinations and bare-metal parser/XML/verifier builds. |
| Parser + verifier + CLI crates, with `rssig` facade | Separate package dependency graphs make boundaries more explicit; additive Cargo features still unify for a shared package | Requires new package manifests, publish order, inter-package version requirements and facade re-exports | Defer until independent consumers or release cadence justify the extra boundaries. Requires resolving the concrete coupling below. |
| Separate crate per format or host adapter | Could narrow format dependencies further | Many package/version combinations and cross-format CMS/report dependencies | Defer. MSI/AppX already have independent feature gates; no demonstrated need for separate releases. |

Cargo features are additive. Disabling defaults in one dependency does not stop
another dependency from enabling `cli`, `std` or native roots on the same package.
A crate split could improve dependency ownership, but cannot by itself guarantee
that an application's entire graph is `no_std`. The existing bare-metal
production-library checks avoid host dev-dependency feature unification. Native
root enumeration remains an optional root source, never a verifier backend.
`system-roots` currently enables full `verify`, including std format adapters;
it is not an alloc-only core feature.

### Concrete extraction work, if justified later

- Verifier adapters currently add private inherent methods to parser types
  (`src/pe.rs`, `src/cab.rs`, `src/navx.rs`). An external verifier crate cannot
  add inherent implementations to foreign types. Move these to verifier-owned
  functions/newtypes or private extension traits before moving modules.
- PE page hashing currently reads crate-private validated ranges. Define a
  narrowly scoped validated view or relocate that calculation; do not expose
  unchecked mutable layout fields merely to make a split compile.
- DER helpers and CMS interpretation cross module boundaries. Assign structural
  DER decoding to the parser and algorithm/content policy to verification, with
  a one-way parser dependency. Keep domain error conversion on the verifier side
  to avoid a parser-to-verifier dependency cycle.
- Keep reports, trust and timestamp policy together initially. Moving public
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

## Compatibility and reconsideration

No caller migration is required by this decision. Existing `rssig::parse`,
`rssig::verify`, `rssig::domain`, root-level re-exports, feature names, CLI argv,
and JSON contracts remain intact. Concrete parsed verification ownership remains
as documented in [LIB-08](library.md#ownership-reuse-and-api-stability-lib-08).
There are no new fixtures or failing behavior tests for this documentation-only
reassessment because it changes no parsing, hashing, policy or report behavior.

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
32-bit execution remain TEST-04 work; this reassessment does not claim those
checks have been implemented.

Validation for this decision on macOS: `cargo test --locked`,
`cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`, and
`cargo clippy --locked --lib --no-default-features --features verify-core --target
thumbv7em-none-eabi -- -D warnings` passed. Normal parser and `verify-core`
dependency trees were reviewed: the parser excludes verifier crypto, Clap and
native roots; the core excludes Clap, native roots and prohibited crypto backends.
Dependencies and lockfile are unchanged. Linux execution remains for CI.
