# Coverage by invariant (TEST-01)

The maintained evidence index is [`tests/coverage-inventory.json`](../tests/coverage-inventory.json).
Its 28 invariant groups link representative declarative case IDs to specific
claims. Its error map lists every current `ErrorCode`, representative cases that
assert that serialized code, or an explicit gap. Its independent-case index
links producer evidence and mutation counterparts through the fixture manifest.
It is a coverage inventory, not an assertion that all supported combinations are
covered. Multiple formats exercising the same CMS failure are one cryptographic
invariant with multiple dispatch paths.

`cargo test --locked` validates the references, error assertions and manifest
links through `coverage_inventory_references_existing_assertions_and_provenance`.
The normal spec runner executes the referenced cases. Neither test regenerates
fixtures or uses external signers/network services. These checks establish that
references remain live; reviewing whether a fixture actually isolates an
invariant remains a human responsibility.

## Scope and evidence

| Area | Inventory groups / native evidence | Limits and missing pairs |
| --- | --- | --- |
| PE32/PE32+ | `pe-image`, `page-hashes`, `nested`; `tests/fixtures.rs` checks the isolated payload mutation | Existing synthetic pairs do not establish independent PE interoperability or arbitrary section-layout support. |
| MSI/MSP | `msi-sip`, `msp-sip`; CLI MSI/MSP suites cover metadata, streams and CFB variants | MSP reuses MSI SIP evidence; applicability and Windows patch authorization are outside scope. |
| CAB/NAVX | `cab-sip`, `navx-sip`; independent jsign artifacts and payload mutations | Limited documented container layouts; not every producer/layout combination. |
| PowerShell/XML | `powershell-sip`, `psxml-sip`; encoding/BOM and independent jsign pairs | XML hash-comment SIP differs from XMLDSig. Positive encoding cases do not prove every malformed boundary. |
| WSH | `wsh-sip`; JS/JSE/VBS/VBE/WSF plus independent jsign mutations | Encoded scripts are opaque; signatures are not script execution checks. |
| RDP | `rdp-scope`; nfedera/rdpsign artifact, changed signed/unsigned settings | No Microsoft rdpsign.exe producer evidence. |
| MSIX/AppX packages/bundles | `appx-package`, `appx-bundle`; CLI AppX suites cover block maps, Publisher binding and children | CodeIntegrity catalogs are hashed, not independently signature-verified. No deployment-policy claim. |
| Digests and keys | `sha2`, `sha1-policy`, `key-algorithms`; `src/crypto.rs` and signing fixtures | SHA-384/512 content tests do not establish P-384 signature coverage. Inventory needs a systematic RSA-size/P-256/P-384 and digest/key mismatch matrix (SEC-13). |
| CMS/signers | `cms-binding`, `cms-structure`, `signer-selection`; SEC-04/05 native signature-math and shared-path tests | See `cms-security.md` for version/opaque-value exceptions. |
| Trust paths | `trust-root`, `trust-policy`, `trust-validity`; `src/trust.rs` tests | BasicConstraints, path length, name constraints, unknown critical extensions, cross-signing, cycles and same-subject different-key issuers need a dedicated inventory and paired assertions (SEC-06). |
| Timestamps | `timestamp`; `src/verify/timestamp.rs` parsing tests | Multiplicity, full TSTInfo structure and independent producer diversity remain SEC-08/INTEROP work. |
| Revocation | `revocation`; local signed good/revoked/stale/forged CRLs | Competing evidence/applicability and per-chain CRLs actually used remain SEC-10/11. No OCSP, delta or indirect CRL support. |
| Reduced-policy modes | `policy-modes`; `tests/cli/policy.rs` | Success in integrity-only mode cannot be counted as trusted-chain evidence. |
| Retrieval | `retrieval`; `src/retrieval/http.rs` bounded response tests | Injected responses establish validation behavior, not public network interoperability. AIA/HTTPS remain unsupported. |
| Resource limits | `work-budgets`, `host-budgets`; native budget callback tests | Byte/work limits and typed failure snapshots are different from fuzz coverage (TEST-02). |
| Inspection/API/CLI streams | `tests/parse*.rs`, `tests/library_stability.rs`, `tests/cli_interface.rs`, spec `parse-*` cases | Parsing establishes no trust. Writer failures are native I/O contracts, not verification JSON failures. |

## Stable error inventory

The JSON `errors` map is the authoritative case index. Cases must assert the
actual serialized code; an input name or matching diagnostic text is insufficient.
Current gaps are explicit:

- `revocation_unknown`, `invalid_crl`, `invalid_certificate`: no declarative code
  assertions. Add narrowly isolated reachable verification cases; malformed CLI
  trust-file configuration errors do not substitute for engine failures.
- `invalid_arguments`, `configuration`: CLI configuration/argument diagnostics
  intentionally use plain stderr and exit 2. Native typed-library coverage and
  CLI text assertions must be distinguished from verification JSON coverage.
- `invalid_test_suite`, `test_assertion_failed`: legacy enum surface; the product
  test subcommand is removed. Audit reachability/API compatibility rather than
  inventing product commands to exercise these codes.
- `internal_error`: no declarative case. Fault injection and panic/exception
  boundaries require separate design; a passing suite does not demonstrate it.

## Independent producer evidence

Use each indexed case's input to find its artifact in
[`manifest.json`](../tests/fixtures/manifest.json). Read the source, tool/version,
license, recipe and description there. The index includes negative mutations and
unsupported encodings as well as successes: inclusion does not mean acceptance.

Current producer families include jsign (MSI/MSP, CAB, NAVX, PowerShell/XML, WSH,
MSIX/AppX packages/bundles), upstream signtool artifacts (MSI and AppX), and
nfedera/rdpsign (RDP). Shared keys or a copied CMS fixture are not a new independent
producer. No Windows oracle is run. Independent PE, Relic-produced pairs, and
broader timestamp/chain/CRL producer combinations remain gaps; consult the
INTEROP backlog before adding redistributable artifacts.

## Gap closed in this change

The existing CRL cases proved output validation but their portable expectations
could not assert provider invocation. `expect.crl_requests` now specifies exact
ordered URLs, including failed requests, using the existing injected response
map. Three new cases reuse the committed discovery PE, root and CRLs:

- Offline invocation with a supplied good CRL makes zero provider calls.
- Opt-in fetching with a supplied good CRL makes zero provider calls.
- A supplied expired issuer CRL fails with `crl_expired` and makes zero calls;
  retrieval must not silently replace that evidence.

Existing injected retrieval cases now assert one exact request. Named in-process
CLI tests additionally assert empty retrieval artifacts or absent retrieval
metadata and `revocation_checked: true` on success. No product behavior or domain
schema changes were necessary. The observed initial failure was the spec
adapter rejecting the new expectation field, not a cryptographic regression.

## Maintenance

When adding an invariant, update its claim and explicit case IDs. Keep good/bad
pairs isolated and record whether evidence is synthetic, independently signed,
or a mutation of an independent artifact. Update the error map whenever adding
an ErrorCode or its first declarative assertion; new asserted codes are checked
by the inventory test. An enum with no asserted case requires manual inventory
review. Add producer cases only with manifest provenance. Update open gaps when
closing their roadmap item. Do not treat line coverage, case counts, or a repeated
format test as evidence of a new cryptographic invariant.
