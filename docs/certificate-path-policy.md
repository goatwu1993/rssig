# Certificate-path policy (SEC-06)

rssig uses the locked `rustls-webpki` 0.103.16 path builder with its RustCrypto
signature adapter. The operating system supplies roots only. This profile is
shared by Authenticode, timestamp and RDP verification; the SEC-06 fixtures
exercise it through signed PE files with code-signing certificates. It is not
Windows trust-policy equivalence or a complete RFC 5280 policy implementation.

## Existing coverage and added evidence

Before SEC-06, `bad-signer-eku`, `bad-signer-key-usage`, `wrong-tsa-eku`,
`intermediate-without-eku` and `ca-key-usage` covered wrong leaf EKU/KeyUsage,
TSA EKU, unrestricted intermediate EKU and missing intermediate keyCertSign.
`intermediate-current-crls`, certificate validity and certificate-signature cases
provided basic trusted-chain evidence. They did not isolate the path policies
below or select among competing issuers/anchors.

The 38 SEC-06 cases in [`tests/cases.json`](../tests/cases.json) have individually
named tests in [`tests/cli/path_policy.rs`](../tests/cli/path_policy.rs). Every
invocation pins time to `1800000000`, disables system roots, supplies explicit
roots and local, correctly signed CRLs, and leaves revocation checking enabled.
Success assertions pin the entire ordered chain by certificate SHA-256; Rust
assertions also compare the exact DER with committed certificate witnesses.
Failures assert typed `code` and `stage`; diagnostic fragments further establish
which policy was exercised, but are not stable consumer identifiers.

| Policy | Focused evidence | Expected behavior |
| --- | --- | --- |
| BasicConstraints | `good-sec06-basic`, `bad-sec06-ca-false`, `bad-sec06-ca-missing-bc`, `bad-sec06-leaf-ca`, `good-sec06-leaf-no-bc` | Intermediates need cA=true. A CA cannot act as the signing leaf. A leaf may omit BasicConstraints. |
| Path length | `good-sec06-basic`, `good-sec06-pathlen`, `bad-sec06-pathlen` | pathLen=0 allows an issuing CA directly above the leaf; an upper CA with one subordinate CA needs pathLen at least 1. Only the upper CA's limit changes in the rejection pair. |
| DNS name constraints | `good-sec06-name-good`, `bad-sec06-name-outside`, `bad-sec06-name-excluded` | Permit a SAN within the allowed subtree; reject an outside SAN or one in an excluded subtree. The permitted subtree and excluded subtree coexist. |
| Unknown extensions | `good-sec06-{leaf,ca}-noncritical`, `bad-sec06-{leaf,ca}-critical` | Ignore an unfamiliar noncritical extension, preserving certificate DER; reject the same extension when critical on the leaf or intermediate. |
| EKU/KeyUsage | `good-sec06-ca-good-eku`, `bad-sec06-ca-eku`, `bad-sec06-leaf-no-eku`, `bad-sec06-ca-ku`, `good-sec06-{leaf,ca}-no-ku` | Require explicit leaf code-signing EKU; a present CA EKU must permit it. A present leaf KU needs digitalSignature, a present CA KU needs keyCertSign. Absent KU is unrestricted. The bad CA KU retains cRLSign so a CRL-usage failure cannot mask the target policy. |
| Callback rejection and retry | `good-sec06-ca-ku-{first,last}` | An otherwise valid CA missing keyCertSign cannot prevent selection of an acceptable alternative with the same subject/key. |
| Same subject, different keys | `bad-sec06-wrong-key`, `good-sec06-wrong-key-{first,last}` | A matching issuer DN alone does not establish issuer identity. Reject when only the wrong key is available; choose the signature-valid issuer in either order. |
| Cross-signing | `bad-sec06-cross-untrusted`, `good-sec06-cross-{first,last,other-root}` | An embedded root does not establish trust. Choose the cross-signature leading to the configured root, including when the other cross-signature appears first; changing the configured root changes the selected chain. |
| Cycles | `bad-sec06-cycle`, `bad-sec06-cycle-reversed`, `good-sec06-cycle-escape`, `good-sec06-cycle-escape-reversed` | The cryptographically valid A→B→A cycle terminates with untrusted_root in either order. Adding an anchored variant of A yields the direct trusted path in either order. |
| Anchor profile | `good-sec06-root-expired`, `good-sec06-root-profile` | Configured anchors retain the treatment described below, separate from intermediate policy. |
| Anchor constraints and reporting | `good-sec06-root-name`, `bad-sec06-root-name`, `good-sec06-root-selection` | Apply anchor name constraints, and report the anchor whose constraints actually accepted the path when subject/key are identical. |

BasicConstraints, path-length, name-constraint, critical-extension and wrong-key
failures use `certificate_chain_invalid` at `certificate_chain`. Missing anchored
paths and cycles use `untrusted_root` at `certificate_chain`. Intermediate EKU
and KU failures use `invalid_eku` and `invalid_key_usage` at `certificate_chain`;
missing leaf EKU uses `invalid_eku` at `certificate`. No new error codes or domain
schema fields were needed. A failure reports no successful selected chain.

The synthetic corpus uses public deterministic P-256 keys, signed inert PE
containers, and a fixed time. The fixture signature-math test independently
checks image/CMS integrity and every embedded certificate signature, including
both edges of the cycle. Thus a bad signature, malformed container, stale CRL or
unavailable issuer key cannot substitute for the intended policy failure.
Certificate witnesses can supply missing issuer keys to this *test-only math
check*; they are never implicitly loaded as production trust anchors.

Provenance, hashes and case links are in the
[fixture manifest](../tests/fixtures/manifest.json). Builders live in
[`src/tests/path_policy.rs`](../src/tests/path_policy.rs) and run only through
explicit ignored maintenance tests. Normal tests read committed artifacts.
These are policy regression fixtures, not new independent-producer or Windows
interoperability evidence.

## Applicable profile and boundaries

- rssig requires the leaf's requested EKU explicitly. webpki's
  `KeyUsage::required_if_present` propagates that usage through intermediates;
  absent CA EKU is unrestricted. rssig separately checks digitalSignature on
  the leaf and keyCertSign on the selected intermediate path, because webpki's
  TLS-oriented checks do not supply those CMS requirements. Timestamp EKU also
  has rssig's critical/exclusive timeStamping checks; further TSA combinations
  remain SEC-08.
- webpki checks non-anchor validity, certificate signatures, BasicConstraints,
  path length and applicable name constraints, and rejects unknown critical
  extensions. Its profile is not a general certificate-policy tree processor:
  certificatePolicies/policyMappings and Windows trust lists are not supported.
  Critical policy extensions it does not recognize are rejected.
- DNS constraints operate on DNS SANs; a publisher CN is not interpreted as a
  DNS identity, and rssig does not perform TLS hostname verification. The new
  fixtures isolate DNS constraints at intermediates and anchors. The locked
  webpki implementation also processes IP constraints; IP pairs, wildcard/name
  encoding combinations and self-issued rollover semantics are not established
  by this corpus. Directory-name constraints are rejected; URI constraints are
  rejected when a URI SAN is present. Other unsupported name forms are rejected
  when the corresponding constrained form occurs. GeneralSubtree minimum and
  maximum fields must be absent. These limits come from webpki's
  `subject_name/mod.rs`, not a claim of complete name-constraint support.
- Only configured roots become anchors. `anchor_from_trusted_cert` extracts
  subject, public key and name constraints from a certificate already trusted
  by configuration. Anchor expiry, self-signature, BasicConstraints (including
  path length), KU and EKU are **not** checked as path-certificate policy.
  The expired-root and combined CA=false/pathLen=0/restrictive-KU/EKU root cases
  pin this distinction. Name constraints **are** applied. The anchor conversion
  also ignores unfamiliar critical extensions; root loading diagnostics and
  excluded/unsupported anchors remain SEC-07.
- Paths are tried against configured anchors and supplied untrusted candidate
  certificates. The first acceptable path is reported; no universal shortest,
  newest, or strongest path preference is promised. The order-pair tests have
  one acceptable chain. webpki prevents repeating a subject/SPKI pair within a
  path and bounds search work; rssig's aggregate budgets additionally bound
  path attempts and cryptographic operations. See
  [verification budgets](verification-budgets.md).
- Revocation remains required across the selected non-anchor chain, with local
  evidence in these tests. Supplied CRLs are not individually labeled verified
  merely because loaded. CRL applicability/selection and reporting which CRLs
  were used remain SEC-10/11. AIA fetching remains unimplemented; future fetched
  intermediates must enter as untrusted candidates under the same policy.

## Regression and validation

The first focused run passed 37 cases and failed `good_sec06_root_selection`:
verification succeeded, but `trust.chain` named the configured root whose DNS
constraints had rejected the leaf. The reporting lookup compared subject and
SPKI only. Adding name-constraint equality makes it identify an anchor with the
same complete trust inputs as webpki's selected anchor. Validation decisions and
existing expected failures are unchanged.

Validation on macOS: the full `cargo test --locked` suite (778 portable cases),
`cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`,
verify-core feature tests, CLI tests without native roots, and verify-core
Clippy for `thumbv7em-none-eabi`. Explicit SEC-06 regeneration reproduces the
committed artifact hashes. Dependencies are unchanged. Linux execution remains
in CI; no Windows oracle was run.
