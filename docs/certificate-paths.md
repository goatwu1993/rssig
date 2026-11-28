# Certificate paths (PATH-T001)

rssig uses the locked `rustls-webpki` 0.103.16 path builder with its RustCrypto
signature adapter. The operating system supplies roots only. This profile is
shared by Authenticode, timestamp and RDP verification; the PATH-T001 fixtures
exercise it through signed PE files with code-signing certificates. It is not
Windows trust-policy equivalence or a complete RFC 5280 policy implementation.
The numbered decisions behind this page, with their status and sources, are
[Certificate-path decisions](path.md) (`PATH-001` to `PATH-013`).

## Existing coverage and added evidence

Before PATH-T001, `path-007-bad-signer-eku`, `path-008-bad-signer-key-usage`, `tsa-003-wrong-tsa-eku`,
`path-007-intermediate-without-eku` and `path-008-ca-key-usage` covered wrong leaf EKU/KeyUsage,
TSA EKU, unrestricted intermediate EKU and missing intermediate keyCertSign.
`intermediate-current-crls`, certificate validity and certificate-signature cases
provided basic trusted-chain evidence. They did not isolate the path rules
below or select among competing issuers/anchors.

The 38 PATH-T001 cases in [`tests/cases.json`](../tests/cases.json) have individually
named tests in [`tests/cli/certificate_paths.rs`](../tests/cli/certificate_paths.rs). Every
invocation pins time to `1800000000`, disables system roots, supplies explicit
roots and local, correctly signed CRLs, and leaves revocation checking enabled.
Success assertions pin the entire ordered chain by certificate SHA-256; Rust
assertions also compare the exact DER with committed certificate witnesses.
Failures assert typed `code` and `stage`; diagnostic fragments further establish
which rule was exercised, but are not stable consumer identifiers.

| Rule | Focused evidence | Expected behavior |
| --- | --- | --- |
| BasicConstraints | `path-003-good-basic`, `path-003-bad-ca-false`, `path-003-bad-ca-missing-bc`, `path-003-bad-leaf-ca`, `path-003-good-leaf-no-bc` | Intermediates need cA=true. A CA cannot act as the signing leaf. A leaf may omit BasicConstraints. |
| Path length | `path-003-good-basic`, `path-004-good-pathlen`, `path-004-bad-pathlen` | pathLen=0 allows an issuing CA directly above the leaf; an upper CA with one subordinate CA needs pathLen at least 1. Only the upper CA's limit changes in the rejection pair. |
| DNS name constraints | `path-005-good-name-good`, `path-005-bad-name-outside`, `path-005-bad-name-excluded` | Permit a SAN within the allowed subtree; reject an outside SAN or one in an excluded subtree. The permitted subtree and excluded subtree coexist. |
| Unknown extensions | `path-006-good-leaf-noncritical`, `path-006-good-ca-noncritical`, `path-006-bad-leaf-critical`, `path-006-bad-ca-critical` | Ignore an unfamiliar noncritical extension, preserving certificate DER; reject the same extension when critical on the leaf or intermediate. |
| Malformed extensions | `path-013-bad-leaf-malformed-*`, `path-013-bad-ca-malformed-*` (basicConstraints, keyUsage, extKeyUsage, subjectAltName, nameConstraints, cRLDistributionPoints, subjectKeyIdentifier, authorityKeyIdentifier), `path-013-bad-leaf-san-non-ascii`, `path-013-bad-rdp-leaf-malformed-eku`, `path-013-bad-rdp-leaf-malformed-eku-empty-store` (`untrusted_root` first with no configured root), `path-013-bad-tsa-malformed-{ski,bc,ku,eku}`, `path-013-bad-tsa-counter-malformed-eku` (judged before TSA-003), `path-013-bad-ca-san-not-a-sequence`, `path-013-good-integrity-only-leaf-malformed-{ski,bc,ku,eku}`, `path-013-good-integrity-only-ca-malformed-{bc,ku,eku}`, `path-013-good-integrity-only-rdp-leaf-malformed-eku`, `path-013-good-integrity-only-tsa-malformed-{ski,bc,ku,eku}`, `path-013-good-integrity-only-tsa-counter-malformed-eku` (integrity-only builds no path), `path-015-good-parse-leaf-malformed-bc` (the report marks the extension, PATH-015) | Reject a leaf, intermediate, timestamp signer or RDP signer whose extension rssig or webpki decodes does not decode, including an IA5String with a byte above 0x7F, with `details.reason` `malformed_extension` ([PATH-013](path.md#path-013-a-path-certificate-whose-extension-does-not-decode-fails-the-path)). |
| Malformed candidates | `path-013-good-ca-malformed-first`, `path-013-bad-ca-malformed-first-under-another-root`, `path-013-bad-ca-malformed-ski-under-another-root`, `path-013-bad-ca-malformed-ski-revoked-reports-the-extension`, `path-013-bad-ca-ku-and-malformed-reports-the-extension`, `path-013-bad-unrelated-malformed-issuer-is-not-blamed`, `path-013-good-ca-malformed-bc-first` | Pass over a malformed candidate for a valid issuer (PATH-009); name it only when a path through it reached a configured root, never for a wrong root or an unrelated chain; a certificate whose basicConstraints, keyUsage or extKeyUsage the report cannot decode is reported with `undecoded_extensions`, on or off the path, and fails nothing by itself. |
| Repeated extensions | `path-014-bad-leaf-repeated-ski`, `path-014-bad-leaf-repeated-eku`, `path-014-bad-leaf-repeated-unfamiliar`, `path-014-bad-ca-repeated-ski`, `path-014-bad-ca-repeated-bc`, `path-014-good-ca-repeated-first`, `path-014-bad-ca-repeated-first-under-another-root`, `path-014-good-integrity-only-leaf-repeated-ski`, `path-014-good-integrity-only-leaf-repeated-eku`, `path-014-good-integrity-only-ca-repeated-bc` (integrity-only builds no path), `path-014-bad-tsa-repeated-ski`, `path-014-bad-rdp-leaf-repeated-eku`, `path-014-bad-rdp-leaf-repeated-eku-empty-store` (`untrusted_root` first with no configured root), `path-014-bad-leaf-repeated-and-malformed-reports-the-repeat`, `path-014-bad-ca-repeated-and-malformed-reports-the-repeat`, `path-014-bad-ca-repeated-san`, `path-014-good-ca-repeated-san-first` | Reject a leaf, intermediate, timestamp signer or RDP signer that carries two extensions with one OID, whatever the extension, with `details.reason` `repeated_extension`, before a value that does not decode ([PATH-014](path.md#path-014-a-path-certificate-that-repeats-an-extension-fails-the-path)); webpki rejects a repeat of an extension it keeps in an intermediate itself. Pass over a repeating candidate for a valid issuer (PATH-009). |
| Embedded candidate webpki cannot parse | `path-bad-ca-repeated-san-first-under-another-root`, `path-bad-unrelated-repeated-issuer-fails-in-webpki` (claimed under the PATH candidate rule `unparsed-candidate`) | Where the result would otherwise be `untrusted_root`, report webpki's parse failure of an embedded candidate (here a repeated subjectAltName), even one on no path; whether that is right is PATH-T019's. |
| EKU/KeyUsage | `path-007-good-ca-good-eku`, `path-007-bad-ca-eku`, `path-007-bad-leaf-no-eku`, `path-008-bad-ca-ku`, `path-008-good-leaf-no-ku`, `path-008-good-ca-no-ku` | Require explicit leaf code-signing EKU; a present CA EKU must permit it. A present leaf KU needs digitalSignature, a present CA KU needs keyCertSign. Absent KU is unrestricted. The bad CA KU retains cRLSign so a CRL-usage failure cannot mask the target rule. |
| Callback rejection and retry | `path-009-good-ca-ku-first`, `path-009-good-ca-ku-last` | An otherwise valid CA missing keyCertSign cannot prevent selection of an acceptable alternative with the same subject/key. |
| Same subject, different keys | `path-002-bad-wrong-key`, `path-002-good-wrong-key-first`, `path-002-good-wrong-key-last` | A matching issuer DN alone does not establish issuer identity. Reject when only the wrong key is available; choose the signature-valid issuer in either order. |
| Cross-signing | `path-001-bad-cross-untrusted`, `path-010-good-cross-first`, `path-010-good-cross-last`, `path-010-good-cross-other-root` | An embedded root does not establish trust. Choose the cross-signature leading to the configured root, including when the other cross-signature appears first; changing the configured root changes the selected chain. |
| Cycles | `path-001-bad-cycle`, `path-001-bad-cycle-reversed`, `path-010-good-cycle-escape`, `path-010-good-cycle-escape-reversed` | The cryptographically valid A→B→A cycle terminates with untrusted_root in either order. Adding an anchored variant of A yields the direct trusted path in either order. |
| Anchor profile | `path-011-good-root-expired`, `path-011-good-root-profile`, `crl-015-root-no-crl-sign-accepted` | Configured anchors retain the treatment described below, separate from intermediate rules. An anchor's KeyUsage does not restrict CRL signing either: a root without cRLSign still issues usable CRLs, while an intermediate CRL issuer without cRLSign is `invalid_key_usage` at `revocation`. |
| Anchor constraints and reporting | `path-005-good-root-name`, `path-005-bad-root-name`, `path-012-good-root-selection` | Apply anchor name constraints, and report the anchor whose constraints actually accepted the path when subject/key are identical. |

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
unavailable issuer key cannot substitute for the intended rule failure.
Certificate witnesses can supply missing issuer keys to this *test-only math
check*; they are never implicitly loaded as production trust anchors.

Provenance, hashes and case links are in the
[fixture manifest](../tests/fixtures/manifest.json). Builders live in
[`engine/src/tests/certificate_paths.rs`](../engine/src/tests/certificate_paths.rs) and run only through
explicit ignored maintenance tests. Normal tests read committed artifacts.
These are rule regression fixtures, not new independent-producer or Windows
interoperability evidence.

## Applicable profile and boundaries

- rssig requires the leaf's requested EKU explicitly. webpki's
  `KeyUsage::required_if_present` propagates that usage through intermediates;
  absent CA EKU is unrestricted. rssig separately checks digitalSignature on
  the leaf and keyCertSign on the selected intermediate path, because webpki's
  TLS-oriented checks do not supply those CMS requirements. Timestamp EKU also
  has rssig's critical/exclusive timeStamping checks; further TSA combinations
  remain TSA-T001.
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
  path length), KU and EKU are **not** checked as path-certificate rules.
  The expired-root and combined CA=false/pathLen=0/restrictive-KU/EKU root cases
  pin this distinction. Name constraints **are** applied. The anchor conversion
  also ignores unfamiliar critical extensions. [Root loading](trust-loading.md)
  rejects unsupported anchor extraction atomically instead of silently excluding
  anchors; extraction still does not enforce additional root checks.
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
  were used remain CRL-T001 and CRL-T002. AIA fetching remains unimplemented; future fetched
  intermediates must enter as untrusted candidates under the same rules.

## Regression and validation

The first focused run passed 37 cases and failed `good_path_root_selection`:
verification succeeded, but `trust.chain` named the configured root whose DNS
constraints had rejected the leaf. The reporting lookup compared subject and
SPKI only. Adding name-constraint equality makes it identify an anchor with the
same complete trust inputs as webpki's selected anchor. Validation decisions and
existing expected failures are unchanged.

Validation on macOS: the full `cargo test --locked` suite (778 portable cases),
`cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`,
verify-core feature tests, CLI tests without native roots, and verify-core
Clippy for `thumbv7em-none-eabi`. Explicit PATH-T001 regeneration reproduces the
committed artifact hashes. Dependencies are unchanged. Linux execution remains
in CI; no Windows oracle was run.
