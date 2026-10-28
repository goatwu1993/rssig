# Verification-only implementation comparison

Reviewed 2026-10-28. This compares implementation paths, not signing features,
performance, security audit results, or Windows policy equivalence. Competitors
were inspected as source; they were not built or run against a common corpus.
An implemented feature is not proof that all edge cases are correct.

## Source snapshots and local references

The following directories are independent, ignored Git clones. Treat them as
read-only implementation references, never build/runtime dependencies. Updating a
clone requires revisiting the observations below. The revision links also work
without local clones.

| Project | Local directory | Inspected revision | Version context |
| --- | --- | --- | --- |
| rssig | repository root | `5a9c9cb67c288dec005314b83a3c3f7b929fed2f` | 0.1.0 |
| [authenticode-rs](https://github.com/google/authenticode-rs/tree/25382676bbf4594b5bd69c2c55a5d88932aa27b7) | `authenticode-rs/` | `25382676bbf4594b5bd69c2c55a5d88932aa27b7` | 0.6.0 |
| [authenticode-parser](https://github.com/vthib/authenticode-parser/tree/c84440b134ebfda661cf6a058a6dec6d901bc94b) | `authenticode-parser/` | `c84440b134ebfda661cf6a058a6dec6d901bc94b` | exact `v0.5.0` tag; C submodule `d538f330c88ba6a792862b85fd84c220b4503c84` |
| [cross-authenticode](https://github.com/secana/cross-authenticode/tree/f51cca964891d825fecd09fbd412fea9e15aa515) | `cross-authenticode/` | `f51cca964891d825fecd09fbd412fea9e15aa515` | checkout declares 1.0.3; docs.rs latest inspected was 1.0.2 |
| [rsigncode](https://github.com/divvun/rsigncode/tree/5e75fa1dcaff3a1720e1ba89b624fd1cf4d6825d) | `rsigncode/` | `5e75fa1dcaff3a1720e1ba89b624fd1cf4d6825d` | 0.1.0, early development |
| [pe-sign](https://github.com/0xlane/pe-sign/tree/b94777828990e21d065ed2482fb31b432a359a2f) | `pe-sign/` | `b94777828990e21d065ed2482fb31b432a359a2f` | 0.1.10 |
| [verifysign](https://github.com/I-Alzamil/verifysign/tree/5bc23fcdd55739e2f66fb0bb8273a6ef2d0d6a8c) | `verifysign/` | `5bc23fcdd55739e2f66fb0bb8273a6ef2d0d6a8c` | 1.0.1, matching the linked docs.rs version |
| [Jsign](https://github.com/ebourg/jsign/tree/cf5d2ceaf2ec80cb793f7377749ef811d4be4d34) | `jsign/` | `cf5d2ceaf2ec80cb793f7377749ef811d4be4d34` | development branch: verification marked since 8.0; README lists 7.6 release |
| [Relic](https://github.com/sassoftware/relic/tree/02c54d584ca9eaa8f648763cd53bc77c4ff3d19c) | `relic/` | `02c54d584ca9eaa8f648763cd53bc77c4ff3d19c` | v8 module |

Although hosted under `google`, authenticode-rs explicitly says it is not an
official or supported Google project.

`authenticode-parser` 0.5.0 is a separate project: Rust bindings maintained in
`vthib/authenticode-parser` around Avast's C/OpenSSL implementation. It is not
Google's `authenticode` crate or its `authenticode-tool` CLI. Its pinned C source
is retained inside `authenticode-parser/authenticode-parser-sys/authenticode-parser/`.

## What verification actually means

These checks answer different questions:

1. Does the format-specific file digest match the digest carried in CMS?
2. Do CMS signed attributes, content binding, and the public-key signature verify?
3. Does the signer chain reach a configured trust anchor under the required
   validity, constraints, key usage, and EKU policy?
4. Is a timestamp bound to this signature, cryptographically valid, and issued
   by a trusted TSA? Does policy allow using its time?
5. Is revocation status known and acceptable for the relevant chains?

A matching file digest alone proves no publisher identity: that digest is stored
in the input file. A valid CMS signature alone also does not establish trust.

## Capability matrix

“Absent” means absent from the inspected verification path, not impossible to
implement using that project's lower-level dependencies.

| Verification concern | rssig | authenticode-rs | cross-authenticode | rsigncode | Jsign development | Relic |
| --- | --- | --- | --- | --- | --- | --- |
| PE digest computation | Yes | Yes | Yes | Yes | Yes | Yes |
| CMS public-key verification | Yes | Absent | Absent | Yes | Yes | Yes |
| Certificate trust path | webpki + RustCrypto | Absent | Absent | Optional signature walk to supplied CA; limited policy | Bouncy Castle PKIX | Go X.509 |
| Required code-signing EKU | Yes | Absent | Absent | No check in chain walker | Yes | CLI passes `ExtKeyUsageAny` |
| RFC 3161 / legacy timestamp verification | Both, including binding and TSA trust in trusted mode | Absent | Absent | Partial; see below | Both, including binding and TSA trust | Both, including binding and TSA trust |
| Revocation in normal verification | Local CRLs; unknown status denied | Absent | Absent | No implemented CRL path found | Disabled in inspected rules | No CRL/OCSP check found in CLI path |
| Nested signatures | Yes, bounded depth | No recursive verification | No recursive verification | Primary + immediate nested blobs | Yes, via signature extraction | Yes, via Authenticode extraction |
| PE page-hash verification | Yes | No verifier | No verifier | No check found | Not established in this review | Implemented in PE verifier |
| Other relevant Windows formats | MSI/MSP, CAB, NAVX, PowerShell/XML, WSH, RDP, AppX/MSIX packages and bundles | PE only | PE only | PE only | Broad Signable handlers, including MSI/MSP, CAB, scripts, AppX, CAT, NAVX | MSI, CAB, AppX, PowerShell, CAT and others |
| CLI reporting | One JSON document, typed errors and domain reports | Human-readable inspection / DER certificate extraction | Library API | Human-readable diagnostics | Structured Java result; human-readable CLI | Human-readable CLI; library signature structs |
| Runtime model | Rust; OS roots only | `no_std` + alloc library; Rust CLI | Rust library | Rust application with additional native dependency concerns | JVM + Bouncy Castle | Go; platform X.509 policy requires care |

Format lists describe handlers and the reviewed scope, not universal acceptance
of every format variant. For example, catalog signature verification does not
by itself establish membership of an arbitrary file in that catalog.

pe-sign's corresponding capabilities are listed separately to keep the matrix
readable:

| Verification concern | pe-sign | Difference from rssig |
| --- | --- | --- |
| PE digest + CMS verification | RSA PKCS#1 v1.5 signature and signed-attribute digest checks | More than digest-only verification; no ECDSA verifier in the inspected path |
| Trust path | Custom certificate signature walk, bundled or explicit PEM CA set | No full path-policy checks; automatic AIA retrieval |
| Code-signing / TSA EKU | Not enforced by verification path | rssig enforces purpose-specific EKUs in trusted mode |
| Certificate time | Current wall-clock validity, optional bypass | No fixed-time option or authenticated historical timestamp policy |
| Timestamp verification | Parsing/extraction helpers; absent from normal verification | rssig checks binding, cryptography, and TSA trust |
| Revocation | No CRL/OCSP validation found | rssig requires supplied CRL coverage by default |
| Nested signatures | Extraction; CLI `--embed` selects a nested signature | No automatic all-signature verification policy |
| PE page hashes / other formats | No page-hash check found; PE only | rssig verifies page hashes and additional Windows formats |
| CLI/API reporting | Status enum + errors; human-readable CLI | CLI prints invalid statuses without converting them to failure exits |
| Runtime model | RustCrypto RSA, `std`, blocking HTTP client | OpenSSL removed; inspected library is not actually `no_std` |

The Rust bindings in authenticode-parser 0.5.0 expose a C verification engine:

| Verification concern | authenticode-parser 0.5.0 | Difference from rssig |
| --- | --- | --- |
| PE digest | `parse_pe()` calculates and compares it | `parse()` accepts signature bytes only; caller must compare file digest |
| CMS verification | OpenSSL PKCS#7 public-key/content verification | Real cryptographic checking; not a digest-only parser |
| Trust path | Reconstructed for inspection; verification result ignored | No trusted-chain conclusion or configurable trust-anchor workflow |
| Timestamps | Legacy PKCS#9 and Microsoft PKCS#7/CMS timestamp signature and parent-digest checks | No TSA trust validation or trusted historical signer policy |
| Revocation | No CRL/OCSP policy in exposed parse APIs | rssig requires local CRL coverage in normal trusted mode |
| Nested signatures | Recursive extraction with per-attribute count limits | No claim of equivalent resource limits or all-signature acceptance policy |
| Other formats / page hashes | PE-focused; no page-hash verification found | rssig supports additional formats and verifies PE page hashes |
| Output | Signature arrays, metadata, primary and countersignature verification enums | `Valid` is not equivalent to rssig trusted success; no comparable JSON CLI |
| Engine dependencies | C compiler, FFI, OpenSSL libcrypto; optional static OpenSSL linking | Incompatible with rssig's pure-Rust/no-OpenSSL engine constraints |

verifysign has a different platform/format boundary:

| Verification concern | verifysign 1.0.1 | Difference from rssig |
| --- | --- | --- |
| Supported hosts | Windows and macOS; compile error elsewhere | rssig targets macOS and Linux |
| Windows Authenticode on macOS/Linux | No portable Authenticode implementation | rssig's central use case |
| Verification engine | Windows WinTrust / macOS Security code-signing services | Native verification conflicts with rssig's engine constraints |
| Windows catalog membership | System catalog lookup and WinTrust verification | Capability rssig does not currently implement |
| Timestamp / certificate path | Delegated to OS policy; strict-expiration option | rssig implements and reports its own explicit policy |
| Revocation | Disabled by default; configurable native chain checks and network policy | rssig defaults to required local CRL coverage |
| Custom roots and time | No root-bundle or validation-time setter in public VerifyPolicy | rssig supports explicit roots and fixed time |
| Process / Apple code signatures | PID verification; native macOS binaries and app bundles | Outside rssig's current Windows-artifact scope |
| Output | Rust result, leaf names/serial/thumbprints, OS error codes; no supplied CLI | rssig supplies JSON domain bundles, selected chains, timestamps, CRLs and typed stages |

## Significant source findings

### authenticode-rs: a parsing and hashing reference

`authenticode/src/signature.rs` explicitly distinguishes parsing from actual
signature verification. `authenticode-tool/src/main.rs` offers `Info` and
`GetCert`; it calculates hashes, displays signature metadata, and extracts
certificates. It has no trust, timestamp, or revocation verification workflow.
Its `no_std` design and generic PE/digest interfaces are useful references for
small reusable components. rssig currently depends on `std`.

### authenticode-parser 0.5.0: C/OpenSSL integrity verification behind Rust bindings

The [versioned Rust API](https://docs.rs/authenticode-parser/0.5.0/authenticode_parser/)
exposes signature arrays, certificates, countersignatures and verification enums.
`parse_pe()` includes PE digest checks; `parse()` has no PE bytes and explicitly
leaves file-digest comparison to the caller. A non-null parse result is not an
acceptance decision: callers must inspect every relevant verification status.

The pinned C engine's
[authenticode implementation](https://github.com/avast/authenticode-parser/blob/d538f330c88ba6a792862b85fd84c220b4503c84/src/authenticode.c)
calls `PKCS7_signatureVerify`, compares file digests for PE inputs, and extracts
nested signatures. Its
[countersignature implementation](https://github.com/avast/authenticode-parser/blob/d538f330c88ba6a792862b85fd84c220b4503c84/src/countersignature.c)
checks legacy and Microsoft timestamp cryptography and binding to the parent's
signature bytes. These checks are more extensive than Google's parser or
cross-authenticode's digest comparison.

However, the
[certificate implementation](https://github.com/avast/authenticode-parser/blob/d538f330c88ba6a792862b85fd84c220b4503c84/src/certificate.c)
explicitly ignores the return value of `X509_verify_cert` and uses it only to
construct a chain. Neither signer nor TSA trust is established. A `Valid`
signature/countersignature status therefore does not establish a trusted
publisher or trusted signing time. The parse APIs expose no trust-anchor,
validation-time, or revocation-policy configuration.

Its [build script](https://github.com/vthib/authenticode-parser/blob/c84440b134ebfda661cf6a058a6dec6d901bc94b/authenticode-parser-sys/build.rs)
compiles the C implementation and links libcrypto directly. The `openssl-static`
feature changes linkage rather than removing OpenSSL. Dependency audits must
inspect build scripts, not just look for an `openssl` Cargo package. This makes
it a useful independent integrity/parser reference, but not an eligible engine
dependency for rssig. No competitor execution or interoperability claim was
added as part of this source review.

### cross-authenticode: digest comparison is its verification boundary

In `src/authenticode_info.rs`, `AuthenticodeInfo::verify()` compares a computed
SHA-1 or SHA-256 PE digest to the embedded digest. The generic hash API permits
other digest implementations. Neither path verifies the CMS public-key
signature or a certificate chain. Certificate fingerprints support inspection
or an additional pinning policy; extracting them does not authenticate the file.

This is materially less than rssig's `--integrity-only`, which still checks
CMS cryptography and content binding.

### rsigncode: real CMS checks, incomplete trust and timestamp policy

`crates/rsigncode/src/crypto/verify.rs` verifies content digests and CMS signatures.
However, chain verification only runs when CA certificates are supplied;
`VerifyResult::all_ok()` treats absent chain/timestamp results as acceptable.

`crypto/chain.rs` walks certificate signatures to an explicitly supplied CA,
with cycle/depth limits. It does not enforce validity periods, BasicConstraints,
KeyUsage, EKU, name constraints, or path-length policy. It does not trust an
arbitrary embedded self-signed certificate, but its successful walk is still
weaker than certificate-path validation.

The Microsoft RFC 3161 branch in `verify_timestamp()` verifies TSA CMS
signatures without checking the parent signature imprint or TSA trust there.
Legacy countersignature verification is absent from that function. Options
`tsa_ca_certs`, `time`, `ignore_cdp`, and `ignore_crl` are populated or declared
but not consumed by the verification engine at this snapshot. Standard-OID
timestamp work is partly delegated to its CMS dependency; that does not fill
these explicit gaps.

Its CMS dependency uses a RustCrypto fork, but the application also depends on
default-feature `reqwest` and `cryptoki`; its lockfile includes OpenSSL/native
TLS, ring, and aws-lc packages. Lockfile presence alone does not prove each is
active on every target. A resolved target-specific dependency audit would be
required before reuse under rssig's stricter dependency rules.

### pe-sign: RSA verification with limited certificate policy

The inspected 0.1.10 source performs real RSA signature and CMS message-digest
checks. `PeSign::verify_pe_*` also compares the PE digest; plain
`PeSign::verify()` only verifies the parsed SignedData. Callers must choose the
file-verification API to detect modified PE contents.

The [certificate-chain implementation](https://github.com/0xlane/pe-sign/blob/b94777828990e21d065ed2482fb31b432a359a2f/src/cert/certificate_chain.rs)
uses a bundled PEM trust set or caller-supplied certificates, links certificates
by subject/issuer names, and checks RSA certificate signatures. Its trust path
does not enforce CA BasicConstraints, path length, KeyUsage, EKU, name constraints,
or unknown critical extensions. It substitutes trusted certificates with matching
subjects and has no visible cycle/depth budget in chain construction. Missing
issuers can trigger AIA HTTP downloads with per-request timeouts. Time checking
uses the current clock, not a caller-pinned validation time.

The [SignedData implementation](https://github.com/0xlane/pe-sign/blob/b94777828990e21d065ed2482fb31b432a359a2f/src/signed_data.rs)
parses legacy countersignatures and Microsoft timestamp tokens and can extract
signing times and TSA chains. Its normal `verify()` path does not invoke these
to verify parent binding, TSA signatures/trust, or historical signer validity.
No CRL/OCSP validation is performed there; parsed revocation extensions are
inspection metadata. Nested signatures are exposed through an extraction helper;
the CLI selects a nested signature with `--embed` rather than checking all of them.

The [CLI implementation](https://github.com/0xlane/pe-sign/blob/b94777828990e21d065ed2482fb31b432a359a2f/src/main.rs)
prints `Invalid`, `Expired`, or `UntrustedCertificateChain` and then returns
`Ok(())`. Unsigned input also returns `Ok(())`. This differs from rssig's
verification-failure exit code and matters for CI consumers.

Despite the repository description's `no_std` label, this snapshot directly
imports `std`, uses blocking reqwest and a clock, and enables dependency `std`
features. It removes OpenSSL and uses RustCrypto RSA, but should not be presented
as an embedded `no_std` verifier. It remains useful as a PE inspection, certificate
display, and RSA verification reference.

### verifysign: native platform verification, a different use case

The [linked crate documentation](https://docs.rs/verifysign/1.0.1/verifysign/)
describes a Rust wrapper around platform verification. On Windows it calls
WinTrust for Authenticode and falls back to system catalog lookup; on macOS it
uses Apple's code-signing services. macOS support therefore means verifying
native Apple code signatures, not verifying Windows PE Authenticode on macOS.
Linux is explicitly unsupported.

The [Windows implementation](https://github.com/I-Alzamil/verifysign/blob/5bc23fcdd55739e2f66fb0bb8273a6ef2d0d6a8c/src/windows/mod.rs)
uses `WINTRUST_ACTION_GENERIC_VERIFY_V2` and searches catalogs by SHA-256 then
SHA-1 when appropriate. This is a meaningful advantage for Windows-native
verification of catalog-signed files. Its effective decisions depend on the
Windows trust environment, installed catalogs, cache, and selected policy.

The [policy implementation](https://github.com/I-Alzamil/verifysign/blob/5bc23fcdd55739e2f66fb0bb8273a6ef2d0d6a8c/src/policy.rs)
defaults revocation off and exposes leaf/chain revocation, network access, and
strict expiration. macOS additionally supports code requirements and validation
of all architectures. It does not expose rssig-style local CRL artifacts,
caller-pinned validation time, or a PEM root-store configuration.

verifysign is a better fit when the requirement is to ask the host OS whether a
native file/process satisfies its code-signing policy. rssig is a better fit
when the requirement is portable Windows-artifact verification on macOS/Linux
with explicit roots, time, local revocation evidence, and JSON results. This is
an architectural fit comparison, not a claim that rssig surpasses Windows native
policy. verifysign cannot replace rssig's engine under the native-verification
prohibition. A future Windows-only differential harness could use it separately;
that work remains deferred.

### Jsign: distinguish released tooling from the new verifier

The inspected README labels `verify` as new in 8.0 development. Describing all
Jsign versions as lacking verification, or attributing this verifier to 7.6,
would both be inaccurate.

`verify/SignatureVerifier.java` checks file integrity, timestamps, certificate
trust, and CMS signatures. Its trust rules use Bouncy Castle PKIX, completed
certificate chains, explicit trusted certificates, and bundled Windows trusted
public-key hashes. This differs from rssig's configured-root-only model.

`CertificateVerifier` can enable revocation, but the inspected signer and TSA
rules do not enable it. `TimestampRule` explicitly handles lifetime-signing EKU
and prioritizes legacy timestamps over RFC 3161. rssig instead rejects multiple
timestamps and has no explicit lifetime-signing branch in `verify_timestamp()`.
These are concrete policy differences worth documenting and testing.

### Relic: a broader verification reference with different defaults

`lib/authenticode/peverify.go` and the equivalent MSI/CAB APIs expressly leave
chain validation to their caller. The CLI supplies that step in
`cmdline/verify/verify.go`, unless `--no-trust-chain` is selected.

The CLI passes `x509.ExtKeyUsageAny` for the primary signer. Timestamp chain
validation separately requests timestamping EKU. `lib/pkcs9` checks timestamp
binding and uses the authenticated timestamp for the primary chain. The reviewed
CLI path does not add CRL/OCSP validation.

Relic has broader package coverage, including standalone catalogs and generic
detached-content handling that rssig lacks. Its Go `Certificate.Verify` call
also means platform verifier behavior must be examined before assuming all
verification on macOS is independent of native trust APIs.

## Where rssig is stronger, and where confidence is still limited

rssig offers a more complete verification policy than the four inspected Rust
PE implementations (authenticode-rs, cross-authenticode, rsigncode, and pe-sign):
CMS checks, configured trust anchors, signer/TSA EKUs, timestamp
binding, chain revocation, and explicit reporting when trust or revocation is
disabled. Its shared engine applies that policy across Windows formats.
`src/crypto.rs`, `src/trust.rs`, and `src/verify.rs` are the implementation
references; `src/domain.rs` defines the consumer contract.

The dependency graph uses RustCrypto with webpki's native crypto features
disabled. The macOS root adapter includes Security Framework bindings for root
enumeration. That is distinct from delegating verification to the OS.

This does not establish that rssig is more secure or more interoperable than
Jsign or Relic. Important limits remain:

- Parser/resource hardening and broader adversarial input coverage remain
  priorities. Existing truncation/bounds tests do not replace fuzzing.
- Certificate policy needs more alternative-chain, constraint, and critical
  extension coverage. A TLS-oriented path library requires explicit Authenticode
  policy decisions; current code adds leaf and intermediate KeyUsage checks.
- Timestamp multiplicity, lifetime signing, time encodings, and historical
  revocation need clearer policy coverage. Current CRLs conservatively reject a
  revoked signer even when the recorded revocation date follows signing.
- No automatic AIA/CRL fetching, OCSP, RSA-PSS, standalone catalog verification,
  or generic detached Authenticode input. Some PE layouts, script encodings,
  CAB variants, and bundle layouts are intentionally rejected.
- MSP support verifies its embedded MSI-family signature, not patch semantics,
  applicability, installation results, or Windows patch authorization.

The corpus already includes independent Jsign signatures for MSI/MSP, CAB,
PowerShell/XML, WSH, AppX packages and a bundle, upstream SignTool artifacts,
and an independently produced RDP signature. See
[the fixture manifest](../tests/fixtures/manifest.json) and format documents for
provenance and exact expectations. Some are integrity-only checks; the legacy
SignTool MSI is intentionally rejected for weak RSA. They establish specific
behaviors, not general trust-policy parity. The roadmap's independent-fixture
item predates some of these additions and should not be read as “none exist.”

## Verification-focused priorities

1. Harden parsers and bound total work; extend path-policy and timestamp-policy
   fixtures before adding formats.
2. Expand independent PE, nested-signature, timestamp, and revocation fixtures
   from Jsign/Relic. Record expected policy differences rather than assuming
   either tool is an oracle. Preserve offline, fixture-first Cargo tests.
3. Make lifetime-signing, duplicate timestamp, and historical revocation policy
   explicit. Improve reporting of which supplied CRLs actually validated paths.
4. Add controlled retrieval, OCSP, RSA-PSS, catalog signatures/membership, or
   detached inputs only when each has evidence-backed demand and test coverage.

Windows oracle integration remains deferred. No signing functionality is needed
for these priorities.

## Local validation

`cargo test --locked` passed during this review, including the in-process CLI
tests, manifest checks, and all 645 declarative cases. Maintenance/regeneration
tests remained ignored. The host was macOS; Linux was not run locally. A normal
resolved dependency graph inspection found no OpenSSL, ring, or aws-lc packages
in rssig's active host graph. No competitor performance or differential
verification benchmark was run.

`cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings`, and
`git diff --check` also passed. This review changes documentation and reference
clone ignore rules only; it does not change verifier behavior.
