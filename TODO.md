# Prioritized roadmap

Work from the top down. Rank reflects verification correctness and confidence
before convenience or additional formats. Every behavior change starts with a
committed fixture, declarative specification case, and named Rust test that fails for the intended reason; follow
[AGENTS.md](AGENTS.md). Production verification stays pure Rust, with the OS used
only to load roots. All CLI output stays serialized domain data.

The [verification-only comparison](docs/comparison.md) informs the priorities
below. Competitor behavior is evidence for a testcase or policy decision, not an
oracle. Preserve configured-root trust and fail-closed revocation rather than
copying permissive defaults. PE digest, CMS content binding, RSA PKCS#1 v1.5,
and ECDSA verification are already implemented; they are not missing features.

## P0 — Verification correctness

1. [ ] **Harden parser and resource limits.** Audit PE offset arithmetic, section
   ranges, ASN.1 lengths, nesting, certificate counts, and total signature limits
   across multiple certificate-table entries. Bound allocations and expensive
   cryptographic work. Add adversarial fixtures and a local fuzzing harness;
   require errors rather than panics or unbounded work. Apply aggregate budgets
   across nested signatures, timestamps, candidate chains, and embedded AppX
   packages; a per-node/depth limit alone does not bound total work. Include
   cyclic/branching issuer candidates and many individually valid signatures.
2. [ ] **Expand certificate-path policy tests.** Cover intermediate CA KeyUsage,
   EKU restrictions, path-length and name constraints, unknown critical
   extensions, alternative/cross-signed chains, and roots embedded by attackers.
   Assert the exact selected chain and error codes. Review the limitations of
   webpki's profile before describing it as complete Authenticode trust policy.
   Add same-subject/different-key issuer and root fixtures, and a chain with
   mathematically valid certificate signatures but invalid CA constraints.
   These distinguish full path validation from the simpler walks in pe-sign
   and rsigncode. Embedded or AIA-provided certificates remain untrusted candidates.
3. [ ] **Strengthen timestamp validation.** Cover malformed TSTInfo fields,
   fractional GeneralizedTime, TSA EKU/KeyUsage, duplicate timestamp attributes,
   timestamp-signature tampering, and parent-signature substitution. Define and
   test lifetime-signing and post-signing revocation policy explicitly. In
   particular, test an expired signer carrying lifetime-signing EKU plus an
   otherwise valid timestamp: add explicit handling or reject the unsupported
   policy rather than silently extending validity. Jsign's implementation is
   a reference for this distinction, not proof of Windows equivalence. Pin
   rejection of duplicate and mixed legacy/RFC 3161 timestamps; supporting a
   selection policy later requires explicit precedence and failure semantics.
4. [ ] **Strengthen CRL correctness and reporting.** Test intermediate revocation,
   missing issuer coverage, future thisUpdate, missing nextUpdate, competing
   CRLs, distribution-point scope, and unsupported delta/indirect CRLs. Report
   which CRLs were actually used without labeling every supplied artifact
   verified. Include the affected certificate/CRL in structured failures.
   Keep the current conservative post-signing-revocation rejection documented
   and tested; do not infer historical good status from a current CRL alone.

## P1 — Local coverage and dependable results

5. [ ] **Commit broader algorithm fixtures.** Audit existing CLI coverage and
   fill remaining good/bad SHA-384, SHA-512, ECDSA P-384, legacy SHA-1 opt-in,
   weak RSA, and mismatched algorithm cases, including independent artifacts.
   Check the parsed certificate,
   EKUs, trust chain, and signature metadata in the expected JSON.
6. [ ] **Make every failure classification precise.** Audit remaining generic
   anyhow fallbacks so malformed CMS, certificate-table data, invalid
   certificates/CRLs, weak algorithms, and unsupported features retain their
   actual domain code and stage. Add code/stage/details assertions, not just
   message matching.
7. [ ] **Expand PE layout coverage.** Cover multiple WIN_CERTIFICATE entries,
   section-table ordering, header/section padding, overlays, PE32/PE32+, page
   sizes, and page hashes. Document deliberately rejected layouts; do not
   silently broaden hashing rules without fixture evidence.
8. [ ] **Protect verification boundaries and failure exits.** Extend isolated
   fixtures that keep the PE digest valid while corrupting CMS content binding,
   signed attributes, or the public-key signature. Check valid-but-untrusted,
   wrong-EKU, missing/revoked-CRL, and invalid-TSA cases across the shared engine.
   Assert that integrity-only bypasses trust and revocation, while disabling
   revocation retains trust validation, with matching JSON flags. Invalid
   cryptography and unsigned input must fail in every mode; untrusted input
   must fail in trusted mode and must never be reported as trusted. This guards against the
   digest-only, unchecked-status, and optional-trust pitfalls in the comparison;
   preserve existing tests rather than duplicating them.
9. [ ] **Automate the verification dependency boundary.** Check resolved normal
   dependency graphs for Linux and macOS, including enabled features, and
   inspect build scripts/native linkage when adding dependencies. Reject
   OpenSSL, ring, aws-lc, native validation, and subprocess crypto in the engine.
   authenticode-parser links libcrypto directly from its build script, so a
   search for an `openssl` Cargo package alone is insufficient. Keep the native
   root adapter's permitted enumeration role separate from verification.
10. [x] **Move CLI coverage into Cargo.** Keep individually named in-process
    Clap tests and the Serde-loaded JSON specification with committed fixtures.
    The product has no custom test runner.
11. [x] **Run Rust tests on Linux and macOS with coverage artifacts.** Check
    formatting, Clippy, and `cargo test --locked`; publish Cobertura XML and HTML.

## P2 — Interoperability and additional features

12. [ ] **Expand independently produced local fixtures.** Existing Jsign-signed
    MSI/MSP, CAB, PowerShell/XML, WSH, AppX packages/bundles, upstream SignTool
    artifacts, and the independent RDP signature are a baseline. Add independent
    PE, nested-signature, timestamp, and trusted-chain/revocation combinations,
    including Relic-produced artifacts and narrow bad counterparts. Record tool
    versions, licensing, hashes, and provenance; distinguish integrity-only
    checks from trusted verification. Keep normal tests offline. A synthetic
    fixture's expected result is not proof of Windows acceptance.
13. [ ] **Record reproducible cross-tool verification differences.** For selected
    committed fixtures, record independently obtained digest/CMS/timestamp
    results from pinned Jsign, Relic, and other relevant implementations. Pin
    roots, time, algorithms, revocation/network settings, and each tool's actual
    verification boundary. Resolve disagreements against format evidence and
    explicit rssig policy; do not treat a competitor's `Valid` or exit 0 as a
    trusted verdict. Replay portable expectations through cases.json and native
    Cargo tests without requiring competitors or native crypto at test/runtime.
14. [ ] **Add controlled retrieval and additional revocation mechanisms.** Start
    with bounded CRL/AIA retrieval, explicit offline behavior, timeouts, cache
    policy, and pure Rust transport/validation. Bound redirects, response sizes,
    total requests and total elapsed work for certificate-controlled URLs, with
    a defined destination policy. Never promote retrieved issuers to trust
    anchors or silently enable network access. Add OCSP only with responder
    authorization, freshness, signature, and failure-policy tests. Avoid hidden
    system verifier calls or native crypto dependencies.
15. [ ] **Extend supported algorithms/formats as justified.** Consider RSA-PSS,
    catalog signatures/membership, generic detached Authenticode inputs, and
    additional formats after the current PE verification path has sufficient
    coverage. Fail with an explicit unsupported
    result until each feature is implemented and tested. Relic's catalog/detached
    support and verifysign's Windows catalog lookup are reference use cases;
    implement portable verification in Rust rather than delegating to native
    APIs. Test catalog signer trust and target-file membership separately; a
    valid catalog signature alone does not authenticate an arbitrary file.

## Deferred — Oracle integration

- [ ] Windows/SignTool/WinVerifyTrust oracle integration and differential
  verification are deferred at the user's request. They are not prerequisites
  for local development. Do not add a Windows runner as part of the work above.
- [ ] If resumed later, record reference tool/OS versions, root stores,
  validation time, revocation/network settings, and policy differences. Keep
  reference tools separate from rssig's verification engine and replay recorded
  expectations locally.

## Completed baseline

- [x] Pure Rust PE image/page hashing, CMS verification, nested signatures,
  certificate-chain validation, timestamps, and supplied-CRL validation.
- [x] Serializable verification bundles and typed errors, parsed CN/RDNs, EKUs,
  certificate chains, timestamps, and CRL artifacts.
- [x] Local fixture corpus, native in-process CLI tests, provenance/hash manifest, and
  fixture-first TDD guide and language-independent JSON specification.
- [x] Explicit unsupported digest/signature OID errors and correct classification
  of nonzero trailing WIN_CERTIFICATE payloads, with three regression fixtures.

The original 142 fixture cases and subsequent format regressions have native
Rust tests, alongside CLI interface, parser, crypto, domain, and portable
specification tests. Explicit maintenance helpers are ignored during
ordinary tests. Coverage reports measure exercised source lines; they do not
establish Windows policy equivalence or constitute a security certification.
