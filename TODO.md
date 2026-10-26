# Prioritized roadmap

Work from the top down. Rank reflects verification correctness and confidence
before convenience or additional formats. Every behavior change starts with a
committed fixture and JSON testcase that fails for the intended reason; follow
[AGENTS.md](AGENTS.md). Production verification stays pure Rust, with the OS used
only to load roots. All CLI output stays serialized domain data.

## P0 — Verification correctness

1. [ ] **Harden parser and resource limits.** Audit PE offset arithmetic, section
   ranges, ASN.1 lengths, nesting, certificate counts, and total signature limits
   across multiple certificate-table entries. Bound allocations and expensive
   cryptographic work. Add adversarial fixtures and a local fuzzing harness;
   require errors rather than panics or unbounded work.
2. [ ] **Expand certificate-path policy tests.** Cover intermediate CA KeyUsage,
   EKU restrictions, path-length and name constraints, unknown critical
   extensions, alternative/cross-signed chains, and roots embedded by attackers.
   Assert the exact selected chain and error codes. Review the limitations of
   webpki's profile before describing it as complete Authenticode trust policy.
3. [ ] **Strengthen timestamp validation.** Cover malformed TSTInfo fields,
   fractional GeneralizedTime, TSA EKU/KeyUsage, duplicate timestamp attributes,
   timestamp-signature tampering, and parent-signature substitution. Define and
   test lifetime-signing and post-signing revocation policy explicitly.
4. [ ] **Strengthen CRL correctness and reporting.** Test intermediate revocation,
   missing issuer coverage, future thisUpdate, missing nextUpdate, competing
   CRLs, distribution-point scope, and unsupported delta/indirect CRLs. Report
   which CRLs were actually used without labeling every supplied artifact
   verified. Include the affected certificate/CRL in structured failures.

## P1 — Local coverage and dependable results

5. [ ] **Commit broader algorithm fixtures.** Move RSA coverage beyond unit tests
   into the CLI corpus; add good/bad SHA-384, SHA-512, ECDSA P-384, legacy SHA-1
   opt-in, weak RSA, and mismatched algorithm cases. Check the parsed certificate,
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
8. [ ] **Harden the local JSON testcase runner.** Add regression tests for wrong
   expectations, malformed suites, duplicate IDs, recursive commands, invalid
   JSON stdout, and process timeouts. Ensure the fixture manifest covers every
   artifact and detects unexpected additions or omissions.
9. [ ] **Run ordinary Rust/fixture CI on Linux and macOS.** Check formatting,
   Clippy, tests, and the JSON suite; retain JSON reports. Confirm Linux behavior
   before claiming Linux execution has been validated. This requires no oracle.

## P2 — Interoperability and additional features

10. [ ] **Add independently produced local fixtures.** Include redistributable
    jsign/relic-signed artifacts with tool versions, licensing, hashes, and
    provenance. Keep normal tests offline. A synthetic fixture's expected result
    is a project assertion, not proof of Windows acceptance.
11. [ ] **Add controlled retrieval and additional revocation mechanisms.** Start
    with bounded CRL/AIA retrieval, explicit offline behavior, timeouts, cache
    policy, and pure Rust transport/validation. Add OCSP only with responder
    authorization, freshness, signature, and failure-policy tests. Avoid hidden
    system verifier calls or native crypto dependencies.
12. [ ] **Extend supported algorithms/formats as justified.** Consider RSA-PSS,
    catalog signatures, and additional Authenticode formats after the current PE
    verification path has sufficient coverage. Fail with an explicit unsupported
    result until each feature is implemented and tested.

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
- [x] Local fixture corpus, JSON testcase runner, provenance/hash manifest, and
  fixture-first TDD guide.
- [x] Explicit unsupported digest/signature OID errors and correct classification
  of nonzero trailing WIN_CERTIFICATE payloads, with three regression fixtures.

Current local suite: 33 JSON cases and 12 passing Rust tests; the explicit fixture
regenerator is ignored during ordinary tests. These counts describe local
coverage, not an external compatibility or security certification.
