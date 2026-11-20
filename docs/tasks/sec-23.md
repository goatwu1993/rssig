# SEC-23: Follow-ups left open by the PR #60 review.

Task detail for **SEC-23** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox.

The review of
PR #60 was concluded with these items not changed in that PR. Reasons and
references are in
[SEC-10](../../docs/tasks/sec-10-crl-applicability.md) ("Case reasons (PR #60)").
Decided since: a supplied CRL that is not yet valid, scoped elsewhere or
uses an unsupported feature, or is malformed, is refreshed by
`--fetch-crls`, as an expired one is; one with a bad signature or an
unsupported signature algorithm, or from an issuer without cRLSign, is
not (SEC-10, "Case reasons (refresh of an unusable supplied
CRL)").
Also decided since: a CRL without nextUpdate that lists the certificate,
alone, is `certificate_revoked`, as in OpenSSL, BoringSSL and Bouncy
Castle (SEC-10, "Case reasons (a CRL without nextUpdate that lists the
certificate)").
Retrieval and the built-in HTTP source:
- The CLI's fetch limits are per file, so a batch is bounded only by its
  file count (up to 16 requests, 32 MiB and 30 s each). Consider an
  optional batch-wide cap.
- A DNS timeout closes the built-in source for the rest of the run, even
  when only a short remaining deadline caused it. Reopening once the
  stale resolver finished was reverted (timing-dependent results, and
  `HttpCrlSource` stopped being `Sync`); find a deterministic,
  `Sync`-safe way.
- `retrieval_trust_bytes` and the other engine limits end the whole
  verification with `resource_limit_exceeded`, rather than recording the
  remaining points and finishing with the evidence gathered.
- With `fetch_each`, the first over-allowance body of a request is the
  engine's `resource_limit_exceeded` and later ones the source's
  `crl_fetch_failed`; the allowance counts accepted bodies only.
- A URL-less failure beside an answer by certificate is recorded without
  the points it concerned.
- The built-in URL check lists reserved labels; other private-use suffixes
  (`.lan`, `.corp`, `.localdomain`) rely on the DNS-answer address check.
Report shape:
- `CrlRetrievalArtifact.url`/`final_url` are omitted when absent while
  `CrlRetrievalFailure.url` serializes as `null`; pick one (with
  PRODUCT-03).
- On the RDP fallback path (a revocation that is another error type's
  source), the merged error loses the outer error's cause messages.
- Distribution-point URIs are compared byte for byte (webpki's rule), so a
  scheme or host that differs only in case does not match.
Specification coverage (with TEST-05): the spec's injected CRL source maps
URLs or certificates to bodies and error kinds, so it cannot express
URL-less failures, whole-request errors, several entries per request, a
point shared by certificates of two issuers, or the built-in source's
deadline and byte-cap behavior. Those are unit-tested only
(`docs/testing.md`); extend the case format before pinning them
portably.
Left open by the refresh of unusable supplied CRLs (SEC-10, "Case reasons
(refresh of an unusable supplied CRL)"):
- The three gap keys (`certificates_without_crl`,
  `certificates_with_expired_crl`, `certificates_with_replaceable_crl`) are
  string literals in `src/trust.rs`, `src/retrieval.rs` and `src/rdp.rs`,
  and `choose_usage_failure` sizes its merge from the RDP-only `KEYS`.
  Define them once with a shared list (this is part of SEC-22's typed
  channel), so that a fourth key cannot be missed in one place.
- When no path a source could complete has a gap, `unknown_status` falls
  back to every path and names the certificates on stuck paths too (one
  with a forged or no-cRLSign CRL), so `--fetch-crls` asks about them in
  vain. `main` pins this on purpose (unit test
  `a_revocation_then_a_missing_crl_then_the_most_specific_failure_decides`:
  a certificate without any CRL is named "so that it can still be
  retrieved"); changing it is the owner's call. The expired and
  replaceable lists are built the same way, so the decision covers all
  three.
- Beside a usable CRL, a newer complete CRL without nextUpdate that leaves
  the certificate out does not clear an older listing (it does when no CRL
  is usable). OpenSSL's best-scored newest CRL would give good status.
  Clearing it would loosen an acceptance pin: owner's decision.
- A CRL whose signature algorithm the engine cannot verify is reported
  (`unsupported_signature_algorithm`, not replaceable) even when its
  authorityKeyIdentifier names another key, whereas a CRL that fails
  verification in that case is set aside silently (`names_another_key`).
  A stray such CRL with the issuer's name makes the path one no source
  can complete. Setting it aside would let another CRL decide, which can
  turn a rejection into acceptance: owner's decision.
- An entry with reasonCode removeFromCRL releases the certificate in a
  CRL without nextUpdate standing alone (as OpenSSL's `cert_crl`), but
  beside a usable CRL any authenticated listing still revokes (PR #60
  rule), so the code depends on whether an older usable CRL is supplied.
  Releasing it there too would turn a revocation into acceptance: owner's
  decision.
- A CRL without nextUpdate that does not re-encode to its own bytes is
  never judged by webpki, so even one known to cover another point is
  reported as malformed (replaceable) instead of set aside, and a source
  may be asked about the certificate. By design, as for any CRL webpki
  would reject: its scope is not trusted enough to set it aside silently.
  A canonical encoding of the same CRL is set aside. Acceptance is the
  same either way.
- A listing that a newer CRL cleared is not logged: only an accepted
  path's ignored listings reach the logger.
- A CRL whose only defect is a missing nextUpdate is not offered to a
  source (rank above replaceable), by decision: OpenSSL, BoringSSL and
  Bouncy Castle would use it and not look again. So a stray such CRL for
  the issuer beside an expired one keeps `--fetch-crls` from asking,
  though a fetched CRL with nextUpdate would decide. Offering it would
  make retrieval fire where the references stay quiet: owner's decision.
- A CRL without nextUpdate is decoded, re-encoded and parsed by webpki a
  second time on every verification pass (each retrieval round included)
  to judge it apart from nextUpdate; that work is not charged to the
  decode budget. Cache the verdict per CRL or charge it (with SEC-17's
  other extra CRL decoding, since SEC-24 keeps webpki's parse only to
  report unsupported features).
- The conditions for a CRL without nextUpdate (when it revokes, clears
  an older listing or is set aside) are pinned by unit tests on
  `evaluate_crls` in `src/trust.rs`, not all by spec cases: the cRLSign,
  delta, removeFromCRL, not-yet-valid, malformed-AKI and unreadable-point
  variants have no committed fixture.
- `unknown_status` names every outcome passed to it, and relies on its
  callers to exclude paths no source could complete (`completable_first`,
  or the key strip in the no-viable-path branch of
  `revocation_failure`); a new caller must do the same.
Not from this PR's changes, found during its review:
- `rssig::cli::command()` is a hidden public function kept for the spec
  runner (#59).
- `tests/manifest.rs` `fixtures_are_never_indexed_as_sources` creates its
  scratch directory without the drop guard its sibling test uses.
- The strict root decoding in the CRL prefilter (see SEC-17).
