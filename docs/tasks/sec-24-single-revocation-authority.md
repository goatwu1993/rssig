# SEC-24: Make rssig the only revocation authority

Task detail for **SEC-24** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox. SEC-10, SEC-16, SEC-17 and SEC-18 are items in that file.

**Status:** complete. No case in `tests/cases.json` changed.

## Problem

Since PR #60, revocation was decided twice for every verification with CRLs:

1. rssig's per-certificate evaluation in the `verify_for_usage` path callback
   (`evaluate_crls`), modelled on OpenSSL's `check_cert_crl` and Bouncy
   Castle's `X509RevocationChecker`. It picks a CRL by issuer key and
   authorityKeyIdentifier, and lets webpki try another path when one is
   rejected.
2. A second `verify_for_usage` call on the accepted path with webpki
   `RevocationOptions` holding only the CRLs chosen in step 1. Any
   disagreement rejected the file.

webpki 0.103.16 picks a CRL by issuer name and issuingDistributionPoint only.
It has no key matching, delta CRLs or indirect CRLs. So the second call could
only reject what step 1 accepted. Keeping the two in step needed a special case
for self-issued key rollover (confirming the signer only, at `EndEntity`
depth). It also meant any CRL feature webpki lacks could never be accepted,
whatever step 1 decided (SEC-18).

## Change

- The second webpki call is removed. webpki builds paths without revocation
  options; the callback is the only revocation check.
- The one result the second call decided on its own is now an rssig rule on
  the accepted path, `ambiguous_issuer_keys` in `src/trust.rs`. It applies
  when two certificates on the path have issuers of one name with different
  keys, and the CRLs chosen for them do not both name their issuer's key in an
  authorityKeyIdentifier. The result is the same as before:
  `certificate_chain_invalid` at `certificate_chain` with `details.reason`
  `ambiguous_issuer_keys` (first `confirmation`; renamed in PR #64 with the
  owner's approval, see "Left open").
- `LoadedCrl.webpki` (webpki's CRL parse) is kept, but only to report
  unsupported CRL features as `invalid_crl`. Removing that parse, and with it
  the extra CRL decoding, stays in SEC-17.
- The removed webpki check is kept as a **test-only cross-check**
  (`src/trust/crosscheck.rs`, feature `revocation-crosscheck`). See below.

## Why the rule is right

The case it keeps is
`sec16-self-issued-rollover-with-both-crls-is-rejected`, a **Decided**
acceptance pin from PR #60. Its `decision` in `tests/cases.json` records what
the references do. OpenSSL 3.0.13 and BoringSSL keep one CRL per issuer name
and reject after its signature fails; Bouncy Castle tries the next CRL and
accepts. The owner chose to reject. The references are unchanged by this task:
only the code that enforces the decision moved from webpki into rssig. When
both CRLs name their issuer's key, all three references give each certificate
its own key's CRL and accept, as rssig still does
(`sec16-self-issued-rollover-with-key-identified-crls-verifies`, both orders).

## Evidence

| Check | Result |
| --- | --- |
| Full `cargo test --locked` before the change | Passed |
| Cross-check run: second webpki call kept, rssig rule added, panic on any disagreement, full suite | Passed, 0 disagreements. About 1,210 accepted-path confirmations (three log lines were interleaved with test output and not counted): at least 1,205 accepted by both, and 3 rejected by both (the SEC-16 case once in the spec and in both `--crl` orders in the named test). Not committed. |
| Rule disabled (`if false && …`) | `sec16_a_self_issued_rollover_path_needs_key_identified_crls` and the spec case fail: the file verifies (exit 0). The rule is what rejects it. |
| Full `cargo test --locked` after the change | Passed with the same test counts as before |
| `cargo fmt --check`, `cargo clippy --all-targets --locked -- -D warnings` | Passed |

The cross-check covers the committed corpus only. It shows that no committed
case depends on the removed call, not that the two engines agree on every
possible input.

## Cases

No case was added or changed.

| Case | Kind | Pins | Status |
| --- | --- | --- | --- |
| `sec16-self-issued-rollover-with-both-crls-is-rejected` | Decided (PR #60), unchanged | Acceptance | Now enforced by `ambiguous_issuer_keys` |
| `sec16-self-issued-rollover-with-key-identified-crls-verifies` and `-reversed` | Decided (PR #60), unchanged | Acceptance | Unchanged |
| `sec16-self-issued-rollover-revoked-by-key-identified-crl-is-rejected` | Unchanged | Acceptance | Decided by rssig's per-key evaluation, as before |

## Test-only cross-check

In production, rssig no longer has a second, independent revocation engine.
To keep webpki as an oracle where it can judge, the removed call runs in
every test build:

- After rssig decides an accepted path, `crosscheck::confirm` re-runs
  webpki's `verify_for_usage` with `RevocationOptions` holding the CRLs rssig
  chose, with the same rollover rule as the former production check. It
  panics if webpki and rssig disagree in either direction.
- It uses the unbudgeted algorithms and logs nothing, so it cannot change a
  result, a budget outcome or a log.
- It is compiled only with `debug_assertions`, in addition to the feature. A
  release build can never contain it, even through `cargo build --release
  --all-targets`, which unifies the self dev-dependency's feature. Release
  test runs therefore skip the cross-check.
- It asserts that every chosen CRL is one webpki can parse, which holds
  today because rssig sets such CRLs aside. Supporting CRL features webpki
  lacks (SEC-18) must make it skip those paths on purpose.
- The `revocation-crosscheck` feature enables no other feature. A
  self dev-dependency (`rssig = { path = ".", default-features = false,
  features = ["revocation-crosscheck"] }`) turns it on for unit and
  integration test builds only. Plain release and debug product builds do
  not pass `--cfg feature="revocation-crosscheck"` (checked with `cargo build
  -v`). `cargo build --all-targets` does, because the self dev-dependency's
  feature is unified with the library and binary built in the same
  invocation (checked, PR #64): a debug binary from that command contains the
  cross-check, which never changes a result but panics on a disagreement,
  and a release one still compiles it out (`debug_assertions`). Build
  product binaries without `--all-targets`. Reduced-feature CI runs keep their feature sets: the test counts for
  `--no-default-features`, `verify-core` and `verify` match the previous
  commit (36, 107, 219).

**Accepted risk:** production has no runtime backstop for revocation any
more. A regression in serial matching or CRL signature handling is caught by
the cases and, in debug test runs, by this cross-check; a release build or a
test run without it has neither. CI runs `cargo test --locked` in debug, and a
compile-time guard in the unit-test module (`src/tests/crosscheck_active.rs`)
fails the debug test build if the cross-check is not compiled in, for example
if the self dev-dependency is removed.

What it can catch is limited. webpki only sees the CRLs rssig chose, so it
checks serial lookup, the CRL signature under the algorithm adapter, and the
scope and expiry of those CRLs. It cannot catch rssig choosing the wrong CRL
or ignoring one that applies; the SEC-10 and SEC-16 cases and their OpenSSL
and Bouncy Castle comparisons remain the only check on selection. Any later
change to revocation follows AGENTS.md "Pinned expectations", item 6.

Evidence that it runs: with the new rule disabled, the named SEC-16 test
fails on the cross-check panic ("rssig accepts the accepted path, webpki
returned Some(InvalidSignatureForPublicKey)"), while the product binary, run
on the same input, exits 0 without a panic.

## Left open

- The accepted-path rule (`ambiguous_issuer_keys`) runs after webpki has
  accepted a path, so a later candidate path with unambiguous issuer keys is
  never tried. The removed webpki confirmation behaved the same way. Moving
  the rule into the path callback would let the search continue, but it
  changes error precedence and needs a fixture with two candidate paths
  first.
- ~~`details.reason` `confirmation` described history, not a webpki call.~~
  Renamed to `ambiguous_issuer_keys` in PR #64, with the owner's approval: a
  wording-only change to the Decided case
  `sec16-self-issued-rollover-with-both-crls-is-rejected` (which still pins the
  rejection and `certificate_chain_invalid`). The case, retrieval's finality
  rule and the docs changed together; the case failed against the old name.
- `ambiguous_issuer_keys` tells two same-name issuers apart by their
  complete SubjectPublicKeyInfo bytes, where the former rule compared the
  chosen CRLs' authorityKeyIdentifiers. One key encoded two ways in one path
  (for example RSA parameters NULL versus absent), with a chosen CRL that has
  no authorityKeyIdentifier, now counts as two keys and is rejected, where
  the former check would have gone on to accept it. It fails closed and no
  committed fixture has such a path; compare the key bits, with a paired
  fixture, if a case needs it.
- SEC-17: drop `LoadedCrl.webpki`, detecting unsupported features without
  webpki, so each CRL is decoded once.
- SEC-18: with no webpki veto, supporting delta CRLs or skipping known
  unsupported CRLs is now rssig's own decision.
