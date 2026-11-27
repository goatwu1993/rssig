# PATH-T014 test: Pin the rest of PATH-014 in `tests/cases.json`

Task detail for **PATH-T014** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox. From the PR #102 review.

[PATH-014](../path.md#path-014-a-path-certificate-that-repeats-an-extension-fails-the-path)'s
cases cover a PE code-signing leaf and intermediate. Not yet pinned by a case:

- **A timestamp signer and an RDP signer** that repeat an extension. Both
  reach `check_signer`; PATH-013 has `path-013-bad-tsa-malformed-ski` and
  `path-013-bad-rdp-leaf-malformed-eku`.
- **A certificate with both defects** (a repeat, and a value that does not
  decode): the repeat is reported. Only the unit test
  `a_repeat_of_any_extension_is_found_and_reported_first` pins the order.
- **A repeat of an extension webpki keeps, in a candidate offered before a
  valid issuer** (`bad-path-ca-repeated-bc.exe` has no "first" variant):
  whether path building goes on (PATH-009).
- **The same repeat in an embedded certificate that is on no path, or under
  another root**: the review reports that webpki 0.103.16 parses every
  embedded candidate before comparing its subject (`verify_cert.rs`), so the
  result may be `certificate_chain_invalid` with `ExtensionValueInvalid`
  rather than `untrusted_root`. Measure it first; PATH-013 has
  `path-013-bad-unrelated-malformed-issuer-is-not-blamed`, and PATH-T011
  tracks how such errors rank.
