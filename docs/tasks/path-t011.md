# PATH-T011 test: Pin how the PATH-013 callback rejection ranks against webpki's errors

Task detail for **PATH-T011** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox.

The path callback rejects a path through an intermediate whose extension does
not decode with `TrailingData(RevokedCertEntry)` (`MALFORMED_INTERMEDIATE` in
`engine/src/trust.rs`), which webpki 0.103.16 ranks 40 (`error.rs`, `rank`).
Which error webpki reports depends on that rank, and no fixture pins it:

- **Search limits.** The rank is below `MaximumPathDepthExceeded` (61), so an
  unfinished search is still reported as one (`search_limit` in `path_error`).
  No fixture combines a path past webpki's depth limit with a malformed
  duplicate issuer, so a change of that rank would go unseen.
- **Equal rank.** webpki's own `MalformedExtensions` and `TrailingData` also
  rank 40, and webpki keeps the first error of equal rank. An embedded
  certificate that webpki itself cannot parse, ahead of the malformed issuer,
  hides PATH-013's `details.reason`; in the other order it is reported. Decide
  which is reported, and pin it in both orders.
- **Never raised by webpki.** `path_error` reads the callback's error as a
  malformed intermediate only with one recorded, and a `debug_assert!` checks
  that webpki never raises it itself while building a path; in a release
  build it would be reported as an unknown issuer. Pin with a test that
  fails if webpki starts to raise it (for example when built with webpki's
  revocation options).
