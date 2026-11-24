# CRL-T040: Offer every listed point to the source and cap only the report

Found while reviewing CRL-T039, which moved the request and distinct-URL totals
to the `CrlSource` implementations ([CRL-039](../crl.md#crl-039-fetch-limits-bound-one-verification)).

## Problem

[CRL-024](../crl.md#crl-024-one-certificates-distribution-points-never-end-the-run)
offers a source at most 16 of a certificate's points and records the rest as
one `crl_urls` failure. Neither OpenSSL nor Bouncy Castle has such a limit; the
fetch policy is the application's. A source that could handle more never sees
points 17 and later.

The number protects the engine's own bookkeeping, not the source: the `points`
list of a request, the `asked` map and one failure entry per listed point in
`crl_retrieval.failures`. The verification budget bounds the certificates and
the input size, not that output: a URI of about 30 bytes becomes a failure entry
of about a kilobyte. The amplification has not been measured.

## Proposal

- Offer every listed point (after hygiene screening and deduplication) to the
  source; the source decides how many it tries.
- Cap the failure entries the report records per certificate, and count the
  rest in one entry (`details.omitted`), as CRL-024 already does for points that
  are not discovered.
- Keep `crl_url_bytes` (2,048 bytes per URI) unless hygiene screening moves too.

## Needs

- The owner's approval: CRL-024 is Decided, so the entry changes only with it,
  recorded in the PR.
- Measure the report size for a certificate listing many URIs before choosing
  the report cap.
- A spec case or unit test that a certificate listing more than 16 points
  reaches the source in full, and one that the report stays bounded.
