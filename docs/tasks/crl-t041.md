# CRL-T041: Move the per-issuer request dedup out of the engine

Found while reviewing CRL-T039, which moved the request and distinct-URL totals
to the `CrlSource` implementations ([CRL-039](../crl.md#crl-039-fetch-limits-bound-one-verification)).

## Problem

[CRL-033](../crl.md#crl-033-retrieval-asks-per-certificate-only-about-what-lacks-a-crl)
asks a source once per certificate, and the engine skips a certificate that has
no new point and whose issuer name, authorityKeyIdentifier bytes and CA role
(`IssuerKey`, `asked_issuers` in `engine/src/retrieval.rs`) were already asked about:
CRLs are per issuer key and role, so one answer serves them all.

OpenSSL's verifier has no such rule. It calls `get_crl` or `lookup_crls` for
each certificate, and any reuse is the application's (a cache in the callback).
That makes the skip a source-side cache by OpenSSL's boundary.

It is not only an optimization: the skipped certificate is still reported, with
the failures of the points it shares recorded against it, so the report shows
every listed point for every certificate (CRL-049). Moving the skip changes what
the source is asked and, unless the engine keeps that accounting, what the
report says.

## Recommendation

Move it out. The skip is a cache, not a verdict: it decides nothing about
revocation, and the report is the same without it, because a skipped
certificate's points are recorded against it before the skip.

- The engine asks the source about every certificate the verifier reports
  without a usable CRL, once each, and keeps no `IssuerKey`, `asked_issuers` or
  `issuer_key` (including the raw authorityKeyIdentifier handling).
- Reuse is the source's: a source with a cache or a directory keyed by issuer
  answers repeats itself; one without gets one more call per certificate of an
  issuer already asked about, bounded by the certificates the verification
  budget allows.
- A call that carries no points does no HTTP in `HttpCrlSource`, so it must not
  be charged to the 64-request cap (`MAX_SOURCE_REQUESTS`); otherwise a chain
  of many same-issuer certificates could reach the cap sooner than today.
- An extra call to a source that answers by certificate may return more
  evidence. Every CRL is authenticated before it counts (CRL-048), so that
  cannot weaken a result.

## Needs

- The owner's approval, recorded in the PR: CRL-033 is Decided.
- Check `tests/cases.json` and the named tests for any case that pins how many
  times a source is asked, and keep each result (a changed call count is the
  only intended difference).
- Unit tests: every certificate of one issuer is offered to the source; the
  report still lists each certificate's shared points; `HttpCrlSource` does not
  charge a call with no points (and keeps
  `the_built_in_source_aborts_after_its_request_cap_until_a_new_verification`
  passing for calls with points).
