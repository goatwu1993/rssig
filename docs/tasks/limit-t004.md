# LIMIT-T004: Finish with the gathered evidence when an engine limit is reached

## The decision to implement (retrieval byte allowance)

Decided by the owner (delegated the call) while reviewing CRL-T037. It is not
yet an entry: this task writes it, in the index
[decisions.md](../decisions.md#which-index) gives it, and changes the cases.

1. **Two limits, two owners, both kept.** How much to fetch is the source's:
   `HttpCrlSource` already bounds its network bytes (`MAX_NETWORK_BYTES`) and
   reports `abort` when they are spent. How much the engine accepts back is
   the engine's (`MAX_CRL_BYTES`, `MAX_TOTAL_BYTES`), because a `CrlSource` is
   not trusted and a library caller can supply any source. The allowance in
   `CrlRequest` stays: it tells a source what the engine will still accept.
2. **A spent engine allowance is missing evidence, not the end of the run.**
   When the bytes accepted reach the engine's total, retrieval stops as it
   does for a source's `abort` (CRL-047): the points left are recorded as not
   tried (CRL-046), nothing more is asked, and the result is the verifier's,
   `crl_fetch_aborted` where retrieval was cut short, a definite result
   keeping its code. It is never a top-level `resource_limit_exceeded`
   (`retrieval_trust_bytes`). Both outcomes reject, so this changes
   diagnostics only and fails closed.

Today the next certificate asked about after a spent allowance ends the whole
verification with `retrieval_trust_bytes`;
`crl-046-a-spent-byte-allowance-leaves-the-points-left-not-tried` reaches that
and leaves the top-level code unpinned for this task to pin.

## Sources

- OpenSSL 3.3 (7f736187): the size limit is on the download, not in the
  verifier. `include/openssl/http.h:39` (`OSSL_HTTP_DEFAULT_MAX_CRL_LEN`,
  32 MiB) is applied by `crypto/x509/x_all.c:102` (`X509_CRL_load_http`) and
  enforced at `crypto/http/http_client.c:507-512`
  (`HTTP_R_MAX_RESP_LEN_EXCEEDED`). The fetcher is the application's callback,
  `apps/lib/apps.c:2434-2461` (`crls_http_cb`, set as `lookup_crls` at
  `:2465`), which returns no CRL when the download fails (`:468`, `:2447-2451`).
  The verifier, `crypto/x509/x509_vfy.c:1560-1602` (`get_crl_delta`), counts
  no bytes, and a lookup that yields nothing is
  `X509_V_ERR_UNABLE_TO_GET_CRL` for that certificate (`:1032-1036`), the same
  error as a CRL that does not exist.
- Bouncy Castle (bb81bfa7): the fetcher, `CrlCache.java:185-192`, sets
  timeouts and no size limit. A failed fetch is caught per distribution
  point and the next URI is tried
  (`CertPathValidatorUtilities.java:602-618`); when every one failed the
  result is a missing-CRL error naming the causes (`:628-630`), else the
  generic one (`:1340`). Validation is never ended by a fetch limit.
- So in both, a fetch limit belongs to the fetcher and its effect is "no CRL
  for this certificate". Neither has a second cap in the verifier: their
  fetcher is trusted code of the caller. rssig keeps one because its source
  is not trusted ([crl-retrieval.md](../crl-retrieval.md#where-the-engine-ends-and-the-application-begins)),
  which departs from both and is why point 1 keeps the engine's caps.
