# Opt-in CRL discovery and retrieval (CRL-T030)

The CLI can discover CRLs after authenticating the input's signatures and
configured-root paths:

```sh
rssig verify application.exe --fetch-crls
rssig verify application.exe --fetch-crls --no-system-roots --roots roots.pem
```

`--fetch-crls` is explicit and conflicts with `--integrity-only` and
`--no-revocation`. Existing verification entry points and ordinary CLI invocations
remain offline. Local `--crl` files can be combined with retrieval. Retrieval
never decides whether a CRL applies; verification does. No CRL applicability
rule is restated for retrieval.

1. Verify with revocation required, against the supplied CRLs. The path is
   always built first, so integrity and trust failures end the run before
   any request (`crl-011-fetch-untrusted-chain-requests-nothing`). That
   verification stops at the first signer without a CRL, so before the
   first request the whole input (every signature, nested signature,
   timestamp and bundle member) is verified once without revocation; a
   failure there is the result and nothing is asked
   (`crl-011-fetch-invalid-nested-signature-requests-nothing`). A good result,
   or any failure but `revocation_unknown`, is final, with the exceptions
   below (a revocation naming another path's gap, and an expired or
   replaceable CRL): a forged or revoking local CRL is reported as it is without
   `--fetch-crls`, unless another CRL of the same issuer is usable (the best
   CRL decides). An unknown status names, in
   `details.certificates_without_crl`, every certificate on a tried path that
   has no CRL at all, each in full (`unusable_crl` adds the most specific CRL
   that exists but could not be used). A revocation on one candidate path
   decides. When another tried path passes every other path check and has
   certificates with no CRL at all, the revocation also names them in
   `details.certificates_without_crl`
   (`crl-027-cross-revoked-path-beside-path-without-crl-names-it`), and those
   whose only CRLs have expired in `details.certificates_with_expired_crl`
   (`crl-031-cross-revoked-path-beside-path-with-expired-crl-names-it`): those
   are asked about, the other path verifies if one is found
   (`crl-017-fetch-completes-the-path-without-a-crl-beside-a-revoked-path`,
   `crl-022-fetch-refreshes-the-path-with-an-expired-crl-beside-a-revoked-path`),
   and otherwise the revocation stands
   (`crl-027-fetch-revocation-stands-when-the-other-path-stays-without-crl`). A
   path that would fail another check, such as a missing keyCertSign, is
   neither named nor considered for an unknown status
   (`crl-027-cross-revoked-path-beside-path-failing-key-usage-is-revoked`,
   `crl-027-cross-unusable-crl-decides-beside-path-failing-key-usage`), and its
   revocation does not hide such a path's own CRL failure. When no path
   passes the other path checks, revocation is still reported first, as on
   `main`, with an empty `certificates_without_crl`: no CRL could make such
   a path verify, so retrieval asks nothing. With `--fetch-crls` the whole
   input is then checked without revocation and that failure, such as
   `invalid_key_usage`, is the result
   (`crl-027-fetch-path-failing-key-usage-asks-nothing`). The same
   empty list marks a certificate the verifier could not name. When a source
   answers by certificate and its answer does not settle that certificate's
   status, the listed points it left unused are recorded as not used
   (`crl-034-fetch-by-certificate-unusable-answer-records-unused-points`). A
   certificate whose only CRLs have expired is offered to the source too, as
   Bouncy Castle drops expired CRLs and fetches from the certificate's
   points: `crl_expired` names it in `details.certificates_with_expired_crl`
   (an unknown status lists such certificates under the same key), a
   fresh CRL verifies (`crl-019-stale-local-refreshed-by-provider`), and without
   one `crl_expired` stands (`crl-019-stale-local-asks-provider`). So is one
   whose only CRLs are unusable for another reason that a source's CRL could
   replace: not yet valid, with an issuingDistributionPoint that cannot be
   used, or using an unsupported feature (an unknown critical extension, a
   delta, indirect or reasons-partitioned CRL). A CRL known to cover another
   point is not a failure: it is set aside and its certificate is listed as
   one without a CRL, as before. OpenSSL and BoringSSL look the issuer's CRLs up
   again for these, and Bouncy Castle fetches. The error that stands
   (`crl_not_yet_valid`, `invalid_crl`, an unknown status or another path's
   revocation) names it in `details.certificates_with_replaceable_crl`; a usable
   fetched CRL verifies
   (`crl-020-not-yet-valid-local-refreshed-by-provider`,
   `crl-020-unknown-critical-extension-local-refreshed-by-provider`,
   `crl-020-fetch-unusable-scope-supplied-crl-refreshed`), and without one the
   error stands (`crl-036-not-yet-valid-local-asks-provider`,
   `crl-036-fetch-unusable-scope-supplied-crl-stands-without-answer`). A
   certificate with a CRL that cannot be replaced is not offered: a bad
   signature (`crl-018-forged-local-asks-nothing`; OpenSSL and BoringSSL report
   it without another lookup), an unsupported signature algorithm, an issuer
   without cRLSign, or one whose only defect is a missing nextUpdate
   (`crl-035-no-next-update-local-asks-nothing`; the references would use such a
   CRL and not look again). A CRL without nextUpdate that has another,
   replaceable defect is offered for that defect, as it would be with
   nextUpdate present
   (`crl-035-no-next-update-point-scope-crl-is-replaceable`,
   `crl-020-fetch-no-next-update-point-scope-crl-replaced-by-certificate`). A malformed CRL is replaceable,
   alone or beside an expired one: BoringSSL drops it when decoding and
   OpenSSL still consults its store
   (`crl-020-malformed-aki-local-refreshed-by-provider`,
   `crl-020-malformed-aki-beside-expired-local-refreshed-by-provider`). The reasons are in
   [CRL-T001](tasks/crl-t001.md) ("Case reasons (refresh of an
   unusable supplied CRL)"). A path that passes every check but lacks CRLs is reported
   ahead of another path's error that webpki ranks higher, such as an
   expired cross certificate
   (`crl-027-cross-expired-path-beside-path-without-crl-names-the-gap`,
   `crl-017-fetch-completes-the-path-beside-an-expired-path`). An unknown
   status carrying `details.reason` `ambiguous_issuer_keys` (a path whose every
   certificate had a CRL) is final: no source is asked.
2. Ask the source about exactly those certificates, once each, as OpenSSL's
   `get_crl` and Bouncy Castle look up CRLs for the certificate being
   checked; a certificate that a supplied CRL covers is never asked about
   (`crl-033-fetch-covered-signer-is-not-asked`,
   `crl-033-fetch-asks-only-the-uncovered-certificate`). A source that answers
   with a CRL naming no URL looked it up by certificate or issuer: the
   points it did not use are not recorded as failures
   (`crl-034-fetch-by-certificate-answer-requests-no-listed-point`). Only a
   body that loads as a CRL of the certificate's issuer counts as such an
   answer, as OpenSSL and Bouncy Castle look CRLs up by issuer name. Those
   unused points stay open: a later certificate listing one still offers it.
   A re-offered URI counts once toward the 64 URIs passed per verification
   (`crl_source_urls`); each offer still costs a source request. When
   the answer adds a full CRL (no issuingDistributionPoint), verification
   runs again before anything else is asked: its name and syntax do not
   establish authority or freshness, so only verification can tell which of
   the issuer's certificates it covers. A body whose URL is withheld from
   the report is not an answer by certificate.
   CRLs are per issuer, so a certificate with no point left to pass on,
   whose issuer was already asked about, is not asked again and does not
   spend the request cap. A list that is present but empty (a certificate
   the verifier could not name) asks nothing.
3. Verify again with what was added, and repeat steps 2 and 3 while a round
   adds a CRL and another certificate is still reported without one.
4. If evidence is still missing, the result is the verifier's own:
   `revocation_unknown`, a revocation, or the failure of a CRL a source
   could have replaced (`crl_expired`, `crl_not_yet_valid`, `invalid_crl`).
   When the source aborted and that cut retrieval short (a certificate
   still named was never asked about, or was being asked about), an unknown
   status is `crl_fetch_aborted` (the verifier's message under
   `revocation_unknown`), and a revocation or CRL failure keeps its code
   with `retrieval_aborted: true`
   (`crl-036-stale-local-source-abort-is-marked`,
   `crl-036-not-yet-valid-local-source-abort-is-marked`,
   `crl-036-unknown-critical-extension-local-source-abort-is-marked`). An abort
   that left nothing unasked changes nothing.

Two kinds of error, and nothing in between:

- **The engine's own limits end the run**: requests to the source (64 per
  verification, `MAX_SOURCE_REQUESTS`, one per certificate), distinct URIs
  passed to it (64 distinct URIs per verification, `crl_source_urls`; one offered again after an answer by certificate left it unused counts once), CRL bodies and
  failures in one response (64, `MAX_RESPONSE_ENTRIES`), retained CRLs,
  combined bytes, and the LIMIT-T002 work budget.
- **Every other error about one listed point is no evidence from that point**:
  a URI over 2,048 bytes (`crl_url_bytes`), the URIs past a certificate's
  first 16 (one `crl_urls` entry; the first 16 still go to the source), as
  OpenSSL and Bouncy Castle never fail a chain over one certificate's points;
  it is not discovered (reasons, cRLIssuer, a relative or non-URI name; at
  most 16 such entries are kept per certificate, and one more counts the
  rest in `details.omitted`), the
  certificate's cRLDistributionPoints is malformed (webpki skips it offline),
  the URI has control characters, whitespace or credentials, or is not an
  absolute URL so that it cannot be screened (reported with its own message;
  OpenSSL's `get_dp_url` takes only `http://` URIs, `apps/lib/apps.c:2833`,
  and Bouncy Castle's `toURL()` fails on a relative one,
  `CrlCache.java:185`) (never passed to the source,
  logged or recorded; input hygiene, not transport policy; any valid scheme
  is passed; a source's own `url` detail is dropped, and a source must not
  put a URL in its message or other details), the response
  is not a CRL or is larger than allowed (not loaded), or the source reports
  `denied`, `failed` or `unknown` (see below).
- **The source reporting `abort` stops retrieval**: nothing further is
  requested, and the run verifies with what it already has.

A source reports a request that produced no CRL as one of four kinds, and the
engine treats them so:

| Kind | Meaning, chosen by the source | Recorded as | Effect |
|---|---|---|---|
| `denied` | Its policy refuses this URL | `crl_fetch_denied` | Go on with other URLs |
| `failed` | The request was made and did not work | `crl_fetch_failed` | Go on |
| `unknown` | Anything it cannot classify | `crl_fetch_failed` | Go on |
| `abort` | It can do no more work (budget spent, deadline, cancelled) | `crl_fetch_aborted` | Request nothing more |

The kind is kept in each failure entry as `source_error`. The built-in
`HttpCrlSource` reports a blocked URL as `denied`, an ordinary request failure
as `failed`, and its spent request or byte budget, its deadline or a DNS
timeout as `abort`.

No evidence never accepts anything: the next verification still requires
evidence for every selected certificate. Each such point is listed in
`crl_retrieval.failures` with the certificate's SHA-256, the URL when there is
one, and the error's code, stage, message, details and causes. A URL is
requested once; if it failed, it is listed again for each further certificate
that lists it. An unsupported point is skipped on its own, so a plain URI
beside it is still requested (`crl-033-fetch-mixed-point-requests-plain-uri`). A
response identical to a CRL already loaded adds nothing and does not trigger
another verification.

When evidence stays missing the result is the verifier's own
`revocation_unknown` (with `details.unusable_crl` naming the most specific CRL
that exists but could not be used, if any), as without `--fetch-crls`, unless the source aborted:
then it is `crl_fetch_aborted` (with the verifier's message in
`details.revocation_unknown`), so that "the source gave up" is distinct from
"no CRL was available". A good result is still returned if the CRLs gathered
before the abort are enough. `crl_fetch_denied` and `crl_fetch_failed` appear
only inside `crl_retrieval.failures`, never as the result.

Certificates that all lack a CRL are asked about in path order, in one round
(`crl-033-fetch-asks-each-certificate-without-crl`). A response that is not a
CRL, or a failed request, is no evidence while another listed point of the
same certificate supplies it
(`crl-033-fetch-bad-response-is-no-evidence-beside-another-point`). Supplied CRLs
stay loaded beside the fetched ones.

Success is only ever the result of a pass with revocation required. A run
verifies once when the supplied CRLs settle it. A run that reaches a request
also verifies once without revocation before the first request (the
whole-input integrity and trust check), and once more per retrieval round: 2
plus the number of rounds in all. All passes share
LIMIT-T002 work allowances, so retrieval mode consumes additional
signature/path/report units and can reach a limit earlier than offline mode.
It does not exhaustively fetch evidence for alternative paths if the final path
search would prefer a different path. Missing embedded intermediates still fail;
AIA issuer fetching is a separate follow-up.

Distribution points follow the [RFC 5280 CRLDistributionPoints structure](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13).
This initial profile accepts full URI names for direct, complete CRLs. Relative
names, reason partitions, indirect CRL issuers and non-URI names are not
discovered: each such point yields no evidence and is listed in
`crl_retrieval.failures`, while other plain URI points of the same certificate
are still requested. Successfully retrieving an
artifact never implies that its signature or revocation status is valid.

## Provider boundary

Enable the optional `crl-fetch` feature for `rssig::retrieval`; `cli` includes it.
The parser and `verify-core` remain usable without network dependencies or std.

- `crl_distribution_points(&Certificate)` decodes URI discovery metadata and
  fails at the first unsupported point; retrieval itself skips such points one
  by one.
- `CrlSource` is the single interface through which the engine obtains CRLs,
  asked once per certificate (see step 2 for the one exception): `crls(&CrlRequest)` receives the certificate
  (DER, as rssig re-encodes it), its issuer name (DER, the key for a store of CRLs by issuer, like
  OpenSSL's `lookup_crls`), its supported listed URIs in order (a hint:
  without URIs already asked about in this verification, deduplicated after
  normalization) and a byte budget for the whole response. It returns a
  `CrlResponse` of zero or more `SourcedCrl` bodies (bytes, and optionally the
  URL and redirect target they came from) plus per-URL `failures`, or a
  `CrlSourceError` for the whole request. Every error carries one of the four
  kinds above (`CrlSourceErrorKind`), a message, an optional URL and optional
  details. A source never returns a trust verdict.
- The engine applies no transport rule: every listed URI, of any scheme, is
  passed to the source, which alone decides where it may look and how (HTTP,
  HTTPS, LDAP, a proxy, a cache, a directory of CRLs by issuer), and refuses
  the rest as `denied`. A source that fetches by URL must screen them, since they
  come from the certificates of the file being verified and can name
  `file:` URLs or internal addresses: `retrieval::check_public_http_url`
  applies the built-in source's URL policy. A custom source therefore owns its own destination
  safety. Implementations must bound their own I/O, allocation and latency;
  the engine independently checks every size.
- `fetch_each(&request, |url, max_bytes| ...)` builds a response for a source
  that works URL by URL: it asks for each listed URI in order, with the bytes
  still allowed, and stops at the first `abort`. `HttpCrlSource` uses it.
- `CrlRequest`, `CrlResponse`, `SourcedCrl`, `CrlSourceError` and
  `CrlSourceErrorKind` are `#[non_exhaustive]`, so fields and kinds can be
  added without breaking sources; build them with their constructors
  (`CrlRequest::new` lets a wrapping source delegate to another).
- `verify_with_crl_source(bytes, filename, options, source)` performs the complete
  flow above. It requires configured trust and required revocation. It clones
  the supplied store; fetched certificates never become roots, and the caller's
  store is not modified.
- `cli::run_with_crl_source(argv, stdout, stderr, source)` injects a source into the
  in-process CLI. The provider is called only with `--fetch-crls`.

## Built-in HTTP policy

`HttpCrlSource` is the built-in `CrlSource`, used by the CLI. The policy below
is its own, not the engine's. It uses Rust URL/HTTP parsing with std sockets. It performs no native
cryptography and uses no subprocesses, system proxy settings, cookies or TLS.
HTTPS, LDAP, FTP and file URLs are unsupported. HTTPS support needs a separately
reviewed pure-Rust TLS backend; no TLS downgrade is attempted.

| Boundary | Limit/policy |
| --- | --- |
| Scheme and port | HTTP, port 80 only |
| URL | At most 2,048 bytes; no credentials, fragments, whitespace (anywhere, including around the URL), control characters or backslashes |
| Destinations | Reject single-label names; names ending in the labels `localhost`, `local`, `internal`, `home.arpa`, `invalid`, `test`, `example`, `onion` or `alt` (whole labels); nonpublic/reserved literal addresses; and an entire DNS answer containing nonpublic addresses. A denied host is reported as not public |
| DNS | At most 16 answers; selected checked address is pinned directly to the TCP connection |
| Redirects | At most three per artifact; resolve, revalidate and pin every new destination |
| Requests | At most 64 requests to the source per verification (one per certificate), and 16 HTTP hops per verification for the built-in HTTP source (redirects included) |
| Response entries | At most 64 CRL bodies and failures together in one source response (`crl_response_entries`, `MAX_RESPONSE_ENTRIES`) |
| Response | At most 8 MiB per artifact; do not allocate from Content-Length |
| Loaded CRLs | At most 64 supplied and fetched artifacts combined |
| Combined trust evidence | At most 32 MiB of original roots/CRLs plus retrieved response bytes per verification |
| Wire bytes | At most 32 MiB of response headers and bodies per verification for the built-in HTTP source |
| HTTP headers | At most 16 KiB and 64 fields; duplicate Content-Length/Location rejected |

PEM responses can contain multiple CRLs. After each response is loaded, the
combined retained count is checked after exact-DER deduplication and before
final verification. An oversized bundle fails with `resource_limit_exceeded`,
resource `retrieval_crl_artifacts`; `used` counts previously retained CRLs and
`requested` counts distinct CRLs added by that response. The failure retains
download provenance but returns no successful signature report.
| HTTP bodies | HTTP 200 only; identity, EOF-terminated body; Content-Length, if present, must match exactly |
| Unsupported framing | Chunked transfer and content encodings fail closed |
| Time | 30 seconds per verification, starting with its first fetch (restarted by `begin_verification`); after them, or after a DNS timeout (which closes the source for the rest of the run), the source reports `abort`: the result is `crl_fetch_aborted` and no further request is made; each DNS/connect/read/write wait is capped at five seconds and the remaining lifetime |

The built-in source's HTTP limits bound one verification, not a batch or a
reused instance: the engine calls `CrlSource::begin_verification` first, so in
the CLI the 16 requests, 32 MiB and 30 seconds start again for each file and
what earlier files fetched never costs a later file its CRL. OpenSSL
(`apps/lib/apps.c` `crls_http_cb`: size, timeout and redirect count per fetch)
and Bouncy Castle (`CrlCache`: timeouts per connection, no request or byte
counters) likewise charge nothing from one validation to the next, and the
owner chose this over a batch-wide bound. A batch is therefore bounded by its
file count (a slow CRL host can cost each file up to 30 seconds), so a batch
over untrusted files should be split or run under the caller's own timeout.
One state does persist: after a DNS timeout the source stays closed for the
rest of the invocation (see below), and each later file that needs a CRL is
reported `crl_fetch_aborted` without a request. This is deterministic, and it
keeps at most one unfinished resolver thread.
There is no persistent HTTP or disk cache. A verification deduplicates requested URLs; final validation checks all
freshness against the caller's validation time. Other invocations fetch again.
HTTP cache headers cannot override signed CRL validity.

The OS resolver has no cancellable std API. DNS runs in a worker with a bounded
wait; a timeout permanently closes the source to further requests. At most one
unfinished resolver worker can remain for that source. It cannot open a socket
or fetch a CRL itself. This bounds the CLI wait but does not cancel the platform
resolver's internal work. IP restrictions describe the built-in address policy,
not a replacement for an application's network routing/firewall policy.

## Results and evidence

Successful retrieval-mode bundles include optional `crl_retrieval.artifacts`:
the `certificate_sha256` the source was asked about, the `url` it names, if
any, the `final_url` (`url` unless a redirect changed it), the response
`sha256`, and `bytes`.
The list can be empty when supplied artifacts cover every selected issuer.
These are retrieval provenance fields, not individual CRL verification verdicts.
Existing CRL reports retain `role: "supplied"`; full chain revocation remains
required. Response hashes cover the original response bytes, including PEM if
supplied, while existing CRL reports describe normalized DER.

Points that yielded no evidence are listed in `crl_retrieval.failures` (omitted
when empty), on success and in failure `details.crl_retrieval`; a successful
result can therefore show that some requests failed or were denied without
that evidence being needed. Missing evidence is always `revocation_unknown`.
The engine's own limits use `resource_limit_exceeded`. Successfully downloaded artifacts remain visible in
failure `details.crl_retrieval`.
Malformed, stale, forged or revoked evidence retains existing verifier error
codes. CLI failures remain ordered entries in one JSON document, without partial
success reports. Host input and retained-output limits still apply.

Committed fixtures have deterministic test-only keys and reserved URLs. Portable
`crl_responses` case mappings and the injected CLI API supply local response
fixtures, keeping Cargo tests offline. Tests authenticate good/revoked/forged/
expired artifacts, check that the engine passes every listed URI to the
source and that the built-in source refuses private destinations and other
schemes before any network access, require
signature/trust checks before retrieval, exercise timestamp/bundle/intermediate
paths, and check HTTP framing, response/header bounds and deadline policy using
in-memory inputs. No fixture is executed, installed, or used to contact a live
CRL endpoint. This does not establish Windows policy equivalence or broad online
interoperability.
