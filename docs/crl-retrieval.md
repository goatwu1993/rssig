# Opt-in CRL discovery and retrieval (FEATURE-01)

The CLI can discover CRLs after authenticating the input's signatures and
configured-root paths:

```sh
rssig verify application.exe --fetch-crls
rssig verify application.exe --fetch-crls --no-system-roots --roots roots.pem
```

`--fetch-crls` is explicit and conflicts with `--integrity-only` and
`--no-revocation`. Existing verification entry points and ordinary CLI invocations
remain offline. Local `--crl` files can be combined with retrieval. An issuer-matching
local artifact suppresses retrieval for that issuer; freshness, authority,
applicability, signatures and revocation are still checked. An expired or forged
local artifact is not silently replaced or ignored.

The implementation first verifies all signatures and candidate trust paths with
revocation omitted internally. It discovers distribution points on selected leaf,
intermediate and timestamp certificates, including bundle children; configured
anchors are excluded. It retrieves missing CRL evidence and repeats verification
with revocation required. Only that final result can be returned as success.
Both passes share SEC-02 work allowances, so retrieval mode consumes additional
signature/path/report units and can reach a limit earlier than offline mode.
It does not exhaustively fetch evidence for alternative paths if the final path
search would prefer a different path. Missing embedded intermediates still fail;
AIA issuer fetching is a separate follow-up.

Distribution points follow the [RFC 5280 CRLDistributionPoints structure](https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13).
This initial profile accepts full URI names for direct, complete CRLs. Relative
names, reason partitions, indirect CRL issuers and non-URI names are rejected
when discovery is required. All declared URIs must satisfy transport policy;
unsupported alternatives are not silently skipped. Successfully retrieving an
artifact never implies that its signature or revocation status is valid.

## Provider boundary

Enable the optional `crl-fetch` feature for `rssig::retrieval`; `cli` includes it.
The parser and `verify-core` remain usable without network dependencies or std.

- `crl_distribution_points(&Certificate)` decodes URI discovery metadata.
- `CrlSource::fetch(url, max_bytes)` returns untrusted `FetchedCrl` bytes and the
  final URL. It never returns a trust verdict. Implementations must bound their
  own I/O, allocation and latency; the engine independently rejects oversized
  returned responses. A custom provider owns its transport policy and may use
  a cache or offline artifacts.
- `verify_with_crl_source(bytes, filename, options, source)` performs the complete
  two-pass flow. It requires configured trust and required revocation. It clones
  the supplied store; fetched certificates never become roots, and the caller's
  store is not modified.
- `cli::run_with_crl_source(argv, stdout, stderr, source)` injects a source into the
  in-process CLI. The provider is called only with `--fetch-crls`.

## Built-in HTTP policy

`HttpCrlSource` uses Rust URL/HTTP parsing with std sockets. It performs no native
cryptography and uses no subprocesses, system proxy settings, cookies or TLS.
HTTPS, LDAP, FTP and file URLs are unsupported. HTTPS support needs a separately
reviewed pure-Rust TLS backend; no TLS downgrade is attempted.

| Boundary | Limit/policy |
| --- | --- |
| Scheme and port | HTTP, port 80 only |
| URL | At most 2,048 bytes; no credentials, fragments, control characters or backslashes |
| Destinations | Reject local/single-label names and nonpublic/reserved literal addresses; reject an entire DNS answer containing nonpublic addresses |
| DNS | At most 16 answers; selected checked address is pinned directly to the TCP connection |
| Redirects | At most three per artifact; resolve, revalidate and pin every new destination |
| Requests | At most 16 distinct artifact fetches per verification and 16 HTTP hops per HTTP source (redirects included) |
| Response | At most 8 MiB per artifact; do not allocate from Content-Length |
| Loaded CRLs | At most 64 supplied and fetched artifacts combined |
| Combined trust evidence | At most 32 MiB of original roots/CRLs plus retrieved response bytes per verification |
| Wire bytes | At most 32 MiB of response headers and bodies per HTTP source |
| HTTP headers | At most 16 KiB and 64 fields; duplicate Content-Length/Location rejected |
| HTTP bodies | HTTP 200 only; identity, EOF-terminated body; Content-Length, if present, must match exactly |
| Unsupported framing | Chunked transfer and content encodings fail closed |
| Time | 30-second source lifetime starting with its first fetch; each DNS/connect/read/write wait is capped at five seconds and the remaining lifetime |

The CLI shares one HTTP source across its batch. Limits persist across files.
There is no persistent HTTP or disk cache. A verification reuses already loaded
issuer evidence and deduplicates requested URLs; final validation checks all
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
requested `url`, provider `final_url`, response `sha256`, and response `bytes`.
The list can be empty when supplied artifacts cover every selected issuer.
These are retrieval provenance fields, not individual CRL verification verdicts.
Existing CRL reports retain `role: "supplied"`; full chain revocation remains
required. Response hashes cover the original response bytes, including PEM if
supplied, while existing CRL reports describe normalized DER.

Retrieval failures use `crl_fetch_failed` or `crl_fetch_denied` at stage
`revocation`. Missing discovery/evidence uses `revocation_unknown`. Budget failures
use `resource_limit_exceeded`. Successfully downloaded artifacts remain visible
in failure `details.crl_retrieval`; a failed provider request includes its URL.
Malformed, stale, forged or revoked evidence retains existing verifier error
codes. CLI failures remain ordered entries in one JSON document, without partial
success reports. Host input and retained-output limits still apply.

Committed fixtures have deterministic test-only keys and reserved URLs. Portable
`crl_responses` case mappings and the injected CLI API supply local response
fixtures, keeping Cargo tests offline. Tests authenticate good/revoked/forged/
expired artifacts, reject private destinations before provider calls, require
signature/trust checks before retrieval, exercise timestamp/bundle/intermediate
paths, and check HTTP framing, response/header bounds and deadline policy using
in-memory inputs. No fixture is executed, installed, or used to contact a live
CRL endpoint. This does not establish Windows policy equivalence or broad online
interoperability.
