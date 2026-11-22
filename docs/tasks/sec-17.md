# SEC-17: Budget and consolidate CRL applicability work.

Task detail for **SEC-17** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox.

Deliberately
skipped in PRs #44 and #45. Every verification re-parses all configured
roots to collect issuer names, outside `budget.decoded_bytes`. The
mismatched-AKI signature probe runs public-key verifications outside the
`Budget` and uses its own signature-OID-to-digest table instead of the
central algorithm mapping. Cache root identities on the `TrustStore`, charge
probe verifications to the budget, and reuse one algorithm mapping.
Since PR #46, each applicable CRL is decoded three times per verification
(x509-cert, webpki borrowed, webpki owned), and the owned form allocates one
map entry per revoked certificate that is not charged beyond the existing
8x byte-length reservation. Cache parsed CRLs on the `TrustStore` and pin the
budget effect for large CRLs.
`--fetch-crls` asks the source only about the certificates the verifier
reports without a usable CRL (`details.certificates_without_crl`), as
OpenSSL's `get_crl` and Bouncy Castle look up CRLs for the certificate being
checked (PR #60). What remains: a run verifies the input up to once per
retrieval round, plus once without revocation before the first request (the
whole-input integrity and trust check), against one budget, and no case
exhausts it on that path. The per-certificate CRL evaluation decodes
each loaded CRL once per verification, but verifies CRL signatures with its
own OID table outside the budgeted algorithm adapter; reuse the adapter.
Repeated work found in the PR #60 review (results unchanged, bounded by
existing limits):
- `LoadedCrl::load` copies each applicable CRL's bytes and tbsCertList and
  builds an owned webpki CRL on every verification and retrieval round,
  only to read its unsupported-feature errors (SEC-24). Borrow from the
  store instead, and detect those features without webpki.
- The CRL signature cache key clones the issuer SPKI on every lookup, even
  on a hit; key it by CRL and issuer index.
- The path callback re-encodes and hashes every certificate on every
  candidate path, uncharged; compute it once per certificate.
- Every configured root is decoded twice per verification (issuer names
  and anchor certificates); decode it once.
With revocation on, building the CRL prefilter's issuer names uses `?` on
each configured root's x509-cert decoding (`src/trust.rs`, as on `main`),
so one root webpki accepts but x509-cert rejects fails every verification
with CRLs; skip such a root, as the anchor list already does, with a
fixture.
Retrieval skips a certificate whose listed points were all asked and
whose issuer, authority key and role (CA or end entity) were already asked
about, so a certificate that an earlier scoped or partial answer did not
cover can stay `revocation_unknown` without a request of its own; re-ask
when the earlier answer added no CRL covering it, with a paired fixture.

From SEC-16 (CRL-041): `names_match` in `src/trust/names.rs` decodes and
prepares both names for every pair of CRL and certificate issuer names that
are not byte equal, in `evaluate_crls` and `crl_may_apply`. An RDN is compared by sorting its
prepared attributes, so one pair costs n log n in the name's size, but the
work is repeated per pair and per candidate path and is not charged to the
budget; decode and prepare each name once per CRL and per path certificate,
or charge it.

Also open: a CRL without nextUpdate is decoded, re-encoded and parsed by
webpki a second time on every verification pass (each retrieval round
included) to judge it apart from nextUpdate, and that work is not charged
to the decode budget. Cache the verdict per CRL or charge it, with the
other extra CRL decoding above.
