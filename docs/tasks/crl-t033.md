# CRL-T033 refactor: Cache trust inputs and charge the remaining CRL work

Task detail for **CRL-T033** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox. These are the parts of CRL-T005 that PR #80 did not change.
That PR prepares a name only when it is compared with different bytes, and
then once per value: once when a CRL is loaded and once per certificate
per candidate path, instead of once per pair. It also decodes each
configured root once per verification, and stops the CRL signature cache
from copying the issuer key on a hit.

- Every verification decodes each configured root and each applicable CRL
  again. The bytes are charged eight times over to `hash_bytes` and
  `decoded_bytes` (`TrustStore::charge_loaded` in `src/trust.rs`), but each
  retrieval round, plus the integrity and trust run before the first
  request, repeats the work against one budget. Cache the decoded roots and
  CRLs on the `TrustStore`.
- `LoadedCrl::load` copies each applicable CRL's bytes and tbsCertList, and
  builds an owned webpki CRL (one map entry per revoked certificate) only to
  read its unsupported-feature errors (CRL-T011). Borrow from the store
  instead, and detect those features without webpki.
- The path callback re-encodes and hashes every certificate on every
  candidate path (`evaluate_crls`), and prepares its issuer name there, with
  no charge. `IssuerKey::of` and `anchor_key` likewise build each issuer's
  `CertificateName` on every candidate path, preparing it again when a
  CRL's authorityKeyIdentifier spells the issuer differently. The CRL
  prefilter decodes, re-encodes and prepares a CRL's issuer, and
  `LoadedCrl::load` does it again. Compute each of these once per
  certificate or CRL.
- Name preparation is not charged, and a prepared form is kept for as long
  as its value: each loaded CRL's issuer and authorityKeyIdentifier names,
  the prefilter's names and every `CertificateName`. Lower-cased text can
  be longer than its bytes. Charge it to `decoded_bytes` when it is first
  prepared.
- A CRL without nextUpdate is decoded, re-encoded and parsed by webpki a
  second time on every verification pass, retrieval rounds included, to
  judge it apart from nextUpdate (`stand_in_verdict`), uncharged. Cache the
  verdict per CRL or charge it.
- CRL signatures are charged to `budget.crypto`, but `signed_by` maps
  signature OIDs to digests with its own table. Verify them through the
  budgeted `ALGORITHMS` adapter instead. This may change which CRLs verify,
  so it needs fixtures.
- No case exhausts the budget with a large CRL or across retrieval rounds.
  Pin one.
