# CRL-T012 fix: Complete the RFC 4518 name preparation for CRL issuer matching

Task detail for **CRL-T012** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox.

[CRL-041](../crl.md#crl-041-a-crls-issuer-name-matches-by-rfc-5280-name-comparison)
applies lower-casing (each character's Unicode lowercase mapping, not the full
RFC 3454 case folding, so `ß` and `ss` differ) and white-space handling. It
applies none of the rest of RFC 4518 section 2: no Unicode normalization
(NFKC), no prohibited-character check and no map-to-nothing characters (soft
hyphen, zero-width space, control and format characters). It compares
TeletexString, BMPString and UniversalString by exact bytes. It therefore
matches fewer names than RFC 5280 section 7.1; a name it does not match leaves
the certificate's status unknown, which rejects.

Decide whether to add each, with a fixture pair that differs only in that
feature.

## Consistency of CRL-041 elsewhere

- Retrieval keys the issuers it has asked about (`asked_issuers`, through
  `issuer_key` in `src/retrieval.rs`) by exact issuer bytes, while a fetched
  CRL counts for an issuer by `names_match`. Two certificates whose issuers
  differ only in case, spacing or string type are asked about separately,
  spending fetch limits (CRL-039) twice. Key them by the prepared name.
- CRL-008's rule for issuers of one name with different keys compares the
  path issuers' names by exact bytes, so two issuers on one path whose names
  differ only in case are two issuers to it, as to webpki; OpenSSL compares
  canonically and would reject such a path when their CRLs name no key.
  Decide which, with a path fixture: two issuers whose names differ only in
  case, with CRLs without and with key identifiers.
