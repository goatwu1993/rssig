# SEC-22: Pass uncovered certificates to retrieval as typed data.

Task detail for **SEC-22** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox.

From the PR #60 review. `--fetch-crls` learns which certificates lack a
usable CRL by reading `certificates_without_crl` back out of the error's JSON
`details` and hex-decoding each `der_hex`. If that schema changes and the
list no longer deserializes, retrieval treats the result as final and
quietly asks nothing (the same holds for `certificates_with_expired_crl`
and `certificates_with_replaceable_crl`),
so `--fetch-crls` stops fetching with no error. Carry the uncovered certificates' DER
beside the error inside the crate, keep the JSON field for consumers, and
pin the request sequence with a test.
Carry the original certificate bytes through that channel too. Today
`CrlRequest.certificate`, its `issuer`, `certificates_without_crl` and
`certificate_sha256` all use rssig's re-encoding, which equals the
original for DER-conformant input. der sorts a SET OF while decoding, so
a certificate whose name has a multi-valued RDN out of DER order reaches a
source with an invalid signature and a sorted issuer key, and a portable
`crl_certificate_responses` implementation hashing the original bytes
disagrees. Add a fixture with such a name before changing it.
