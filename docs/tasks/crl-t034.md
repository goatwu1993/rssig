# CRL-T034 fix: Decide whether an answer by certificate matches its issuer by the compared name

Task detail for **CRL-T034** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox. Found in the review of CRL-T012; PR #79 moved verification
to RFC 5280 name comparison
([CRL-041](../crl.md#crl-041-a-crls-issuer-name-matches-by-rfc-5280-name-comparison)).

Before CRL-T041, retrieval keyed the issuers it had asked about (`asked_issuers`, through
`issuer_key` in `engine/src/retrieval.rs`) by exact issuer bytes, and a fetched CRL
counts as an issuer's answer only by exact bytes too, while verification
matches a CRL by the comparison. Two certificates whose issuers differ only in
case, spacing or string type are therefore asked about separately, spending
fetch limits ([CRL-039](../crl.md#crl-039-fetch-limits-bound-one-verification))
twice.

Since CRL-T041 retrieval keeps no asked issuers: every certificate that
lacks a CRL is asked, and reusing an answer is the source's
([CRL-033](../crl.md#crl-033-retrieval-asks-per-certificate-only-about-what-lacks-a-crl)).
What remains is the answer side below. The original plan was to key the asked issuers by the prepared name (`ComparableName` in
`engine/src/trust/names.rs`). The answer side needs care: an answer counts as the
issuer's only when its issuer is the certificate's byte for byte, because a
CRL equal only under the comparison may be another CA's, which verification
sets aside. Decide how a shared ask is credited to the second certificate, and
pin it with a retrieval case whose two certificates differ only in the case of
the issuer's name, and with a CRL for each spelling.
