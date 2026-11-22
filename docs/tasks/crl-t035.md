# CRL-T035 fix: Decide whether CRL-008 compares issuer names canonically (owner decision)

Task detail for **CRL-T035** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox. Found in the review of CRL-T012.

[CRL-008](../crl.md#crl-008-a-rollover-path-with-crls-that-name-no-key-is-rejected)'s
rule for issuers of one name with different keys compares the names of the
issuers on the path by exact bytes, so two issuers on one path whose names
differ only in case, spacing or string type are two issuers to it, as to
webpki. OpenSSL compares names canonically and would treat them as one, and so
reject the path when their CRLs name no key.

Decide which, and pin it with a path fixture: two issuers whose names differ
only in case, with CRLs without and with key identifiers. Making the rule
canonical rejects more paths, so it needs the owner's approval; webpki still
requires a certificate's issuer to equal its issuer's subject byte for byte
when it builds the path, so such a path is rare.
