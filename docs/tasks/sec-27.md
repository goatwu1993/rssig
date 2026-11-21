# SEC-27: Decide whether a malformed extension in a CA certificate fails the path.

Task detail for **SEC-27** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox.

OpenSSL (`v3_purp.c:550-552`) and BoringSSL (`v3_purp.cc:371-375`) mark a
certificate invalid when an extension they parse does not decode, and fail a
path through such a CA certificate. rssig reads a subjectKeyIdentifier that
does not parse as absent, so the path stands and the CRL it cannot disprove is
forged ([CRL-042](../crl.md#crl-042-an-issuer-without-a-usable-key-identifier-cannot-disprove-another-keys-crl)).
Both outcomes reject a revoked or unproven path, but a malformed extension in a
CA certificate is accepted by the path rules.

This is a `PATH-` question that covers every extension rssig does not parse,
not only this one: audit which extensions webpki and rssig decode, decide
which malformed ones fail the path, and pin each with a fixture.
