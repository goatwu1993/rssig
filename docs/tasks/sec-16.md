# SEC-16: Tighten AKI/SKI matching edge cases.

Task detail for **SEC-16** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox.

Since PR #60 a CRL is
authenticated under the issuer key the path uses. Settled in PR #60 by
cross-checking OpenSSL, BoringSSL and Bouncy Castle (see "Decisions made"
in [SEC-10](../../docs/tasks/sec-10-crl-applicability.md)): on a self-issued
key-rollover path (two issuers of one name with different keys) CRLs that
each name their issuer's key verify, as in all three libraries
(`crl-007-self-issued-rollover-with-key-identified-crls-verifies`). CRLs
without key identifiers are rejected (since SEC-24 by rssig's
`ambiguous_issuer_keys`, formerly by webpki's confirmation pass), as
OpenSSL and BoringSSL reject them and unlike Bouncy Castle
(`crl-008-self-issued-rollover-with-both-crls-is-rejected`); the owner chose
that tiebreaker, so it is Decided.
Deliberately skipped in
PR #45. A name-matching candidate without an SKI cannot disprove a CRL's AKI,
so one SKI-less candidate makes the AKI check vacuous for that name. A
candidate whose SKI fails to parse is treated as having none. Issuer names
compare as exact DER, so an issuer encoded differently (PrintableString vs
UTF8String) is excluded with no diagnostic. Decide whether these should
exclude, reject or be reported, and pin each with fixtures.
An AKI that carries only authorityCertIssuer and serial is not compared at
all; the CRL is matched by issuer name
(`crl-012-root-aki-issuer-serial-crl-name-matched`). That fixture names the
root's real issuer and serial and is signed by the root, so it cannot tell
name-only matching from issuer/serial matching; a fixture with a wrong
serial is needed to pin either behavior.
