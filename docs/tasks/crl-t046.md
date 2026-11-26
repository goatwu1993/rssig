# CRL-T046 refactor: Share a cached CRL body, and its digest, between the requests that repeat it

Task detail for **CRL-T046** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox. Found in the review of CRL-T041.

`HttpCrlSource` keeps each URL's body for one verification and clones it
(up to 8 MiB) into each response that repeats the URL, and the engine hashes
every repeat it receives (`hash_bytes`, 1 GiB), though it decodes one once.
The source bounds replays at 32 MiB per verification (`MAX_REPLAY_BYTES`, a
`crl_replay_bytes` denial past it), so at most about four 8 MiB repeats are
copied and hashed, and a certificate past the allowance gets no replay of a
CRL the store already holds. Sharing the body would make replays cheap enough
to raise or drop that bound. Retention is bounded by `MAX_NETWORK_BYTES`.

Sharing needs `SourcedCrl::bytes` to be shared (`Arc<[u8]>`) and to carry its
SHA-256, so the engine reuses the digest and does not hash a repeat: a public
API change. Weigh it against how often a chain repeats a point.
