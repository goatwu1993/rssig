# CRL-T046 refactor: Share a cached CRL body, and its digest, between the requests that repeat it

Task detail for **CRL-T046** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox. Found in the review of CRL-T041.

`HttpCrlSource` keeps each URL's body for one verification and clones it
(up to 8 MiB) into each response that repeats the URL, and the engine decodes and hashes
every repeat it receives (it remembers no body; `decoded_bytes`, 512 MiB, a
body charged eight times). The source bounds replays at 16 MiB per
verification (`MAX_REPLAY_BYTES`, a `crl_replay_bytes` denial past it), so at
most two 8 MiB repeats are copied, decoded and hashed, and a certificate past the allowance gets no replay of a
CRL the store already holds. Sharing the body would make replays cheap enough
to raise or drop that bound. Retention is bounded by `MAX_NETWORK_BYTES`.

Sharing needs `SourcedCrl::bytes` to be shared (`Arc<[u8]>`): a public API
change. Whether the engine may then skip work for a body it is handed again is
a separate owner decision: CRL-T041 removed its memory of bodies (CRL-033). Weigh it against how often a chain repeats a point.
