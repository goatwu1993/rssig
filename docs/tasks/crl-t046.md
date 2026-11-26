# CRL-T046 refactor: Share a cached CRL body, and its digest, between the requests that repeat it

Task detail for **CRL-T046** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox. Found in the review of CRL-T041.

`HttpCrlSource` keeps each URL's body for one verification and clones it
(up to 8 MiB) into each response that repeats the URL. So 256 certificates
sharing one 8 MiB CRL cost about 2 GiB of copying though one fetch happened.
The engine does not hash a repeat that is exactly a CRL its store holds (it
reuses the digest after a byte comparison), but a repeated PEM body, or one
that did not load, is hashed again for the report (`hash_bytes`, 1 GiB). A hit is neither an HTTP request nor network
bytes, so no source limit bounds it; the engine's budgets do. Retention is
bounded by `MAX_NETWORK_BYTES`. `fetch_each` keeps only the first
body over a request's allowance and drops the others' bytes, so one response
keeps at most its allowance plus one body.

Sharing needs `SourcedCrl::bytes` to be shared (`Arc<[u8]>`) and to carry its
SHA-256, so the engine reuses the digest and does not hash a repeat: a public
API change. Weigh it against how often a chain repeats a point.
