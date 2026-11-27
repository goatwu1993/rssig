# CRL-T045 feat: Decide whether the CLI reuses fetched CRLs across the files of one invocation

Task detail for **CRL-T045** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox. Owner decision. Found with CRL-T041
([CRL-033](../crl.md#crl-033-retrieval-asks-per-certificate-only-about-what-lacks-a-crl),
[CRL-051](../crl.md#crl-051-each-certificate-records-what-its-own-request-yielded-reuse-is-the-sources)).

`HttpCrlSource` keeps each URL's outcome for one verification only, so every
file of a batch fetches again (`docs/crl-retrieval.md`). A caching source
wrapping it for one CLI run would save fetches but:

- make a file's result depend on the files before it;
- leave a file's report without the reused CRL's provenance unless it replays
  where each CRL came from;
- change how the CRL-039 limits apply between files.

It belongs in the application, not the engine (CRL-033). A CRL stays
authenticated and checked for freshness against `--time` each time it is used
(CRL-048), so it is not a safety question.
