# CRL-T043 refactor: Bound the engine's per-point state for a certificate listing many URIs

Task detail for **CRL-T043** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox.

Measured in release mode with a source that answers nothing, before CRL-T041:
200,000 URIs took about 1.0 s and 135 MB (1.3 s and 330 MB before the compact
outcome in `Retrieval::asked`, the boxed `listed_points` errors, hashed
`recorded` and the shared `in_flight` set). CRL-T041 removed `Retrieval::asked`
and `in_flight`; measure again. What remains is the points list, `unanswered`,
the per-request key sets and `recorded` (a fixed-size key per reported point);
a 64 MiB CMS allows far more.

Remaining option: a ceiling on the URIs the engine decodes per certificate.
The report cap of 16 is still unmeasured against real consumers.
