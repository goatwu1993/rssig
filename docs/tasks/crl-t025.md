# CRL-T025 test: Consolidate CRL fixture builders and CRL-T001 fixture provenance

Task detail for **CRL-T025** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox.

Recorded from PR #44 to #53 reviews; none affects verifier behavior. Four
test builders construct a `TbsCertList` by hand (`src/tests.rs::crl`,
`validation_time.rs::crls`, `certificate_paths.rs::write_crl`,
`crl_applicability.rs::crl_full`). `crl_full` takes seven positional
arguments and stamps the signature algorithm from the main test identity
whatever issuer it is given (every test key is P-256 today). The 45 CRL-T001
fixtures come from two generators (`regenerate_crl_fixtures` for the rssig
test root's CRLs, `regenerate_path_fixtures` for the PATH-T001 chain), and the
names do not say which: `crl-root-*.crl` is the rssig test root,
`crl-path-root-*` and `crl-root-no-crl-sign.der` the PATH-T001 root. 57
PATH-T001 manifest entries have no `generator` field, so tests select those
fixtures by filename. The single-URI distribution-point encoding is written
by hand in three builders (`certificate_paths.rs`, `crl_applicability.rs`,
`crl_fetch_fixtures.rs`), and the `ski` helper in `crl_applicability.rs`
compares the OID as a string. `crl-ca-crl-sign-fallback` relies on
embedded-certificate order to exercise fallback and does not assert that the
first candidate was tried. Keep committed bytes unchanged when consolidating.
