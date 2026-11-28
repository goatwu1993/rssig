# CRL-T061 fix: Find a usage failure's typed error as `from_internal` does

Task detail for **CRL-T061** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox. Found in the review of PR #120 (CLI-T005).

Since CLI-T005, `VerificationError::from_internal` takes the outermost typed
layer of a chain: a `VerificationError` or a parser error that is an entry,
the error itself or another error's source (since CLI-T009 a typed value
attached as an anyhow context is not seen, and none is attached).
The RDP usage search in `engine/src/rdp.rs` still takes the first
`VerificationError` that is a chain entry, at these sites:

- the `resource_limit_exceeded` stop in `verify_trust`;
- `signer_alone`;
- `choose_usage_failure`, including its revocation lookup and the gap merges;
- `completable_by_crl`.

A usage failure carrying a parser error that is an entry would be judged under
[CRL-027](../crl.md#crl-027-which-error-a-rejected-chain-reports) by another
code than the one `from_internal` then reports. No usage failure carries one
today. Share one lookup with `from_internal` and pin the ranking with a unit
test that builds such a failure.
