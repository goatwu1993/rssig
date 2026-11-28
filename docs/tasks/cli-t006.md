# CLI-T006 fix: Do not repeat a source's text in `causes` or `message`

Task detail for **CLI-T006** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox. Found in the review of PR #117 (CLI-T004).

An error whose text includes its source's (a wrapper of a
`VerificationError`, or a dependency error that displays its source) puts
that text in `causes` twice, and in an untyped error's `message`, which
`VerificationError::from_internal` builds from the whole chain.

It shows on `bad-rdp-independent-setting.rdp` only in builds where a
dependency's `std` feature is on, as under `cargo test`: `message` is
`signature error: verification error: verification error` and `causes` are
`signature error: verification error`, then `verification error`. A plain
build reports `signature error` once. The repeat in `message` is older than
CLI-T004; the one in `causes` reached the JSON when the public boundary
stopped reducing causes to the message.

Skip a chain entry's repeated suffix in both, and pin the result with a named
test that holds in either build.
