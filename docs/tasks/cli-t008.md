# CLI-T008 test: Guard that no code hands anyhow a boxed typed error

Task detail for **CLI-T008** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox. Found in the review of PR #120 (CLI-T005); reworded from
"recognise" to "guard" by CLI-T009 (PR #122).

`VerificationError::from_internal` finds a `VerificationError` or a
`parse::Error` only as a chain entry of its own type. Two ways of handing
anyhow a typed error hide it, and `from_internal` then reports the caller's
default code:

- an error built from a `Box<dyn Error + Send + Sync>`: `anyhow!` or `bail!`
  on one, or `anyhow::Error::from_boxed`;
- a chain entry that is a `Box<VerificationError>` or `Box<parse::Error>`:
  `anyhow::Error::new` or `?` on one.

No call site does either today. As CLI-T009 did for contexts, extend the
repository check in `tests/repository/typed_text.rs` to reject these forms
rather than recognise them, with self-tests for each.
