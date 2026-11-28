# CLI-T005 fix: Recognise every typed layer in `from_internal`

Task detail for **CLI-T005** in [TODO.md](../../TODO.md), which keeps the ID,
title and checkbox. Found in the review of PR #117 (CLI-T004).

`VerificationError::from_internal` (`engine/src/domain.rs`) misses three
layers:

- The context messages above a `parse::Error` are dropped from `causes`: the
  by-value downcast finds the parser error under them and maps it alone.
- A `parse::Error` that is another error type's `source()` gets the caller's
  default code and stage, and loses its `scope` detail.
- A `VerificationError` attached as an anyhow context (`.context(typed)`) is
  not recognised, so the caller's default code is used.

The last two change codes, so each needs a case and a decision. No call site
is known to reach them today; the fix adds tests that fail if one does.
