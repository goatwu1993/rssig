// The specification runner's file-valued options, kept beside the CLI so the
// unit test `path_options_match_the_cli_definition` in `src/cli.rs` can
// compare them with the private Clap definition. Both that test and
// `tests/common/spec_suite.rs` read this file with `include!`, so it holds
// only this item; the library builds it only in its unit tests.

/// Every long name, alias and short form of an option whose value is a file,
/// as the runner sees it before a path value (`--crl path`) or inline
/// (`--crl=path`).
pub const PATH_OPTIONS: &[&str] = &["--roots", "--crl"];
