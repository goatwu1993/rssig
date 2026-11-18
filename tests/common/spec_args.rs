//! How the specification runner interprets a case's command arguments.
//!
//! Included by `tests/spec.rs`, which resolves the paths, and by
//! `tests/manifest.rs`, which checks that every file a case reads is a listed
//! fixture. Sharing one classification keeps the two from drifting apart.
use std::path::Path;

/// Options whose value is a file, given as `--crl path` or `--crl=path`.
pub const PATH_OPTIONS: &[&str] = &["--roots", "--crl"];

#[derive(Debug, PartialEq, Eq)]
pub enum Argument<'a> {
    /// Passed to the CLI unchanged.
    Plain(&'a str),
    /// A file path, resolved against the directory holding `cases.json`.
    Path(&'a str),
    /// `--flag=path`; the path is resolved like [`Argument::Path`].
    InlinePath { flag: &'a str, path: &'a str },
}

/// Classify each argument. A value following a [`PATH_OPTIONS`] flag, an
/// inline `--flag=path`, and any relative argument whose first components are
/// `fixture_prefix` are paths; everything else is plain.
pub fn classify<'a>(
    command: impl IntoIterator<Item = &'a str>,
    fixture_prefix: &Path,
) -> Vec<Argument<'a>> {
    let mut result = Vec::new();
    let mut path_value = false;
    for argument in command {
        if path_value {
            result.push(Argument::Path(argument));
            path_value = false;
        } else if let Some((flag, path)) = argument.split_once('=')
            && PATH_OPTIONS.contains(&flag)
        {
            result.push(Argument::InlinePath { flag, path });
        } else {
            let path = Path::new(argument);
            result.push(if path.is_relative() && path.starts_with(fixture_prefix) {
                Argument::Path(argument)
            } else {
                Argument::Plain(argument)
            });
            path_value = PATH_OPTIONS.contains(&argument);
        }
    }
    result
}
