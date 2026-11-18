//! The portable case specification (`tests/cases.json`): its types, how the
//! runner interprets command arguments, and which files each case reads.
//!
//! Included by `tests/spec.rs`, which runs the cases, and by
//! `tests/manifest.rs`, which checks that every file a case reads is a listed
//! fixture. One definition keeps the two from drifting apart. Each target uses
//! a different subset of these items.
#![allow(dead_code)]

use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeMap, path::Path};

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suite {
    pub schema_version: u32,
    pub fixtures: String,
    pub cases: Vec<Case>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub id: String,
    pub input: Option<String>,
    pub crl_responses: Option<BTreeMap<String, String>>,
    pub inputs: Option<Vec<String>>,
    pub command: Vec<String>,
    pub expect: Expectation,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expectation {
    pub crl_requests: Option<Vec<String>>,
    pub exit_code: u8,
    pub json: Option<Value>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    #[serde(default)]
    pub stdout_contains: Vec<String>,
    #[serde(default)]
    pub stderr_contains: Vec<String>,
    #[serde(default)]
    pub contains: BTreeMap<String, String>,
}

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

/// A file a case reads.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CaseFile {
    /// A name directly inside the fixture directory.
    Fixture(String),
    /// Any other path: it resolves outside the fixture directory.
    Outside(String),
}

impl Case {
    /// Every file this case makes the runner or the CLI read: `input`,
    /// `inputs`, injected CRL response bodies, arguments the runner resolves as
    /// paths, and plain arguments containing a path separator (the CLI would
    /// read those relative to its working directory).
    pub fn files_read(&self, fixture_prefix: &Path) -> Vec<CaseFile> {
        // Exhaustive on purpose: a new field fails to compile until it is
        // classified here.
        let Case {
            id: _,
            input,
            crl_responses,
            inputs,
            command,
            expect: _,
        } = self;
        let mut files: Vec<CaseFile> = input
            .iter()
            .chain(inputs.iter().flatten())
            .chain(crl_responses.iter().flat_map(BTreeMap::values))
            .map(|name| CaseFile::Fixture(name.clone()))
            .collect();
        for argument in classify(command.iter().map(String::as_str), fixture_prefix) {
            match argument {
                Argument::Path(path) | Argument::InlinePath { path, .. } => {
                    files.push(fixture_path(path, fixture_prefix));
                }
                Argument::Plain(argument)
                    if !argument.contains("://") && argument.contains(['/', '\\']) =>
                {
                    files.push(CaseFile::Outside(argument.to_owned()));
                }
                Argument::Plain(_) => {}
            }
        }
        files
    }
}

/// A path argument names a fixture only when it is `<prefix>/<one name>`.
/// `Path::components` drops `.` segments and a trailing separator, which the
/// CLI would not (`fixtures/x.crl/` is not a readable file), so reject those
/// first.
fn fixture_path(path: &str, prefix: &Path) -> CaseFile {
    if path.ends_with(['/', '\\']) || path.split(['/', '\\']).any(|segment| segment == ".") {
        return CaseFile::Outside(path.to_owned());
    }
    match Path::new(path).strip_prefix(prefix) {
        Ok(rest) if rest.components().count() == 1 => match rest.to_str() {
            Some(name) if !name.is_empty() && name != "." && name != ".." => {
                CaseFile::Fixture(name.to_owned())
            }
            _ => CaseFile::Outside(path.to_owned()),
        },
        _ => CaseFile::Outside(path.to_owned()),
    }
}
