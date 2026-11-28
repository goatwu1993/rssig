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

/// How the injected source answers a request for one certificate.
#[derive(Clone, Deserialize)]
#[serde(try_from = "Value")]
pub enum CertificateAnswer {
    /// This response file alone, as a CRL without a URL.
    Fixture(String),
    Scripted(ScriptedAnswer),
}

/// An answer written out: the response the source returns, or the error it
/// fails the whole request with. None of the certificate's listed URLs is
/// requested.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptedAnswer {
    /// Bodies in the response, in order, each from a response file.
    pub crls: Option<Vec<ScriptedCrl>>,
    /// Failures in the response, in order.
    pub failures: Option<Vec<ScriptedFailure>>,
    /// The source fails the whole request with this error instead of
    /// returning a response. Excludes `crls` and `failures`.
    pub error: Option<ScriptedFailure>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptedCrl {
    pub file: String,
    /// Zero-pad the body to this many bytes, to give a source a body over a
    /// size cap without a large fixture. The engine, not the runner, judges
    /// the size. At least the file's own size.
    pub pad_to: Option<usize>,
    /// The URL the body is said to come from; none for a body offered by
    /// certificate or issuer.
    pub url: Option<String>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScriptedFailure {
    pub kind: rssig_engine::domain::CrlSourceErrorKind,
    /// The URL the failure names; none for one about the whole request.
    pub url: Option<String>,
}

fn has_null(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Array(items) => items.iter().any(has_null),
        Value::Object(fields) => fields.values().any(has_null),
        _ => false,
    }
}

impl TryFrom<Value> for CertificateAnswer {
    type Error = String;

    /// Read through a value so that a mistyped field is named, which an
    /// untagged enum would report as "did not match any variant".
    fn try_from(value: Value) -> Result<Self, String> {
        match value {
            Value::String(name) => Ok(Self::Fixture(name)),
            // A mistyped field is named first, null or not. Then: the schema
            // has no null anywhere in a scripted answer, and serde reads one
            // as an absent field, so leave a field out instead.
            Value::Object(_) => {
                let script = serde_json::from_value(value.clone())
                    .map_err(|error| format!("scripted answer: {error}"))?;
                if has_null(&value) {
                    return Err("scripted answer: null is no value; leave the field out".into());
                }
                Ok(Self::Scripted(script))
            }
            _ => Err("an answer is a fixture file name or a scripted object".into()),
        }
    }
}

impl CertificateAnswer {
    /// The response files this answer reads.
    pub fn files(&self) -> Vec<&String> {
        match self {
            Self::Fixture(name) => vec![name],
            Self::Scripted(answer) => answer.crls.iter().flatten().map(|crl| &crl.file).collect(),
        }
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub id: String,
    pub input: Option<String>,
    pub crl_responses: Option<BTreeMap<String, String>>,
    /// URLs the injected source answers with a fetch error of this kind
    /// instead of a response. Reads no file.
    pub crl_errors: Option<BTreeMap<String, rssig_engine::domain::CrlSourceErrorKind>>,
    /// The injected source also answers a request for the certificate with
    /// this SHA-256 (lowercase hex of its DER): with one response file as a
    /// CRL without a URL, the way a source keyed by certificate or issuer
    /// does, or with a scripted answer. Requires `crl_responses`.
    pub crl_certificate_responses: Option<BTreeMap<String, CertificateAnswer>>,
    /// The decision entry this case pins, such as `CRL-001`, defined in a
    /// decision index under `docs/` (AGENTS.md, "Pinned expectations"). Not
    /// used to run the case.
    pub decision: Option<String>,
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
    /// JSON Pointers (RFC 6901) that must not be a member of the output.
    #[serde(default)]
    pub json_absent: Vec<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    #[serde(default)]
    pub stdout_contains: Vec<String>,
    #[serde(default)]
    pub stderr_contains: Vec<String>,
    #[serde(default)]
    pub stderr_once: Vec<String>,
    #[serde(default)]
    pub contains: BTreeMap<String, String>,
}

include!("../../src/cli/path_options.rs");

#[derive(Debug, PartialEq, Eq)]
pub enum Argument<'a> {
    /// Passed to the CLI unchanged.
    Plain(&'a str),
    /// A file path, resolved against the directory holding `cases.json`.
    Path(&'a str),
    /// `--flag=path`; the path is resolved like [`Argument::Path`].
    InlinePath { flag: &'a str, path: &'a str },
    /// After `--`: passed unchanged, and Clap reads it as a positional file.
    Positional(&'a str),
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
    let mut positional_only = false;
    for argument in command {
        if positional_only {
            result.push(Argument::Positional(argument));
            continue;
        }
        let after_path_option = std::mem::take(&mut path_value);
        // As in Clap, a value starting with `-` after a path option is another
        // flag (the option's value is missing), except a lone `-`.
        if after_path_option && (argument == "-" || !argument.starts_with('-')) {
            result.push(Argument::Path(argument));
        } else if let Some((flag, path)) = argument.split_once('=')
            && PATH_OPTIONS.contains(&flag)
        {
            result.push(Argument::InlinePath { flag, path });
        } else {
            // `--` ends option parsing (unless it is itself a missing value).
            positional_only = argument == "--";
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
    /// An injected CRL response body. Unlike inputs, it must always exist,
    /// because the runner reads it whenever the CLI requests that URL.
    ResponseBody(String),
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
            crl_errors: _,
            crl_certificate_responses,
            decision: _,
            inputs,
            command,
            expect:
                Expectation {
                    crl_requests: _,
                    exit_code: _,
                    json: _,
                    json_absent: _,
                    stdout: _,
                    stderr: _,
                    stdout_contains: _,
                    stderr_contains: _,
                    stderr_once: _,
                    contains: _,
                },
        } = self;
        let named = |name: &String, kind: fn(String) -> CaseFile| {
            if is_fixture_name(name) {
                kind(name.clone())
            } else {
                CaseFile::Outside(name.clone())
            }
        };
        let mut files: Vec<CaseFile> = input
            .iter()
            .chain(inputs.iter().flatten())
            .map(|name| named(name, CaseFile::Fixture))
            .chain(
                crl_responses
                    .iter()
                    .flat_map(BTreeMap::values)
                    .chain(
                        crl_certificate_responses
                            .iter()
                            .flat_map(BTreeMap::values)
                            .flat_map(CertificateAnswer::files),
                    )
                    .map(|name| named(name, CaseFile::ResponseBody)),
            )
            .collect();
        for argument in classify(command.iter().map(String::as_str), fixture_prefix) {
            match argument {
                Argument::Path(path) | Argument::InlinePath { path, .. } => {
                    files.push(fixture_path(path, fixture_prefix));
                }
                // Read relative to the CLI's working directory, never a fixture.
                Argument::Positional(argument) => {
                    files.push(CaseFile::Outside(argument.to_owned()))
                }
                Argument::Plain(argument) => {
                    // `--flag=value`: only the value can be a path or a URL.
                    let value = match argument.split_once('=') {
                        Some((flag, value)) if flag.starts_with('-') => value,
                        _ => argument,
                    };
                    if !is_url(value) && value.contains(['/', '\\']) {
                        files.push(CaseFile::Outside(argument.to_owned()));
                    }
                }
            }
        }
        files
    }
}

/// `scheme://...`: a URL, never a file path. Shared with the manifest check.
pub fn is_url(text: &str) -> bool {
    text.split_once("://").is_some_and(|(scheme, _)| {
        !scheme.is_empty()
            && scheme
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    })
}

/// One plain name directly inside the fixture directory: not empty, `.` or
/// `..`, and without a path separator. Case `input`/`inputs` must be such
/// names, and a path argument names a fixture only as `<prefix>/<name>`.
pub fn is_fixture_name(name: &str) -> bool {
    !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\'])
}

/// `Path::strip_prefix` alone would accept `fixtures/./x` and `fixtures/x/`,
/// which `Path::components` normalizes but the CLI cannot open as `x`.
fn fixture_path(path: &str, prefix: &Path) -> CaseFile {
    let name = Path::new(path)
        .strip_prefix(prefix)
        .ok()
        .and_then(|rest| rest.to_str())
        .filter(|rest| is_fixture_name(rest))
        .filter(|_| !path.ends_with(['/', '\\']) && !path.split(['/', '\\']).any(|s| s == "."));
    match name {
        Some(name) => CaseFile::Fixture(name.to_owned()),
        None => CaseFile::Outside(path.to_owned()),
    }
}
