//! Load the portable CLI specification with Serde and exercise the CLI library.
use rssig::cli;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashSet},
    ffi::OsString,
    path::{Path, PathBuf},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Suite {
    schema_version: u32,
    fixtures: String,
    cases: Vec<Case>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    input: Option<String>,
    inputs: Option<Vec<String>>,
    command: Vec<String>,
    expect: Expectation,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expectation {
    exit_code: u8,
    json: Value,
    #[serde(default)]
    contains: BTreeMap<String, String>,
}
#[derive(Serialize)]
struct CaseResult {
    id: String,
    command: Vec<String>,
    exit_code: u8,
    output: Value,
    failures: Vec<String>,
}
impl Suite {
    fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 || self.fixtures.is_empty() || self.cases.is_empty() {
            return Err("invalid suite version, fixtures path, or empty suite".into());
        }
        let mut ids = HashSet::new();
        for case in &self.cases {
            if case.id.is_empty() || !ids.insert(&case.id) || case.command.is_empty() {
                return Err(format!("empty/duplicate case id or command: {}", case.id));
            }
            if case.input.is_some() && case.inputs.is_some() {
                return Err(format!(
                    "input and inputs are mutually exclusive: {}",
                    case.id
                ));
            }
            if case.inputs.as_ref().is_some_and(Vec::is_empty) {
                return Err(format!("inputs must not be empty: {}", case.id));
            }
            for name in case.input.iter().chain(case.inputs.iter().flatten()) {
                let path = Path::new(name);
                if name.is_empty()
                    || path.is_absolute()
                    || path
                        .components()
                        .any(|c| matches!(c, std::path::Component::ParentDir))
                {
                    return Err(format!("input must be relative to fixtures: {}", case.id));
                }
            }
            if case
                .expect
                .contains
                .keys()
                .any(|p| !p.is_empty() && !p.starts_with('/'))
            {
                return Err(format!("invalid JSON Pointer: {}", case.id));
            }
        }
        Ok(())
    }
}

fn compare(expected: &Value, actual: &Value, pointer: &str, failures: &mut Vec<String>) {
    match (expected, actual) {
        (Value::Object(expected), Value::Object(actual)) => {
            for (key, value) in expected {
                let child = format!("{pointer}/{}", key.replace('~', "~0").replace('/', "~1"));
                match actual.get(key) {
                    Some(actual) => compare(value, actual, &child, failures),
                    None => failures.push(format!("{child}: missing expected field")),
                }
            }
        }
        (Value::Array(expected), Value::Array(actual)) => {
            if expected.len() != actual.len() {
                failures.push(format!(
                    "{pointer}: expected {} array elements, got {}",
                    expected.len(),
                    actual.len()
                ));
            }
            for (i, (expected, actual)) in expected.iter().zip(actual).enumerate() {
                compare(expected, actual, &format!("{pointer}/{i}"), failures);
            }
        }
        _ if expected == actual => {}
        _ => failures.push(format!("{pointer}: expected {expected}, got {actual}")),
    }
}

fn argv(case: &Case, parent: &Path, fixtures: &Path, fixture_prefix: &Path) -> Vec<OsString> {
    let mut args = vec![OsString::from("rssig")];
    let mut path_argument = false;
    for arg in &case.command {
        let path = Path::new(arg);
        if path_argument {
            args.push(parent.join(path).into_os_string());
            path_argument = false;
        } else if let Some((flag, value)) = arg.split_once('=')
            && matches!(flag, "--roots" | "--crl")
        {
            args.push(format!("{flag}={}", parent.join(value).display()).into());
        } else {
            args.push(if path.is_relative() && path.starts_with(fixture_prefix) {
                parent.join(path).into_os_string()
            } else {
                arg.into()
            });
            path_argument = matches!(arg.as_str(), "--roots" | "--crl");
        }
    }
    args.extend(
        case.input
            .iter()
            .chain(case.inputs.iter().flatten())
            .map(|name| fixtures.join(name).into_os_string()),
    );
    args
}

fn execute(case: &Case, parent: &Path, fixtures: &Path, fixture_prefix: &Path) -> CaseResult {
    let command = argv(case, parent, fixtures, fixture_prefix);
    let mut stdout = Vec::new();
    let exit_code = cli::run(&command, &mut stdout).unwrap();
    let output: Value = serde_json::from_slice(&stdout).unwrap_or_else(|error| {
        panic!(
            "{}: stdout must be exactly one JSON document: {error}",
            case.id
        )
    });
    let mut failures = Vec::new();
    if exit_code != case.expect.exit_code {
        failures.push(format!(
            "exit code: expected {}, got {exit_code}",
            case.expect.exit_code
        ));
    }
    compare(&case.expect.json, &output, "", &mut failures);
    for (pointer, fragment) in &case.expect.contains {
        if !output
            .pointer(pointer)
            .and_then(Value::as_str)
            .is_some_and(|s| s.contains(fragment))
        {
            failures.push(format!(
                "{pointer}: expected string containing {fragment:?}"
            ));
        }
    }
    CaseResult {
        id: case.id.clone(),
        command: command
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect(),
        exit_code,
        output,
        failures,
    }
}

#[test]
fn cli_conforms_to_committed_json_specification() {
    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let suite: Suite =
        serde_json::from_slice(&std::fs::read(parent.join("cases.json")).unwrap()).unwrap();
    suite.validate().unwrap();
    let fixtures = parent.join(&suite.fixtures);
    let results: Vec<_> = suite
        .cases
        .iter()
        .map(|case| execute(case, &parent, &fixtures, Path::new(&suite.fixtures)))
        .collect();
    let failed: Vec<_> = results
        .iter()
        .filter(|c| !c.failures.is_empty())
        .map(|c| (&c.id, &c.failures))
        .collect();
    if let Some(path) = std::env::var_os("RSSIG_SPEC_REPORT") {
        let path = PathBuf::from(path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        let report = serde_json::json!({"ok":failed.is_empty(),"total":results.len(),"passed":results.len()-failed.len(),"failed":failed.len(),"results":results});
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
    assert!(failed.is_empty(), "specification failures: {failed:#?}");
}

#[test]
fn specification_comparison_requires_exact_scalars_and_arrays() {
    let mut failures = Vec::new();
    compare(
        &serde_json::json!({"ok":false}),
        &serde_json::json!({"ok":0}),
        "",
        &mut failures,
    );
    assert_eq!(failures.len(), 1);
    failures.clear();
    compare(
        &serde_json::json!({"items":[1]}),
        &serde_json::json!({"items":[1,2]}),
        "",
        &mut failures,
    );
    assert_eq!(failures.len(), 1);
    failures.clear();
    compare(
        &serde_json::json!({"items":[1]}),
        &serde_json::json!({"items":[1],"extra":true}),
        "",
        &mut failures,
    );
    assert!(failures.is_empty());
}

#[test]
fn specification_comparison_escapes_json_pointers() {
    let mut failures = Vec::new();
    compare(
        &serde_json::json!({"a/b":{"~key":1}}),
        &serde_json::json!({"a/b":{}}),
        "",
        &mut failures,
    );
    assert_eq!(failures, ["/a~1b/~0key: missing expected field"]);
}

#[test]
fn specification_rejects_duplicate_case_ids() {
    let case = serde_json::json!({"id":"duplicate","command":["--help"],"expect":{"exit_code":0,"json":{"ok":true}}});
    let suite: Suite = serde_json::from_value(
        serde_json::json!({"schema_version":1,"fixtures":"fixtures","cases":[case,case]}),
    )
    .unwrap();
    assert!(suite.validate().unwrap_err().contains("duplicate"));
}
