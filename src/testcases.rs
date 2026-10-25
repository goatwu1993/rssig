//! Black-box fixture runner. Commands are argv arrays, never shell programs.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, HashSet},
    path::Path,
    process::Command,
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
    input: String,
    command: Vec<String>,
    expect: Expected,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    exit_code: i32,
    json: Value,
    #[serde(default)]
    contains: BTreeMap<String, String>,
}

#[derive(Serialize)]
struct TestCaseReport {
    id: String,
    input: String,
    command: Vec<String>,
    ok: bool,
    exit_code: Option<i32>,
    output: Option<Value>,
    failures: Vec<String>,
}
#[derive(Serialize)]
struct TestSuiteReport {
    schema_version: u32,
    command: String,
    ok: bool,
    total: usize,
    passed: usize,
    failed: usize,
    results: Vec<TestCaseReport>,
}

pub(crate) fn run(path: &Path) -> Result<(Value, u8)> {
    let path = path
        .canonicalize()
        .with_context(|| format!("opening testcase suite {}", path.display()))?;
    let suite: Suite =
        serde_json::from_slice(&std::fs::read(&path)?).context("invalid testcase JSON")?;
    ensure!(
        suite.schema_version == 1,
        "unsupported testcase schema_version"
    );
    ensure!(
        !suite.fixtures.is_empty(),
        "fixtures directory must not be empty"
    );
    ensure!(!suite.cases.is_empty(), "testcase suite is empty");
    let parent = path.parent().context("testcase suite has no directory")?;
    let fixtures = parent.join(&suite.fixtures);
    let exe = std::env::current_exe()?;
    let mut ids = HashSet::new();
    // Validate the entire suite before running it; recursive runner commands
    // and arbitrary executables are deliberately excluded.
    for case in &suite.cases {
        ensure!(
            !case.id.is_empty() && ids.insert(&case.id),
            "empty or duplicate testcase id: {}",
            case.id
        );
        ensure!(
            case.command.first().map(String::as_str) == Some("verify"),
            "testcase {} must invoke verify",
            case.id
        );
        ensure!(
            !case.input.is_empty(),
            "testcase {} needs an input file",
            case.id
        );
        ensure!(
            (0..=255).contains(&case.expect.exit_code),
            "testcase {} has invalid exit code",
            case.id
        );
    }
    let mut results = Vec::new();
    let mut passed = 0;
    for case in &suite.cases {
        let input = fixtures.join(&case.input);
        let output = Command::new(&exe)
            .args(&case.command)
            .arg(&input)
            .current_dir(parent)
            .output()
            .with_context(|| format!("running testcase {}", case.id))?;
        let mut failures = Vec::new();
        let code = output.status.code();
        if code != Some(case.expect.exit_code) {
            failures.push(format!(
                "exit code: expected {}, got {code:?}",
                case.expect.exit_code
            ));
        }
        let actual: Option<Value> = match serde_json::from_slice(&output.stdout) {
            Ok(value) => Some(value),
            Err(error) => {
                failures.push(format!("stdout is not one JSON document: {error}"));
                None
            }
        };
        if !output.stderr.is_empty() {
            failures.push(format!(
                "unexpected stderr: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        if let Some(actual) = &actual {
            compare_subset(&case.expect.json, actual, "", &mut failures);
            for (pointer, expected) in &case.expect.contains {
                match actual.pointer(pointer).and_then(Value::as_str) {
                    Some(value) if value.contains(expected) => {}
                    value => failures.push(format!(
                        "{pointer}: expected string containing {expected:?}, got {value:?}"
                    )),
                }
            }
        }
        let ok = failures.is_empty();
        passed += usize::from(ok);
        results.push(TestCaseReport {
            id: case.id.clone(),
            input: case.input.clone(),
            command: case.command.clone(),
            ok,
            exit_code: code,
            output: actual,
            failures,
        });
    }
    let ok = passed == suite.cases.len();
    Ok((
        serde_json::to_value(TestSuiteReport {
            schema_version: 1,
            command: "test".into(),
            ok,
            total: suite.cases.len(),
            passed,
            failed: suite.cases.len() - passed,
            results,
        })?,
        if ok { 0 } else { 1 },
    ))
}

/// Object expectations are subsets; arrays must have the exact expected length.
fn compare_subset(expected: &Value, actual: &Value, pointer: &str, failures: &mut Vec<String>) {
    match (expected, actual) {
        (Value::Object(expected), Value::Object(actual)) => {
            for (key, value) in expected {
                let child = format!("{pointer}/{}", key.replace('~', "~0").replace('/', "~1"));
                match actual.get(key) {
                    Some(actual) => compare_subset(value, actual, &child, failures),
                    None => failures.push(format!("{child}: missing expected field")),
                }
            }
        }
        (Value::Array(expected), Value::Array(actual)) => {
            if expected.len() != actual.len() {
                failures.push(format!(
                    "{pointer}: expected {} elements, got {}",
                    expected.len(),
                    actual.len()
                ));
            }
            for (i, (expected, actual)) in expected.iter().zip(actual).enumerate() {
                compare_subset(expected, actual, &format!("{pointer}/{i}"), failures);
            }
        }
        _ if expected == actual => {}
        _ => failures.push(format!("{pointer}: expected {expected}, got {actual}")),
    }
}
