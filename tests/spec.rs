//! Load the portable CLI specification with Serde and exercise the CLI library.
#[path = "common/spec_suite.rs"]
mod spec_suite;

use rssig::cli;
use serde::Serialize;
use serde_json::Value;
use spec_suite::{Argument, Case, Suite};
use std::{
    collections::{BTreeMap, HashSet},
    ffi::OsString,
    path::{Path, PathBuf},
};

/// One `### CRL-001: title` entry of a decision index under `docs/`
/// (AGENTS.md, "Pinned expectations").
#[derive(Debug)]
struct DecisionEntry {
    status: String,
}

impl DecisionEntry {
    /// `Decided` and `Observed` entries may be named by a case; `Retired` and
    /// `Superseded by` ones may not.
    fn in_force(&self) -> bool {
        matches!(self.status.as_str(), "Decided" | "Observed")
    }
}

/// Reads every decision entry from the given documents: a level-three
/// heading `### PREFIX-NNN: title` followed by `- **Status:**`,
/// `- **Decided by:**` and `- **Pins:**` lines before the next heading.
fn parse_decisions(
    documents: impl IntoIterator<Item = (String, String)>,
) -> Result<BTreeMap<String, DecisionEntry>, String> {
    let is_id = |id: &str| {
        id.split_once('-').is_some_and(|(prefix, number)| {
            !prefix.is_empty()
                && prefix.bytes().all(|b| b.is_ascii_uppercase())
                && number.len() == 3
                && number.bytes().all(|b| b.is_ascii_digit())
        })
    };
    let mut entries = BTreeMap::new();
    let mut superseded = Vec::new();
    for (name, text) in documents {
        let mut lines = text.lines().peekable();
        while let Some(line) = lines.next() {
            let Some((id, _title)) = line.strip_prefix("### ").and_then(|h| h.split_once(": "))
            else {
                continue;
            };
            if !is_id(id) {
                continue;
            }
            let mut field = BTreeMap::new();
            while let Some(next) = lines.next_if(|l| !l.starts_with('#')) {
                for key in ["Status", "Decided by", "Pins"] {
                    if let Some(value) = next.strip_prefix(&format!("- **{key}:**")) {
                        field.insert(key, value.trim().to_owned());
                    }
                }
            }
            let get = |key| field.get(key).cloned().unwrap_or_default();
            let (status, by, pins) = (get("Status"), get("Decided by"), get("Pins"));
            let target = status.strip_prefix("Superseded by ");
            if !matches!(status.as_str(), "Decided" | "Observed" | "Retired")
                && !target.is_some_and(is_id)
            {
                return Err(format!("{name}: {id} has an unknown status {status:?}"));
            }
            if by.is_empty() || (by == "—") != (status == "Observed") {
                return Err(format!(
                    "{name}: {id} needs decided by `—` exactly when Observed, got {by:?}"
                ));
            }
            if !matches!(pins.as_str(), "acceptance" | "diagnostics") {
                return Err(format!(
                    "{name}: {id} pins must be acceptance or diagnostics, got {pins:?}"
                ));
            }
            if let Some(target) = target {
                superseded.push((id.to_owned(), target.to_owned()));
            }
            if entries
                .insert(id.to_owned(), DecisionEntry { status })
                .is_some()
            {
                return Err(format!("{name}: duplicate decision {id}"));
            }
        }
    }
    for (id, target) in superseded {
        if !entries.contains_key(&target) {
            return Err(format!(
                "{id} is superseded by {target}, which is not defined"
            ));
        }
    }
    Ok(entries)
}

/// The decision entries of every Markdown document directly under `docs/`.
fn committed_decisions() -> Result<&'static BTreeMap<String, DecisionEntry>, String> {
    static INDEX: std::sync::OnceLock<Result<BTreeMap<String, DecisionEntry>, String>> =
        std::sync::OnceLock::new();
    INDEX
        .get_or_init(|| {
            let docs = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs");
            let mut documents = Vec::new();
            for entry in std::fs::read_dir(&docs).map_err(|e| format!("docs/: {e}"))? {
                let path = entry.map_err(|e| format!("docs/: {e}"))?.path();
                if path.extension().is_some_and(|e| e == "md") {
                    let text = std::fs::read_to_string(&path)
                        .map_err(|e| format!("{}: {e}", path.display()))?;
                    documents.push((
                        format!("docs/{}", path.file_name().unwrap().to_string_lossy()),
                        text,
                    ));
                }
            }
            parse_decisions(documents)
        })
        .as_ref()
        .map_err(Clone::clone)
}

#[derive(Serialize)]
struct CaseResult {
    id: String,
    command: Vec<String>,
    exit_code: u8,
    output: Value,
    stdout: String,
    stderr: String,
    failures: Vec<String>,
}
impl Suite {
    fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1 || self.fixtures.is_empty() || self.cases.is_empty() {
            return Err("invalid suite version, fixtures path, or empty suite".into());
        }
        let mut ids = HashSet::new();
        for case in &self.cases {
            if let Some(id) = &case.decision {
                match committed_decisions()?.get(id) {
                    None => {
                        return Err(format!(
                            "case {} names decision {id}, which no index under docs/ defines",
                            case.id
                        ));
                    }
                    Some(entry) if !entry.in_force() => {
                        return Err(format!(
                            "case {} names decision {id}, whose status is {}",
                            case.id, entry.status
                        ));
                    }
                    Some(_) => {}
                }
            }
            let expect = &case.expect;
            if case.crl_errors.is_some() && case.crl_responses.is_none() {
                return Err(format!("crl_errors requires crl_responses: {}", case.id));
            }
            if let Some(answers) = &case.crl_certificate_responses {
                if case.crl_responses.is_none() {
                    return Err(format!(
                        "crl_certificate_responses requires crl_responses: {}",
                        case.id
                    ));
                }
                let digest = |key: &String| {
                    key.len() == 64
                        && key
                            .bytes()
                            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                };
                if !answers
                    .iter()
                    .all(|(key, name)| digest(key) && spec_suite::is_fixture_name(name))
                {
                    return Err(format!(
                        "crl_certificate_responses maps a lowercase SHA-256 to a fixture file name: {}",
                        case.id
                    ));
                }
            }
            if expect.crl_requests.is_some() && case.crl_responses.is_none() {
                return Err(format!(
                    "crl_requests requires an injected source: {}",
                    case.id
                ));
            }
            let modes = usize::from(expect.json.is_some())
                + usize::from(!expect.stdout_contains.is_empty())
                + usize::from(!expect.stderr_contains.is_empty());
            if modes != 1 || (expect.json.is_none() && !expect.contains.is_empty()) {
                return Err(format!(
                    "expected one JSON or text output mode: {}",
                    case.id
                ));
            }
            if !expect.stderr_once.is_empty() && expect.stderr_contains.is_empty() {
                return Err(format!("stderr_once requires stderr_contains: {}", case.id));
            }
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
            if !case
                .input
                .iter()
                .chain(case.inputs.iter().flatten())
                .all(|name| spec_suite::is_fixture_name(name))
            {
                return Err(format!("input must be a fixture file name: {}", case.id));
            }
            if !case
                .crl_responses
                .iter()
                .flat_map(BTreeMap::values)
                .all(|name| spec_suite::is_fixture_name(name))
            {
                return Err(format!(
                    "crl_responses body must be a fixture file name: {}",
                    case.id
                ));
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
    for argument in spec_suite::classify(case.command.iter().map(String::as_str), fixture_prefix) {
        args.push(match argument {
            Argument::Plain(argument) | Argument::Positional(argument) => argument.into(),
            Argument::Path(path) => parent.join(path).into_os_string(),
            Argument::InlinePath { flag, path } => {
                format!("{flag}={}", parent.join(path).display()).into()
            }
        });
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
    let mut stderr = Vec::new();
    struct Source<'a> {
        responses: &'a BTreeMap<String, String>,
        by_certificate: Option<&'a BTreeMap<String, String>>,
        errors: Option<&'a BTreeMap<String, rssig::domain::CrlSourceErrorKind>>,
        fixtures: &'a Path,
        requests: &'a mut Vec<String>,
    }
    impl rssig::retrieval::CrlSource for Source<'_> {
        fn crls(
            &mut self,
            request: &rssig::retrieval::CrlRequest<'_>,
        ) -> Result<rssig::retrieval::CrlResponse, rssig::retrieval::CrlSourceError> {
            use sha2::Digest;
            let certificate: String = sha2::Sha256::digest(request.certificate)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let by_certificate = self
                .by_certificate
                .and_then(|answers| answers.get(&certificate))
                .map(|name| std::fs::read(self.fixtures.join(name)).unwrap());
            // A source keyed by certificate answers such a certificate with
            // its CRL alone, within the allowance, and requests none of its
            // listed URLs.
            if let Some(bytes) = by_certificate {
                assert!(bytes.len() <= request.max_bytes);
                return Ok(rssig::retrieval::CrlResponse::new()
                    .with_crl(rssig::retrieval::SourcedCrl::new(bytes)));
            }
            let response = rssig::retrieval::fetch_each(request, |url, max_bytes| {
                use rssig::domain::CrlSourceErrorKind;
                use rssig::retrieval::CrlSourceError;
                self.requests.push(url.to_owned());
                if let Some(kind) = self.errors.and_then(|errors| errors.get(url)) {
                    return Err(CrlSourceError::new(*kind, "injected CRL fetch error"));
                }
                let name = self.responses.get(url).ok_or_else(|| {
                    CrlSourceError::new(CrlSourceErrorKind::Failed, "no injected CRL response")
                })?;
                let path = Path::new(name);
                assert!(
                    path.is_relative()
                        && !path
                            .components()
                            .any(|c| matches!(c, std::path::Component::ParentDir))
                );
                let bytes = std::fs::read(self.fixtures.join(path)).unwrap();
                assert!(bytes.len() <= max_bytes);
                Ok(rssig::retrieval::SourcedCrl::new(bytes))
            });
            Ok(response)
        }
    }
    let mut requests = Vec::new();
    let exit_code = if let Some(responses) = &case.crl_responses {
        cli::run_with_crl_source(
            &command,
            &mut stdout,
            &mut stderr,
            &mut Source {
                responses,
                by_certificate: case.crl_certificate_responses.as_ref(),
                errors: case.crl_errors.as_ref(),
                fixtures,
                requests: &mut requests,
            },
        )
        .unwrap()
    } else {
        cli::run_with_writers(&command, &mut stdout, &mut stderr).unwrap()
    };
    let output = serde_json::from_slice::<Value>(&stdout);
    let mut failures = Vec::new();
    if let Some(expected) = &case.expect.crl_requests {
        compare(
            &serde_json::json!(expected),
            &serde_json::json!(requests),
            "/crl_requests",
            &mut failures,
        );
    }
    if let Some(expected) = &case.expect.json {
        match &output {
            Ok(output) => compare(expected, output, "", &mut failures),
            Err(error) => {
                failures.push(format!("stdout must be exactly one JSON document: {error}"))
            }
        }
    } else if output.is_ok() || serde_json::from_slice::<Value>(&stderr).is_ok() {
        failures.push("command diagnostics must be plain text, not JSON".into());
    }
    let output = output.unwrap_or(Value::Null);
    let stdout = String::from_utf8(stdout).unwrap();
    let stderr = String::from_utf8(stderr).unwrap();
    for (name, actual, expected, fragments) in [
        (
            "stdout",
            &stdout,
            case.expect.stdout.as_deref(),
            &case.expect.stdout_contains,
        ),
        (
            "stderr",
            &stderr,
            case.expect.stderr.as_deref(),
            &case.expect.stderr_contains,
        ),
    ] {
        if let Some(expected) = expected {
            if actual != expected {
                failures.push(format!("{name}: expected {expected:?}, got {actual:?}"));
            }
        } else if name == "stderr" && fragments.is_empty() && !actual.is_empty() {
            failures.push(format!("unexpected stderr: {actual:?}"));
        }
        for fragment in fragments {
            if !actual.contains(fragment) {
                failures.push(format!("{name}: expected {fragment:?}, got {actual:?}"));
            }
        }
    }
    for fragment in &case.expect.stderr_once {
        let count = stderr.matches(fragment.as_str()).count();
        if count != 1 {
            failures.push(format!(
                "stderr: expected {fragment:?} exactly once, found {count}: {stderr:?}"
            ));
        }
    }
    if exit_code != case.expect.exit_code {
        failures.push(format!(
            "exit code: expected {}, got {exit_code}",
            case.expect.exit_code
        ));
    }
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
        stdout,
        stderr,
        failures,
    }
}

/// Every case's `decision` names an entry in force in a committed decision
/// index, and the committed indexes are well formed.
#[test]
fn case_decisions_name_committed_entries() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let suite: Suite =
        serde_json::from_slice(&std::fs::read(root.join("tests/cases.json")).unwrap()).unwrap();
    suite.validate().unwrap();
    let decisions = committed_decisions().unwrap();
    assert!(
        decisions.contains_key("CRL-001"),
        "docs/crl.md is not indexed"
    );
    assert!(
        suite.cases.iter().any(|case| case.decision.is_some()),
        "no case names a decision"
    );
}

/// Every case without a `decision` is claimed by exactly one decision index
/// and one of its candidate rules in `tests/decision-claims.json`, and each
/// candidate key is listed in that index's "Candidate rules" section.
#[test]
fn undecided_cases_are_claimed_by_exactly_one_index() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let suite: Suite =
        serde_json::from_slice(&std::fs::read(root.join("tests/cases.json")).unwrap()).unwrap();
    let claims: Value =
        serde_json::from_slice(&std::fs::read(root.join("tests/decision-claims.json")).unwrap())
            .unwrap();
    let index = std::fs::read_to_string(root.join("docs/decisions.md")).unwrap();
    let files: BTreeMap<&str, &str> = index
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("| `")?;
            let (prefix, rest) = rest.split_once("-` | [")?;
            let (_, rest) = rest.split_once("](")?;
            Some((prefix, rest.split_once(')')?.0))
        })
        .collect();
    let decided: HashSet<&str> = suite
        .cases
        .iter()
        .filter(|case| case.decision.is_some())
        .map(|case| case.id.as_str())
        .collect();
    let mut claimed = HashSet::new();
    for (prefix, keys) in claims["claims"].as_object().expect("claims object") {
        let file = files
            .get(prefix.as_str())
            .unwrap_or_else(|| panic!("{prefix} is not listed in docs/decisions.md"));
        let text = std::fs::read_to_string(root.join("docs").join(file)).unwrap();
        for (key, ids) in keys.as_object().expect("candidate keys") {
            assert!(
                text.contains(&format!("- `{key}`:")),
                "docs/{file} does not list candidate rule `{key}`"
            );
            for id in ids.as_array().expect("case list") {
                let id = id.as_str().expect("case id");
                assert!(
                    !decided.contains(id),
                    "{id} names a decision but is still claimed"
                );
                assert!(claimed.insert(id.to_owned()), "{id} is claimed twice");
            }
        }
    }
    let unclaimed: Vec<_> = suite
        .cases
        .iter()
        .filter(|case| case.decision.is_none() && !claimed.contains(&case.id))
        .map(|case| case.id.as_str())
        .collect();
    assert!(unclaimed.is_empty(), "unclaimed cases: {unclaimed:?}");
    let unknown: Vec<_> = claimed
        .iter()
        .filter(|id| !suite.cases.iter().any(|case| &case.id == *id))
        .collect();
    assert!(unknown.is_empty(), "claims name unknown cases: {unknown:?}");
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
fn path_options_match_the_cli_definition() {
    // Every name, alias and short form of each option whose value Clap parses
    // as a PathBuf, read from the real command rather than its source.
    let command = cli::command();
    let mut declared = std::collections::BTreeSet::new();
    for argument in command
        .get_arguments()
        .chain(command.get_subcommands().flat_map(|s| s.get_arguments()))
        .filter(|a| !a.is_positional())
        .filter(|a| a.get_value_parser().type_id() == std::any::TypeId::of::<PathBuf>())
    {
        let longs = argument
            .get_long()
            .into_iter()
            .chain(argument.get_all_aliases().into_iter().flatten());
        declared.extend(longs.map(|long| format!("--{long}")));
        let shorts = argument
            .get_short()
            .into_iter()
            .chain(argument.get_all_short_aliases().into_iter().flatten());
        declared.extend(shorts.map(|short| format!("-{short}")));
    }
    let shared: std::collections::BTreeSet<String> = spec_suite::PATH_OPTIONS
        .iter()
        .map(|o| (*o).to_owned())
        .collect();
    assert_eq!(
        declared, shared,
        "update PATH_OPTIONS in tests/common/spec_suite.rs to match the CLI"
    );
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

#[test]
fn specification_inputs_are_plain_fixture_names() {
    for input in [
        "good-pe32.exe",
        "./good-pe32.exe",
        "sub/x.exe",
        "..",
        "/abs.exe",
        "",
    ] {
        let case = serde_json::json!({"id":"one","input":input,"command":["verify"],"expect":{"exit_code":0,"json":{"ok":true}}});
        let suite: Suite = serde_json::from_value(
            serde_json::json!({"schema_version":1,"fixtures":"fixtures","cases":[case]}),
        )
        .unwrap();
        let result = suite.validate();
        if input == "good-pe32.exe" {
            assert!(result.is_ok(), "{input}: {result:?}");
        } else {
            assert!(result.unwrap_err().contains("fixture file name"), "{input}");
        }
    }
}

#[test]
fn specification_crl_response_bodies_are_plain_fixture_names() {
    for body in ["good.crl", "sub/good.crl", "./good.crl", "/abs.crl", ""] {
        let case = serde_json::json!({"id":"one","input":"good-pe32.exe","crl_responses":{"http://crl.example.invalid/x":body},"command":["verify"],"expect":{"exit_code":0,"json":{"ok":true}}});
        let suite: Suite = serde_json::from_value(
            serde_json::json!({"schema_version":1,"fixtures":"fixtures","cases":[case]}),
        )
        .unwrap();
        let result = suite.validate();
        if body == "good.crl" {
            assert!(result.is_ok(), "{body}: {result:?}");
        } else {
            assert!(result.unwrap_err().contains("crl_responses body"), "{body}");
        }
    }
}

#[test]
fn specification_detects_incorrect_provider_request_expectations() {
    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut suite: Suite = serde_json::from_str(include_str!("cases.json")).unwrap();
    let case = suite
        .cases
        .iter_mut()
        .find(|c| c.id == "crl-fetch-injected-good")
        .unwrap();
    case.expect.crl_requests = Some(Vec::new());
    let result = execute(
        case,
        &parent,
        &parent.join(&suite.fixtures),
        Path::new(&suite.fixtures),
    );
    assert_eq!(result.exit_code, 0);
    assert!(result.failures.iter().any(|f| f.contains("/crl_requests")));
    case.crl_responses = None;
    assert!(
        suite
            .validate()
            .unwrap_err()
            .contains("requires an injected source")
    );
}

#[test]
fn specification_stderr_once_requires_text_stderr_and_counts_repeats() {
    let case = serde_json::json!({"id":"one","command":["--help"],"expect":{"exit_code":0,"json":{"ok":true},"stderr_once":["x"]}});
    let suite: Suite = serde_json::from_value(
        serde_json::json!({"schema_version":1,"fixtures":"fixtures","cases":[case]}),
    )
    .unwrap();
    assert_eq!(
        suite.validate().unwrap_err(),
        "stderr_once requires stderr_contains: one"
    );

    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut suite: Suite = serde_json::from_str(include_str!("cases.json")).unwrap();
    let case = suite
        .cases
        .iter_mut()
        .find(|c| c.id == "sec07-empty-roots")
        .unwrap();
    let fixtures = parent.join(&suite.fixtures);
    let prefix = Path::new(&suite.fixtures);
    assert!(
        execute(case, &parent, &fixtures, prefix)
            .failures
            .is_empty()
    );
    // "e" occurs many times in the diagnostic, so an exactly-once check must fail.
    case.expect.stderr_once = vec!["e".into()];
    let result = execute(case, &parent, &fixtures, prefix);
    assert!(
        result.failures.iter().any(|f| f.contains("exactly once")),
        "{:?}",
        result.failures
    );
}

#[test]
fn specification_checks_case_decisions() {
    let case = serde_json::json!({
        "id": "crl-005-root-crl-no-next-update",
        "command": ["verify"],
        "expect": {"exit_code": 1, "json": {}},
        "decision": "CRL-001"
    });
    let mut suite = serde_json::json!({"schema_version":1,"fixtures":"fixtures","cases":[case]});
    let validate = |suite: &Value| {
        serde_json::from_value::<Suite>(suite.clone())
            .unwrap()
            .validate()
    };
    validate(&suite).unwrap();
    suite["cases"][0]["decision"] = "CRL-999".into();
    assert!(validate(&suite).unwrap_err().contains("no index"));
}

#[test]
fn decision_index_rejects_malformed_entries() {
    let entry = |status: &str, by: &str, pins: &str| {
        format!(
            "# Index\n\n### CRL-001: A rule\n\nText.\n\n- **Status:** {status}\n- **Decided by:** {by}\n- **Pins:** {pins}\n"
        )
    };
    let parse = |text: String| parse_decisions([("docs/x.md".to_owned(), text)]);
    let good = parse(entry("Decided", "owner, PR #1", "acceptance")).unwrap();
    assert!(good["CRL-001"].in_force());
    assert!(parse(entry("Observed", "—", "diagnostics")).unwrap()["CRL-001"].in_force());
    for (status, by, pins, error) in [
        ("Approved", "owner, PR #1", "acceptance", "status"),
        ("Decided", "—", "acceptance", "decided by"),
        ("Decided", "", "acceptance", "decided by"),
        ("Observed", "owner, PR #1", "acceptance", "decided by"),
        ("Decided", "owner, PR #1", "both", "pins"),
        (
            "Superseded by CRL-002",
            "owner, PR #1",
            "acceptance",
            "superseded",
        ),
    ] {
        let err = parse(entry(status, by, pins)).err().unwrap_or_default();
        assert!(err.contains(error), "{status}/{by}/{pins}: {err}");
    }
    let mut two = entry("Decided", "owner, PR #1", "acceptance");
    two.push_str(&two.clone());
    assert!(parse(two).unwrap_err().contains("duplicate"));
    let missing = "### CRL-001: A rule\n\n- **Status:** Decided\n".to_owned();
    assert!(parse(missing).unwrap_err().contains("decided by"));
    let mut superseded = entry("Superseded by CRL-002", "owner, PR #1", "acceptance");
    superseded.push_str(
        "\n### CRL-002: Its replacement\n\n- **Status:** Decided\n- **Decided by:** owner, PR #2\n- **Pins:** acceptance\n",
    );
    let index = parse(superseded).unwrap();
    assert!(!index["CRL-001"].in_force());
    assert!(index["CRL-002"].in_force());
}
