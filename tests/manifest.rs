//! Consistency of `tests/fixtures/manifest.json` with the committed fixtures,
//! the portable case specification, and the tests and generators it names.
//!
//! `check` is a pure function over an in-memory [`Corpus`], so every rule is
//! also exercised against a deliberately broken copy. Nothing here regenerates
//! or rewrites a fixture. See `docs/testing.md` for the rules and exceptions.
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::LazyLock,
};

const MANIFEST: &str = "manifest.json";

/// Files in `tests/fixtures/` that the manifest intentionally does not list.
/// Diagnostic JSON and helper data are ordinary listed artifacts.
const UNLISTED: &[&str] = &[MANIFEST];

/// Inputs that cases name because they do not exist. Each must stay absent
/// from both the manifest and the directory.
const ABSENT_INPUTS: &[&str] = &[
    "missing.exe",
    "missing-root.der",
    "missing.crl",
    "missing-parse-input.exe",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Rule {
    /// Unknown, missing or mistyped manifest fields, or an unsupported version.
    Schema,
    /// `file` is not a single plain file name inside the fixture directory.
    UnsafePath,
    DuplicateFile,
    /// Listed in the manifest, absent from the directory.
    MissingFile,
    /// Present in the directory (or a subdirectory), absent from the manifest.
    UnlistedFile,
    ByteCount,
    Sha256,
    Description,
    /// Provenance or license information is absent or empty.
    Provenance,
    /// A named generator source file or function does not exist.
    Generator,
    /// An artifact names a case ID that `cases.json` does not define.
    UnknownCase,
    /// A case uses a fixture the manifest does not list.
    UnlistedCaseInput,
    /// An artifact names a Rust test that does not exist.
    UnknownTest,
    PairedGood,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Problem {
    rule: Rule,
    subject: String,
}

fn problem(rule: Rule, subject: impl Into<String>) -> Problem {
    Problem {
        rule,
        subject: subject.into(),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    provenance: DefaultProvenance,
    artifacts: Vec<Artifact>,
}

/// Provenance inherited by every artifact that records none of its own.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DefaultProvenance {
    kind: String,
    generator: String,
    command: String,
    crypto: String,
    license: String,
    #[allow(dead_code)]
    validation_time: u64,
    warning: String,
    interop_status: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    file: String,
    sha256: String,
    bytes: u64,
    description: String,
    #[serde(default)]
    cases: Vec<String>,
    #[serde(default)]
    tests: Vec<String>,
    provenance: Option<BTreeMap<String, String>>,
    generator: Option<String>,
    license: Option<String>,
    paired_good: Option<String>,
    source: Option<String>,
    signer: Option<String>,
    command: Option<String>,
    key_recipe: Option<String>,
    signer_jar_sha256: Option<String>,
    upstream_revision: Option<String>,
}

/// Everything the checks read, loaded once and cloned for mutation tests.
#[derive(Clone)]
struct Corpus {
    manifest: Value,
    /// Regular files directly inside `tests/fixtures/`.
    files: BTreeMap<String, Vec<u8>>,
    /// Anything else found there; fixtures live in one flat directory.
    other_entries: BTreeSet<String>,
    cases: Value,
    /// Repository-relative path to Rust source text, for `src/` and `tests/cli/`.
    sources: BTreeMap<String, String>,
}

fn read_sources(root: &Path, relative: &str, sources: &mut BTreeMap<String, String>) {
    for entry in std::fs::read_dir(root.join(relative)).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        let path = format!("{relative}/{name}");
        if entry.file_type().unwrap().is_dir() {
            read_sources(root, &path, sources);
        } else if name.ends_with(".rs") {
            sources.insert(path, std::fs::read_to_string(entry.path()).unwrap());
        }
    }
}

static COMMITTED: LazyLock<Corpus> = LazyLock::new(|| {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let directory = root.join("tests/fixtures");
    let mut files = BTreeMap::new();
    let mut other_entries = BTreeSet::new();
    for entry in std::fs::read_dir(&directory).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        if entry.file_type().unwrap().is_file() {
            files.insert(name, std::fs::read(entry.path()).unwrap());
        } else {
            other_entries.insert(name);
        }
    }
    let mut sources = BTreeMap::new();
    read_sources(root, "src", &mut sources);
    read_sources(root, "tests/cli", &mut sources);
    Corpus {
        manifest: serde_json::from_slice(&files[MANIFEST]).unwrap(),
        files,
        other_entries,
        cases: serde_json::from_slice(&std::fs::read(root.join("tests/cases.json")).unwrap())
            .unwrap(),
        sources,
    }
});

fn safe_file_name(name: &str) -> bool {
    name != MANIFEST
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn blank(text: &str) -> bool {
    text.trim().is_empty()
}

/// Whether `source` declares a function called exactly `name`.
fn defines_function(source: &str, name: &str) -> bool {
    let declaration = format!("fn {name}");
    source.match_indices(&declaration).any(|(index, _)| {
        !source[index + declaration.len()..]
            .starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
    })
}

/// `path/to/file.rs` or `path/to/file.rs::function`, optionally followed by a note.
fn generator_exists(sources: &BTreeMap<String, String>, generator: &str) -> bool {
    let reference = generator.split_whitespace().next().unwrap_or_default();
    let (path, function) = match reference.split_once("::") {
        Some((path, function)) => (path, Some(function)),
        None => (reference, None),
    };
    sources
        .get(path)
        .is_some_and(|source| function.is_none_or(|name| defines_function(source, name)))
}

/// `module::function` in `tests/cli/<module>.rs`.
fn test_exists(sources: &BTreeMap<String, String>, test: &str) -> bool {
    test.split_once("::").is_some_and(|(module, function)| {
        sources
            .get(&format!("tests/cli/{module}.rs"))
            .is_some_and(|source| defines_function(source, function))
    })
}

/// Case IDs and, per case, every fixture file name it reads: `input`, `inputs`,
/// injected CRL response bodies, and `<fixtures>/<name>` command arguments.
fn case_fixtures(cases: &Value) -> BTreeMap<String, BTreeSet<String>> {
    let prefix = format!("{}/", cases["fixtures"].as_str().unwrap());
    let mut result = BTreeMap::new();
    for case in cases["cases"].as_array().unwrap() {
        let mut used = BTreeSet::new();
        let mut add = |value: &Value| used.extend(value.as_str().map(str::to_owned));
        add(&case["input"]);
        case["inputs"]
            .as_array()
            .into_iter()
            .flatten()
            .for_each(&mut add);
        case["crl_responses"]
            .as_object()
            .into_iter()
            .flat_map(|responses| responses.values())
            .for_each(&mut add);
        for argument in case["command"].as_array().into_iter().flatten() {
            if let Some(name) = argument.as_str().and_then(|a| a.strip_prefix(&prefix)) {
                used.insert(name.to_owned());
            }
        }
        result.insert(case["id"].as_str().unwrap().to_owned(), used);
    }
    result
}

fn check(corpus: &Corpus) -> Vec<Problem> {
    let manifest: Manifest = match serde_json::from_value(corpus.manifest.clone()) {
        Ok(manifest) => manifest,
        Err(error) => return vec![problem(Rule::Schema, error.to_string())],
    };
    let mut problems = Vec::new();
    if manifest.schema_version != 1 {
        problems.push(problem(Rule::Schema, "schema_version"));
    }

    let default = &manifest.provenance;
    for (field, value) in [
        ("kind", &default.kind),
        ("generator", &default.generator),
        ("command", &default.command),
        ("crypto", &default.crypto),
        ("license", &default.license),
        ("warning", &default.warning),
        ("interop_status", &default.interop_status),
    ] {
        if blank(value) {
            problems.push(problem(Rule::Provenance, format!("manifest {field}")));
        }
    }
    if !generator_exists(&corpus.sources, &default.generator) {
        problems.push(problem(Rule::Generator, "manifest"));
    }

    let cases = case_fixtures(&corpus.cases);
    let mut listed = BTreeSet::new();
    for artifact in &manifest.artifacts {
        let file = artifact.file.as_str();
        if !safe_file_name(file) {
            // Never join an unsafe name to the fixture directory or report it as listed.
            problems.push(problem(Rule::UnsafePath, file));
            continue;
        }
        if !listed.insert(file) {
            problems.push(problem(Rule::DuplicateFile, file));
            continue;
        }
        match corpus.files.get(file) {
            None => problems.push(problem(Rule::MissingFile, file)),
            Some(bytes) => {
                if u64::try_from(bytes.len()) != Ok(artifact.bytes) {
                    problems.push(problem(Rule::ByteCount, file));
                }
                let digest: String = Sha256::digest(bytes)
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect();
                if artifact.sha256 != digest {
                    problems.push(problem(Rule::Sha256, file));
                }
            }
        }
        if blank(&artifact.description) {
            problems.push(problem(Rule::Description, file));
        }

        // An artifact with no provenance of its own inherits the manifest
        // default. Whatever it does record must be usable.
        let recorded = [
            &artifact.license,
            &artifact.source,
            &artifact.signer,
            &artifact.command,
            &artifact.key_recipe,
            &artifact.signer_jar_sha256,
            &artifact.upstream_revision,
            &artifact.generator,
        ];
        let mut provenance_ok = recorded
            .iter()
            .all(|v| v.as_deref().is_none_or(|v| !blank(v)));
        if let Some(provenance) = &artifact.provenance {
            provenance_ok &= provenance.values().all(|value| !blank(value))
                && provenance.contains_key("license")
                && ["source", "generator", "command"]
                    .iter()
                    .any(|origin| provenance.contains_key(*origin));
        }
        if !provenance_ok {
            problems.push(problem(Rule::Provenance, file));
        }
        let nested = artifact
            .provenance
            .as_ref()
            .and_then(|p| p.get("generator"));
        if [artifact.generator.as_ref(), nested]
            .into_iter()
            .flatten()
            .any(|generator| !generator_exists(&corpus.sources, generator))
        {
            problems.push(problem(Rule::Generator, file));
        }

        let mut seen = BTreeSet::new();
        for case in &artifact.cases {
            if !cases.contains_key(case) || !seen.insert(case) {
                problems.push(problem(Rule::UnknownCase, format!("{file}: {case}")));
            }
        }
        for test in &artifact.tests {
            if !test_exists(&corpus.sources, test) {
                problems.push(problem(Rule::UnknownTest, format!("{file}: {test}")));
            }
        }
    }
    for artifact in &manifest.artifacts {
        if let Some(good) = artifact.paired_good.as_deref()
            && (good == artifact.file || !listed.contains(good))
        {
            problems.push(problem(Rule::PairedGood, artifact.file.as_str()));
        }
    }

    for name in corpus.files.keys() {
        if !listed.contains(name.as_str()) && !UNLISTED.contains(&name.as_str()) {
            problems.push(problem(Rule::UnlistedFile, name.as_str()));
        }
    }
    for name in &corpus.other_entries {
        problems.push(problem(Rule::UnlistedFile, name.as_str()));
    }

    for (case, used) in &cases {
        for name in used {
            let absent = ABSENT_INPUTS.contains(&name.as_str());
            let present = listed.contains(name.as_str()) || corpus.files.contains_key(name);
            if absent == present {
                problems.push(problem(Rule::UnlistedCaseInput, format!("{case}: {name}")));
            }
        }
    }
    for name in ABSENT_INPUTS {
        if !cases.values().any(|used| used.contains(*name)) {
            problems.push(problem(
                Rule::UnlistedCaseInput,
                format!("unused exception: {name}"),
            ));
        }
    }
    problems.sort();
    problems
}

#[test]
fn committed_manifest_fixtures_and_cases_are_consistent() {
    let problems = check(&COMMITTED);
    assert!(problems.is_empty(), "{problems:#?}");
}

// Each rule must reject a narrowly broken copy of the committed corpus, and
// report nothing else. A fixture whose artifact entry is used below is listed
// by exactly one case, has a paired good artifact, or has a named test.
const FILE: &str = "bad-image-digest.exe";

fn broken(change: impl FnOnce(&mut Corpus)) -> Vec<(Rule, String)> {
    let mut corpus = COMMITTED.clone();
    change(&mut corpus);
    check(&corpus)
        .into_iter()
        .map(|problem| (problem.rule, problem.subject))
        .collect()
}

fn artifact<'a>(corpus: &'a mut Corpus, file: &str) -> &'a mut Value {
    corpus.manifest["artifacts"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|artifact| artifact["file"] == file)
        .unwrap()
}

fn one(rule: Rule, subject: &str) -> Vec<(Rule, String)> {
    vec![(rule, subject.to_owned())]
}

#[test]
fn rejects_unknown_fields_wrong_types_and_versions() {
    let unknown = broken(|c| artifact(c, FILE)["sha265"] = json!("typo"));
    assert_eq!(unknown.len(), 1);
    assert_eq!(unknown[0].0, Rule::Schema);
    assert!(unknown[0].1.contains("sha265"), "{unknown:?}");

    let mistyped = broken(|c| artifact(c, FILE)["bytes"] = json!("2224"));
    assert_eq!(mistyped[0].0, Rule::Schema);
    let missing = broken(|c| {
        artifact(c, FILE)
            .as_object_mut()
            .unwrap()
            .remove("description");
    });
    assert_eq!(missing[0].0, Rule::Schema);
    let default = broken(|c| c.manifest["provenance"]["licence"] = json!("typo"));
    assert_eq!(default[0].0, Rule::Schema);

    assert_eq!(
        broken(|c| c.manifest["schema_version"] = json!(2)),
        one(Rule::Schema, "schema_version")
    );
}

#[test]
fn rejects_paths_that_leave_or_hide_in_the_fixture_directory() {
    for name in [
        "../Cargo.toml",
        "nested/file.exe",
        "/etc/hosts",
        "back\\slash.exe",
        ".hidden",
        "",
        "manifest.json",
        "space name.exe",
    ] {
        let problems = broken(|c| artifact(c, FILE)["file"] = json!(name));
        assert!(
            problems.contains(&(Rule::UnsafePath, name.to_owned())),
            "{name}: {problems:?}"
        );
        // The renamed artifact's real file is now unlisted; nothing else may be reported.
        assert!(
            problems.iter().all(|(rule, _)| matches!(
                rule,
                Rule::UnsafePath | Rule::UnlistedFile | Rule::UnlistedCaseInput
            )),
            "{name}: {problems:?}"
        );
    }
}

#[test]
fn rejects_duplicate_missing_and_unlisted_files() {
    let duplicate = broken(|c| {
        let copy = artifact(c, FILE).clone();
        c.manifest["artifacts"].as_array_mut().unwrap().push(copy);
    });
    assert_eq!(duplicate, one(Rule::DuplicateFile, FILE));

    let missing = broken(|c| {
        c.files.remove("attribute-certificate-v1.der");
    });
    assert_eq!(
        missing,
        one(Rule::MissingFile, "attribute-certificate-v1.der")
    );

    let unlisted = broken(|c| {
        c.files.insert("stray.exe".to_owned(), vec![0x4d, 0x5a]);
    });
    assert_eq!(unlisted, one(Rule::UnlistedFile, "stray.exe"));

    let directory = broken(|c| {
        c.other_entries.insert("nested".to_owned());
    });
    assert_eq!(directory, one(Rule::UnlistedFile, "nested"));

    // Removing an entry leaves its file unlisted. No case reads this one.
    let removed = broken(|c| {
        c.manifest["artifacts"]
            .as_array_mut()
            .unwrap()
            .retain(|artifact| artifact["file"] != "attribute-certificate-v1.der");
    });
    assert_eq!(
        removed,
        one(Rule::UnlistedFile, "attribute-certificate-v1.der")
    );
}

#[test]
fn rejects_wrong_byte_counts_and_digests() {
    let count = broken(|c| {
        let bytes = artifact(c, FILE)["bytes"].as_u64().unwrap();
        artifact(c, FILE)["bytes"] = json!(bytes + 1);
    });
    assert_eq!(count, one(Rule::ByteCount, FILE));

    // A changed fixture with a stale manifest entry: the count still matches.
    let changed = broken(|c| c.files.get_mut(FILE).unwrap()[700] ^= 1);
    assert_eq!(changed, one(Rule::Sha256, FILE));

    let truncated = broken(|c| {
        c.files.get_mut(FILE).unwrap().pop();
    });
    assert_eq!(
        truncated,
        vec![
            (Rule::ByteCount, FILE.to_owned()),
            (Rule::Sha256, FILE.to_owned())
        ]
    );

    // Digests are lowercase hexadecimal, so comparisons are exact.
    let uppercase = broken(|c| {
        let digest = artifact(c, FILE)["sha256"].as_str().unwrap().to_uppercase();
        artifact(c, FILE)["sha256"] = json!(digest);
    });
    assert_eq!(uppercase, one(Rule::Sha256, FILE));
}

#[test]
fn rejects_blank_descriptions_and_unusable_provenance() {
    assert_eq!(
        broken(|c| artifact(c, FILE)["description"] = json!(" \n")),
        one(Rule::Description, FILE)
    );
    assert_eq!(
        broken(|c| artifact(c, FILE)["license"] = json!("")),
        one(Rule::Provenance, FILE)
    );
    assert_eq!(
        broken(|c| c.manifest["provenance"]["license"] = json!(" ")),
        one(Rule::Provenance, "manifest license")
    );

    // An explicit provenance record needs a license and an origin.
    const EXTERNAL: &str = "appx-independent-signtool.msix";
    assert_eq!(
        broken(|c| {
            let provenance = artifact(c, EXTERNAL)["provenance"].as_object_mut().unwrap();
            provenance.remove("license");
        }),
        one(Rule::Provenance, EXTERNAL)
    );
    assert_eq!(
        broken(|c| {
            let provenance = artifact(c, EXTERNAL)["provenance"].as_object_mut().unwrap();
            provenance.retain(|key, _| !matches!(key.as_str(), "source" | "generator" | "command"));
        }),
        one(Rule::Provenance, EXTERNAL)
    );
    assert_eq!(
        broken(|c| artifact(c, EXTERNAL)["provenance"]["tool"] = json!("")),
        one(Rule::Provenance, EXTERNAL)
    );
    // The committed record is otherwise acceptable as it stands.
    assert!(
        COMMITTED.manifest["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| { a["file"] == EXTERNAL && a["provenance"]["source"].as_str().is_some() })
    );
}

#[test]
fn rejects_generators_that_do_not_exist() {
    assert_eq!(
        broken(|c| artifact(c, FILE)["generator"] = json!("src/tests/absent.rs::write")),
        one(Rule::Generator, FILE)
    );
    assert_eq!(
        broken(|c| artifact(c, FILE)["generator"] = json!("src/tests.rs::regenerate_cli")),
        one(Rule::Generator, FILE),
        "a prefix of a real function name is not that function"
    );
    assert_eq!(
        broken(|c| artifact(c, FILE)["generator"] = json!("src/tests.rs::regenerate_cli_fixtures")),
        vec![]
    );
    assert_eq!(
        broken(|c| c.manifest["provenance"]["generator"] = json!("src/tests.rs::absent")),
        one(Rule::Generator, "manifest")
    );
    const NESTED: &str = "appx-independent-signtool.msix";
    assert_eq!(
        broken(|c| artifact(c, NESTED)["provenance"]["generator"] = json!("tests/absent.rs")),
        one(Rule::Generator, NESTED)
    );
}

#[test]
fn rejects_unknown_or_repeated_cases_and_unknown_tests() {
    assert_eq!(
        broken(|c| artifact(c, FILE)["cases"] = json!(["no-such-case"])),
        one(Rule::UnknownCase, &format!("{FILE}: no-such-case"))
    );
    assert_eq!(
        broken(|c| artifact(c, FILE)["cases"] = json!(["pe64", "pe64"])),
        one(Rule::UnknownCase, &format!("{FILE}: pe64"))
    );
    for test in ["pe::no_such_test", "absent::test", "no_module"] {
        assert_eq!(
            broken(|c| artifact(c, FILE)["tests"] = json!([test])),
            one(Rule::UnknownTest, &format!("{FILE}: {test}"))
        );
    }
}

#[test]
fn rejects_case_inputs_the_manifest_does_not_list() {
    let input = broken(|c| c.cases["cases"][0]["input"] = json!("unlisted.exe"));
    assert_eq!(input, one(Rule::UnlistedCaseInput, "pe32: unlisted.exe"));

    let argument = broken(|c| {
        let command = c.cases["cases"][0]["command"].as_array_mut().unwrap();
        command.push(json!("fixtures/unlisted.crl"));
    });
    assert_eq!(argument, one(Rule::UnlistedCaseInput, "pe32: unlisted.crl"));

    let response = broken(|c| {
        c.cases["cases"][0]["crl_responses"] =
            json!({"http://crl.example.invalid/x": "unlisted.crl"});
    });
    assert_eq!(response, one(Rule::UnlistedCaseInput, "pe32: unlisted.crl"));

    let several =
        broken(|c| c.cases["cases"][0]["inputs"] = json!(["good-pe64.exe", "unlisted.exe"]));
    assert_eq!(several, one(Rule::UnlistedCaseInput, "pe32: unlisted.exe"));
}

#[test]
fn intentionally_absent_inputs_must_stay_absent_and_used() {
    let present = broken(|c| {
        c.files.insert("missing.exe".to_owned(), Vec::new());
    });
    assert!(
        present.contains(&(Rule::UnlistedFile, "missing.exe".to_owned())),
        "{present:?}"
    );
    assert!(
        present
            .iter()
            .any(|(rule, subject)| *rule == Rule::UnlistedCaseInput
                && subject.ends_with(": missing.exe")),
        "{present:?}"
    );

    let unused = broken(|c| {
        for case in c.cases["cases"].as_array_mut().unwrap() {
            if case["input"] == "missing.exe" {
                case["input"] = json!("good-pe64.exe");
            }
            for argument in case["command"].as_array_mut().unwrap() {
                if *argument == "fixtures/missing.exe" {
                    *argument = json!("fixtures/good-pe64.exe");
                }
            }
            for input in case["inputs"].as_array_mut().into_iter().flatten() {
                if *input == "missing.exe" {
                    *input = json!("good-pe64.exe");
                }
            }
        }
    });
    assert_eq!(
        unused,
        one(Rule::UnlistedCaseInput, "unused exception: missing.exe")
    );
}

#[test]
fn rejects_paired_good_references_that_do_not_resolve() {
    assert_eq!(
        broken(|c| artifact(c, FILE)["paired_good"] = json!("no-such-good.exe")),
        one(Rule::PairedGood, FILE)
    );
    assert_eq!(
        broken(|c| artifact(c, FILE)["paired_good"] = json!(FILE)),
        one(Rule::PairedGood, FILE)
    );
    assert_eq!(
        broken(|c| artifact(c, FILE)["paired_good"] = json!("good-pe64.exe")),
        vec![]
    );
}

#[test]
fn function_lookup_requires_the_whole_name() {
    let source = "fn write_all() {}\npub(crate) fn regenerate<T>() {}";
    assert!(defines_function(source, "write_all"));
    assert!(defines_function(source, "regenerate"));
    assert!(!defines_function(source, "write"));
    assert!(!defines_function(source, "all"));
}
