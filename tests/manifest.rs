//! Consistency of `tests/fixtures/manifest.json` with the committed fixtures,
//! the portable case specification, and the tests and generators it names.
//!
//! `check` is a pure function over an in-memory [`Corpus`], so every rule is
//! also exercised against a deliberately broken copy. Nothing here regenerates
//! or rewrites a fixture. See `docs/testing.md` for the rules and exceptions.
#[path = "common/spec_args.rs"]
mod spec_args;

use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use spec_args::Argument;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::LazyLock,
};

const MANIFEST: &str = "manifest.json";

/// Files in `tests/fixtures/` that the manifest intentionally does not list.
/// Diagnostic JSON and helper data are ordinary listed artifacts.
const UNLISTED: &[&str] = &[MANIFEST];

/// Local operating-system and editor by-products, never committed: ignored so
/// that `cargo test` does not fail on a developer machine. The fixture rules
/// still reject them as artifact names.
fn local_by_product(name: &str) -> bool {
    name == ".DS_Store" || name.starts_with("._") || name.ends_with(".swp") || name.ends_with('~')
}

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
    /// A `source` that is not a URL must name another listed artifact.
    DerivedSource,
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

/// What the checks need from a fixture file, computed once so mutation tests
/// can copy the corpus cheaply.
#[derive(Clone)]
struct FileFacts {
    bytes: u64,
    sha256: String,
}

impl FileFacts {
    fn of(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.len() as u64,
            sha256: Sha256::digest(bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        }
    }
}

/// Everything the checks read, loaded once and cloned for mutation tests.
#[derive(Clone)]
struct Corpus {
    manifest: Value,
    /// Regular files directly inside `tests/fixtures/`.
    files: BTreeMap<String, FileFacts>,
    /// Anything else found there; fixtures live in one flat directory.
    other_entries: BTreeSet<String>,
    cases: Value,
    /// Repository-relative path to the text of every Rust file under `src/` and
    /// `tests/`, plus `build.rs` when present.
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

/// Regular files and other entries directly inside `directory`, skipping
/// [`local_by_product`] names.
fn read_fixture_directory(directory: &Path) -> (BTreeMap<String, FileFacts>, BTreeSet<String>) {
    let mut files = BTreeMap::new();
    let mut other_entries = BTreeSet::new();
    for entry in std::fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().into_string().unwrap();
        if local_by_product(&name) {
            continue;
        }
        if entry.file_type().unwrap().is_file() {
            files.insert(name, FileFacts::of(&std::fs::read(entry.path()).unwrap()));
        } else {
            other_entries.insert(name);
        }
    }
    (files, other_entries)
}

static COMMITTED: LazyLock<Corpus> = LazyLock::new(|| {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let directory = root.join("tests/fixtures");
    let (files, other_entries) = read_fixture_directory(&directory);
    let mut sources = BTreeMap::new();
    read_sources(root, "src", &mut sources);
    read_sources(root, "tests", &mut sources);
    if let Ok(build) = std::fs::read_to_string(root.join("build.rs")) {
        sources.insert("build.rs".to_owned(), build);
    }
    Corpus {
        manifest: serde_json::from_slice(&std::fs::read(directory.join(MANIFEST)).unwrap())
            .unwrap(),
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

fn is_url(text: &str) -> bool {
    text.starts_with("https://") || text.starts_with("http://")
}

fn blank(text: &str) -> bool {
    text.trim().is_empty()
}

/// Line indices where `source` declares a function called exactly `name`: a
/// line that, after indentation, visibility, and `const`/`async`/`unsafe`/
/// `extern "ABI"` qualifiers, begins `fn name` followed by `(` or `<`. Lines in
/// `//` and `/* */` comments, and text after the start of a line, never count.
/// A line inside a multi-line string literal is not recognized as such.
fn declarations(source: &str, name: &str) -> Vec<usize> {
    let mut found = Vec::new();
    let mut in_block = false;
    for (index, line) in source.lines().enumerate() {
        let code = line.split("//").next().unwrap_or_default();
        if in_block {
            in_block = !code.contains("*/");
            continue;
        }
        if declares(line, name) {
            found.push(index);
        }
        if let Some(open) = code.rfind("/*") {
            in_block = !code[open..].contains("*/");
        }
    }
    found
}

fn declares(line: &str, name: &str) -> bool {
    let mut rest = line.trim_start();
    if let Some(after) = rest.strip_prefix("pub") {
        rest = match after.strip_prefix('(') {
            Some(scope) => match scope.split_once(')') {
                Some((_, after)) => after,
                None => return false,
            },
            None => after,
        };
        if !rest.starts_with(' ') {
            return false;
        }
        rest = rest.trim_start();
    }
    loop {
        if let Some(after) = ["const ", "async ", "unsafe "]
            .iter()
            .find_map(|qualifier| rest.strip_prefix(qualifier))
        {
            rest = after.trim_start();
        } else if let Some(after) = rest.strip_prefix("extern ") {
            rest = after.trim_start();
            if let Some(abi) = rest.strip_prefix('"') {
                match abi.split_once('"') {
                    Some((_, after)) => rest = after.trim_start(),
                    None => return false,
                }
            }
        } else {
            break;
        }
    }
    rest.strip_prefix("fn ")
        .and_then(|after| after.trim_start().strip_prefix(name))
        .is_some_and(|after| after.trim_start().starts_with(['(', '<']))
}

fn defines_function(source: &str, name: &str) -> bool {
    !declarations(source, name).is_empty()
}

/// Whether a declaration of `name` carries `#[test]` among the attribute and
/// comment lines directly above it.
fn declares_test(source: &str, name: &str) -> bool {
    let lines: Vec<&str> = source.lines().collect();
    declarations(source, name).into_iter().any(|index| {
        lines[..index]
            .iter()
            .rev()
            .map(|line| line.trim())
            .take_while(|line| line.starts_with("#[") || line.starts_with("//"))
            .any(|line| line.starts_with("#[test]"))
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

/// `module::function`: a `#[test]` function in `tests/cli/<module>.rs`, which a
/// test target under `tests/` includes as a module.
fn test_exists(sources: &BTreeMap<String, String>, test: &str) -> bool {
    let Some((module, function)) = test.split_once("::") else {
        return false;
    };
    let included = format!("#[path = \"cli/{module}.rs\"]");
    let harness = sources.iter().any(|(path, source)| {
        path.strip_prefix("tests/")
            .is_some_and(|name| !name.contains('/'))
            && source.lines().any(|line| line.trim() == included)
    });
    harness
        && sources
            .get(&format!("tests/cli/{module}.rs"))
            .is_some_and(|source| declares_test(source, function))
}

/// The fixture name a path argument resolves to, or the path itself when it
/// leaves the fixture directory (so it can never match a listed artifact).
fn fixture_name(path: &str, prefix: &Path) -> String {
    match Path::new(path).strip_prefix(prefix) {
        Ok(rest) if rest.components().count() == 1 && rest.to_str().is_some_and(safe_file_name) => {
            rest.to_str().unwrap().to_owned()
        }
        _ => path.to_owned(),
    }
}

/// Case IDs and, per case, every file it reads: `input`, `inputs`, injected
/// CRL response bodies, and command arguments that `tests/spec.rs` resolves as
/// paths (see `common/spec_args.rs`). A plain argument containing a path
/// separator is recorded too: the CLI would read it relative to its working
/// directory, outside the fixture directory.
fn case_fixtures(cases: &Value) -> BTreeMap<String, BTreeSet<String>> {
    let prefix = Path::new(cases["fixtures"].as_str().unwrap());
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
        let command = case["command"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|argument| argument.as_str().unwrap_or_default());
        for argument in spec_args::classify(command, prefix) {
            match argument {
                Argument::Path(path) | Argument::InlinePath { path, .. } => {
                    used.insert(fixture_name(path, prefix));
                }
                Argument::Plain(argument)
                    if !argument.contains("://") && argument.contains(['/', '\\']) =>
                {
                    used.insert(argument.to_owned());
                }
                Argument::Plain(_) => {}
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
    // macOS CI checks out onto a case-insensitive filesystem.
    let mut folded = BTreeSet::new();
    for artifact in &manifest.artifacts {
        let file = artifact.file.as_str();
        // An unsafe or duplicate name is never looked up or counted as listed,
        // but the entry's other fields are still checked.
        if !safe_file_name(file) {
            problems.push(problem(Rule::UnsafePath, file));
        } else if !folded.insert(file.to_ascii_lowercase()) {
            problems.push(problem(Rule::DuplicateFile, file));
        } else {
            listed.insert(file);
            match corpus.files.get(file) {
                None => problems.push(problem(Rule::MissingFile, file)),
                Some(facts) => {
                    if facts.bytes != artifact.bytes {
                        problems.push(problem(Rule::ByteCount, file));
                    }
                    if facts.sha256 != artifact.sha256 {
                        problems.push(problem(Rule::Sha256, file));
                    }
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
        // Signed or fetched outside this repository: the repository-generated
        // default license cannot apply, so the artifact must state its own.
        let external = artifact.signer.is_some()
            || artifact.signer_jar_sha256.is_some()
            || artifact.upstream_revision.is_some()
            || artifact.source.as_deref().is_some_and(is_url);
        if external && artifact.license.is_none() && artifact.provenance.is_none() {
            provenance_ok = false;
        }
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
        if let Some(source) = artifact.source.as_deref()
            && !is_url(source)
            && (source == artifact.file || !listed.contains(source))
        {
            problems.push(problem(Rule::DerivedSource, artifact.file.as_str()));
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
            // Exempt files such as manifest.json are not fixtures: a case may
            // read only listed artifacts.
            let bad = if absent {
                listed.contains(name.as_str()) || corpus.files.contains_key(name)
            } else {
                !listed.contains(name.as_str())
            };
            if bad {
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

/// A listed fixture that no case reads, so removing it affects only file rules.
const UNUSED: &str = "attribute-certificate-v1.der";

fn assert_unused_by_cases(name: &str) {
    let used = case_fixtures(&COMMITTED.cases);
    let readers: Vec<_> = used
        .iter()
        .filter(|(_, used)| used.contains(name))
        .collect();
    assert!(
        readers.is_empty(),
        "{name} is now read by {readers:?}; choose a fixture no case reads"
    );
}

fn one(rule: Rule, subject: &str) -> Vec<(Rule, String)> {
    vec![(rule, subject.to_owned())]
}

/// `UnlistedCaseInput` for every committed case that reads `name`.
fn readers_of(name: &str) -> Vec<(Rule, String)> {
    case_fixtures(&COMMITTED.cases)
        .into_iter()
        .filter(|(_, used)| used.contains(name))
        .map(|(case, _)| (Rule::UnlistedCaseInput, format!("{case}: {name}")))
        .collect()
}

fn sorted(mut problems: Vec<(Rule, String)>) -> Vec<(Rule, String)> {
    problems.sort();
    problems
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
        // The renamed artifact's real file becomes unlisted, and so does the
        // input of every case that reads it. Nothing else may be reported.
        let mut expected = vec![
            (Rule::UnsafePath, name.to_owned()),
            (Rule::UnlistedFile, FILE.to_owned()),
        ];
        expected.extend(readers_of(FILE));
        assert_eq!(
            broken(|c| artifact(c, FILE)["file"] = json!(name)),
            sorted(expected),
            "{name}"
        );
    }
}

#[test]
fn rejects_duplicate_missing_and_unlisted_files() {
    assert_unused_by_cases(UNUSED);
    let duplicate = broken(|c| {
        let copy = artifact(c, FILE).clone();
        c.manifest["artifacts"].as_array_mut().unwrap().push(copy);
    });
    assert_eq!(duplicate, one(Rule::DuplicateFile, FILE));

    let missing = broken(|c| {
        c.files.remove(UNUSED);
    });
    assert_eq!(missing, one(Rule::MissingFile, UNUSED));

    let unlisted = broken(|c| {
        c.files
            .insert("stray.exe".to_owned(), FileFacts::of(&[0x4d, 0x5a]));
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
            .retain(|artifact| artifact["file"] != UNUSED);
    });
    assert_eq!(removed, one(Rule::UnlistedFile, UNUSED));
}

#[test]
fn rejects_wrong_byte_counts_and_digests() {
    let count = broken(|c| {
        let bytes = artifact(c, FILE)["bytes"].as_u64().unwrap();
        artifact(c, FILE)["bytes"] = json!(bytes + 1);
    });
    assert_eq!(count, one(Rule::ByteCount, FILE));

    // A changed fixture with a stale manifest entry: the count still matches.
    let mut bytes = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(FILE),
    )
    .unwrap();
    bytes[700] ^= 1;
    let changed = broken(|c| {
        c.files.insert(FILE.to_owned(), FileFacts::of(&bytes));
    });
    assert_eq!(changed, one(Rule::Sha256, FILE));

    bytes[700] ^= 1;
    bytes.pop();
    let truncated = broken(|c| {
        c.files.insert(FILE.to_owned(), FileFacts::of(&bytes));
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
    for test in [
        "pe::no_such_test",
        "absent::test",
        "no_module",
        // A helper function, not a #[test].
        "support::run_fixture",
    ] {
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
        c.files.insert("missing.exe".to_owned(), FileFacts::of(&[]));
    });
    let mut expected = vec![(Rule::UnlistedFile, "missing.exe".to_owned())];
    let readers = readers_of("missing.exe");
    assert!(!readers.is_empty());
    expected.extend(readers);
    assert_eq!(present, sorted(expected));

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

#[test]
fn reads_path_options_in_both_forms_and_outside_the_fixture_directory() {
    for (command, expected) in [
        (vec!["--crl=fixtures/unlisted.crl"], "pe32: unlisted.crl"),
        (vec!["--roots=fixtures/unlisted.der"], "pe32: unlisted.der"),
        (vec!["--crl", "elsewhere.crl"], "pe32: elsewhere.crl"),
        (vec!["--roots=../root.der"], "pe32: ../root.der"),
    ] {
        let problems = broken(|c| {
            let arguments = c.cases["cases"][0]["command"].as_array_mut().unwrap();
            arguments.extend(command.iter().map(|argument| json!(argument)));
        });
        assert_eq!(
            problems,
            one(Rule::UnlistedCaseInput, expected),
            "{command:?}"
        );
    }
    // The listed form is accepted, and an unrelated `=` option is not a path.
    assert_eq!(
        broken(|c| {
            let arguments = c.cases["cases"][0]["command"].as_array_mut().unwrap();
            arguments.push(json!("--crl=fixtures/good.crl"));
            arguments.push(json!("--time=1800000000"));
        }),
        vec![]
    );
}

#[test]
fn a_case_may_not_read_an_exempt_unlisted_file() {
    assert_eq!(
        broken(|c| c.cases["cases"][0]["input"] = json!(MANIFEST)),
        one(Rule::UnlistedCaseInput, "pe32: manifest.json")
    );
}

#[test]
fn rejects_names_that_collide_on_case_insensitive_filesystems() {
    let problems = broken(|c| {
        let mut copy = artifact(c, FILE).clone();
        copy["file"] = json!(FILE.to_uppercase());
        c.manifest["artifacts"].as_array_mut().unwrap().push(copy);
    });
    assert_eq!(problems, one(Rule::DuplicateFile, &FILE.to_uppercase()));
}

#[test]
fn externally_produced_artifacts_must_state_a_license() {
    // Top-level external fields, as the jsign-signed MSI records them.
    const SIGNED: &str = "msi-independent-jsign.msi";
    assert_eq!(
        broken(|c| {
            artifact(c, SIGNED)
                .as_object_mut()
                .unwrap()
                .remove("license");
        }),
        one(Rule::Provenance, SIGNED)
    );
    for (field, value) in [
        ("signer", "an external tool"),
        ("upstream_revision", "0123456789abcdef"),
        ("signer_jar_sha256", "00"),
        ("source", "https://example.invalid/artifact"),
    ] {
        assert_eq!(
            broken(|c| artifact(c, FILE)[field] = json!(value)),
            one(Rule::Provenance, FILE),
            "{field}"
        );
    }
    // Derived from a listed fixture: the repository default still applies.
    assert_eq!(
        broken(|c| artifact(c, FILE)["source"] = json!("good-pe64.exe")),
        vec![]
    );
}

#[test]
fn rejects_derived_sources_that_do_not_resolve() {
    const DERIVED: &str = "parse-rfc3161.der";
    assert!(
        COMMITTED.manifest["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["file"] == DERIVED && a["source"] == "good-rfc3161.exe")
    );
    assert_eq!(
        broken(|c| artifact(c, DERIVED)["source"] = json!("good-rfc316.exe")),
        one(Rule::DerivedSource, DERIVED)
    );
    assert_eq!(
        broken(|c| artifact(c, DERIVED)["source"] = json!(DERIVED)),
        one(Rule::DerivedSource, DERIVED)
    );
}

#[test]
fn function_lookup_ignores_comments_strings_and_mid_line_text() {
    for source in [
        "// fn write() is gone",
        "/// see fn write(",
        "let text = \"fn write()\";",
        "    call(fn write());",
        "fn writer() {}",
        "pubfn write() {}",
    ] {
        assert!(!defines_function(source, "write"), "{source:?}");
    }
    for source in [
        "fn write() {}",
        "    fn write(bytes: &[u8]) {}",
        "pub fn write() {}",
        "pub(crate) fn write() {}",
        "pub(super) const unsafe fn write() {}",
        "async fn write<T>() {}",
    ] {
        assert!(defines_function(source, "write"), "{source:?}");
    }
}

#[test]
fn test_links_need_a_test_attribute_and_an_including_harness() {
    let named = "support::run_fixture";
    let source = &COMMITTED.sources["tests/cli/support.rs"];
    assert!(
        defines_function(source, "run_fixture"),
        "{named} still exists"
    );
    assert!(!declares_test(source, "run_fixture"));
    assert!(declares_test(
        "#[test]\n#[ignore = \"slow\"]\n/// docs\nfn slow() {}",
        "slow"
    ));
    assert!(!declares_test(
        "#[test]\nfn other() {}\n\nfn slow() {}",
        "slow"
    ));

    // A real test whose module no harness includes is not a test link.
    let real = COMMITTED.manifest["artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|a| a["tests"].as_array().into_iter().flatten())
        .filter_map(Value::as_str)
        .next()
        .unwrap()
        .to_owned();
    let module = real.split_once("::").unwrap().0.to_owned();
    let orphaned = broken(|c| {
        for (path, source) in c.sources.iter_mut() {
            if path
                .strip_prefix("tests/")
                .is_some_and(|n| !n.contains('/'))
            {
                *source = source.replace(&format!("#[path = \"cli/{module}.rs\"]"), "");
            }
        }
    });
    assert!(
        !orphaned.is_empty()
            && orphaned
                .iter()
                .all(|(rule, subject)| *rule == Rule::UnknownTest
                    && subject.contains(&format!(": {module}::"))),
        "{orphaned:?}"
    );
}

#[test]
fn generators_may_live_anywhere_under_src_or_tests() {
    assert_eq!(
        broken(|c| artifact(c, FILE)["generator"] =
            json!("tests/fixtures.rs::problem_details_preserve_typed_causes_and_roundtrip")),
        vec![]
    );
}

#[test]
fn function_lookup_ignores_block_comments_and_reads_extern_functions() {
    let commented = "/*\nfn write() {}\n*/\nfn other() {}";
    assert!(!defines_function(commented, "write"));
    assert!(defines_function(commented, "other"));
    assert!(!defines_function(
        "let x = 1; /* start\nfn write() {}\n end */",
        "write"
    ));
    assert!(defines_function("/* closed */\nfn write() {}", "write"));
    assert!(defines_function("pub extern \"C\" fn write() {}", "write"));
    assert!(defines_function(
        "unsafe extern \"system\" fn write() {}",
        "write"
    ));
    assert!(defines_function("extern fn write() {}", "write"));
}

#[test]
fn plain_arguments_with_a_path_separator_are_case_inputs() {
    for (argument, expected) in [
        (
            "tests/fixtures/good-pe64.exe",
            "pe32: tests/fixtures/good-pe64.exe",
        ),
        (
            "../fixtures/good-pe64.exe",
            "pe32: ../fixtures/good-pe64.exe",
        ),
        (
            "fixtures/../good-pe64.exe",
            "pe32: fixtures/../good-pe64.exe",
        ),
    ] {
        assert_eq!(
            broken(|c| {
                c.cases["cases"][0]["command"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!(argument));
            }),
            one(Rule::UnlistedCaseInput, expected),
            "{argument}"
        );
    }
    // A fixture path with a doubled separator still names the fixture, and URLs are not paths.
    assert_eq!(
        broken(|c| {
            let command = c.cases["cases"][0]["command"].as_array_mut().unwrap();
            command.push(json!("fixtures//good.crl"));
            command.push(json!("http://crl.example.invalid/x.crl"));
        }),
        vec![]
    );
}

#[test]
fn an_unsafe_or_duplicate_entry_still_reports_its_other_problems() {
    let problems = broken(|c| {
        let mut copy = artifact(c, FILE).clone();
        copy["license"] = json!("");
        copy["cases"] = json!(["no-such-case"]);
        c.manifest["artifacts"].as_array_mut().unwrap().push(copy);
    });
    assert_eq!(
        problems,
        vec![
            (Rule::DuplicateFile, FILE.to_owned()),
            (Rule::Provenance, FILE.to_owned()),
            (Rule::UnknownCase, format!("{FILE}: no-such-case")),
        ]
    );
}

#[test]
fn local_by_products_are_not_fixtures() {
    for name in [".DS_Store", "._good.exe", ".manifest.json.swp", "notes~"] {
        assert!(local_by_product(name), "{name}");
        assert!(!safe_file_name(name), "{name}");
    }
    assert!(!local_by_product("good.exe"));

    let directory = std::env::temp_dir().join(format!("rssig-manifest-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(directory.join("nested")).unwrap();
    for name in [
        "good.exe",
        ".DS_Store",
        "._good.exe",
        "good.exe.swp",
        "good.exe~",
    ] {
        std::fs::write(directory.join(name), b"MZ").unwrap();
    }
    let (files, other_entries) = read_fixture_directory(&directory);
    std::fs::remove_dir_all(&directory).unwrap();
    assert_eq!(files.keys().collect::<Vec<_>>(), ["good.exe"]);
    assert_eq!(other_entries.iter().collect::<Vec<_>>(), ["nested"]);
}
