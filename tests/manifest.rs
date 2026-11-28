//! Consistency of `tests/fixtures/manifest.json` with the committed fixtures,
//! the portable case specification, and the tests and generators it names.
//!
//! `check` is a pure function over an in-memory [`Corpus`], so every rule is
//! also exercised against a deliberately broken copy. Nothing here regenerates
//! or rewrites a fixture. See `docs/testing.md` for the rules and exceptions.
#[path = "common/by_product.rs"]
mod by_product;
#[path = "common/crosscheck.rs"]
mod crosscheck;
#[path = "common/spec_suite.rs"]
mod spec_suite;

use by_product::local_by_product;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use spec_suite::{CaseFile, Suite};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::LazyLock,
};
use syn::visit::{self, Visit};

const MANIFEST: &str = "manifest.json";

/// The fixture directory, relative to `tests/`: where the manifest lives and
/// what `cases.json` must name as its `fixtures` directory.
const FIXTURES: &str = "fixtures";

/// Files in `tests/fixtures/` that the manifest intentionally does not list.
/// Diagnostic JSON and helper data are ordinary listed artifacts.
const UNLISTED: &[&str] = &[MANIFEST];

/// Inputs that cases name because they do not exist. Each must stay absent
/// from both the manifest and the directory, and stay used by a case.
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
    /// Listed twice, compared case-insensitively.
    DuplicateFile,
    /// Listed in the manifest, absent from the directory.
    MissingFile,
    /// Present in the directory, absent from the manifest.
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
    /// An artifact names the same case ID twice.
    DuplicateCase,
    /// A case reads a file that is not a listed artifact.
    UnlistedCaseInput,
    /// An intentionally absent input exists or is listed.
    PresentAbsentInput,
    /// An intentionally absent input that no case names any more.
    UnusedException,
    /// An artifact names a Rust test that does not exist.
    UnknownTest,
    PairedGood,
    /// A `source` that is not a URL must name another listed artifact.
    DerivedSource,
    /// `cases.json` reads fixtures from a directory other than the one the
    /// manifest describes.
    FixtureDirectory,
    /// Two cases in `cases.json` share an ID.
    DuplicateCaseId,
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

/// What the checks need from a fixture file, computed once.
#[derive(Clone)]
struct FileFacts {
    bytes: u64,
    sha256: String,
}

impl FileFacts {
    fn of(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(bytes)),
        }
    }
}

/// What the checks need from a Rust source file, parsed once with `syn`, so
/// comments and string literals can never be mistaken for code.
#[derive(Clone, Debug, Default)]
struct SourceIndex {
    /// Free functions by path from the file root: `name`, or `inner::name`
    /// inside an inline `mod inner`. Methods and functions nested in function
    /// bodies cannot be named by a link and are left out.
    functions: BTreeSet<String>,
    /// The subset of [`Self::functions`] marked `#[test]`.
    tests: BTreeSet<String>,
    /// `#[path = "..."]` values on module declarations.
    included: BTreeSet<String>,
    /// Why parts of the file could not be indexed. Committed sources must
    /// index without errors; see `committed_sources_index_without_errors`.
    errors: Vec<String>,
    /// Inline modules enclosing the item being visited.
    modules: Vec<String>,
}

impl SourceIndex {
    fn parse(text: &str) -> syn::Result<Self> {
        let mut index = Self::default();
        index.visit_file(&syn::parse_file(text)?);
        Ok(index)
    }

    /// Never panics: a file that is not UTF-8 or that `syn` cannot parse is
    /// indexed as empty and the error is recorded, so one bad file cannot
    /// fail every check.
    fn parse_recording(text: &str) -> Self {
        Self::parse(text).unwrap_or_else(|error| Self {
            errors: vec![format!("not parsable: {error}")],
            ..Self::default()
        })
    }

    fn read(bytes: &[u8]) -> Self {
        match std::str::from_utf8(bytes) {
            Ok(text) => Self::parse_recording(text),
            Err(error) => Self {
                errors: vec![format!("not UTF-8: {error}")],
                ..Self::default()
            },
        }
    }
}

impl<'ast> Visit<'ast> for SourceIndex {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        let mut path = self.modules.clone();
        path.push(item.sig.ident.to_string());
        let path = path.join("::");
        if item.attrs.iter().any(|a| a.path().is_ident("test")) {
            self.tests.insert(path.clone());
        }
        self.functions.insert(path);
        visit::visit_item_fn(self, item);
    }
    /// Items inside any block (function and method bodies, closures, const
    /// initializers) cannot be named by a link, so never index them.
    fn visit_block(&mut self, _: &'ast syn::Block) {}
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        for attribute in &item.attrs {
            if attribute.path().is_ident("path")
                && let syn::Meta::NameValue(pair) = &attribute.meta
                && let syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::Str(path),
                    ..
                }) = &pair.value
            {
                self.included.insert(path.value());
            }
        }
        self.modules.push(item.ident.to_string());
        visit::visit_item_mod(self, item);
        self.modules.pop();
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
    cases: Suite,
    /// Every Rust file under each package's `src/` and `tests/` (the
    /// application's and `engine/`'s), plus `build.rs` when present, by
    /// repository-relative path.
    sources: BTreeMap<String, SourceIndex>,
}

fn read_sources(root: &Path, relative: &str, sources: &mut BTreeMap<String, SourceIndex>) {
    for entry in std::fs::read_dir(root.join(relative)).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = format!("{relative}/{name}");
        // Fixtures are data, even a fixture named `*.rs`.
        if path == format!("tests/{FIXTURES}") {
            continue;
        }
        if entry.file_type().unwrap().is_dir() {
            read_sources(root, &path, sources);
        } else if name.ends_with(".rs") {
            sources.insert(
                path,
                SourceIndex::read(&std::fs::read(entry.path()).unwrap()),
            );
        }
    }
}

/// Regular files and other entries directly inside `directory`, skipping
/// [`local_by_product`] regular files: no such name can be an artifact name
/// (see [`safe_file_name`]).
fn read_fixture_directory(directory: &Path) -> (BTreeMap<String, FileFacts>, BTreeSet<String>) {
    let mut files = BTreeMap::new();
    let mut other_entries = BTreeSet::new();
    for entry in std::fs::read_dir(directory).unwrap() {
        let entry = entry.unwrap();
        // A non-UTF-8 name becomes a lossy one, which is never a safe artifact
        // name, so it is reported as unlisted instead of panicking.
        let name = entry.file_name().to_string_lossy().into_owned();
        let is_file = entry.file_type().unwrap().is_file();
        if is_file && local_by_product(&name) {
            continue;
        }
        if is_file {
            files.insert(name, FileFacts::of(&std::fs::read(entry.path()).unwrap()));
        } else {
            other_entries.insert(name);
        }
    }
    (files, other_entries)
}

static COMMITTED: LazyLock<Corpus> = LazyLock::new(|| {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let directory = root.join("tests").join(FIXTURES);
    let (files, other_entries) = read_fixture_directory(&directory);
    let mut sources = BTreeMap::new();
    read_sources(root, "src", &mut sources);
    read_sources(root, "tests", &mut sources);
    read_sources(root, "engine/src", &mut sources);
    read_sources(root, "engine/tests", &mut sources);
    if let Ok(bytes) = std::fs::read(root.join("build.rs")) {
        sources.insert("build.rs".to_owned(), SourceIndex::read(&bytes));
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

/// One plain name: an ASCII letter or digit, then letters, digits, `.`, `_`
/// and `-`. Never the manifest itself, in any letter case.
fn safe_file_name(name: &str) -> bool {
    !name.eq_ignore_ascii_case(MANIFEST)
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

use spec_suite::is_url;

fn blank(text: &str) -> bool {
    text.trim().is_empty()
}

/// `path/to/file.rs`, or `path/to/file.rs::function` for a function declared
/// in it, optionally followed by whitespace and a note.
fn generator_exists(sources: &BTreeMap<String, SourceIndex>, generator: &str) -> bool {
    let reference = generator.split_whitespace().next().unwrap_or_default();
    let (path, function) = match reference.split_once("::") {
        Some((path, function)) => (path, Some(function)),
        None => (reference, None),
    };
    sources
        .get(path)
        .is_some_and(|index| function.is_none_or(|name| index.functions.contains(name)))
}

/// Reference clones kept at the repository root (the block under the
/// "Reference clones" header in .gitignore, up to the first blank line) must
/// be excluded from the workspace, or Cargo refuses to run inside a Rust one.
#[test]
fn reference_clones_are_excluded_from_the_workspace() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let manifest = std::fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let exclude = manifest
        .split_once("\nexclude = [")
        .and_then(|(_, rest)| rest.split_once(']'))
        .map(|(list, _)| list)
        .expect("the workspace has an exclude list");
    let ignored = std::fs::read_to_string(root.join(".gitignore")).unwrap();
    let clones: Vec<&str> = ignored
        .lines()
        .skip_while(|line| !line.starts_with("# Reference clones"))
        .take_while(|line| !line.is_empty())
        .filter(|line| !line.starts_with('#'))
        .collect();
    assert!(clones.contains(&"pe-sign"), "{clones:?}");
    for clone in clones {
        let name = clone.trim_matches('/');
        assert!(exclude.contains(&format!("\"{name}\"")), "{clone}");
    }
}

/// Every integration test crate of both packages includes its package's
/// revocation cross-check guard (CRL-T011): `cargo test --test <name>` builds
/// no other target, so a crate without it would run without the oracle
/// unnoticed.
#[test]
fn every_test_crate_includes_the_crosscheck_guard() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut crates = 0;
    for directory in ["tests", "engine/tests"] {
        for entry in std::fs::read_dir(root.join(directory)).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().is_some_and(|e| e == "rs") {
                crates += 1;
                let source = std::fs::read_to_string(&path).unwrap();
                assert!(
                    source.contains("#[path = \"common/crosscheck.rs\"]\nmod crosscheck;"),
                    "{} does not include common/crosscheck.rs",
                    path.display()
                );
            }
        }
    }
    assert!(crates >= 18, "{crates}");
    // The unit-test crates take the same guard from their lib.rs.
    for (lib, guard) in [
        (
            "src/lib.rs",
            "#[cfg(test)]\n#[path = \"../tests/common/crosscheck.rs\"]\nmod crosscheck;",
        ),
        (
            "engine/src/lib.rs",
            "#[cfg(all(test, feature = \"verify-core\"))]\n#[path = \"tests/crosscheck_active.rs\"]\nmod crosscheck_active;",
        ),
    ] {
        let source = std::fs::read_to_string(root.join(lib)).unwrap();
        assert!(source.contains(guard), "{lib} does not include its guard");
    }
}

/// The engine package publishes its own copies of the licence files; they
/// must stay identical to the repository's.
#[test]
fn the_engine_licence_files_match_the_repository() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for name in ["LICENSE", "NOTICE"] {
        assert_eq!(
            std::fs::read(root.join("engine").join(name)).unwrap(),
            std::fs::read(root.join(name)).unwrap(),
            "engine/{name}"
        );
    }
}

/// `cli/<module>.rs` paths that a test target directly under `tests/` includes.
fn harness_modules(sources: &BTreeMap<String, SourceIndex>) -> BTreeSet<&str> {
    sources
        .iter()
        .filter(|(path, _)| {
            path.strip_prefix("tests/")
                .is_some_and(|name| !name.contains('/'))
        })
        .flat_map(|(_, index)| index.included.iter().map(String::as_str))
        .collect()
}

/// `module::function`: a `#[test]` function in `tests/cli/<module>.rs`, which
/// a test target includes.
fn test_exists(
    sources: &BTreeMap<String, SourceIndex>,
    harness: &BTreeSet<&str>,
    test: &str,
) -> bool {
    test.split_once("::").is_some_and(|(module, function)| {
        // Top-level tests only: `module::inner::name` is not a test link.
        !function.contains("::")
            && harness.contains(format!("cli/{module}.rs").as_str())
            && sources
                .get(&format!("tests/cli/{module}.rs"))
                .is_some_and(|index| index.tests.contains(function))
    })
}

/// Case IDs and the files each case reads, as `tests/spec.rs` resolves them.
/// A repeated ID merges its cases' files, so none are lost; the repetition
/// itself is reported as [`Rule::DuplicateCaseId`].
fn case_files(suite: &Suite) -> BTreeMap<String, BTreeSet<CaseFile>> {
    let prefix = Path::new(&suite.fixtures);
    let mut result: BTreeMap<String, BTreeSet<CaseFile>> = BTreeMap::new();
    for case in &suite.cases {
        result
            .entry(case.id.clone())
            .or_default()
            .extend(case.files_read(prefix));
    }
    result
}

fn check(corpus: &Corpus) -> Vec<Problem> {
    let manifest = match Manifest::deserialize(&corpus.manifest) {
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

    // Against another directory, every case input would be misreported; one
    // problem says what is wrong, and case inputs are not checked.
    let same_directory = corpus.cases.fixtures == FIXTURES;
    if !same_directory {
        problems.push(problem(Rule::FixtureDirectory, &corpus.cases.fixtures));
    }
    let mut ids = BTreeSet::new();
    for case in &corpus.cases.cases {
        if !ids.insert(case.id.as_str()) {
            problems.push(problem(Rule::DuplicateCaseId, case.id.as_str()));
        }
    }
    let cases = case_files(&corpus.cases);
    let harness = harness_modules(&corpus.sources);
    let mut listed = BTreeSet::new();
    // macOS CI checks out onto a case-insensitive filesystem.
    let mut folded = BTreeSet::new();
    // Artifacts with third-party provenance; anything derived from one must
    // state its own license rather than inherit the repository default.
    let mut third_party = BTreeSet::new();
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
        if external || artifact.provenance.is_some() {
            third_party.insert(file);
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
            if !cases.contains_key(case) {
                problems.push(problem(Rule::UnknownCase, format!("{file}: {case}")));
            } else if !seen.insert(case) {
                problems.push(problem(Rule::DuplicateCase, format!("{file}: {case}")));
            }
        }
        for test in &artifact.tests {
            if !test_exists(&corpus.sources, &harness, test) {
                problems.push(problem(Rule::UnknownTest, format!("{file}: {test}")));
            }
        }
    }
    // Third-party content stays third-party through any chain of derivation.
    loop {
        let derived: Vec<&str> = manifest
            .artifacts
            .iter()
            .filter(|a| !third_party.contains(a.file.as_str()))
            .filter(|a| a.source.as_deref().is_some_and(|s| third_party.contains(s)))
            .map(|a| a.file.as_str())
            .collect();
        if derived.is_empty() {
            break;
        }
        third_party.extend(derived);
    }
    for artifact in &manifest.artifacts {
        if let Some(good) = artifact.paired_good.as_deref()
            && (good == artifact.file || !listed.contains(good))
        {
            problems.push(problem(Rule::PairedGood, artifact.file.as_str()));
        }
        if let Some(source) = artifact.source.as_deref()
            && !is_url(source)
        {
            if source == artifact.file || !listed.contains(source) {
                problems.push(problem(Rule::DerivedSource, artifact.file.as_str()));
            } else if third_party.contains(source)
                && artifact.license.is_none()
                && artifact.provenance.is_none()
            {
                problems.push(problem(Rule::Provenance, artifact.file.as_str()));
            }
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

    for (case, files) in cases.iter().filter(|_| same_directory) {
        for file in files {
            match file {
                CaseFile::Outside(path) => problems.push(problem(
                    Rule::UnlistedCaseInput,
                    format!("{case}: {path} (outside the fixture directory)"),
                )),
                // A response body is read whenever its URL is requested, so it
                // can never be one of the intentionally absent inputs.
                CaseFile::ResponseBody(name) if !listed.contains(name.as_str()) => {
                    problems.push(problem(Rule::UnlistedCaseInput, format!("{case}: {name}")));
                }
                CaseFile::ResponseBody(_) => {}
                CaseFile::Fixture(name) if ABSENT_INPUTS.contains(&name.as_str()) => {
                    // Case-insensitive: on macOS `Missing.exe` would be opened.
                    if folded.contains(&name.to_ascii_lowercase())
                        || corpus
                            .files
                            .keys()
                            .any(|file| file.eq_ignore_ascii_case(name))
                    {
                        problems.push(problem(Rule::PresentAbsentInput, format!("{case}: {name}")));
                    }
                }
                // Exempt files such as manifest.json are not fixtures: a case
                // may read only listed artifacts.
                CaseFile::Fixture(name) if !listed.contains(name.as_str()) => {
                    problems.push(problem(Rule::UnlistedCaseInput, format!("{case}: {name}")));
                }
                CaseFile::Fixture(_) => {}
            }
        }
    }
    for name in ABSENT_INPUTS.iter().filter(|_| same_directory) {
        let fixture = CaseFile::Fixture((*name).to_owned());
        if !cases.values().any(|files| files.contains(&fixture)) {
            problems.push(problem(Rule::UnusedException, *name));
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
// report exactly the expected problems.
const FILE: &str = "bad-image-digest.exe";

/// A listed fixture that no case reads, so removing it affects only file rules.
const UNUSED: &str = "attribute-certificate-v1.der";

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

/// The first committed case, `pe-006-pe32`, which reads only listed fixtures.
fn first_case(corpus: &mut Corpus) -> &mut spec_suite::Case {
    let case = &mut corpus.cases.cases[0];
    assert_eq!(case.id, "pe-006-pe32");
    case
}

fn one(rule: Rule, subject: &str) -> Vec<(Rule, String)> {
    vec![(rule, subject.to_owned())]
}

static COMMITTED_CASE_FILES: LazyLock<BTreeMap<String, BTreeSet<CaseFile>>> =
    LazyLock::new(|| case_files(&COMMITTED.cases));

/// Case IDs that read fixture `name`.
fn readers(name: &str) -> Vec<String> {
    let fixture = CaseFile::Fixture(name.to_owned());
    COMMITTED_CASE_FILES
        .iter()
        .filter(|(_, files)| files.contains(&fixture))
        .map(|(case, _)| case.clone())
        .collect()
}

fn sorted(mut problems: Vec<(Rule, String)>) -> Vec<(Rule, String)> {
    problems.sort();
    problems
}

fn outside(path: &str) -> String {
    format!("pe-006-pe32: {path} (outside the fixture directory)")
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
    let readers = readers(FILE);
    assert!(!readers.is_empty());
    for name in [
        "../Cargo.toml",
        "nested/file.exe",
        "/etc/hosts",
        "back\\slash.exe",
        ".hidden",
        "",
        "manifest.json",
        "Manifest.JSON",
        "space name.exe",
        "_leading.exe",
        "-leading.exe",
    ] {
        // The renamed artifact's real file becomes unlisted, and so does the
        // input of every case that reads it. Nothing else may be reported.
        let mut expected = vec![
            (Rule::UnsafePath, name.to_owned()),
            (Rule::UnlistedFile, FILE.to_owned()),
        ];
        expected.extend(
            readers
                .iter()
                .map(|case| (Rule::UnlistedCaseInput, format!("{case}: {FILE}"))),
        );
        assert_eq!(
            broken(|c| artifact(c, FILE)["file"] = json!(name)),
            sorted(expected),
            "{name}"
        );
    }
}

#[test]
fn rejects_duplicate_missing_and_unlisted_files() {
    assert!(
        readers(UNUSED).is_empty(),
        "{UNUSED} is now read by a case; choose a fixture no case reads"
    );
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
fn rejects_names_that_collide_on_case_insensitive_filesystems() {
    let problems = broken(|c| {
        let mut copy = artifact(c, FILE).clone();
        copy["file"] = json!(FILE.to_uppercase());
        c.manifest["artifacts"].as_array_mut().unwrap().push(copy);
    });
    assert_eq!(problems, one(Rule::DuplicateFile, &FILE.to_uppercase()));
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
    assert!(
        COMMITTED.manifest["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["file"] == EXTERNAL && a["provenance"]["source"].as_str().is_some())
    );
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
fn rejects_generators_that_do_not_exist() {
    assert_eq!(
        broken(|c| artifact(c, FILE)["generator"] = json!("src/absent.rs::write")),
        one(Rule::Generator, FILE)
    );
    assert_eq!(
        broken(|c| artifact(c, FILE)["generator"] = json!("tests/manifest.rs::rejects_generators")),
        one(Rule::Generator, FILE),
        "a prefix of a real function name is not that function"
    );
    assert_eq!(
        broken(|c| c.manifest["provenance"]["generator"] = json!("tests/manifest.rs::absent")),
        one(Rule::Generator, "manifest")
    );
    // References into the engine package are checked the same way.
    for generator in [
        "engine/src/tests/absent.rs::write",
        "engine/src/tests.rs::regenerate_cli",
    ] {
        assert_eq!(
            broken(|c| artifact(c, FILE)["generator"] = json!(generator)),
            one(Rule::Generator, FILE),
            "{generator}"
        );
    }
    const NESTED: &str = "appx-independent-signtool.msix";
    assert_eq!(
        broken(|c| artifact(c, NESTED)["provenance"]["generator"] = json!("tests/absent.rs")),
        one(Rule::Generator, NESTED)
    );
    // Accepted: a function in a package's src/ or tests/, a whole file, and a trailing note.
    for generator in [
        "engine/src/tests.rs::regenerate_cli_fixtures",
        "engine/tests/fixtures.rs::mismatched_image_fixture_preserves_the_original_signature",
        "engine/src/tests/crl_fetch_fixtures.rs",
        "engine/src/tests/trust_loading.rs::write via regenerate_cli_fixtures",
        "tests/manifest.rs::rejects_generators_that_do_not_exist",
    ] {
        assert_eq!(
            broken(|c| artifact(c, FILE)["generator"] = json!(generator)),
            vec![],
            "{generator}"
        );
    }
}

#[test]
fn rejects_unknown_or_repeated_cases_and_unknown_tests() {
    assert_eq!(
        broken(|c| artifact(c, FILE)["cases"] = json!(["no-such-case"])),
        one(Rule::UnknownCase, &format!("{FILE}: no-such-case"))
    );
    assert_eq!(
        broken(|c| artifact(c, FILE)["cases"] = json!(["pe-006-pe64", "pe-006-pe64"])),
        one(Rule::DuplicateCase, &format!("{FILE}: pe-006-pe64"))
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
fn test_links_need_a_test_attribute_and_an_including_harness() {
    let support = &COMMITTED.sources["tests/cli/support.rs"];
    assert!(support.functions.contains("run_fixture"));
    assert!(!support.tests.contains("run_fixture"));

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
        for index in c.sources.values_mut() {
            index.included.remove(&format!("cli/{module}.rs"));
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
fn rejects_case_inputs_the_manifest_does_not_list() {
    let input = broken(|c| first_case(c).input = Some("unlisted.exe".to_owned()));
    assert_eq!(
        input,
        one(Rule::UnlistedCaseInput, "pe-006-pe32: unlisted.exe")
    );

    let argument = broken(|c| {
        first_case(c)
            .command
            .push("fixtures/unlisted.crl".to_owned())
    });
    assert_eq!(
        argument,
        one(Rule::UnlistedCaseInput, "pe-006-pe32: unlisted.crl")
    );

    let response = broken(|c| {
        first_case(c).crl_responses = Some(BTreeMap::from([(
            "http://crl.example.invalid/x".to_owned(),
            "unlisted.crl".to_owned(),
        )]));
    });
    assert_eq!(
        response,
        one(Rule::UnlistedCaseInput, "pe-006-pe32: unlisted.crl")
    );

    let several = broken(|c| {
        let case = first_case(c);
        case.input = None;
        case.inputs = Some(vec!["good-pe32.exe".to_owned(), "unlisted.exe".to_owned()]);
    });
    assert_eq!(
        several,
        one(Rule::UnlistedCaseInput, "pe-006-pe32: unlisted.exe")
    );
}

#[test]
fn reads_path_options_in_both_forms_and_rejects_paths_outside_fixtures() {
    for (command, expected) in [
        (
            vec!["--crl=fixtures/unlisted.crl"],
            "pe-006-pe32: unlisted.crl".to_owned(),
        ),
        (
            vec!["--roots=fixtures/unlisted.der"],
            "pe-006-pe32: unlisted.der".to_owned(),
        ),
        // A listed name without the prefix resolves beside cases.json, not to the fixture.
        (vec!["--crl", "good.crl"], outside("good.crl")),
        (vec!["--crl=good.crl"], outside("good.crl")),
        (vec!["--roots=../root.der"], outside("../root.der")),
        (
            vec!["--crl", "fixtures/../good.crl"],
            outside("fixtures/../good.crl"),
        ),
        // The CLI cannot open these as the fixture, though `Path` normalizes them.
        (
            vec!["--crl", "fixtures/good.crl/"],
            outside("fixtures/good.crl/"),
        ),
        (
            vec!["--crl=fixtures/./good.crl"],
            outside("fixtures/./good.crl"),
        ),
    ] {
        let problems = broken(|c| {
            first_case(c)
                .command
                .extend(command.iter().map(|argument| (*argument).to_owned()))
        });
        assert_eq!(
            problems,
            one(Rule::UnlistedCaseInput, &expected),
            "{command:?}"
        );
    }
    // The listed form is accepted, and an unrelated `=` option is not a path.
    assert_eq!(
        broken(|c| first_case(c)
            .command
            .extend(["--crl=fixtures/good.crl", "--time=1800000000"].map(str::to_owned))),
        vec![]
    );
}

#[test]
fn plain_arguments_with_a_path_separator_are_case_inputs() {
    for argument in [
        "tests/fixtures/good-pe64.exe",
        "../fixtures/good-pe64.exe",
        "fixtures/../good-pe64.exe",
    ] {
        assert_eq!(
            broken(|c| first_case(c).command.push(argument.to_owned())),
            one(Rule::UnlistedCaseInput, &outside(argument)),
            "{argument}"
        );
    }
    // A doubled separator still names the fixture, and URLs are not paths.
    assert_eq!(
        broken(|c| first_case(c)
            .command
            .extend(["fixtures//good.crl", "http://crl.example.invalid/x.crl"].map(str::to_owned))),
        vec![]
    );
}

#[test]
fn a_case_may_not_read_an_exempt_unlisted_file() {
    assert_eq!(
        broken(|c| first_case(c).input = Some(MANIFEST.to_owned())),
        one(Rule::UnlistedCaseInput, "pe-006-pe32: manifest.json")
    );
}

#[test]
fn intentionally_absent_inputs_must_stay_absent_and_used() {
    let readers = readers("missing.exe");
    assert!(!readers.is_empty());
    let present = broken(|c| {
        c.files.insert("missing.exe".to_owned(), FileFacts::of(&[]));
    });
    let mut expected = vec![(Rule::UnlistedFile, "missing.exe".to_owned())];
    expected.extend(
        readers
            .iter()
            .map(|case| (Rule::PresentAbsentInput, format!("{case}: missing.exe"))),
    );
    assert_eq!(present, sorted(expected));

    // macOS checkouts are case-insensitive, so `Missing.exe` would be opened.
    let differently_cased = broken(|c| {
        c.files.insert("Missing.exe".to_owned(), FileFacts::of(&[]));
    });
    let mut expected = vec![(Rule::UnlistedFile, "Missing.exe".to_owned())];
    expected.extend(
        readers
            .iter()
            .map(|case| (Rule::PresentAbsentInput, format!("{case}: missing.exe"))),
    );
    assert_eq!(differently_cased, sorted(expected));

    let unused = broken(|c| {
        for case in &mut c.cases.cases {
            for name in case
                .input
                .iter_mut()
                .chain(case.inputs.iter_mut().flatten())
            {
                if name == "missing.exe" {
                    *name = "good-pe64.exe".to_owned();
                }
            }
            for argument in &mut case.command {
                if argument == "fixtures/missing.exe" {
                    *argument = "fixtures/good-pe64.exe".to_owned();
                }
            }
        }
    });
    assert_eq!(unused, one(Rule::UnusedException, "missing.exe"));
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
fn source_index_reads_code_never_comments_or_strings() {
    let index = SourceIndex::parse(
        r####"
        // fn line_comment() {}
        /* fn block_comment() {}
           fn still_comment() {} */
        /// fn doc_comment() {}
        const GLOB: &str = "fixtures/*.der";
        const URL: &str = "http://example.invalid/"; /* fn after_url() {} */
        const RAW: &str = r#"
        fn in_raw_string() {}
        "#;
        fn writer() {}
        pub(super) const unsafe fn qualified() {}
        pub extern "C" fn external() {}
        mod inner {
            pub(crate) async fn nested<T>() {}
        }
        struct S;
        impl S {
            fn method(&self) {}
        }
        trait T {
            fn provided() {}
        }
        #[cfg(test)]
        #[test]
        #[ignore = "slow"]
        /// Documented.
        fn slow() {}
        #[path = "cli/pe.rs"]
        mod pe;
        "####,
    )
    .unwrap();
    for absent in [
        "line_comment",
        "block_comment",
        "still_comment",
        "doc_comment",
        "after_url",
        "in_raw_string",
        "write",
    ] {
        assert!(!index.functions.contains(absent), "{absent}");
    }
    for present in ["writer", "qualified", "external", "inner::nested", "slow"] {
        assert!(index.functions.contains(present), "{present}");
    }
    // Only free functions, by their path from the file root, can be linked.
    for unlinkable in ["nested", "method", "provided"] {
        assert!(!index.functions.contains(unlinkable), "{unlinkable}");
    }
    assert_eq!(index.tests, BTreeSet::from(["slow".to_owned()]));
    assert_eq!(index.included, BTreeSet::from(["cli/pe.rs".to_owned()]));
}

/// Removes a scratch directory even if the test panics.
struct Scratch(std::path::PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn local_by_products_are_skipped_and_can_never_be_artifacts() {
    for name in [
        ".DS_Store",
        "._good.exe",
        ".good.exe.swp",
        "..swp",
        "good.exe~",
    ] {
        assert!(local_by_product(name), "{name}");
        assert!(!safe_file_name(name), "{name}");
    }
    // Anything else is never skipped, so a committed one must be listed.
    // `.swp` alone does not match `.gitignore`'s `.*.swp`.
    for name in [
        "good.exe",
        "good.exe.swp",
        ".swp",
        "_x",
        ".keep",
        ".gitattributes",
    ] {
        assert!(!local_by_product(name), "{name}");
    }

    // Per process: test runs sharing a target directory must not collide.
    let scratch = Scratch(
        Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("manifest-by-products-{}", std::process::id())),
    );
    let directory = &scratch.0;
    let _ = std::fs::remove_dir_all(directory);
    std::fs::create_dir_all(directory.join("nested")).unwrap();
    std::fs::create_dir_all(directory.join(".cache")).unwrap();
    for name in [
        "good.exe",
        "good.exe.swp",
        ".DS_Store",
        "._good.exe",
        "good.exe~",
        ".keep",
    ] {
        std::fs::write(directory.join(name), b"MZ").unwrap();
    }
    let (files, other_entries) = read_fixture_directory(directory);
    drop(scratch);
    assert_eq!(
        files.keys().collect::<Vec<_>>(),
        [".keep", "good.exe", "good.exe.swp"]
    );
    assert_eq!(
        other_entries.iter().collect::<Vec<_>>(),
        [".cache", "nested"]
    );
}

#[test]
fn cases_must_read_the_fixture_directory_the_manifest_describes() {
    assert_eq!(COMMITTED.cases.fixtures, FIXTURES);
    // Renaming only the directory leaves every `fixtures/...` argument
    // pointing elsewhere; that is still one problem, not one per input.
    assert_eq!(
        broken(|c| c.cases.fixtures = "fixtures-v2".to_owned()),
        one(Rule::FixtureDirectory, "fixtures-v2")
    );
    // A complete move to another directory is reported once, not per input.
    assert_eq!(
        broken(|c| {
            c.cases.fixtures = "fixtures-v2".to_owned();
            for case in &mut c.cases.cases {
                for argument in &mut case.command {
                    if let Some(rest) = argument.strip_prefix("fixtures/") {
                        *argument = format!("fixtures-v2/{rest}");
                    }
                }
            }
        }),
        one(Rule::FixtureDirectory, "fixtures-v2")
    );
}

#[test]
fn duplicate_case_ids_are_reported_and_keep_every_input() {
    let problems = broken(|c| {
        let mut copy = c.cases.cases[0].clone();
        copy.command.push("fixtures/unlisted.crl".to_owned());
        c.cases.cases.insert(0, copy);
    });
    assert_eq!(
        problems,
        sorted(vec![
            (
                Rule::UnlistedCaseInput,
                "pe-006-pe32: unlisted.crl".to_owned()
            ),
            (Rule::DuplicateCaseId, "pe-006-pe32".to_owned()),
        ])
    );
}

#[test]
fn a_flag_after_a_path_option_is_not_a_path() {
    assert_eq!(
        spec_suite::classify(["--roots", "--no-system-roots"], Path::new(FIXTURES)),
        [
            spec_suite::Argument::Plain("--roots"),
            spec_suite::Argument::Plain("--no-system-roots"),
        ]
    );
    assert_eq!(
        broken(|c| first_case(c)
            .command
            .extend(["--crl", "--no-revocation"].map(str::to_owned))),
        vec![]
    );
}

#[test]
fn committed_sources_index_without_errors() {
    let errors: Vec<_> = COMMITTED
        .sources
        .iter()
        .filter(|(_, index)| !index.errors.is_empty())
        .map(|(path, index)| (path, &index.errors))
        .collect();
    assert!(errors.is_empty(), "{errors:#?}");
}

#[test]
fn path_option_state_never_leaks_past_one_argument() {
    use spec_suite::Argument::{InlinePath, Path as PathArgument, Plain};
    let prefix = Path::new(FIXTURES);
    assert_eq!(
        spec_suite::classify(["--roots", "--crl=fixtures/good.crl", "pe"], prefix),
        [
            Plain("--roots"),
            InlinePath {
                flag: "--crl",
                path: "fixtures/good.crl"
            },
            Plain("pe"),
        ]
    );
    // As in Clap, `-name.der` after a path option is a flag (the value is
    // missing); only a lone `-` is a value.
    assert_eq!(
        spec_suite::classify(["--crl", "-", "--roots", "-dash.der", "x"], prefix),
        [
            Plain("--crl"),
            PathArgument("-"),
            Plain("--roots"),
            Plain("-dash.der"),
            Plain("x"),
        ]
    );
}

#[test]
fn response_bodies_must_be_listed_plain_names() {
    let response = |c: &mut Corpus, body: &str| {
        first_case(c).crl_responses = Some(BTreeMap::from([(
            "http://crl.example.invalid/x".to_owned(),
            body.to_owned(),
        )]));
    };
    // Never an intentionally absent input: the runner would fail reading it.
    assert_eq!(
        broken(|c| response(c, "missing.crl")),
        one(Rule::UnlistedCaseInput, "pe-006-pe32: missing.crl")
    );
    for body in ["sub/good.crl", "./good.crl", "/abs.crl"] {
        assert_eq!(
            broken(|c| response(c, body)),
            one(Rule::UnlistedCaseInput, &outside(body)),
            "{body}"
        );
    }
    assert_eq!(broken(|c| response(c, "good.crl")), vec![]);
}

#[test]
fn nested_test_links_and_body_local_functions_are_not_linkable() {
    let index = SourceIndex::parse(
        r#"
        struct S;
        impl S {
            fn build(&self) {
                fn helper() {}
                #[test]
                fn in_method() {}
            }
        }
        fn outer() {
            fn in_function() {}
        }
        const C: () = {
            fn in_const() {}
        };
        mod tests {
            #[test]
            fn nested() {}
        }
        "#,
    )
    .unwrap();
    assert_eq!(
        index.functions,
        BTreeSet::from(["outer".to_owned(), "tests::nested".to_owned()])
    );
    assert_eq!(index.tests, BTreeSet::from(["tests::nested".to_owned()]));

    // A test inside an inline module is not a top-level test link.
    let module = "pe";
    let problems = broken(|c| {
        c.sources
            .get_mut(&format!("tests/cli/{module}.rs"))
            .unwrap()
            .tests
            .insert("inner::nested".to_owned());
        artifact(c, FILE)["tests"] = json!([format!("{module}::inner::nested")]);
    });
    assert_eq!(
        problems,
        one(Rule::UnknownTest, &format!("{FILE}: pe::inner::nested"))
    );
}

#[test]
fn artifacts_derived_from_third_party_ones_state_a_license() {
    // Derived from a repository-generated artifact: the default applies.
    assert_eq!(
        broken(|c| artifact(c, FILE)["source"] = json!("good-pe64.exe")),
        vec![]
    );
    // Derived from an externally signed one: it must say so.
    assert_eq!(
        broken(|c| artifact(c, FILE)["source"] = json!("msi-independent-jsign.msi")),
        one(Rule::Provenance, FILE)
    );
    assert_eq!(
        broken(|c| {
            artifact(c, FILE)["source"] = json!("msi-independent-jsign.msi");
            artifact(c, FILE)["license"] = json!("Apache-2.0 (derived from a jsign 7.6 signature)");
        }),
        vec![]
    );
}

#[test]
fn any_scheme_is_a_url_in_both_halves_of_the_check() {
    for url in [
        "git://host/repo",
        "ftp://host/file",
        "file:///x",
        "https://h/x",
    ] {
        assert!(is_url(url), "{url}");
        // Never resolved as a derived fixture, and treated as external.
        assert_eq!(
            broken(|c| artifact(c, FILE)["source"] = json!(url)),
            one(Rule::Provenance, FILE),
            "{url}"
        );
    }
    for path in ["fixtures/x", "://x", "a b://x"] {
        assert!(!is_url(path), "{path}");
    }
}

#[test]
fn third_party_content_stays_third_party_through_derivation() {
    // FILE derives from a jsign-signed artifact and states a license; UNUSED
    // derives from FILE without one, so it must not inherit the default.
    assert_eq!(
        broken(|c| {
            artifact(c, FILE)["source"] = json!("msi-independent-jsign.msi");
            artifact(c, FILE)["license"] = json!("Apache-2.0 (derived from jsign output)");
            artifact(c, UNUSED)["source"] = json!(FILE);
        }),
        one(Rule::Provenance, UNUSED)
    );
}

#[test]
fn arguments_after_a_double_dash_are_positional_files() {
    use spec_suite::Argument::{Plain, Positional};
    assert_eq!(
        spec_suite::classify(
            ["verify", "--", "--crl=fixtures/good.crl"],
            Path::new(FIXTURES)
        ),
        [
            Plain("verify"),
            Plain("--"),
            Positional("--crl=fixtures/good.crl")
        ]
    );
    assert_eq!(
        broken(|c| first_case(c)
            .command
            .extend(["--", "--crl=fixtures/good.crl"].map(str::to_owned))),
        one(Rule::UnlistedCaseInput, &outside("--crl=fixtures/good.crl"))
    );
}

#[test]
fn url_values_of_options_are_not_files() {
    assert_eq!(
        broken(|c| first_case(c)
            .command
            .push("--crl-url=http://crl.example.invalid/x.crl".to_owned())),
        vec![]
    );
    // A path value of an unknown option is still a file read outside fixtures.
    assert_eq!(
        broken(|c| first_case(c).command.push("--other=sub/x.der".to_owned())),
        one(Rule::UnlistedCaseInput, &outside("--other=sub/x.der"))
    );
}

#[test]
fn fixtures_are_never_indexed_as_sources() {
    assert!(
        COMMITTED
            .sources
            .keys()
            .all(|path| !path.starts_with(&format!("tests/{FIXTURES}/")))
    );
    let scratch = Scratch(
        Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("manifest-sources-{}", std::process::id())),
    );
    let root = &scratch.0;
    let _ = std::fs::remove_dir_all(root);
    std::fs::create_dir_all(root.join("tests").join(FIXTURES)).unwrap();
    std::fs::write(root.join("tests/kept.rs"), "fn kept() {}").unwrap();
    std::fs::write(root.join("tests").join(FIXTURES).join("sample.rs"), "fn (").unwrap();
    let mut sources = BTreeMap::new();
    read_sources(root, "tests", &mut sources);
    assert_eq!(sources.keys().collect::<Vec<_>>(), ["tests/kept.rs"]);
}

#[test]
fn unreadable_sources_are_recorded_not_fatal() {
    assert!(SourceIndex::parse("fn (").is_err());
    let unparsable = SourceIndex::parse_recording("fn (");
    assert!(unparsable.functions.is_empty());
    assert!(unparsable.errors[0].starts_with("not parsable"));
    let not_utf8 = SourceIndex::read(&[0x66, 0x6e, 0xff]);
    assert!(not_utf8.errors[0].starts_with("not UTF-8"));
}
