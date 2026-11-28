//! Load the portable CLI specification with Serde and exercise the CLI library.
#[path = "common/crosscheck.rs"]
mod crosscheck;
#[path = "common/spec_suite.rs"]
mod spec_suite;

use rssig::cli;
use serde::Serialize;
use serde_json::Value;
use spec_suite::{Argument, Case, Suite};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    ffi::OsString,
    path::{Path, PathBuf},
};

/// Reads the IDs of every decision entry (AGENTS.md, "Pinned expectations")
/// from the given documents: a level-three heading `### PREFIX-NNN: title`
/// followed by `- **Status:**`, `- **Decided by:**` and `- **Pins:**` lines
/// before the next heading. Status is `Decided` or `Observed`: a dropped entry
/// leaves its index in a reindex instead of staying as a tombstone
/// (docs/decisions.md, "IDs").
fn parse_decisions(
    documents: impl IntoIterator<Item = (String, String)>,
) -> Result<BTreeSet<String>, String> {
    let is_id = |id: &str| {
        id.split_once('-').is_some_and(|(prefix, number)| {
            !prefix.is_empty()
                && prefix.bytes().all(|b| b.is_ascii_uppercase())
                && number.len() == 3
                && number.bytes().all(|b| b.is_ascii_digit())
        })
    };
    let mut entries = BTreeSet::new();
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
            if !matches!(status.as_str(), "Decided" | "Observed") {
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
            if !entries.insert(id.to_owned()) {
                return Err(format!("{name}: duplicate decision {id}"));
            }
        }
    }
    Ok(entries)
}

/// The decision entries of every Markdown document directly under `docs/`.
fn committed_decisions() -> Result<&'static BTreeSet<String>, String> {
    static INDEX: std::sync::OnceLock<Result<BTreeSet<String>, String>> =
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
            if let Some(id) = &case.decision
                && !committed_decisions()?.contains(id)
            {
                return Err(format!(
                    "case {} names decision {id}, which no index under docs/ defines",
                    case.id
                ));
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
                if !answers.iter().all(|(key, answer)| {
                    digest(key)
                        && answer
                            .files()
                            .into_iter()
                            .all(|name| spec_suite::is_fixture_name(name))
                }) {
                    return Err(format!(
                        "crl_certificate_responses maps a lowercase SHA-256 to a fixture file name or a scripted answer: {}",
                        case.id
                    ));
                }
                let mut padded = 0_usize;
                for answer in answers.values() {
                    if let spec_suite::CertificateAnswer::Scripted(script) = answer {
                        if let Some(problem) = scripted_answer_problem(script) {
                            return Err(format!("a scripted answer {problem}: {}", case.id));
                        }
                        // Saturating: the count of bodies is not bounded, and
                        // a sum that wraps on a 32-bit host would pass.
                        padded = script
                            .crls
                            .iter()
                            .flatten()
                            .filter_map(|crl| crl.pad_to)
                            .fold(padded, usize::saturating_add);
                    }
                }
                if padded > MAX_PAD_TOTAL {
                    return Err(format!(
                        "the pad_to values of a case add up to at most {MAX_PAD_TOTAL}: {}",
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
            validate_json_absent(&case.id, expect)?;
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

/// The most one body may pad to: twice the 8 MiB a retrieved CRL may have, so a
/// body over the cap fits and a typo cannot make the runner allocate without
/// bound. The schema states it as `maximum`. `validate` checks it and the
/// case total; `execute` checks it again, and the total of each response.
const MAX_PAD_TO: usize = 2 * rssig_engine::retrieval::MAX_CRL_BYTES;

/// The most the `pad_to` values of a case may add up to: twice the 32 MiB of
/// trust evidence a verification may take in all (supplied roots and CRLs
/// included), so a case can exceed that allowance. Unpadded bodies are
/// committed fixtures, whose size the manifest pins.
const MAX_PAD_TOTAL: usize = 2 * rssig_engine::retrieval::MAX_TOTAL_BYTES;

/// What is wrong with a scripted answer, by the rules the schema states: it
/// holds bodies and failures, or one error; a list that is present is not
/// empty; a url is not empty; a pad_to is between 1 and [`MAX_PAD_TO`].
fn scripted_answer_problem(script: &spec_suite::ScriptedAnswer) -> Option<String> {
    let lists = script.crls.is_some() || script.failures.is_some();
    if script.error.is_none() && !lists {
        return Some("holds nothing".to_owned());
    }
    if script.error.is_some() && lists {
        return Some("holds an error beside bodies or failures".to_owned());
    }
    if script.crls.as_ref().is_some_and(Vec::is_empty)
        || script.failures.as_ref().is_some_and(Vec::is_empty)
    {
        return Some("has an empty list".to_owned());
    }
    let urls = script.crls.iter().flatten().map(|crl| &crl.url).chain(
        script
            .failures
            .iter()
            .flatten()
            .chain(script.error.iter())
            .map(|failure| &failure.url),
    );
    if urls.into_iter().any(|url| url.as_deref() == Some("")) {
        return Some("has an empty url".to_owned());
    }
    if script.crls.iter().flatten().any(|crl| {
        crl.pad_to
            .is_some_and(|size| !(1..=MAX_PAD_TO).contains(&size))
    }) {
        return Some(format!("has a pad_to outside 1 to {MAX_PAD_TO}"));
    }
    None
}

/// The rules for `expect.json_absent` that hold before a case runs. A mistyped
/// ancestor that `json` does not mention is caught by `check_absent` instead.
fn validate_json_absent(id: &str, expect: &spec_suite::Expectation) -> Result<(), String> {
    if expect.json_absent.is_empty() {
        return Ok(());
    }
    let Some(json) = &expect.json else {
        return Err(format!("json_absent requires json: {id}"));
    };
    let mut seen = BTreeSet::new();
    for pointer in &expect.json_absent {
        if !seen.insert(pointer) {
            return Err(format!("json_absent repeats a pointer: {id}"));
        }
        // Every token names something (no empty member name), and only the
        // escapes ~0 and ~1 occur.
        let valid = pointer.strip_prefix('/').is_some_and(|rest| {
            rest.split('/').all(|token| {
                !token.is_empty()
                    && token
                        .split('~')
                        .skip(1)
                        .all(|after| after.starts_with(['0', '1']))
            })
        });
        if !valid {
            return Err(format!(
                "json_absent holds a JSON Pointer to a member: {id}"
            ));
        }
        if json.pointer(pointer).is_some() {
            return Err(format!("json_absent contradicts json: {id}"));
        }
        // `json` already shows that the parent cannot be an object, so the
        // case could never pass.
        let parent = pointer.rsplit_once('/').map_or("", |(parent, _)| parent);
        if json
            .pointer(parent)
            .is_some_and(|parent| !parent.is_object())
        {
            return Err(format!("json_absent parent is not an object in json: {id}"));
        }
    }
    Ok(())
}

/// A plain fixture-name answer is a body the source may return, so it must fit
/// both the request's allowance and the 8 MiB a body may have (CRL-045): a body
/// over either is given on purpose with `pad_to`, never by a fixture that happens
/// to be large.
fn unpadded_answer_over_allowance(name: &str, len: usize, max_bytes: usize) -> Option<String> {
    let cap = max_bytes.min(rssig_engine::retrieval::MAX_CRL_BYTES);
    (len > cap).then(|| {
        format!(
            "the answer {name} ({len} bytes) exceeds the {cap} bytes a body may have here; \
             use a scripted body with pad_to to return one over a cap"
        )
    })
}

/// `name` under `fixtures`. A test may run a case it changed without
/// validating it, so the name is checked here too: relative, and never
/// climbing out of the fixture directory.
fn fixture_path(fixtures: &Path, name: &str) -> std::path::PathBuf {
    let path = Path::new(name);
    assert!(
        path.is_relative()
            && !path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir)),
        "a fixture name must stay in the fixture directory: {name}"
    );
    fixtures.join(path)
}

/// The size each scripted body is sent at, and what is wrong with the bodies,
/// the files being `lens` bytes long, under an allowance of `max_bytes`.
/// A body is padded to its `pad_to` when that is in range and the response's
/// padded total stays within [`MAX_PAD_TOTAL`]; otherwise it goes at its own
/// size. Each body is judged by what the bodies before it left of the
/// allowance, counted from the sizes actually sent, as the engine counts it:
/// a body within the caps spends it, one over them does not.
fn scripted_bodies(
    crls: &[spec_suite::ScriptedCrl],
    lens: &[usize],
    max_bytes: usize,
) -> (Vec<usize>, Vec<String>) {
    let mut remaining = max_bytes;
    let mut padded = 0_usize;
    let mut sizes = Vec::new();
    let mut problems = Vec::new();
    for (crl, &len) in crls.iter().zip(lens) {
        problems.extend(pad_to_problem(crl, len));
        let mut size = len;
        // A pad_to of the file's own size pads nothing and counts for nothing.
        if let Some(pad) = crl.pad_to.filter(|&pad| pad > len && pad <= MAX_PAD_TO) {
            // Bounded here too, per response, as each pad_to is: a test may
            // run a changed case without validating it. `validate` bounds
            // the case total.
            if padded.saturating_add(pad) > MAX_PAD_TOTAL {
                problems.push(format!(
                    "the pad_to values of a response add up to at most {MAX_PAD_TOTAL}"
                ));
            } else {
                padded += pad;
                size = pad;
            }
        }
        // A body sent at its own size, for whatever reason, must fit the
        // caps: only a body padded on purpose may be over one, since a source
        // that returns more than it may is a case, and the engine judges it.
        if size == len {
            problems.extend(unpadded_answer_over_allowance(&crl.file, len, remaining));
        }
        if size <= remaining.min(rssig_engine::retrieval::MAX_CRL_BYTES) {
            remaining -= size;
        }
        sizes.push(size);
    }
    (sizes, problems)
}

/// What is wrong with a scripted body's `pad_to`, the file being `len`
/// bytes long: a `pad_to` only pads, so one under the file's size would cut
/// it. One outside 1 to [`MAX_PAD_TO`] is `scripted_answer_problem`'s, named
/// once, and is never padded to.
fn pad_to_problem(crl: &spec_suite::ScriptedCrl, len: usize) -> Option<String> {
    crl.pad_to
        .filter(|&size| (1..=MAX_PAD_TO).contains(&size) && size < len)
        .map(|size| format!("pad_to {size} is shorter than {} ({len} bytes)", crl.file))
}

/// Every pointer in `pointers` must name a member that is absent from an
/// object that exists in `actual`.
fn check_absent(pointers: &[String], actual: &Value, failures: &mut Vec<String>) {
    for pointer in pointers {
        let (parent, member) = pointer.rsplit_once('/').unwrap_or(("", pointer));
        // RFC 6901 section 4: decode ~1 before ~0.
        let member = member.replace("~1", "/").replace("~0", "~");
        match actual.pointer(parent) {
            Some(Value::Object(object)) => {
                if let Some(found) = object.get(&member) {
                    failures.push(format!("{pointer}: expected absent, found {found}"));
                }
            }
            // A missing parent would make a typo in the pointer pass.
            _ => failures.push(format!(
                "{pointer}: the parent is not an object, so absence proves nothing"
            )),
        }
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

/// Whether a scripted URL names one of the listed points: spelled as listed,
/// or equal to it after both are normalized as URLs (the WHATWG URL
/// serialization, which the engine compares).
fn names_a_listed_point(url: &str, points: &[String]) -> bool {
    let normalized = |raw: &str| url::Url::parse(raw).ok().map(String::from);
    points.iter().any(|point| {
        point == url || normalized(url).is_some_and(|url| normalized(point) == Some(url))
    })
}

fn execute(case: &Case, parent: &Path, fixtures: &Path, fixture_prefix: &Path) -> CaseResult {
    let command = argv(case, parent, fixtures, fixture_prefix);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    struct Source<'a> {
        responses: &'a BTreeMap<String, String>,
        by_certificate: Option<&'a BTreeMap<String, spec_suite::CertificateAnswer>>,
        errors: Option<&'a BTreeMap<String, rssig_engine::domain::CrlSourceErrorKind>>,
        fixtures: &'a Path,
        requests: &'a mut Vec<String>,
        /// What is wrong with the case itself, reported as its failures.
        problems: &'a mut Vec<String>,
        /// The certificates whose answer, plain or scripted, the engine asked for.
        asked: &'a mut std::collections::BTreeSet<String>,
    }
    impl rssig_engine::retrieval::CrlSource for Source<'_> {
        fn crls(
            &mut self,
            request: &rssig_engine::retrieval::CrlRequest<'_>,
        ) -> Result<rssig_engine::retrieval::CrlResponse, rssig_engine::retrieval::CrlSourceError>
        {
            use sha2::Digest;
            let certificate: String = sha2::Sha256::digest(request.certificate)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            // A source keyed by certificate answers such a certificate with
            // its answer alone, within the allowance, and requests none of
            // its listed URLs.
            if let Some(answer) = self
                .by_certificate
                .and_then(|answers| answers.get(&certificate))
            {
                self.asked.insert(certificate.clone());
                use rssig_engine::retrieval::{CrlResponse, CrlSourceError, SourcedCrl};
                let read =
                    |name: &String| std::fs::read(fixture_path(self.fixtures, name)).unwrap();
                let failure = |failure: &spec_suite::ScriptedFailure| {
                    let error = CrlSourceError::new(failure.kind, "injected CRL source failure");
                    match &failure.url {
                        Some(url) => error.with_url(url.clone()),
                        None => error,
                    }
                };
                // A scripted URL that is no listed point of this request would
                // turn a case about the point into one about a URL outside
                // the request. A source may name one, but a case must not do
                // it by accident. A point may be named as listed or in its
                // normalized form, which the engine matches too.
                let unlisted = |url: &Option<String>| {
                    url.as_ref()
                        .filter(|url| !names_a_listed_point(url, request.distribution_points))
                        .map(|url| {
                            format!(
                                "scripted url {url} is not a listed point of the request {:?} \
                                 (spell it as listed or in its normalized form)",
                                request.distribution_points
                            )
                        })
                };
                return match answer {
                    spec_suite::CertificateAnswer::Fixture(name) => {
                        let bytes = read(name);
                        self.problems.extend(unpadded_answer_over_allowance(
                            name,
                            bytes.len(),
                            request.max_bytes,
                        ));
                        Ok(CrlResponse::new().with_crl(SourcedCrl::new(bytes)))
                    }
                    spec_suite::CertificateAnswer::Scripted(script) => {
                        // Every problem of the answer is found first: its shape
                        // (checked here too, as a test may run a changed case
                        // without validating it), its sizes and its URLs. An
                        // answer with any problem is never sent: the source
                        // aborts instead, so the engine never runs a response
                        // other than the one the case scripts, and the case
                        // fails on the problems, each named.
                        let crls = script.crls.as_deref().unwrap_or_default();
                        let files: Vec<Vec<u8>> = crls.iter().map(|crl| read(&crl.file)).collect();
                        let lens: Vec<usize> = files.iter().map(Vec::len).collect();
                        let (sizes, mut problems) = scripted_bodies(crls, &lens, request.max_bytes);
                        if let Some(problem) = scripted_answer_problem(script) {
                            problems.push(format!("a scripted answer {problem}"));
                        }
                        let urls = crls
                            .iter()
                            .map(|crl| &crl.url)
                            .chain(script.failures.iter().flatten().map(|f| &f.url))
                            .chain(script.error.iter().map(|e| &e.url));
                        for url in urls {
                            problems.extend(unlisted(url));
                        }
                        if !problems.is_empty() {
                            self.problems.extend(problems);
                            return Err(CrlSourceError::new(
                                rssig_engine::domain::CrlSourceErrorKind::Abort,
                                "the case's scripted answer has a problem; nothing is sent",
                            ));
                        }
                        if let Some(error) = &script.error {
                            return Err(failure(error));
                        }
                        let mut response = CrlResponse::new();
                        for ((crl, mut bytes), size) in crls.iter().zip(files).zip(sizes) {
                            bytes.resize(size, 0);
                            let body = SourcedCrl::new(bytes);
                            response = response.with_crl(match &crl.url {
                                Some(url) => body.with_url(url.clone()),
                                None => body,
                            });
                        }
                        for item in script.failures.iter().flatten() {
                            response = response.with_failure(failure(item));
                        }
                        Ok(response)
                    }
                };
            }
            let response = rssig_engine::retrieval::fetch_each(request, |url, max_bytes| {
                use rssig_engine::domain::CrlSourceErrorKind;
                use rssig_engine::retrieval::CrlSourceError;
                self.requests.push(url.to_owned());
                if let Some(kind) = self.errors.and_then(|errors| errors.get(url)) {
                    return Err(CrlSourceError::new(*kind, "injected CRL fetch error"));
                }
                let name = self.responses.get(url).ok_or_else(|| {
                    CrlSourceError::new(CrlSourceErrorKind::Failed, "no injected CRL response")
                })?;
                let bytes = std::fs::read(fixture_path(self.fixtures, name)).unwrap();
                self.problems
                    .extend(unpadded_answer_over_allowance(name, bytes.len(), max_bytes));
                Ok(rssig_engine::retrieval::SourcedCrl::new(bytes))
            });
            Ok(response)
        }
    }
    let mut requests = Vec::new();
    let mut problems = Vec::new();
    let mut asked = std::collections::BTreeSet::new();
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
                problems: &mut problems,
                asked: &mut asked,
            },
        )
        .unwrap()
    } else {
        cli::run_with_writers(&command, &mut stdout, &mut stderr).unwrap()
    };
    let output = serde_json::from_slice::<Value>(&stdout);
    // The engine asks about several certificates, and a source is called for
    // each: say each problem once.
    problems.sort_unstable();
    problems.dedup();
    let mut failures = problems;
    // An answer, plain or scripted, nobody asked for means the case no longer tests what
    // it says: the certificate's hash went stale, or the engine stopped asking.
    for key in case
        .crl_certificate_responses
        .iter()
        .flat_map(BTreeMap::keys)
    {
        if !asked.contains(key) {
            failures.push(format!(
                "the injected answer for certificate {key} was never requested (a stale \
                 hash, or the engine stopped before asking: look at the other failures first)"
            ));
        }
    }
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
            Ok(output) => {
                compare(expected, output, "", &mut failures);
                check_absent(&case.expect.json_absent, output, &mut failures);
            }
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
    assert!(decisions.contains("CRL-001"), "docs/crl.md is not indexed");
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
        let section = text
            .split_once("\n## Candidate rules\n")
            .map(|(_, rest)| rest.split("\n## ").next().unwrap_or(rest))
            .unwrap_or_else(|| panic!("docs/{file} has no Candidate rules section"));
        for (key, ids) in keys.as_object().expect("candidate keys") {
            assert!(
                section.contains(&format!("- `{key}`:")),
                "docs/{file} does not list candidate rule `{key}` under Candidate rules"
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
fn specification_absence_names_a_missing_member_of_an_existing_object() {
    let actual = serde_json::json!({
        "error": {"code": "x", "details": {"a/b": 1, "none": null}}
    });
    let check = |pointers: &[&str]| {
        let pointers: Vec<String> = pointers.iter().map(|p| (*p).to_owned()).collect();
        let mut failures = Vec::new();
        check_absent(&pointers, &actual, &mut failures);
        failures
    };
    // A member that is not there passes.
    assert!(check(&["/error/details/unusable_crl"]).is_empty());
    // A member that is there fails, whatever its value, null included.
    assert_eq!(
        check(&["/error/code"]),
        ["/error/code: expected absent, found \"x\""]
    );
    assert_eq!(
        check(&["/error/details/none"]),
        ["/error/details/none: expected absent, found null"]
    );
    // Pointer escapes name the member as compare() does.
    assert_eq!(
        check(&["/error/details/a~1b"]),
        ["/error/details/a~1b: expected absent, found 1"]
    );
    // ~01 is the member named ~1, not /.
    let escaped = serde_json::json!({"d": {"~1": 1, "/": 2}});
    let mut failures = Vec::new();
    check_absent(&["/d/~01".to_owned()], &escaped, &mut failures);
    assert_eq!(failures, ["/d/~01: expected absent, found 1"]);
    // A parent that is missing, or not an object, proves nothing: a typo in
    // the pointer must not pass.
    assert_eq!(
        check(&["/error/detail/unusable_crl"]),
        ["/error/detail/unusable_crl: the parent is not an object, so absence proves nothing"]
    );
    assert_eq!(
        check(&["/error/code/x"]),
        ["/error/code/x: the parent is not an object, so absence proves nothing"]
    );
    // Every pointer is checked.
    assert_eq!(
        check(&["/error/code", "/error/details/none", "/error/x"]).len(),
        2
    );
}

/// A forged CRL is reported with `unusable_crl`, so asserting that member
/// absent fails for it and passes for a set-aside CRL: the end-to-end check
/// that `json_absent` can tell the two apart.
#[test]
fn specification_absence_tells_a_forged_crl_from_a_set_aside_one() {
    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut suite: Suite = serde_json::from_str(include_str!("cases.json")).unwrap();
    let fixtures = parent.join(&suite.fixtures);
    let prefix = Path::new(&suite.fixtures);
    let absent = vec!["/results/0/error/details/unusable_crl".to_owned()];
    let (set_aside, forged_id) = (
        "crl-040-forged-crl-naming-another-key-is-set-aside",
        "crl-040-forged-crl-naming-a-same-key-roots-identifier-is-forged",
    );
    let committed = suite
        .cases
        .iter()
        .find(|c| c.id == set_aside)
        .unwrap()
        .expect
        .json_absent
        .clone();
    assert_eq!(committed, absent);
    let mut run = |id: &str, absent: &[String]| {
        let case = suite.cases.iter_mut().find(|c| c.id == id).unwrap();
        case.expect.json_absent = absent.to_vec();
        execute(case, &parent, &fixtures, prefix).failures
    };
    // The set-aside case carries the assertion as committed and passes in
    // `cli_conforms_to_committed_json_specification`. The forged case passes
    // without it, so its failure with it comes from the assertion alone.
    assert!(run(forged_id, &[]).is_empty());
    let forged = run(forged_id, &absent);
    assert!(
        forged.iter().any(|f| f.contains("expected absent, found")),
        "{forged:?}"
    );
}

#[test]
fn specification_json_absent_needs_json_and_contradicts_none_of_it() {
    let validate = |expect: Value| {
        let case = serde_json::json!({"id":"one","command":["--help"],"expect":expect});
        serde_json::from_value::<Suite>(
            serde_json::json!({"schema_version":1,"fixtures":"fixtures","cases":[case]}),
        )
        .unwrap()
        .validate()
    };
    assert!(
        validate(serde_json::json!({"exit_code":0,"json":{"a":{}},"json_absent":["/a/b"]})).is_ok()
    );
    for (expect, message) in [
        (
            serde_json::json!({"exit_code":0,"stderr_contains":["x"],"json_absent":["/a/b"]}),
            "json_absent requires json: one",
        ),
        (
            serde_json::json!({"exit_code":0,"json":{"a":{"b":1}},"json_absent":["/a/b"]}),
            "json_absent contradicts json: one",
        ),
        (
            serde_json::json!({"exit_code":0,"json":{"a":{}},"json_absent":["a/b"]}),
            "json_absent holds a JSON Pointer to a member: one",
        ),
        (
            serde_json::json!({"exit_code":0,"json":{"a":{}},"json_absent":[""]}),
            "json_absent holds a JSON Pointer to a member: one",
        ),
        (
            serde_json::json!({"exit_code":0,"json":{"a":{}},"json_absent":["/a/b","/a/b"]}),
            "json_absent repeats a pointer: one",
        ),
        (
            serde_json::json!({"exit_code":0,"json":{"a":1},"json_absent":["/a/b"]}),
            "json_absent parent is not an object in json: one",
        ),
        (
            serde_json::json!({"exit_code":0,"json":{"a":[]},"json_absent":["/a/0"]}),
            "json_absent parent is not an object in json: one",
        ),
        (
            serde_json::json!({"exit_code":0,"json":{"a":{}},"json_absent":["/a/"]}),
            "json_absent holds a JSON Pointer to a member: one",
        ),
        (
            serde_json::json!({"exit_code":0,"json":{"a":{}},"json_absent":["/a//b"]}),
            "json_absent holds a JSON Pointer to a member: one",
        ),
        (
            serde_json::json!({"exit_code":0,"json":{"a":{}},"json_absent":["//"]}),
            "json_absent holds a JSON Pointer to a member: one",
        ),
        (
            serde_json::json!({"exit_code":0,"json":{"a":{}},"json_absent":["/a/b~2"]}),
            "json_absent holds a JSON Pointer to a member: one",
        ),
        (
            serde_json::json!({"exit_code":0,"json":{"a":{}},"json_absent":["/a/b~"]}),
            "json_absent holds a JSON Pointer to a member: one",
        ),
    ] {
        assert_eq!(validate(expect).unwrap_err(), message);
    }
}

#[test]
fn specification_scripted_answers_hold_bodies_and_failures_or_one_error() {
    let key = "a".repeat(64);
    let suite = |answer: Value| {
        let case = serde_json::json!({
            "id": "one", "command": ["--help"], "crl_responses": {},
            "crl_certificate_responses": {key.clone(): answer},
            "expect": {"exit_code": 0, "json": {"ok": true}}
        });
        serde_json::from_value::<Suite>(
            serde_json::json!({"schema_version":1,"fixtures":"fixtures","cases":[case]}),
        )
    };
    let valid = |answer: Value| suite(answer).unwrap().validate();
    // One file as before, bodies with failures, a failure alone, and an error.
    for answer in [
        serde_json::json!("a.crl"),
        serde_json::json!({"crls": [{"file": "a.crl"}, {"file": "b.crl", "url": "http://x/"}]}),
        serde_json::json!({"failures": [{"kind": "denied"}, {"kind": "abort", "url": "http://x/"}]}),
        serde_json::json!({"crls": [{"file": "a.crl"}], "failures": [{"kind": "failed"}]}),
        serde_json::json!({"error": {"kind": "unknown"}}),
    ] {
        assert!(valid(answer.clone()).is_ok(), "{answer}");
    }
    // Each mistake is named, so a case author knows which rule was broken.
    for (answer, reason) in [
        (serde_json::json!({}), "holds nothing"),
        (serde_json::json!({"crls": []}), "has an empty list"),
        (serde_json::json!({"failures": []}), "has an empty list"),
        (
            serde_json::json!({"crls": [{"file": "a.crl"}], "failures": []}),
            "has an empty list",
        ),
        (
            serde_json::json!({"error": {"kind": "failed"}, "crls": []}),
            "holds an error beside bodies or failures",
        ),
        (
            serde_json::json!({"error": {"kind": "failed"}, "failures": [{"kind": "failed"}]}),
            "holds an error beside bodies or failures",
        ),
        (
            serde_json::json!({"error": {"kind": "failed"}, "crls": [{"file": "a.crl"}]}),
            "holds an error beside bodies or failures",
        ),
        (
            serde_json::json!({"crls": [{"file": "a.crl", "url": ""}]}),
            "has an empty url",
        ),
        (
            serde_json::json!({"failures": [{"kind": "denied", "url": ""}]}),
            "has an empty url",
        ),
        (
            serde_json::json!({"error": {"kind": "failed", "url": ""}}),
            "has an empty url",
        ),
        (
            serde_json::json!({"crls": [{"file": "a.crl", "pad_to": 0}]}),
            "has a pad_to outside 1 to 16777216",
        ),
        (
            serde_json::json!({"crls": [{"file": "a.crl", "pad_to": MAX_PAD_TO + 1}]}),
            "has a pad_to outside 1 to 16777216",
        ),
    ] {
        assert_eq!(
            valid(answer.clone()).unwrap_err(),
            format!("a scripted answer {reason}: one"),
            "{answer}"
        );
    }
    // The bodies of a case pad to the total limit in all, not each.
    let bodies = |count: usize| {
        let crls: Vec<Value> = (0..count)
            .map(|i| serde_json::json!({"file": format!("{i}.crl"), "pad_to": 16777216}))
            .collect();
        let case = serde_json::json!({
            "id": "one", "command": ["--help"], "crl_responses": {},
            "crl_certificate_responses": {key.clone(): {"crls": crls}},
            "expect": {"exit_code": 0, "json": {"ok": true}}
        });
        serde_json::from_value::<Suite>(
            serde_json::json!({"schema_version":1,"fixtures":"fixtures","cases":[case]}),
        )
        .unwrap()
        .validate()
    };
    assert!(bodies(4).is_ok());
    assert_eq!(
        bodies(5).unwrap_err(),
        "the pad_to values of a case add up to at most 67108864: one"
    );
    // The largest pad_to is accepted.
    assert!(valid(serde_json::json!({"crls": [{"file": "a.crl", "pad_to": 16777216}]})).is_ok());
    // A body file is a plain fixture name.
    assert!(
        valid(serde_json::json!({"crls": [{"file": "../a.crl"}]}))
            .unwrap_err()
            .starts_with("crl_certificate_responses maps a lowercase SHA-256")
    );
    // An unknown field, kind or a missing kind is not read, and the error
    // names it.
    for (answer, named) in [
        (
            serde_json::json!({"crl": [{"file": "a.crl"}]}),
            "unknown field `crl`",
        ),
        (
            serde_json::json!({"failures": [{"kind": "broken"}]}),
            "unknown variant `broken`",
        ),
        (
            serde_json::json!({"failures": [{"url": "http://x/"}]}),
            "missing field `kind`",
        ),
        (
            serde_json::json!({"crls": [{"url": "http://x/"}]}),
            "missing field `file`",
        ),
        (
            serde_json::json!(7),
            "fixture file name or a scripted object",
        ),
        (
            serde_json::json!({"error": {"kind": "failed"}, "crls": null}),
            "null is no value",
        ),
        (
            serde_json::json!({"failures": [{"kind": "denied", "url": null}]}),
            "null is no value",
        ),
        (
            serde_json::json!({"crls": [{"file": "a.crl", "pad_to": null}]}),
            "null is no value",
        ),
        // A mistyped field set to null is named as mistyped, not as a null.
        (
            serde_json::json!({"error": {"kind": "failed"}, "crl": null}),
            "unknown field `crl`",
        ),
        (
            serde_json::json!({"failures": [{"kind": "denied", "uri": null}]}),
            "unknown field `uri`",
        ),
    ] {
        let error = suite(answer.clone()).err().unwrap().to_string();
        assert!(error.contains(named), "{answer}: {error}");
    }
}

/// A case that says "the source names the listed point" must really name it:
/// a URL that went stale or was mistyped would turn the case into a test of a
/// URL outside the request, which still passes if the expectation repeats it.
#[test]
fn specification_a_scripted_url_must_name_a_listed_point() {
    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut suite: Suite = serde_json::from_str(include_str!("cases.json")).unwrap();
    let fixtures = parent.join(&suite.fixtures);
    let prefix = Path::new(&suite.fixtures);
    let case = suite
        .cases
        .iter_mut()
        .find(|c| c.id == "crl-026-a-failure-naming-the-point-is-recorded-for-it")
        .unwrap();
    // As committed it names the listed point and passes.
    assert!(
        execute(case, &parent, &fixtures, prefix)
            .failures
            .is_empty()
    );
    let answers = case.crl_certificate_responses.as_mut().unwrap();
    let Some(spec_suite::CertificateAnswer::Scripted(script)) = answers.values_mut().next() else {
        panic!("the case scripts its answer");
    };
    for failure in script.failures.iter_mut().flatten() {
        failure.url = Some("http://crl.example.invalid/typo.crl".into());
    }
    let result = execute(case, &parent, &fixtures, prefix);
    let reported = result
        .failures
        .iter()
        .filter(|f| f.contains("is not a listed point of the request"))
        .count();
    assert_eq!(reported, 1, "{:?}", result.failures);
}

/// The case that names its point by the normalized URL tests that only while
/// its spelling differs from the listed one and normalizes to it: spelled as
/// listed, it would pass as the exact-spelling case does, and spelled as some
/// other point, the runner fails it.
#[test]
fn specification_a_point_named_by_its_normalized_url_is_spelled_otherwise() {
    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let suite: Suite = serde_json::from_str(include_str!("cases.json")).unwrap();
    let fixtures = parent.join(&suite.fixtures);
    let prefix = Path::new(&suite.fixtures);
    let case = suite
        .cases
        .iter()
        .find(|c| {
            c.id == "crl-026-a-failure-naming-the-point-by-its-normalized-url-is-recorded-for-it"
        })
        .unwrap();
    let answers = case.crl_certificate_responses.as_ref().unwrap();
    let Some(spec_suite::CertificateAnswer::Scripted(script)) = answers.values().next() else {
        panic!("the case scripts its answer");
    };
    let urls: Vec<&str> = script
        .failures
        .iter()
        .flatten()
        .filter_map(|f| f.url.as_deref())
        .collect();
    let listed = "http://crl.example.invalid/test.crl";
    assert_eq!(urls.len(), 1, "{urls:?}");
    assert_ne!(urls[0], listed);
    assert!(names_a_listed_point(urls[0], &[listed.to_owned()]));
    // The runner accepts it, and the engine records the source's spelling.
    let result = execute(case, &parent, &fixtures, prefix);
    assert!(result.failures.is_empty(), "{:?}", result.failures);
    // Another point, or a typo, is still no listed point.
    for other in [
        "http://crl.example.invalid/other.crl",
        "http://crl2.example.invalid/test.crl",
        "https://crl.example.invalid/test.crl",
        "not a url",
    ] {
        assert!(
            !names_a_listed_point(other, &[listed.to_owned()]),
            "{other}"
        );
    }
}

/// The per-body limit is stated twice, in the schema and in the runner.
#[test]
fn specification_the_schema_and_the_runner_agree_on_the_pad_to_limit() {
    let schema: Value = serde_json::from_str(include_str!("cases.schema.json")).unwrap();
    let maximum = &schema["$defs"]["scriptedAnswer"]["properties"]["crls"]["items"]["properties"]["pad_to"]
        ["maximum"];
    assert_eq!(*maximum, serde_json::json!(MAX_PAD_TO));
    // The total is prose in the schema and the docs: both must state the
    // runner's number.
    let total = MAX_PAD_TOTAL.to_string();
    let described = schema["$defs"]["scriptedAnswer"]["properties"]["crls"]["items"]["properties"]
        ["pad_to"]["description"]
        .as_str()
        .unwrap();
    assert!(described.contains(&total), "{described}");
    assert!(include_str!("../docs/testing.md").contains(&format!("add up to at most {total}")));
}

/// A reviewer once said the schema cannot state the rules of a scripted answer;
/// it does, and this keeps it so. The runner and the schema each enforce them,
/// and nothing else ties the two until the schema is validated mechanically
/// (TEST-T003).
#[test]
fn specification_the_schema_states_the_rules_of_a_scripted_answer() {
    use rssig_engine::domain::CrlSourceErrorKind::{self, Abort, Denied, Failed, Unknown};
    let schema: Value = serde_json::from_str(include_str!("cases.schema.json")).unwrap();
    let defs = &schema["$defs"];
    let answer = &defs["scriptedAnswer"];
    // An answer says something, nothing else is a field, and an error is the
    // whole answer.
    assert_eq!(answer["minProperties"], 1);
    assert_eq!(answer["additionalProperties"], false);
    assert_eq!(
        answer["dependentSchemas"]["error"]["not"]["anyOf"],
        serde_json::json!([{"required": ["crls"]}, {"required": ["failures"]}])
    );
    // A list that is present is not empty, a url is not empty, a pad_to is at
    // least 1.
    assert_eq!(answer["properties"]["crls"]["minItems"], 1);
    assert_eq!(answer["properties"]["failures"]["minItems"], 1);
    let body = &answer["properties"]["crls"]["items"];
    assert_eq!(body["additionalProperties"], false);
    assert_eq!(body["properties"]["url"]["minLength"], 1);
    assert_eq!(body["properties"]["pad_to"]["minimum"], 1);
    let failure = &defs["scriptedFailure"];
    assert_eq!(failure["additionalProperties"], false);
    assert_eq!(failure["properties"]["url"]["minLength"], 1);
    assert_eq!(failure["required"], serde_json::json!(["kind"]));
    // The kinds are the source's four. Every kind the schema lists is one the
    // type reads, and the four are listed; a fifth added to the type is not
    // caught here, since the type is non-exhaustive.
    let listed = failure["properties"]["kind"]["enum"].as_array().unwrap();
    for kind in listed {
        serde_json::from_value::<CrlSourceErrorKind>(kind.clone())
            .unwrap_or_else(|e| panic!("{kind}: {e}"));
    }
    let named: Vec<Value> = [Denied, Failed, Abort, Unknown]
        .iter()
        .map(|kind| serde_json::to_value(kind).unwrap())
        .collect();
    assert_eq!(listed, &named);
}

/// An answer keyed by URL may go unrequested: two cases map one to show that
/// nothing is asked. `expect.crl_requests` is what defends them, so a case that
/// expects the request fails when the engine does not make it.
#[test]
fn specification_an_unrequested_url_answer_is_defended_by_the_request_expectation() {
    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut suite: Suite = serde_json::from_str(include_str!("cases.json")).unwrap();
    let fixtures = parent.join(&suite.fixtures);
    let prefix = Path::new(&suite.fixtures);
    for id in [
        "crl-018-forged-local-asks-nothing",
        "crl-035-no-next-update-local-asks-nothing",
    ] {
        let case = suite.cases.iter_mut().find(|c| c.id == id).unwrap();
        // The answer is mapped, nothing is requested, and the case says so.
        assert!(!case.crl_responses.as_ref().unwrap().is_empty(), "{id}");
        assert_eq!(case.expect.crl_requests.as_deref(), Some(&[][..]), "{id}");
        assert!(
            execute(case, &parent, &fixtures, prefix)
                .failures
                .is_empty(),
            "{id}"
        );
        // Were the request expected, the case would fail on it.
        case.expect.crl_requests = Some(vec!["http://crl.example.invalid/test.crl".into()]);
        let result = execute(case, &parent, &fixtures, prefix);
        assert!(
            result
                .failures
                .iter()
                .any(|f| f.starts_with("/crl_requests")),
            "{id}: {:?}",
            result.failures
        );
    }
}

#[test]
fn specification_an_unpadded_answer_over_the_allowance_is_a_problem_of_the_case() {
    assert_eq!(unpadded_answer_over_allowance("a.crl", 10, 10), None);
    assert_eq!(unpadded_answer_over_allowance("a.crl", 0, 10), None);
    let problem = unpadded_answer_over_allowance("a.crl", 11, 10).unwrap();
    assert!(problem.contains("a.crl (11 bytes) exceeds the 10 bytes a body may have here"));
    assert!(problem.contains("pad_to"));
    // The per-body cap applies under a larger allowance too.
    let cap = rssig_engine::retrieval::MAX_CRL_BYTES;
    let allowance = rssig_engine::retrieval::MAX_TOTAL_BYTES;
    assert_eq!(
        unpadded_answer_over_allowance("a.crl", cap, allowance),
        None
    );
    assert!(unpadded_answer_over_allowance("a.crl", cap + 1, allowance).is_some());
    // A scripted body is held to the same caps unless pad_to gives its size,
    // and pad_to never cuts the file.
    let body = |pad_to| spec_suite::ScriptedCrl {
        file: "a.crl".into(),
        pad_to,
        url: None,
    };
    let one = |pad_to, len, remaining| scripted_bodies(&[body(pad_to)], &[len], remaining).1;
    let over = |len, remaining| unpadded_answer_over_allowance("a.crl", len, remaining).unwrap();
    assert!(one(None, 10, 10).is_empty());
    assert_eq!(one(None, 11, 10), [over(11, 10)]);
    // A pad_to of the file's own size pads nothing, so it is held to the caps.
    assert_eq!(one(Some(11), 11, 10), [over(11, 10)]);
    assert!(one(Some(12), 11, 10).is_empty());
    assert!(one(Some(cap + 1), 11, 10).is_empty());
    // A pad_to that would cut the file is named, and the body, sent at its
    // own size, is held to the caps too.
    assert_eq!(
        one(Some(10), 11, 10),
        [
            "pad_to 10 is shorter than a.crl (11 bytes)".to_owned(),
            over(11, 10)
        ]
    );
    // A pad_to over the limit is never padded to, so the body is held to the
    // caps; the limit itself is `scripted_answer_problem`'s, named once.
    assert_eq!(one(Some(usize::MAX), 11, 10), [over(11, 10)]);
    assert!(one(Some(0), 1, 10).is_empty());
}

/// An unpadded body is held to what the bodies before it left of the
/// allowance, as the engine counts it, so a case never reaches the allowance
/// by accident; padded bodies over it are the CRL-045 case itself.
#[test]
fn specification_an_unpadded_body_after_a_spent_allowance_is_a_problem_of_the_case() {
    let body = |pad_to| spec_suite::ScriptedCrl {
        file: "a.crl".into(),
        pad_to,
        url: None,
    };
    let cap = rssig_engine::retrieval::MAX_CRL_BYTES;
    // Two padded bodies spend 90 of 100 bytes; an unpadded 10 still fits.
    let spent = [body(Some(45)), body(Some(45)), body(None)];
    assert!(scripted_bodies(&spent, &[1, 1, 10], 100).1.is_empty());
    // One more byte and it does not.
    assert_eq!(
        scripted_bodies(&spent, &[1, 1, 11], 100).1,
        [unpadded_answer_over_allowance("a.crl", 11, 10).unwrap()]
    );
    // A padded body over what is left spends nothing, as the engine counts
    // it (CRL-045), so the body after it still has the room.
    let skipped = [body(Some(90)), body(Some(20)), body(None)];
    assert!(scripted_bodies(&skipped, &[1, 1, 10], 100).1.is_empty());
    // Nor does a padded body over the per-body cap.
    let over = [body(Some(cap + 1)), body(None)];
    assert!(scripted_bodies(&over, &[1, 100], 100).1.is_empty());
    // An unpadded body never spends room it was not given.
    let unpadded = [body(None), body(None)];
    assert_eq!(
        scripted_bodies(&unpadded, &[60, 60], 100).1,
        [unpadded_answer_over_allowance("a.crl", 60, 40).unwrap()]
    );
    // Past the response's padded total a body goes at its own size, and the
    // allowance is counted from the sizes sent. Eight bodies at the cap reach
    // the total; the ninth is sent as its one byte, so the room it would
    // have spent padded is left for the tenth, unpadded.
    let fit = MAX_PAD_TOTAL / cap;
    let many: Vec<_> = (0..=fit)
        .map(|_| body(Some(cap)))
        .chain([body(None)])
        .collect();
    let lens = vec![1; many.len()];
    let (sizes, problems) = scripted_bodies(&many, &lens, (fit + 1) * cap);
    let mut expected = vec![cap; fit];
    expected.extend([1, 1]);
    assert_eq!(sizes, expected);
    assert_eq!(
        problems,
        [format!(
            "the pad_to values of a response add up to at most {MAX_PAD_TOTAL}"
        )]
    );
    // A pad_to of the file's own size counts nothing toward the total.
    let mut noop: Vec<_> = (0..fit).map(|_| body(Some(cap))).collect();
    noop.insert(0, body(Some(1)));
    let (sizes, problems) = scripted_bodies(&noop, &vec![1; noop.len()], usize::MAX);
    assert_eq!(sizes[0], 1);
    assert!(sizes[1..].iter().all(|&size| size == cap));
    assert!(problems.is_empty(), "{problems:?}");
    // A body sent at its own size that way is still held to the allowance.
    let (_, problems) = scripted_bodies(&many, &lens, fit * cap);
    assert_eq!(
        problems,
        [
            format!("the pad_to values of a response add up to at most {MAX_PAD_TOTAL}"),
            unpadded_answer_over_allowance("a.crl", 1, 0).unwrap(),
            unpadded_answer_over_allowance("a.crl", 1, 0).unwrap(),
        ]
    );
    // The committed CRL-045 case passes the runner's own check.
    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let suite: Suite = serde_json::from_str(include_str!("cases.json")).unwrap();
    let fixtures = parent.join(&suite.fixtures);
    let prefix = Path::new(&suite.fixtures);
    let case = suite
        .cases
        .iter()
        .find(|c| c.id == "crl-045-over-allowance-body-does-not-count-against-the-next")
        .unwrap();
    assert!(
        execute(case, &parent, &fixtures, prefix)
            .failures
            .is_empty()
    );
}

/// A changed case run without validation still has its scripted answer's
/// shape checked: an error beside bodies is named, not run as an error.
#[test]
fn specification_execute_names_a_misshapen_scripted_answer() {
    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut suite: Suite = serde_json::from_str(include_str!("cases.json")).unwrap();
    let fixtures = parent.join(&suite.fixtures);
    let prefix = Path::new(&suite.fixtures);
    let case = suite
        .cases
        .iter_mut()
        .find(|c| c.id == "crl-045-body-over-the-size-cap-is-no-answer")
        .unwrap();
    let answers = case.crl_certificate_responses.as_mut().unwrap();
    let Some(spec_suite::CertificateAnswer::Scripted(script)) = answers.values_mut().next() else {
        panic!("the case scripts its answer");
    };
    script.error = Some(spec_suite::ScriptedFailure {
        kind: rssig_engine::domain::CrlSourceErrorKind::Failed,
        url: None,
    });
    let result = execute(case, &parent, &fixtures, prefix);
    assert!(
        result
            .failures
            .iter()
            .any(|f| f.contains("a scripted answer holds an error beside bodies or failures")),
        "{:?}",
        result.failures
    );
}

/// An answer with a problem is never sent: the source aborts, so the engine
/// runs no response other than the one the case scripts, while the runner
/// still names every problem of the answer.
#[test]
fn specification_an_answer_with_a_problem_is_never_sent() {
    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut suite: Suite = serde_json::from_str(include_str!("cases.json")).unwrap();
    let fixtures = parent.join(&suite.fixtures);
    let prefix = Path::new(&suite.fixtures);
    let case = suite
        .cases
        .iter_mut()
        .find(|c| c.id == "crl-045-oversized-body-does-not-count-against-the-next")
        .unwrap();
    // Sent, the good body after the two oversized ones would settle the
    // status; the case expects that.
    assert!(
        execute(case, &parent, &fixtures, prefix)
            .failures
            .is_empty()
    );
    let answers = case.crl_certificate_responses.as_mut().unwrap();
    let Some(spec_suite::CertificateAnswer::Scripted(script)) = answers.values_mut().next() else {
        panic!("the case scripts its answer");
    };
    // Two problems, in the first body and the last.
    let bodies = script.crls.as_mut().unwrap();
    bodies[0].pad_to = Some(MAX_PAD_TO + 1);
    bodies.last_mut().unwrap().url = Some("http://stale.invalid/".into());
    let result = execute(case, &parent, &fixtures, prefix);
    for named in [
        format!("has a pad_to outside 1 to {MAX_PAD_TO}"),
        "scripted url http://stale.invalid/ is not a listed point".to_owned(),
    ] {
        assert!(
            result.failures.iter().any(|f| f.contains(&named)),
            "{named}: {:?}",
            result.failures
        );
    }
    // Nothing was sent: the source aborted, so the good body, which would
    // have settled the status had the answer gone out, settled nothing.
    assert!(
        result
            .failures
            .iter()
            .any(|f| f == "/results/0/ok: expected true, got false"),
        "{:?}",
        result.failures
    );
}

/// A test may run a changed case without validating it; a fixture name that
/// climbs out of the fixture directory still stops it.
#[test]
#[should_panic(expected = "a fixture name must stay in the fixture directory")]
fn specification_a_fixture_name_never_leaves_the_fixture_directory() {
    fixture_path(Path::new("fixtures"), "../cases.json");
}

/// The CRL-045 cases rest on the engine's caps: each pads its bodies to sizes
/// chosen against `MAX_CRL_BYTES` and `MAX_TOTAL_BYTES`. If a cap moves, the
/// case would pass without testing what it says, so this fails instead.
#[test]
fn specification_the_crl_045_cases_rest_on_the_engines_caps() {
    use rssig_engine::retrieval::{MAX_CRL_BYTES, MAX_TOTAL_BYTES};
    let suite: Suite = serde_json::from_str(include_str!("cases.json")).unwrap();
    let bodies_of = |id: &str| scripted_answer_bodies(&suite, id);
    let pads =
        |id: &str| -> Vec<Option<usize>> { bodies_of(id).iter().map(|c| c.pad_to).collect() };
    // One body over the per-body cap.
    let [Some(over)] = pads("crl-045-body-over-the-size-cap-is-no-answer")[..] else {
        panic!("one padded body");
    };
    assert!(over > MAX_CRL_BYTES);
    // Two bodies over the per-body cap that, if they counted, would spend the
    // whole allowance before the last.
    let [Some(a), Some(b), None] =
        pads("crl-045-oversized-body-does-not-count-against-the-next")[..]
    else {
        panic!("two padded bodies, then one unpadded");
    };
    assert!(a > MAX_CRL_BYTES && b > MAX_CRL_BYTES);
    assert!(a + b >= MAX_TOTAL_BYTES);
    // Bodies within the per-body cap: four fit the allowance, the fifth does
    // not, and the room the four leave still takes the last. The allowance
    // is what the supplied roots (`--roots`) leave of the total.
    let id = "crl-045-over-allowance-body-does-not-count-against-the-next";
    let bodies = pads(id);
    let [Some(size), .., None] = bodies[..] else {
        panic!("padded bodies, then one unpadded");
    };
    assert_eq!(bodies.len(), 6);
    assert!(bodies[..5].iter().all(|&pad| pad == Some(size)));
    assert!(size <= MAX_CRL_BYTES);
    let fixtures = suite_fixtures(&suite);
    let allowance = scripted_request_allowance(&suite, id);
    let last_file = bodies_of(id).pop().unwrap().file;
    let last = std::fs::metadata(fixtures.join(last_file)).unwrap().len() as usize;
    assert!(4 * size + last <= allowance && 5 * size > allowance);
}

/// The bodies of the one scripted answer case `id` holds.
fn scripted_answer_bodies(suite: &Suite, id: &str) -> Vec<spec_suite::ScriptedCrl> {
    let case = suite.cases.iter().find(|c| c.id == id).unwrap();
    let answers = case.crl_certificate_responses.as_ref().unwrap();
    let [spec_suite::CertificateAnswer::Scripted(script)] =
        answers.values().collect::<Vec<_>>()[..]
    else {
        panic!("{id} scripts one answer");
    };
    script.crls.clone().unwrap()
}

/// The directory the suite's fixtures are in.
fn suite_fixtures(suite: &Suite) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(&suite.fixtures)
}

/// The byte allowance of the one request case `id` scripts an answer for:
/// what the supplied roots (`--roots`) leave of `MAX_TOTAL_BYTES`. Panics
/// when anything else could spend it: OS roots, a supplied CRL, or an answer
/// by URL.
fn scripted_request_allowance(suite: &Suite, id: &str) -> usize {
    let fixtures = suite_fixtures(suite);
    let case = suite.cases.iter().find(|c| c.id == id).unwrap();
    let roots: usize = case
        .command
        .windows(2)
        .filter(|pair| pair[0] == "--roots")
        .map(|pair| {
            let prefix = format!("{}/", suite.fixtures);
            let name = pair[1]
                .strip_prefix(&prefix)
                .unwrap_or_else(|| panic!("{id}: root {} is not under {prefix}", pair[1]));
            // The engine counts a root's DER, which is the file only when the
            // file is DER: a PEM root would be measured wrong.
            let bytes = std::fs::read(fixtures.join(name)).unwrap();
            assert_eq!(bytes.first(), Some(&0x30), "{id}: root {name} is DER");
            bytes.len()
        })
        .sum();
    assert!(roots > 0, "{id} supplies its roots with --roots");
    // OS roots would spend the allowance uncounted.
    assert!(
        case.command.iter().any(|arg| arg == "--no-system-roots"),
        "{id} passes --no-system-roots"
    );
    // A root given as `--roots=<path>` would go uncounted.
    assert!(
        !case.command.iter().any(|arg| arg.starts_with("--roots=")),
        "{id} gives each root as a separate argument"
    );
    // A CRL an earlier request loaded would spend it too (the allowance is
    // what the store does not yet hold); only the one scripted answer
    // returns bodies, and nothing is answered by URL.
    assert!(
        case.crl_responses.as_ref().is_none_or(|r| r.is_empty()),
        "{id} answers nothing by URL"
    );
    let answers = case.crl_certificate_responses.as_ref().unwrap();
    assert_eq!(answers.len(), 1, "{id} scripts one answer");
    // Supplied CRLs would spend the allowance too; the case has none.
    assert!(
        !case
            .command
            .iter()
            .any(|arg| arg == "--crl" || arg.starts_with("--crl=")),
        "{id} supplies no CRL"
    );
    rssig_engine::retrieval::MAX_TOTAL_BYTES - roots
}

/// The CRL-046 cases for a spent allowance rest on the engine's caps: their
/// bodies, each within `MAX_CRL_BYTES`, add up to exactly the request's
/// allowance, or to one byte less. If a cap or the roots move, the first
/// would no longer spend the allowance, or the second would, and each would
/// test the other's point, so this fails instead.
#[test]
fn specification_the_crl_046_allowance_cases_rest_on_the_engines_caps() {
    use rssig_engine::retrieval::MAX_CRL_BYTES;
    let suite: Suite = serde_json::from_str(include_str!("cases.json")).unwrap();
    for (id, short) in [
        (
            "crl-046-a-spent-byte-allowance-leaves-the-point-not-tried",
            0,
        ),
        (
            "crl-046-a-byte-short-of-the-allowance-leaves-the-point-to-the-last-body",
            1,
        ),
    ] {
        let pads: Vec<usize> = scripted_answer_bodies(&suite, id)
            .iter()
            .map(|c| c.pad_to.expect("every body is padded"))
            .collect();
        // Within the per-body cap, every body is accepted and spends bytes.
        // That no body loads as a CRL (CRL-034 would then leave the point
        // unused) is pinned by each case's four `invalid_crl` failures.
        assert!(pads.iter().all(|&pad| pad <= MAX_CRL_BYTES), "{id}");
        let allowance = scripted_request_allowance(&suite, id);
        assert_eq!(pads.iter().sum::<usize>() + short, allowance, "{id}");
    }
}

/// `pad_to` only pads: a size under the file's own would cut it, and the case
/// would then test a truncated CRL without saying so.
#[test]
fn specification_pad_to_never_shrinks_a_file() {
    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut suite: Suite = serde_json::from_str(include_str!("cases.json")).unwrap();
    let fixtures = parent.join(&suite.fixtures);
    let prefix = Path::new(&suite.fixtures);
    let case = suite
        .cases
        .iter_mut()
        .find(|c| c.id == "crl-045-body-over-the-size-cap-is-no-answer")
        .unwrap();
    assert!(
        execute(case, &parent, &fixtures, prefix)
            .failures
            .is_empty()
    );
    let answers = case.crl_certificate_responses.as_mut().unwrap();
    let Some(spec_suite::CertificateAnswer::Scripted(script)) = answers.values_mut().next() else {
        panic!("the case scripts its answer");
    };
    script.crls.as_mut().unwrap()[0].pad_to = Some(10);
    let result = execute(case, &parent, &fixtures, prefix);
    assert!(
        result
            .failures
            .iter()
            .any(|f| f.contains("pad_to 10 is shorter than good.crl")),
        "{:?}",
        result.failures
    );
    // Nor does an unvalidated pad_to over the limit allocate: it is named.
    let answers = case.crl_certificate_responses.as_mut().unwrap();
    let Some(spec_suite::CertificateAnswer::Scripted(script)) = answers.values_mut().next() else {
        panic!("the case scripts its answer");
    };
    script.crls.as_mut().unwrap()[0].pad_to = Some(usize::MAX);
    let result = execute(case, &parent, &fixtures, prefix);
    let expected = format!("has a pad_to outside 1 to {MAX_PAD_TO}");
    assert_eq!(
        result
            .failures
            .iter()
            .filter(|f| f.contains(&expected))
            .count(),
        1,
        "named once: {:?}",
        result.failures
    );
    // Nor do many bodies within the limit each: their total is bounded too.
    let answers = case.crl_certificate_responses.as_mut().unwrap();
    let Some(spec_suite::CertificateAnswer::Scripted(script)) = answers.values_mut().next() else {
        panic!("the case scripts its answer");
    };
    let body = script.crls.as_ref().unwrap()[0].clone();
    script.crls = Some(vec![
        spec_suite::ScriptedCrl {
            pad_to: Some(MAX_PAD_TO),
            ..body
        };
        MAX_PAD_TOTAL / MAX_PAD_TO + 2
    ]);
    // A body after the one past the total names a stale URL: it is still
    // checked.
    script.crls.as_mut().unwrap().last_mut().unwrap().url = Some("http://stale.invalid/".into());
    let result = execute(case, &parent, &fixtures, prefix);
    let expected = format!("the pad_to values of a response add up to at most {MAX_PAD_TOTAL}");
    assert!(
        result.failures.iter().any(|f| f.contains(&expected)),
        "{:?}",
        result.failures
    );
    assert!(
        result
            .failures
            .iter()
            .any(|f| f.contains("scripted url http://stale.invalid/ is not a listed point")),
        "{:?}",
        result.failures
    );
}

/// An answer keyed by a certificate nobody asks about is dead: the case would
/// go on to test the URL path, or nothing, and still look fine.
#[test]
fn specification_a_scripted_answer_nobody_asks_for_fails_the_case() {
    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut suite: Suite = serde_json::from_str(include_str!("cases.json")).unwrap();
    let fixtures = parent.join(&suite.fixtures);
    let prefix = Path::new(&suite.fixtures);
    let case = suite
        .cases
        .iter_mut()
        .find(|c| c.id == "crl-026-url-less-denial-answers-the-listed-point")
        .unwrap();
    assert!(
        execute(case, &parent, &fixtures, prefix)
            .failures
            .is_empty()
    );
    let answers = case.crl_certificate_responses.as_mut().unwrap();
    let (_, answer) = answers.pop_first().unwrap();
    let stale = "0".repeat(64);
    answers.insert(stale.clone(), answer);
    let result = execute(case, &parent, &fixtures, prefix);
    assert!(
        result.failures.iter().any(|f| f.contains(&format!(
            "the injected answer for certificate {stale} was never requested"
        ))),
        "{:?}",
        result.failures
    );
}

#[test]
fn specification_reads_the_files_of_scripted_answers() {
    let key = "a".repeat(64);
    let case: Case = serde_json::from_value(serde_json::json!({
        "id": "one", "command": ["--help"], "crl_responses": {"http://x/": "u.crl"},
        "crl_certificate_responses": {
            key.clone(): {"crls": [{"file": "a.crl"}, {"file": "../b.crl"}], "failures": [{"kind": "denied"}]}
        },
        "expect": {"exit_code": 0, "json": {"ok": true}}
    }))
    .unwrap();
    let files = case.files_read(Path::new("fixtures"));
    // Response bodies must exist; one outside the fixture directory is flagged.
    assert!(files.contains(&spec_suite::CaseFile::ResponseBody("u.crl".into())));
    assert!(files.contains(&spec_suite::CaseFile::ResponseBody("a.crl".into())));
    assert!(files.contains(&spec_suite::CaseFile::Outside("../b.crl".into())));
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
        .find(|c| c.id == "trust-empty-roots")
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
    assert!(parse(entry("Decided", "owner, PR #1", "acceptance")).is_ok());
    assert!(parse(entry("Observed", "—", "diagnostics")).is_ok());
    for (status, by, pins, error) in [
        ("Approved", "owner, PR #1", "acceptance", "status"),
        ("Decided", "—", "acceptance", "decided by"),
        ("Decided", "", "acceptance", "decided by"),
        ("Observed", "owner, PR #1", "acceptance", "decided by"),
        ("Decided", "owner, PR #1", "both", "pins"),
        // No tombstones: a dropped entry leaves its index in a reindex.
        ("Retired", "owner, PR #1", "acceptance", "status"),
        (
            "Superseded by CRL-002",
            "owner, PR #1",
            "acceptance",
            "status",
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
}
