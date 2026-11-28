//! No code attaches a typed error as an anyhow context.
//!
//! `VerificationError::from_internal` finds a `VerificationError` or a
//! `parse::Error` only as an entry of the error chain: the error itself or
//! another error's `source()`. anyhow keeps a value attached with
//! `.context(..)`, `.with_context(..)` or `anyhow::Error::msg(..)` beside the
//! chain, where a downcast of an entry does not find it, so a typed error
//! attached that way would be reported with the caller's default code (CLI
//! candidate rule `typed-layer` in `docs/cli.md`). Every such value in the
//! engine and the CLI is text; this check keeps it so, reading the sources
//! as tokens, so a comment or a string that names a call is not one, and
//! following each file they compile in from elsewhere.

use std::path::Path;

/// The sources checked: every `.rs` file under these directories of the
/// repository, the engine's and the application's.
const SOURCES: [&str; 2] = ["engine/src", "src"];

#[derive(Clone, Debug, PartialEq)]
enum Kind {
    Ident(String),
    Punct(char),
    /// A string literal of any form: plain, raw, byte or C.
    Str,
    /// A character, byte, number or lifetime: nothing the check matches.
    Other,
}

#[derive(Clone, Debug)]
struct Token {
    kind: Kind,
    start: usize,
    end: usize,
    line: usize,
}

/// The tokens of `source`, without whitespace and comments. Literal contents
/// are not tokens, so a call named in a string or a comment is not seen.
/// Panics on an unterminated comment or literal: the scan would be wrong.
fn tokens(source: &str) -> Vec<Token> {
    let bytes = source.as_bytes();
    let mut out = Vec::new();
    let mut at = 0;
    let newlines: Vec<usize> = source.match_indices('\n').map(|(i, _)| i).collect();
    let line = |at: usize| newlines.partition_point(|&n| n < at) + 1;
    let ident = |c: u8| c == b'_' || c.is_ascii_alphanumeric() || c >= 0x80;
    while at < bytes.len() {
        let start = at;
        let c = bytes[at];
        let kind = if c.is_ascii_whitespace() {
            at += 1;
            continue;
        } else if bytes[at..].starts_with(b"//") {
            at = bytes[at..]
                .iter()
                .position(|&b| b == b'\n')
                .map_or(bytes.len(), |n| at + n);
            continue;
        } else if bytes[at..].starts_with(b"/*") {
            // Bytes, not `str` slices: a comment may hold any character.
            let mut depth = 0;
            loop {
                assert!(
                    at < bytes.len(),
                    "unterminated block comment at line {}",
                    line(start)
                );
                if bytes[at..].starts_with(b"/*") {
                    depth += 1;
                    at += 2;
                } else if bytes[at..].starts_with(b"*/") {
                    depth -= 1;
                    at += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    at += 1;
                }
            }
            continue;
        } else if ident(c) {
            while at < bytes.len() && ident(bytes[at]) {
                at += 1;
            }
            let word = &source[start..at];
            let next = bytes.get(at).copied();
            if word == "r" && next == Some(b'#') && bytes.get(at + 1).is_some_and(|&b| ident(b)) {
                // A raw identifier, `r#name`, is the identifier `name`.
                let name = at + 1;
                at = name;
                while at < bytes.len() && ident(bytes[at]) {
                    at += 1;
                }
                Kind::Ident(source[name..at].to_owned())
            } else if matches!(word, "r" | "br" | "cr") && matches!(next, Some(b'"' | b'#')) {
                let hashes = source[at..].bytes().take_while(|&b| b == b'#').count();
                if bytes.get(at + hashes) == Some(&b'"') {
                    let close = format!("\"{}", "#".repeat(hashes));
                    let body = at + hashes + 1;
                    let end = source[body..].find(&close).unwrap_or_else(|| {
                        panic!("unterminated raw string at line {}", line(start))
                    });
                    at = body + end + close.len();
                    Kind::Str
                } else {
                    Kind::Ident(word.to_owned())
                }
            } else if matches!(word, "b" | "c") && next == Some(b'"') {
                at = string_end(source, at);
                Kind::Str
            } else if word == "b" && next == Some(b'\'') {
                at = char_end(source, at).expect("a byte literal");
                Kind::Other
            } else if c.is_ascii_digit() {
                Kind::Other
            } else {
                Kind::Ident(word.to_owned())
            }
        } else if c == b'"' {
            at = string_end(source, at);
            Kind::Str
        } else if c == b'\'' {
            match char_end(source, at) {
                Some(end) => at = end,
                // A lifetime or a label: the quote, then its name.
                None => at += 1,
            }
            Kind::Other
        } else {
            let c = source[at..].chars().next().unwrap();
            at += c.len_utf8();
            Kind::Punct(c)
        };
        out.push(Token {
            kind,
            start,
            end: at,
            line: line(start),
        });
    }
    out
}

/// The end of the string literal whose opening quote is at `at`.
fn string_end(source: &str, at: usize) -> usize {
    let bytes = source.as_bytes();
    let mut i = at + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    panic!("unterminated string at byte {at}")
}

/// The end of the character literal whose opening quote is at `at`, or
/// `None` when the quote begins a lifetime or a label.
fn char_end(source: &str, at: usize) -> Option<usize> {
    let rest = &source[at + 1..];
    if rest.starts_with('\\') {
        let close = rest[2..].find('\'')?;
        return Some(at + 1 + 2 + close + 1);
    }
    let c = rest.chars().next()?;
    rest[c.len_utf8()..]
        .starts_with('\'')
        .then(|| at + 1 + c.len_utf8() + 1)
}

/// The index of the token that closes the group opened at `open`.
fn close(tokens: &[Token], open: usize) -> usize {
    let mut depth = 0usize;
    for (i, token) in tokens.iter().enumerate().skip(open) {
        match token.kind {
            Kind::Punct('(' | '[' | '{') => depth += 1,
            Kind::Punct(')' | ']' | '}') => {
                depth -= 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => {}
        }
    }
    panic!("unclosed group at line {}", tokens[open].line)
}

fn is_ident(token: Option<&Token>, name: &str) -> bool {
    token.is_some_and(|t| t.kind == Kind::Ident(name.to_owned()))
}

fn is_punct(token: Option<&Token>, c: char) -> bool {
    token.is_some_and(|t| t.kind == Kind::Punct(c))
}

/// Whether `tokens` are one text expression: a string literal, a `format!`
/// call, or `String::clone(..)` or `String::from(..)`, which the compiler
/// keeps a `String`.
fn is_text(tokens: &[Token]) -> bool {
    let group = |open: usize| {
        tokens
            .get(open)
            .is_some_and(|t| matches!(t.kind, Kind::Punct('(' | '[' | '{')))
            && close(tokens, open) == tokens.len() - 1
    };
    match tokens {
        [only] => only.kind == Kind::Str,
        [name, bang, ..] if is_ident(Some(name), "format") && is_punct(Some(bang), '!') => group(2),
        [string, colon, other, call, ..]
            if is_ident(Some(string), "String")
                && is_punct(Some(colon), ':')
                && is_punct(Some(other), ':')
                && (is_ident(Some(call), "clone") || is_ident(Some(call), "from")) =>
        {
            is_punct(tokens.get(4), '(') && group(4)
        }
        _ => false,
    }
}

/// Whether `tokens` are a closure without parameters that returns text.
fn is_text_closure(tokens: &[Token]) -> bool {
    let tokens = match tokens.first() {
        Some(first) if is_ident(Some(first), "move") => &tokens[1..],
        _ => tokens,
    };
    let [bar, other, body @ ..] = tokens else {
        return false;
    };
    if !is_punct(Some(bar), '|') || !is_punct(Some(other), '|') {
        return false;
    }
    match body {
        [open, inner @ .., _] if is_punct(Some(open), '{') && close(body, 0) == body.len() - 1 => {
            is_text(inner)
        }
        _ => is_text(body),
    }
}

/// One call that hands anyhow a value: `.context(..)`, `.with_context(..)`
/// or `Error::msg(..)`.
struct Site {
    call: &'static str,
    argument: String,
    line: usize,
    text: bool,
}

/// The sites of `source` and the uses the check cannot judge: `context` or
/// `with_context` named as a path (`Context::context`, `Error::context`, a
/// qualified path), a `msg` path passed as a function, or a method call with
/// a turbofish. Any `::msg` path segment is taken for `Error::msg`, aliases
/// included. A `.context` not followed by
/// `(` or `::` is a field, not a call.
fn sites(source: &str) -> (Vec<Site>, Vec<String>) {
    let tokens = tokens(source);
    let mut sites = Vec::new();
    let mut unjudged = Vec::new();
    for i in 0..tokens.len() {
        let at = |n: usize| tokens.get(i + n);
        // A path segment, whatever comes before it: `Error::msg`, an alias of
        // `Error`, `<anyhow::Error>::msg` or `<_ as Context<..>>::context`.
        let path = is_punct(at(0), ':') && is_punct(at(1), ':');
        let call = if is_punct(at(0), '.') && is_ident(at(1), "context") {
            Some(("context", i + 2))
        } else if is_punct(at(0), '.') && is_ident(at(1), "with_context") {
            Some(("with_context", i + 2))
        } else if path && is_ident(at(2), "msg") {
            Some(("Error::msg", i + 3))
        } else if path && (is_ident(at(2), "context") || is_ident(at(2), "with_context")) {
            let before = i
                .checked_sub(1)
                .map_or("", |b| &source[tokens[b].start..tokens[b].end]);
            unjudged.push(format!(
                "line {}: `{before}::{}` named as a path",
                tokens[i].line,
                &source[tokens[i + 2].start..tokens[i + 2].end]
            ));
            None
        } else {
            None
        };
        let Some((call, open)) = call else { continue };
        if !is_punct(tokens.get(open), '(') {
            let turbofish = is_punct(tokens.get(open), ':') && is_punct(tokens.get(open + 1), ':');
            if call == "Error::msg" || turbofish {
                unjudged.push(format!(
                    "line {}: `{call}` named without its argument",
                    tokens[i].line
                ));
            }
            continue;
        }
        let end = close(&tokens, open);
        let mut argument = &tokens[open + 1..end];
        if argument.last().is_some_and(|t| t.kind == Kind::Punct(',')) {
            argument = &argument[..argument.len() - 1];
        }
        let text = match call {
            "with_context" => is_text_closure(argument),
            _ => is_text(argument),
        };
        let span = match (argument.first(), argument.last()) {
            (Some(first), Some(last)) => &source[first.start..last.end],
            _ => "",
        };
        sites.push(Site {
            call,
            argument: span.split_whitespace().collect::<Vec<_>>().join(" "),
            line: tokens[i].line,
            text,
        });
    }
    (sites, unjudged)
}

/// The problems of the sources: each site whose argument is not text and
/// each use the check cannot judge. `files` are `(path, source)` pairs; the
/// count of sites checked in each of [`SOURCES`] is returned beside them.
fn problems(files: &[(String, String)]) -> (Vec<String>, Vec<usize>) {
    let mut problems = Vec::new();
    let mut counts = vec![0; SOURCES.len()];
    for (path, source) in files {
        let (sites, unjudged) = sites(source);
        for unjudged in unjudged {
            problems.push(format!("{path}: {unjudged}"));
        }
        if let Some(n) = SOURCES
            .iter()
            .position(|dir| path.starts_with(&format!("{dir}/")))
        {
            counts[n] += sites.len();
        }
        for site in sites.iter().filter(|site| !site.text) {
            problems.push(format!(
                "{path}:{}: `{}` takes `{}`, which this check cannot see is text; \
                 from_internal does not see a typed error attached this way \
                 (docs/cli.md, `typed-layer`): attach a string literal, `format!`, \
                 `String::clone(..)` or `String::from(..)`",
                site.line, site.call, site.argument
            ));
        }
    }
    (problems, counts)
}

/// Every `.rs` file under `dir`, as a path relative to `root` with `/`
/// separators, and its contents, in path order.
fn rust_files(root: &Path, dir: &str, out: &mut Vec<(String, String)>) {
    let mut entries: Vec<_> = std::fs::read_dir(root.join(dir))
        .unwrap_or_else(|e| panic!("{dir}: {e}"))
        .map(|entry| entry.unwrap())
        .collect();
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .expect("a UTF-8 source name");
        let path = format!("{dir}/{name}");
        let kind = entry.file_type().unwrap();
        // A file whose name starts with `.` is no module `mod name;` loads
        // (an identifier has no dot), so by-products such as an editor's
        // `.#name.rs` lock link or a macOS `._name.rs` are not read; a
        // `#[path]` or `include!` naming one is followed as an include.
        let directory = std::fs::metadata(root.join(&path)).is_ok_and(|m| m.is_dir());
        if name.starts_with('.') && !directory {
            continue;
        }
        // A link the scan would read could hide sources from it, or loop it.
        assert!(!kind.is_symlink(), "{path} is a symbolic link");
        if kind.is_dir() {
            rust_files(root, &path, out);
        } else if name.ends_with(".rs") {
            let source = std::fs::read_to_string(root.join(&path)).unwrap();
            out.push((path, source));
        }
    }
}

/// The files `source` compiles in from another path: the string of each
/// `#[path = "..."]` attribute and `include!("...")` call; then the names of
/// its `mod name;` declarations that have no `path` attribute. Panics on
/// another form of argument, which the scan could not follow.
fn included(source: &str) -> (Vec<String>, Vec<String>) {
    let tokens = tokens(source);
    let literal = |token: &Token| {
        let text = &source[token.start..token.end];
        assert!(
            token.kind == Kind::Str && text.starts_with('"') && !text.contains('\\'),
            "line {}: an included path the scan cannot follow: {text}",
            token.line
        );
        text[1..text.len() - 1].to_owned()
    };
    let mut out = Vec::new();
    let mut modules = Vec::new();
    // Whether a `path` attribute was read since the last `mod`.
    let mut pending = false;
    // The closing braces of the inline `mod name { .. }` blocks around `i`:
    // rustc resolves a `#[path]` there from another directory.
    let mut inline: Vec<usize> = Vec::new();
    for i in 0..tokens.len() {
        let at = |n: usize| tokens.get(i + n);
        inline.retain(|&end| end > i);
        if is_ident(at(0), "mod") && at(1).is_some_and(|t| matches!(t.kind, Kind::Ident(_))) {
            if is_punct(at(2), '{') {
                // There a `path` names a directory for the modules inside.
                assert!(
                    !pending,
                    "line {}: a `path` attribute on an inline module, which the scan does not follow",
                    tokens[i].line
                );
                inline.push(close(&tokens, i + 2));
            } else if is_punct(at(2), ';') && !pending {
                modules.push(source[tokens[i + 1].start..tokens[i + 1].end].to_owned());
            }
            pending = false;
        }
        let mut path = |value: usize| {
            assert!(
                inline.is_empty(),
                "line {}: a `path` attribute inside an inline module, which the scan does not resolve",
                tokens[value].line
            );
            out.push(literal(&tokens[value]));
            pending = true;
        };
        if is_punct(at(0), '#') && is_punct(at(1), '[') {
            if is_ident(at(2), "path") && is_punct(at(3), '=') {
                path(i + 4);
            } else if is_ident(at(2), "cfg_attr") && is_punct(at(3), '(') {
                // `#[cfg_attr(predicate, .., path = "..")]`: a top-level
                // argument after the predicate.
                let end = close(&tokens, i + 3);
                let mut depth = 0usize;
                for j in i + 4..end {
                    match tokens[j].kind {
                        Kind::Punct('(' | '[' | '{') => depth += 1,
                        Kind::Punct(')' | ']' | '}') => depth -= 1,
                        Kind::Punct(',')
                            if depth == 0
                                && is_ident(tokens.get(j + 1), "path")
                                && is_punct(tokens.get(j + 2), '=') =>
                        {
                            path(j + 3);
                        }
                        Kind::Punct(',')
                            if depth == 0 && is_ident(tokens.get(j + 1), "cfg_attr") =>
                        {
                            panic!(
                                "line {}: a nested `cfg_attr`, which the scan does not follow",
                                tokens[j].line
                            )
                        }
                        _ => {}
                    }
                }
            }
        } else if is_ident(at(0), "include")
            && is_punct(at(1), '!')
            && at(2).is_some_and(|t| matches!(t.kind, Kind::Punct('(' | '[' | '{')))
        {
            out.push(literal(&tokens[i + 3]));
        }
    }
    (out, modules)
}

/// `path` with its `.` and `..` components applied, without reading the file
/// system.
fn normalized(path: &Path) -> std::path::PathBuf {
    let mut out = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

/// Every `.rs` file under [`SOURCES`], then each file one of them compiles in
/// from elsewhere (`#[path]`, `include!`), resolved from the including file's
/// directory, as `(path relative to root, contents)`.
fn scanned_files(root: &Path) -> Vec<(String, String)> {
    let mut files = Vec::new();
    for dir in SOURCES {
        let kind = std::fs::symlink_metadata(root.join(dir))
            .unwrap()
            .file_type();
        assert!(!kind.is_symlink(), "{dir} is a symbolic link");
        rust_files(root, dir, &mut files);
    }
    let root = root.canonicalize().unwrap();
    let mut next = 0;
    while next < files.len() {
        let (path, source) = files[next].clone();
        next += 1;
        let dir = root.join(&path).parent().unwrap().to_path_buf();
        let (targets, modules) = included(&source);
        // A file under SOURCES finds its `mod name;` files there; one compiled
        // in from elsewhere would find them where the walk does not look.
        let outside = !SOURCES
            .iter()
            .any(|dir| path.starts_with(&format!("{dir}/")));
        if let Some(module) = modules.first().filter(|_| outside) {
            panic!(
                "{path}, compiled in from outside {SOURCES:?}, declares `mod {module};`, which the scan does not follow"
            );
        }
        for target in targets {
            let named = dir.join(&target);
            let kind = std::fs::symlink_metadata(&named)
                .unwrap_or_else(|e| panic!("{path} includes {target}, which does not resolve: {e}"))
                .file_type();
            assert!(
                !kind.is_symlink(),
                "{path} includes {target}, a symbolic link"
            );
            let resolved = dir.join(&target).canonicalize().unwrap_or_else(|e| {
                panic!("{path} includes {target}, which does not resolve: {e}")
            });
            // A directory on the way that is a link resolves elsewhere.
            assert_eq!(
                resolved,
                normalized(&named),
                "{path} includes {target} through a symbolic link"
            );
            let relative = resolved
                .strip_prefix(&root)
                .unwrap_or_else(|_| panic!("{path} includes {target}, outside the repository"))
                .to_str()
                .expect("a UTF-8 path")
                .replace('\\', "/");
            if !files.iter().any(|(known, _)| *known == relative) {
                let source = std::fs::read_to_string(&resolved).unwrap();
                files.push((relative, source));
            }
        }
    }
    files
}

#[test]
fn no_code_attaches_a_typed_error_as_an_anyhow_context() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let files = scanned_files(root);
    // `src/lib.rs` compiles in `tests/common/crosscheck.rs`: a scan that no
    // longer follows `#[path]` fails here.
    assert!(
        files
            .iter()
            .any(|(path, _)| path == "tests/common/crosscheck.rs"),
        "the scan did not follow src/lib.rs's #[path]"
    );
    let (problems, counts) = problems(&files);
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    // A scan that read nothing, or matched nothing, would pass above.
    for (dir, count) in SOURCES.iter().zip(counts) {
        assert!(
            count > 0,
            "no anyhow context or message site found under {dir}"
        );
    }
}

fn file(source: &str) -> Vec<(String, String)> {
    vec![("engine/src/x.rs".to_owned(), source.to_owned())]
}

/// The problems of one file.
fn problems_of(source: &str) -> Vec<String> {
    problems(&file(source)).0
}

#[test]
fn text_contexts_pass_the_typed_text_check() {
    let source = r##"
        fn f<'a>(x: &'a str) -> Result<()> {
            let c = '(';
            let q = '\'';
            let b = b')';
            // .context(typed) in a comment is no call.
            /* .context(typed) /* nested */ */
            /* see RFC 5280 — section 4.2, café */
            let s = ".context(typed)";
            let r = r#"".with_context(|| typed)""#;
            run().context("literal")?;
            run().context(r"raw")?;
            run().context(format!("{x}"))?;
            run().with_context(|| format!("{x}, {}", c))?;
            run().with_context(move || "text")?;
            run().with_context(|| { format!("{x}") })?;
            run().context(String::clone(message))?;
            run().with_context(|| String::from(name))?;
            run().context(
                "a trailing comma",
            )?;
            'label: loop { break 'label; }
            let field = options.context;
            let other = options.with_context.len();
            Err(anyhow::Error::msg("text"))
        }
    "##;
    assert_eq!(problems_of(source), Vec::<String>::new());
    assert_eq!(sites(source).0.len(), 10);
}

#[test]
fn typed_contexts_fail_the_typed_text_check() {
    for (source, call, argument) in [
        ("run().context(typed)", "context", "typed"),
        ("run().context(typed.clone())", "context", "typed.clone()"),
        (
            "merged.context(message.clone())",
            "context",
            "message.clone()",
        ),
        (
            "run().context(String::clone(message).len())",
            "context",
            "String::clone(message).len()",
        ),
        (
            "run().context(Other::from(typed))",
            "context",
            "Other::from(typed)",
        ),
        (
            "error.context(VerificationError::new(code, stage, \"m\"))",
            "context",
            "VerificationError::new(code, stage, \"m\")",
        ),
        ("run().with_context(|| typed)", "with_context", "|| typed"),
        ("run().with_context(make)", "with_context", "make"),
        (
            "run().with_context(|| format!(\"{x}\").len())",
            "with_context",
            "|| format!(\"{x}\").len()",
        ),
        ("anyhow::Error::msg(parsed)", "Error::msg", "parsed"),
        ("<anyhow::Error>::msg(parsed)", "Error::msg", "parsed"),
        (
            "use anyhow::Error as E; E::msg(parsed)",
            "Error::msg",
            "parsed",
        ),
        ("run().r#context(typed)", "context", "typed"),
        ("run().r#with_context(make)", "with_context", "make"),
        ("run().context(\"a\" , typed)", "context", "\"a\" , typed"),
    ] {
        let problems = problems_of(source);
        assert_eq!(problems.len(), 1, "{source}: {problems:?}");
        assert!(
            problems[0].contains(&format!("`{call}` takes `{argument}`")),
            "{source}: {problems:?}"
        );
    }
    for (source, problem) in [
        (
            "run().map_err(anyhow::Error::msg)",
            "`Error::msg` named without",
        ),
        (
            "anyhow::Context::context(run(), typed)",
            "`Context::context` named as",
        ),
        (
            "anyhow::Error::context(error, typed)",
            "`Error::context` named as",
        ),
        (
            "run().context::<VerificationError>(typed)",
            "`context` named without",
        ),
        (
            "<_ as anyhow::Context<_, _>>::context(run(), typed)",
            "`>::context` named as",
        ),
        (
            "use anyhow::Error as E; let f = E::msg;",
            "`Error::msg` named without",
        ),
    ] {
        let problems = problems_of(source);
        assert_eq!(problems.len(), 1, "{source}: {problems:?}");
        assert!(problems[0].contains(problem), "{source}: {problems:?}");
    }
}

#[test]
fn the_scan_follows_path_attributes_and_includes() {
    assert_eq!(
        included(
            "#[path = \"a/b.rs\"] mod b; include!(\"c.rs\"); // include!(\"d.rs\")\n#[cfg(test)] mod e;"
        ),
        (
            vec!["a/b.rs".to_owned(), "c.rs".to_owned()],
            vec!["e".to_owned()]
        )
    );
    assert_eq!(
        included(
            "include! { \"a.rs\" } include![\"b.rs\"] #[cfg_attr(test, path = \"c.rs\")] mod c;"
        )
        .0,
        ["a.rs", "b.rs", "c.rs"]
    );
    // Another attribute's `path` key compiles nothing in, and a module that
    // closed is no longer around the attribute after it.
    assert_eq!(
        included(
            "#[arg(path = crate::x)] #[serde(path = \"y\")] struct S; mod m { } #[path = \"z.rs\"] mod z; mod S2;"
        ),
        (vec!["z.rs".to_owned()], vec!["S2".to_owned()])
    );
    for broken in [
        "include!(concat!(\"a\", \"b\"))",
        "#[path = r\"a.rs\"] mod a;",
        "mod tests { #[path = \"a.rs\"] mod a; }",
        "mod tests { #[cfg_attr(test, path = \"a.rs\")] mod a; }",
        "#[cfg_attr(a, cfg_attr(b, path = \"x.rs\"))] mod x;",
        "#[path = \"../extra\"] mod m { mod y; }",
    ] {
        assert!(
            std::panic::catch_unwind(|| included(broken)).is_err(),
            "{broken}"
        );
    }
}

#[test]
fn the_walk_skips_dot_files_and_reports_a_linked_source() {
    let scratch = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("repository-typed-text-{}", std::process::id()));
    let _remove = super::Scratch::new(&scratch);
    std::fs::create_dir_all(scratch.join("src/.hidden")).unwrap();
    std::fs::write(scratch.join("src/a.rs"), "x.context(\"a\");").unwrap();
    std::fs::write(scratch.join("src/._a.rs"), [0xff, 0xfe]).unwrap();
    std::fs::write(scratch.join("src/.hidden/b.rs"), "x.context(\"b\");").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("user@host.1234", scratch.join("src/.#a.rs")).unwrap();
    let mut files = Vec::new();
    rust_files(&scratch, "src", &mut files);
    let paths: Vec<_> = files.iter().map(|(path, _)| path.as_str()).collect();
    // A dot file is skipped; a dot directory is still walked.
    assert_eq!(paths, ["src/.hidden/b.rs", "src/a.rs"]);
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(scratch.join("src/a.rs"), scratch.join("src/c.rs")).unwrap();
        let linked = std::panic::catch_unwind(|| rust_files(&scratch, "src", &mut Vec::new()));
        assert!(linked.is_err());
    }
}

#[test]
fn normalized_applies_dot_components_only() {
    assert_eq!(
        normalized(Path::new("/r/src/./a/../../tests/x.rs")),
        Path::new("/r/tests/x.rs")
    );
}
