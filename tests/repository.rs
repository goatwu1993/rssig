//! Repository checks: committed files that no product code reads, checked so
//! that a malformed one fails `cargo test --locked` instead of passing
//! unnoticed. See `docs/testing.md`, "Repository checks".
//!
//! YAML is parsed with `yaml-rust2`, a real YAML 1.2 parser, never matched
//! with a pattern: a file that a pattern accepts can still be invalid YAML.

#[path = "common/by_product.rs"]
mod by_product;
#[path = "common/crosscheck.rs"]
mod crosscheck;

use by_product::local_by_product;
use std::{collections::BTreeSet, path::Path};
use yaml_rust2::{Yaml, YamlLoader};

/// The directory of the project skills, relative to the repository root.
const SKILLS: &str = ".claude/skills";

/// The file that defines a skill, directly inside its directory.
const SKILL_FILE: &str = "SKILL.md";

/// The YAML frontmatter of a Markdown file: the lines between an opening `---`
/// line, which must be the file's first line, and the next `---` line, which
/// may end the file. CRLF line endings, which a Windows checkout with
/// `core.autocrlf` produces from the committed LF, are read as LF; nothing
/// else is relaxed, so the check is no looser than the committed file.
fn frontmatter(text: &str) -> Result<String, String> {
    // One line ending: `\n`, or `\r\n`, never more; a `\r` alone is not one.
    let content = |line: &str| -> String {
        match line.strip_suffix('\n') {
            Some(line) => line.strip_suffix('\r').unwrap_or(line),
            None => line,
        }
        .to_owned()
    };
    // Whether `line` is a `---` delimiter; a near miss is a problem.
    let delimiter = |line: &str| -> Result<bool, String> {
        if content(line) == "---" {
            Ok(true)
        } else if line.trim_end() == "---" {
            Err("has a `---` line with trailing whitespace or a stray `\\r`".to_owned())
        } else {
            Ok(false)
        }
    };
    let mut lines = text.split_inclusive('\n');
    match lines.next().map(delimiter) {
        Some(Ok(true)) => {}
        Some(Err(problem)) => return Err(problem),
        _ => return Err("does not start with a `---` frontmatter line".to_owned()),
    }
    let mut yaml = String::new();
    for line in lines {
        if delimiter(line)? {
            return Ok(yaml);
        }
        yaml.push_str(&content(line));
        yaml.push('\n');
    }
    Err("has no closing `---` frontmatter line".to_owned())
}

/// The problems of one skill's `SKILL.md`, read from the directory `name`:
/// its frontmatter must be one YAML mapping with a string `name` equal to the
/// directory's name and a nonblank string `description`.
fn skill_problems(name: &str, text: &str) -> Vec<String> {
    let subject = format!("{SKILLS}/{name}/{SKILL_FILE}");
    let yaml = match frontmatter(text) {
        Ok(yaml) => yaml,
        Err(problem) => return vec![format!("{subject} {problem}")],
    };
    let documents = match YamlLoader::load_from_str(&yaml) {
        Ok(documents) => documents,
        Err(error) => return vec![format!("{subject} frontmatter is not valid YAML: {error}")],
    };
    let [document] = documents.as_slice() else {
        return vec![format!(
            "{subject} frontmatter holds {} YAML documents, not one",
            documents.len()
        )];
    };
    let Yaml::Hash(fields) = document else {
        return vec![format!("{subject} frontmatter is not a YAML mapping")];
    };
    let field = |key: &str| fields.get(&Yaml::String(key.to_owned()));
    let mut problems = Vec::new();
    match field("name") {
        None => problems.push(format!("{subject} has no `name`")),
        Some(Yaml::String(value)) if value == name => {}
        Some(Yaml::String(value)) => problems.push(format!(
            "{subject} has `name` {value:?}, not its directory's name {name:?}"
        )),
        Some(Yaml::Null) => problems.push(format!("{subject} has a blank `name`")),
        Some(_) => problems.push(format!("{subject} has a `name` that is not a string")),
    }
    match field("description") {
        None => problems.push(format!("{subject} has no `description`")),
        Some(Yaml::String(value)) if !value.trim().is_empty() => {}
        Some(Yaml::String(_) | Yaml::Null) => {
            problems.push(format!("{subject} has a blank `description`"))
        }
        Some(_) => problems.push(format!(
            "{subject} has a `description` that is not a string"
        )),
    }
    problems
}

/// Checks every entry of `.claude/skills/` but by-product regular files
/// ([`local_by_product`]):
/// each is a directory holding a `SKILL.md` whose frontmatter passes
/// [`skill_problems`]. Returns the names of the skills whose `SKILL.md` was
/// read and the problems found.
fn committed_skills(root: &Path) -> (BTreeSet<String>, Vec<String>) {
    let directory = root.join(SKILLS);
    let mut names = BTreeSet::new();
    let mut problems = Vec::new();
    // Neither `.claude` nor `.claude/skills` may be a symbolic link.
    let mut prefix = root.to_path_buf();
    for component in Path::new(SKILLS).components() {
        prefix.push(component);
        let relative = prefix.strip_prefix(root).unwrap().display().to_string();
        match std::fs::symlink_metadata(&prefix) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return (names, vec![format!("{relative} is a symbolic link")]);
            }
            Ok(_) => return (names, vec![format!("{relative} is not a directory")]),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return (names, vec![format!("{relative} is not a directory")]);
            }
            Err(error) => return (names, vec![format!("{relative}: {error}")]),
        }
    }
    let entries = match std::fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) => return (names, vec![format!("{SKILLS}: {error}")]),
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                problems.push(format!("{SKILLS}: {error}"));
                continue;
            }
        };
        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            Err(name) => {
                problems.push(format!("{SKILLS}/{name:?} is not a UTF-8 name"));
                continue;
            }
        };
        // As in `tests/manifest.rs`, the entry's own type: a symbolic link
        // is never followed, so it is neither skipped nor a skill directory.
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) => {
                problems.push(format!("{SKILLS}/{name}: {error}"));
                continue;
            }
        };
        let path = entry.path();
        if file_type.is_file() && local_by_product(&name) {
            continue;
        }
        if file_type.is_symlink() {
            problems.push(format!("{SKILLS}/{name} is a symbolic link"));
            continue;
        }
        if !file_type.is_dir() {
            problems.push(format!("{SKILLS}/{name} is not a skill directory"));
            continue;
        }
        // Listed by its exact name: a case-insensitive file system (macOS)
        // would otherwise open `skill.md` as `SKILL.md`.
        let listed = std::fs::read_dir(&path).and_then(|entries| {
            for entry in entries {
                let entry = entry?;
                if entry.file_name() == SKILL_FILE {
                    return entry.file_type().map(Some);
                }
            }
            Ok(None)
        });
        match listed {
            Ok(Some(file_type)) if file_type.is_file() => {}
            Ok(Some(file_type)) if file_type.is_symlink() => {
                problems.push(format!("{SKILLS}/{name}/{SKILL_FILE} is a symbolic link"));
                continue;
            }
            Ok(Some(_)) => {
                problems.push(format!(
                    "{SKILLS}/{name}/{SKILL_FILE} is not a regular file"
                ));
                continue;
            }
            Ok(None) => {
                problems.push(format!("{SKILLS}/{name} has no {SKILL_FILE}"));
                continue;
            }
            Err(error) => {
                problems.push(format!("{SKILLS}/{name}: {error}"));
                continue;
            }
        }
        match std::fs::read_to_string(path.join(SKILL_FILE)) {
            Ok(text) => {
                problems.extend(skill_problems(&name, &text));
                names.insert(name);
            }
            Err(error) => problems.push(format!("{SKILLS}/{name}/{SKILL_FILE}: {error}")),
        }
    }
    (names, problems)
}

/// Whether `after` starts with the word `skill` or `skills`, in any case,
/// after any whitespace (a line break too), and not with a longer word.
fn followed_by_the_word_skill(after: &str) -> bool {
    let word: String = after
        .trim_start()
        .chars()
        .take_while(|c| c.is_alphanumeric() || "_-".contains(*c))
        .collect();
    word.eq_ignore_ascii_case("skill") || word.eq_ignore_ascii_case("skills")
}

/// The skills `text` (AGENTS.md) names: a backticked `name` followed by the
/// word `skill`, or a backticked `/name` command. AGENTS.md writes `/name`
/// only for a project skill, so a built-in command written that way fails the
/// check loudly rather than passing. Unbalanced backticks or a code fence would shift the spans, so
/// they fail the check instead of hiding names.
fn named_skills(text: &str) -> BTreeSet<String> {
    assert!(
        !text.contains("``"),
        "AGENTS.md has a code fence or a double backtick"
    );
    assert!(!text.contains("\\`"), "AGENTS.md has an escaped backtick");
    assert!(
        text.matches('`').count().is_multiple_of(2),
        "AGENTS.md has an unbalanced backtick"
    );
    // Any one word: the name format is not this scan's to judge.
    let skill_name =
        |name: &str| !name.is_empty() && !name.contains(|c: char| c.is_whitespace() || c == '/');
    let spans: Vec<&str> = text.split('`').collect();
    let mut names = BTreeSet::new();
    for (index, span) in spans.iter().enumerate().skip(1).step_by(2) {
        // A command is its first word: `/review-loop --fix` names review-loop.
        if let Some(command) = span.strip_prefix('/') {
            let command = command.split_whitespace().next().unwrap_or("");
            assert!(
                skill_name(command),
                "AGENTS.md names a command `{span}` with no name"
            );
            names.insert(command.to_owned());
        } else if skill_name(span)
            && spans
                .get(index + 1)
                .is_some_and(|after| followed_by_the_word_skill(after))
        {
            names.insert((*span).to_owned());
            // A list before the word: "the `a`, `b` and `c` skills".
            let mut at = index;
            while at >= 3
                && matches!(spans[at - 1].trim(), "," | "and" | "or" | ", and" | ", or")
                && skill_name(spans[at - 2])
            {
                names.insert(spans[at - 2].to_owned());
                at -= 2;
            }
        }
    }
    names
}

#[test]
fn project_skills_have_a_name_and_a_description() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let (names, problems) = committed_skills(root);
    assert!(problems.is_empty(), "{}", problems.join("\n"));
    // An empty or unread directory would pass the loop above: every skill
    // AGENTS.md names must be among those checked.
    let named = named_skills(&std::fs::read_to_string(root.join("AGENTS.md")).unwrap());
    // The skills AGENTS.md names today: a rewording the scan no longer sees
    // fails here instead of leaving a skill unchecked.
    for skill in ["owner-question", "pr-maintenance", "review-loop"] {
        assert!(
            named.contains(skill),
            "AGENTS.md no longer names {skill}: {named:?}"
        );
    }
    for skill in &named {
        assert!(
            names.contains(skill),
            "AGENTS.md names {skill}, which {SKILLS} does not define"
        );
    }
}

#[test]
fn agents_md_names_a_skill_in_backticks_or_as_a_command() {
    for broken in [
        "Ask the `owner-question skill.",
        "```\n`review-loop` skill\n```",
        "Use ``a`b`` then `review-loop` skill.",
        "Use \\`x\\` then `review-loop` skill.",
        "Run `/` or `/ --all`.",
    ] {
        assert!(
            std::panic::catch_unwind(|| named_skills(broken)).is_err(),
            "{broken}"
        );
    }
    assert_eq!(
        named_skills(
            "Ask with the `owner-question` skill. `/review-loop` runs. Keep it with the \
             `pr-maintenance`\n  skill. `/fix-it --all` runs. `cargo test` and `docs/x.md` skill and \
             `y` skill_z and `z` skillset are not; `owner_question` skill is, for DOC-T015 to \
             judge, and so are the `a` and `b` Skills and the `c`, `d`, or `e` skills."
        ),
        BTreeSet::from(
            [
                "a",
                "b",
                "c",
                "d",
                "e",
                "fix-it",
                "owner-question",
                "owner_question",
                "pr-maintenance",
                "review-loop"
            ]
            .map(String::from)
        )
    );
}

/// A `SKILL.md` for the directory `review-loop` with `fields` as its
/// frontmatter.
fn skill(fields: &str) -> String {
    format!("---\n{fields}---\n\nBody.\n")
}

#[test]
fn skill_frontmatter_accepts_plain_folded_and_quoted_strings() {
    for fields in [
        "name: review-loop\ndescription: Review a PR.\n",
        "name: \"review-loop\"\ndescription: >-\n  Review a PR: fix every\n  valid finding.\n",
        "name: review-loop\ndescription: \"Review a PR: fix every valid finding.\"\n",
    ] {
        assert_eq!(
            skill_problems("review-loop", &skill(fields)),
            Vec::<String>::new(),
            "{fields}"
        );
    }
}

#[test]
fn skill_frontmatter_must_be_valid_yaml() {
    // An unquoted ": " inside a plain scalar: the case that once passed
    // unnoticed.
    let problems = skill_problems(
        "review-loop",
        &skill("name: review-loop\ndescription: Use when: a PR is pushed.\n"),
    );
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("is not valid YAML"), "{problems:?}");

    let problems = skill_problems(
        "review-loop",
        &skill("name: review-loop\nname: review-loop\ndescription: Review.\n"),
    );
    assert_eq!(problems.len(), 1, "{problems:?}");
    assert!(problems[0].contains("is not valid YAML"), "{problems:?}");
}

#[test]
fn skill_frontmatter_reads_crlf_and_a_closing_last_line() {
    for text in [
        "---\r\nname: review-loop\r\ndescription: Review.\r\n---\r\nBody.\r\n",
        "---\nname: review-loop\ndescription: Review.\n---",
    ] {
        assert_eq!(
            skill_problems("review-loop", text),
            Vec::<String>::new(),
            "{text:?}"
        );
    }
    // Nothing else is relaxed: a byte order mark is no `---` line, and a
    // delimiter with trailing whitespace or a stray `\r` is a near miss.
    let subject = format!("{SKILLS}/review-loop/{SKILL_FILE}");
    let near_miss = "has a `---` line with trailing whitespace or a stray `\\r`";
    for (text, problem) in [
        (
            "\u{feff}---\nname: review-loop\ndescription: Review.\n---\n",
            "does not start with a `---` frontmatter line",
        ),
        (
            "--- \nname: review-loop\ndescription: Review.\n---\n",
            near_miss,
        ),
        (
            "---\r\r\nname: review-loop\ndescription: Review.\n---\n",
            near_miss,
        ),
        (
            "---\nname: review-loop\ndescription: Review.\n---\r",
            near_miss,
        ),
    ] {
        assert_eq!(
            skill_problems("review-loop", text),
            [format!("{subject} {problem}")],
            "{text:?}"
        );
    }
}

#[test]
fn skill_frontmatter_must_open_and_close() {
    let subject = "rssig-skill";
    for (text, problem) in [
        (
            "name: x\n---\n",
            "does not start with a `---` frontmatter line",
        ),
        (
            "\n---\nname: x\n---\n",
            "does not start with a `---` frontmatter line",
        ),
        (
            "---\nname: x\ndescription: y\n",
            "has no closing `---` frontmatter line",
        ),
        (
            "---\nname: x\n--- \nBody.\n---\n",
            "has a `---` line with trailing whitespace or a stray `\\r`",
        ),
    ] {
        assert_eq!(
            skill_problems(subject, text),
            [format!("{SKILLS}/{subject}/{SKILL_FILE} {problem}")],
            "{text:?}"
        );
    }
}

#[test]
fn skill_frontmatter_is_one_mapping() {
    let subject = format!("{SKILLS}/review-loop/{SKILL_FILE}");
    assert_eq!(
        skill_problems("review-loop", &skill("- name\n- description\n")),
        [format!("{subject} frontmatter is not a YAML mapping")]
    );
    assert_eq!(
        skill_problems("review-loop", "---\n---\n"),
        [format!(
            "{subject} frontmatter holds 0 YAML documents, not one"
        )]
    );
    assert_eq!(
        skill_problems("review-loop", &skill("name: review-loop\n...\n--- other\n")),
        [format!(
            "{subject} frontmatter holds 2 YAML documents, not one"
        )]
    );
}

#[test]
fn skill_frontmatter_names_its_directory_and_describes_itself() {
    let subject = format!("{SKILLS}/review-loop/{SKILL_FILE}");
    for (fields, expected) in [
        (
            "description: Review.\n",
            vec![format!("{subject} has no `name`")],
        ),
        (
            "name: code-review\ndescription: Review.\n",
            vec![format!(
                "{subject} has `name` \"code-review\", not its directory's name \"review-loop\""
            )],
        ),
        (
            "name:\ndescription: Review.\n",
            vec![format!("{subject} has a blank `name`")],
        ),
        (
            "name: [review-loop]\ndescription: Review.\n",
            vec![format!("{subject} has a `name` that is not a string")],
        ),
        (
            "name: review-loop\n",
            vec![format!("{subject} has no `description`")],
        ),
        (
            "name: review-loop\ndescription: \"  \"\n",
            vec![format!("{subject} has a blank `description`")],
        ),
        (
            "name: review-loop\ndescription:\n",
            vec![format!("{subject} has a blank `description`")],
        ),
        (
            "name: review-loop\ndescription: 10\n",
            vec![format!(
                "{subject} has a `description` that is not a string"
            )],
        ),
        (
            "other: x\n",
            vec![
                format!("{subject} has no `name`"),
                format!("{subject} has no `description`"),
            ],
        ),
    ] {
        assert_eq!(
            skill_problems("review-loop", &skill(fields)),
            expected,
            "{fields}"
        );
    }
}

/// A scratch directory under `CARGO_TARGET_TMPDIR`, created empty and
/// removed on every path, a failed assertion too.
struct Scratch<'a>(&'a Path);

impl<'a> Scratch<'a> {
    fn new(path: &'a Path) -> Self {
        let _ = std::fs::remove_dir_all(path);
        std::fs::create_dir_all(path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch<'_> {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.0);
    }
}

#[test]
fn committed_skills_needs_real_directories_down_to_the_skills() {
    let scratch = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("repository-skill-root-{}", std::process::id()));
    let _remove = Scratch::new(&scratch);
    let (names, problems) = committed_skills(&scratch);
    assert!(names.is_empty());
    assert_eq!(problems, [".claude is not a directory"]);
    #[cfg(unix)]
    {
        let real = scratch.join("real");
        std::fs::create_dir_all(real.join("skills")).unwrap();
        std::os::unix::fs::symlink(&real, scratch.join(".claude")).unwrap();
        assert_eq!(committed_skills(&scratch).1, [".claude is a symbolic link"]);
        // A real `.claude` whose `skills` is a symbolic link.
        std::fs::remove_file(scratch.join(".claude")).unwrap();
        std::fs::create_dir_all(scratch.join(".claude")).unwrap();
        std::os::unix::fs::symlink(real.join("skills"), scratch.join(SKILLS)).unwrap();
        assert_eq!(
            committed_skills(&scratch).1,
            [format!("{SKILLS} is a symbolic link")]
        );
    }
}

/// An entry whose name is not UTF-8 is reported, never read under a lossy
/// name.
#[cfg(target_os = "linux")]
#[test]
fn committed_skills_reports_a_name_that_is_not_utf8() {
    use std::os::unix::ffi::OsStrExt;
    let scratch = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("repository-skill-utf8-{}", std::process::id()));
    let _remove = Scratch::new(&scratch);
    let skills = scratch.join(SKILLS);
    std::fs::create_dir_all(skills.join(std::ffi::OsStr::from_bytes(b"\xff"))).unwrap();
    let (names, problems) = committed_skills(&scratch);
    assert!(names.is_empty());
    assert_eq!(
        problems,
        [format!("{SKILLS}/\"\\xFF\" is not a UTF-8 name")]
    );
}

#[test]
fn committed_skills_reports_a_directory_without_a_skill_and_a_stray_file() {
    let scratch = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("repository-skills-{}", std::process::id()));
    let skills = scratch.join(SKILLS);
    let _remove = Scratch::new(&scratch);
    std::fs::create_dir_all(skills.join("good")).unwrap();
    std::fs::create_dir_all(skills.join("empty")).unwrap();
    std::fs::write(
        skills.join("good").join(SKILL_FILE),
        "---\nname: good\ndescription: Good.\n---\n",
    )
    .unwrap();
    std::fs::write(skills.join("stray.md"), "").unwrap();
    std::fs::write(skills.join(".DS_Store"), "").unwrap();
    // A symbolic link, even to a skill directory, is not one.
    #[cfg(unix)]
    std::os::unix::fs::symlink(skills.join("good"), skills.join("linked")).unwrap();
    #[cfg(unix)]
    {
        std::fs::create_dir_all(skills.join("pointer")).unwrap();
        std::os::unix::fs::symlink(
            skills.join("good").join(SKILL_FILE),
            skills.join("pointer").join(SKILL_FILE),
        )
        .unwrap();
    }
    // Only the exact name counts, even where the file system ignores case.
    std::fs::create_dir_all(skills.join("lower")).unwrap();
    std::fs::write(
        skills.join("lower").join("skill.md"),
        "---\nname: lower\ndescription: Lower.\n---\n",
    )
    .unwrap();
    // A directory with a by-product name is still a skill directory.
    std::fs::create_dir_all(skills.join("._draft")).unwrap();
    std::fs::write(skills.join("._draft").join(SKILL_FILE), "no frontmatter\n").unwrap();

    let (names, mut problems) = committed_skills(&scratch);
    problems.sort();
    assert_eq!(
        names,
        BTreeSet::from(["._draft".to_owned(), "good".to_owned()])
    );
    #[cfg(unix)]
    {
        let links = [
            format!("{SKILLS}/linked is a symbolic link"),
            format!("{SKILLS}/pointer/{SKILL_FILE} is a symbolic link"),
        ];
        for link in &links {
            assert!(problems.contains(link), "{problems:?}");
        }
        problems.retain(|problem| !links.contains(problem));
    }
    assert_eq!(problems.len(), 4, "{problems:?}");
    assert_eq!(
        problems[0],
        format!("{SKILLS}/._draft/{SKILL_FILE} does not start with a `---` frontmatter line")
    );
    assert_eq!(problems[1], format!("{SKILLS}/empty has no {SKILL_FILE}"));
    assert_eq!(problems[2], format!("{SKILLS}/lower has no {SKILL_FILE}"));
    assert_eq!(
        problems[3],
        format!("{SKILLS}/stray.md is not a skill directory")
    );
}
