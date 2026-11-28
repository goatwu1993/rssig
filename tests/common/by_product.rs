//! Operating-system and editor by-product files: `.DS_Store`, `._name`,
//! `.name.swp`, and `name~`, the patterns `.gitignore` excludes. A directory
//! scan in a repository check skips a regular file with such a name instead
//! of failing on a developer machine; any other hidden file, and every
//! directory, is still reported. Shared by `tests/manifest.rs` and
//! `tests/repository.rs` so the two scans follow one rule.

pub fn local_by_product(name: &str) -> bool {
    name == ".DS_Store"
        || name.starts_with("._")
        // `.*.swp`: a dot, then anything (even nothing), then `.swp`.
        || (name.len() > ".swp".len() && name.starts_with('.') && name.ends_with(".swp"))
        || name.ends_with('~')
}
