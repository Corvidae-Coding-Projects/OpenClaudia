//! Native glob tool — crosslink #567.
//!
//! Parity target: CC `tools/GlobTool/GlobTool.ts`. The CC tool accepts a
//! required `pattern` and an optional `path`, walks the directory, and
//! returns a list of matching file paths (capped at 100 results, with a
//! `truncated` flag).
//!
//! Design notes
//! ────────────
//! * The pattern is interpreted as a *glob* (`*`, `**`, `?`) against the
//!   relative path of each visited file. This intentionally mirrors the
//!   glob dialect already used by `permissions.rs::glob_to_regex` so
//!   operators have a single mental model.
//! * The walker is breadth-bounded by a hard cap on visited entries
//!   (`MAX_WALK_ENTRIES`) so a pathological tree (e.g. a symlink loop
//!   into `/`) cannot blow up the agent.
//! * Hidden directories (`.git`, `.cache`, `node_modules`, `target`) are
//!   skipped by default — the CC tool relies on `.gitignore`, which we
//!   approximate with a small allowlist. Pattern matches inside an
//!   explicitly-given `path` argument still descend hidden subdirs so
//!   `path: ".git"` works.
//!
//! [`PROJECT_ROOT`]: super::PROJECT_ROOT

use super::{resolve_path, secure_fs};
use crate::tools::args::ToolArgs as _;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Hard cap on returned filenames (parity with CC `GlobTool`).
const MAX_RESULTS: usize = 100;

/// Hard cap on directory-walk entries — prevents pathological loops
/// (symlink cycles, deeply-nested generated trees) from stalling the
/// agent.
const MAX_WALK_ENTRIES: usize = 50_000;

/// Directory names that the walker skips by default. Caller can opt
/// back in by passing the directory as the explicit `path` argument.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    ".cache",
    ".svelte-kit",
    ".next",
    "dist",
    "build",
];

/// Execute the `glob` tool.
///
/// Returns `(stdout, is_error)`. Errors include: missing pattern, invalid
/// pattern (uncompilable as regex), invalid `path` (jail violation).
pub fn execute_glob(
    run: &std::sync::Arc<crate::tools::security::ToolRunContext>,
    args: &HashMap<String, Value>,
) -> (String, bool) {
    let pattern = match args.arg_str_strict("pattern") {
        Ok(p) => p,
        Err(e) => return e.into_tool_error(),
    };

    let raw_path = match args.arg_str_or_strict("path", ".") {
        Ok(path) => path,
        Err(e) => return e.into_tool_error(),
    };
    let root = match resolve_path(run, raw_path) {
        Ok(p) => p,
        Err(e) => return (e, true),
    };

    let Some(regex) = glob_to_regex(pattern) else {
        return (format!("Invalid glob pattern: '{pattern}'"), true);
    };

    // Whether the caller explicitly named a dotfile/skip-listed root —
    // if so, we descend into it instead of skipping it.
    let allow_hidden_root = SKIP_DIRS
        .iter()
        .any(|d| root.file_name().is_some_and(|n| n == *d))
        || raw_path.contains("/.")
        || raw_path.starts_with('.');

    let mut matches: Vec<String> = Vec::new();
    let mut visited: usize = 0;
    let mut truncated = false;
    let mut resource_batch = match crate::guardrails::begin_path_resource_batch(run) {
        Ok(batch) => batch,
        Err(error) => return (format!("Blocked by blast radius guardrails: {error}"), true),
    };
    if let Err(error) = resource_batch.check_scope(run, &root) {
        return (format!("Blocked by blast radius guardrails: {error}"), true);
    }

    let directory = match secure_fs::open_directory(run, &root) {
        Ok(directory) => directory,
        Err(error) => {
            return (
                format!(
                    "Failed to securely open glob root '{}': {error}",
                    root.display()
                ),
                true,
            );
        }
    };
    if let Err(error) = walk(
        run,
        &root,
        &directory,
        Path::new(""),
        &regex,
        allow_hidden_root,
        &mut matches,
        &mut visited,
        &mut truncated,
        &mut resource_batch,
    ) {
        return (format!("Blocked by blast radius guardrails: {error}"), true);
    }

    matches.sort();

    let header = if truncated {
        format!(
            "Found {} matches (truncated at {MAX_RESULTS}):",
            matches.len()
        )
    } else {
        format!("Found {} matches:", matches.len())
    };
    let body = matches.join("\n");
    let out = if body.is_empty() {
        header
    } else {
        format!("{header}\n{body}")
    };
    resource_batch.commit();
    (out, false)
}

#[allow(clippy::too_many_arguments)]
fn walk(
    run: &crate::tools::ToolRunContext,
    root: &Path,
    dir: &secure_fs::SecureDirectory,
    relative_dir: &Path,
    regex: &Regex,
    allow_hidden_root: bool,
    matches: &mut Vec<String>,
    visited: &mut usize,
    truncated: &mut bool,
    resource_batch: &mut crate::guardrails::PathResourceBatch,
) -> Result<(), String> {
    if matches.len() >= MAX_RESULTS || *visited >= MAX_WALK_ENTRIES {
        return Ok(());
    }
    let entries = match dir.entries() {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(
                dir = %relative_dir.display(),
                error = %e,
                "glob: skipping unreadable directory",
            );
            return Ok(());
        }
    };
    let mut subdirs: Vec<(secure_fs::SecureDirectory, PathBuf)> = Vec::new();
    for entry in entries {
        *visited += 1;
        if *visited >= MAX_WALK_ENTRIES {
            tracing::warn!(
                limit = MAX_WALK_ENTRIES,
                "glob: visited-entry cap reached; results may be incomplete",
            );
            *truncated = true;
            return Ok(());
        }
        let path = relative_dir.join(&entry.name);
        let absolute = root.join(&path);
        if entry.kind == secure_fs::SecureFileType::Directory {
            let name = entry.name;
            let name_str = name.to_string_lossy();
            // Skip hidden / vendor dirs unless caller explicitly chose
            // to descend (root was named such a dir).
            if !allow_hidden_root
                && (name_str.starts_with('.') || SKIP_DIRS.contains(&name_str.as_ref()))
            {
                continue;
            }
            resource_batch.check_scope(run, &absolute)?;
            match dir.open_child_directory(&name) {
                Ok(child) => subdirs.push((child, path)),
                Err(error) => {
                    tracing::warn!(
                        entry = %path.display(),
                        %error,
                        "glob: directory changed before secure open"
                    );
                }
            }
        } else if entry.kind == secure_fs::SecureFileType::Regular {
            let rel_str = path.to_string_lossy();
            if regex.is_match(&rel_str) {
                resource_batch.reserve_file(run, &absolute)?;
                matches.push(path.display().to_string());
                if matches.len() >= MAX_RESULTS {
                    *truncated = true;
                    return Ok(());
                }
            }
        }
    }
    for (sub, relative) in subdirs {
        walk(
            run,
            root,
            &sub,
            &relative,
            regex,
            false, // descend with default hidden-skip behaviour
            matches,
            visited,
            truncated,
            resource_batch,
        )?;
        if matches.len() >= MAX_RESULTS || *visited >= MAX_WALK_ENTRIES {
            return Ok(());
        }
    }
    Ok(())
}

/// Translate a glob pattern into an anchored regex.
///
/// Mirrors the dialect of `permissions.rs::glob_to_regex` so operators
/// have a single mental model:
/// * `*`  — any sequence of non-`/` characters
/// * `**` — any sequence, including `/`
/// * `?`  — any single non-`/` character
/// * regex specials are escaped
///
/// Returns `None` if the resulting regex fails to compile.
fn glob_to_regex(pattern: &str) -> Option<Regex> {
    let mut re = String::from("^");
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' => {
                if i + 1 < chars.len() && chars[i + 1] == '*' {
                    re.push_str(".*");
                    i += 2;
                    if i < chars.len() && chars[i] == '/' {
                        re.push_str("/?");
                        i += 1;
                    }
                } else {
                    re.push_str("[^/]*");
                    i += 1;
                }
            }
            '?' => {
                re.push_str("[^/]");
                i += 1;
            }
            '.' | '+' | '^' | '$' | '(' | ')' | '{' | '}' | '[' | ']' | '|' | '\\' => {
                re.push('\\');
                re.push(chars[i]);
                i += 1;
            }
            c => {
                re.push(c);
                i += 1;
            }
        }
    }
    re.push('$');
    Regex::new(&re).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::fs::File;
    use std::io::Write as _;
    use tempfile::TempDir;

    fn test_run() -> &'static std::sync::Arc<crate::tools::ToolRunContext> {
        crate::tools::security::test_run_context()
    }

    fn write_file(dir: &Path, rel: &str, body: &str) {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut f = File::create(&p).unwrap();
        f.write_all(body.as_bytes()).unwrap();
    }

    /// Pin: glob walks the named tree and returns paths that match the
    /// `*.rs` pattern at the root level only (`*` does NOT cross `/`).
    /// Subdirs are reached only with `**`.
    #[test]
    fn glob_matches_rust_files_at_root_with_star() {
        let dir = TempDir::new_in(".").unwrap();
        write_file(dir.path(), "lib.rs", "fn x() {}");
        write_file(dir.path(), "main.rs", "fn main() {}");
        write_file(dir.path(), "src/inner.rs", "fn y() {}");
        let mut args = HashMap::new();
        args.insert("pattern".to_string(), json!("*.rs"));
        args.insert(
            "path".to_string(),
            json!(dir.path().to_string_lossy().to_string()),
        );
        let (out, err) = execute_glob(test_run(), &args);
        assert!(!err, "got error: {out}");
        assert!(out.contains("lib.rs"), "lib.rs missing in: {out}");
        assert!(out.contains("main.rs"), "main.rs missing in: {out}");
        assert!(
            !out.contains("src/inner.rs"),
            "single-star must NOT cross '/': {out}"
        );
    }

    /// Pin: `**` crosses path separators — `**/*.rs` reaches subdirs.
    #[test]
    fn glob_double_star_crosses_directories() {
        let dir = TempDir::new_in(".").unwrap();
        write_file(dir.path(), "src/deep/a.rs", "fn a() {}");
        write_file(dir.path(), "src/deep/b.txt", "no");
        let mut args = HashMap::new();
        args.insert("pattern".to_string(), json!("**/*.rs"));
        args.insert(
            "path".to_string(),
            json!(dir.path().to_string_lossy().to_string()),
        );
        let (out, err) = execute_glob(test_run(), &args);
        assert!(!err, "got error: {out}");
        assert!(out.contains("a.rs"), "deep .rs missing in: {out}");
        assert!(!out.contains("b.txt"), "non-rs leaked into matches: {out}");
    }

    /// Pin: a missing `pattern` produces an error rather than panicking.
    #[test]
    fn glob_missing_pattern_errors() {
        let args = HashMap::new();
        let (out, err) = execute_glob(test_run(), &args);
        assert!(err, "missing pattern must be an error: {out}");
        assert!(out.contains("pattern"), "error must name the arg: {out}");
    }

    #[test]
    fn glob_rejects_non_string_pattern() {
        let mut args = HashMap::new();
        args.insert("pattern".to_string(), json!(42));

        let (out, err) = execute_glob(test_run(), &args);

        assert!(err, "non-string pattern must be an error: {out}");
        assert_eq!(out, "Invalid 'pattern' argument: expected string");
    }

    #[test]
    fn glob_rejects_non_string_path() {
        let mut args = HashMap::new();
        args.insert("pattern".to_string(), json!("*.rs"));
        args.insert("path".to_string(), json!(42));

        let (out, err) = execute_glob(test_run(), &args);

        assert!(err, "non-string path must be an error: {out}");
        assert!(
            out.contains("Invalid 'path' argument: expected string"),
            "unexpected error: {out}"
        );
    }

    /// Pin: the glob walker is robust against unusual but legal glob
    /// characters — special regex characters in the pattern are escaped
    /// by `glob_to_regex`, so a literal `[unterminated` matches a
    /// file by that name rather than panicking on regex compile.
    /// This pins the "no panic on weird input" invariant.
    #[test]
    fn glob_special_characters_are_escaped_not_panicking() {
        let dir = TempDir::new_in(".").unwrap();
        // Create a file whose name contains the literal characters we
        // are testing: `[` and `]`. The glob dialect treats these as
        // literals (regex specials are escaped before compile).
        write_file(dir.path(), "weird[name].txt", "ok");
        let mut args = HashMap::new();
        args.insert("pattern".to_string(), json!("weird[name].txt"));
        args.insert(
            "path".to_string(),
            json!(dir.path().to_string_lossy().to_string()),
        );
        let (out, err) = execute_glob(test_run(), &args);
        assert!(!err, "literal-bracket pattern must not error: {out}");
        assert!(
            out.contains("weird[name].txt"),
            "literal-bracket name lost: {out}"
        );
    }
}
