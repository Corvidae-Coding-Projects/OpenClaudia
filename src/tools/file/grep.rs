//! Native grep tool — crosslink #568.
//!
//! Parity target: CC `tools/GrepTool/GrepTool.ts`. The CC tool is backed by
//! ripgrep and supports a rich flag set (`-A` / `-B` / `-C`, file-type
//! filters, glob filters, output modes). This is a minimal parity
//! implementation: regex search across files under `path` with optional
//! ±N context lines.
//!
//! Args
//! ────
//! * `pattern` (required): regex string. Compiled with the `regex` crate.
//! * `path` (optional, default `.`): root directory to search.
//! * `context_lines` (optional, default `0`): non-negative integer ±N context window.
//! * `case_insensitive` (optional, default `false`): toggles `(?i)`.
//!
//! Output is `file:line:match` for every match, with optional
//! `file:line-context` lines for the surrounding window. Capped at
//! `MAX_MATCHES` so a runaway regex does not flood the agent.

use super::{resolve_path, secure_fs};
use crate::tools::args::ToolArgs as _;
use regex::Regex;
use serde_json::Value;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};

/// Hard cap on returned matches before truncation.
const MAX_MATCHES: usize = 200;

/// Hard cap on bytes read per file — keeps the grep tool from blocking
/// on a multi-GB log file.
const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;

/// Hard cap on directories descended, mirroring the glob walker.
const MAX_WALK_ENTRIES: usize = 50_000;

/// Vendor / generated directories the walker skips by default.
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

/// Execute the `grep` tool.
///
/// Returns `(stdout, is_error)`.
pub fn execute_grep(args: &HashMap<String, Value>) -> (String, bool) {
    let pattern = match args.arg_str_strict("pattern") {
        Ok(p) => p.to_string(),
        Err(e) => return e.into_tool_error(),
    };

    let raw_path = match args.arg_str_or_strict("path", ".") {
        Ok(path) => path,
        Err(e) => return e.into_tool_error(),
    };
    let root = match resolve_path(raw_path) {
        Ok(p) => p,
        Err(e) => return (e, true),
    };

    let context = match parse_context_lines_arg(args.get("context_lines")) {
        Ok(context) => context,
        Err(msg) => return (msg, true),
    };
    let case_insensitive = match args.arg_bool_or_strict("case_insensitive", false) {
        Ok(value) => value,
        Err(e) => return e.into_tool_error(),
    };

    let effective_pattern = if case_insensitive {
        format!("(?i){pattern}")
    } else {
        pattern.clone()
    };

    let regex = match Regex::new(&effective_pattern) {
        Ok(r) => r,
        Err(e) => return (format!("Invalid regex '{pattern}': {e}"), true),
    };

    let directory = match secure_fs::open_directory(&root) {
        Ok(directory) => directory,
        Err(error) => {
            return (
                format!(
                    "Failed to securely open grep root '{}': {error}",
                    root.display()
                ),
                true,
            );
        }
    };
    let mut visited: usize = 0;
    let mut output: Vec<String> = Vec::new();
    let mut total_matches: usize = 0;
    let mut files_scanned: usize = 0;
    let mut truncated = false;
    grep_directory(
        &directory,
        Path::new(""),
        &regex,
        context,
        &mut output,
        &mut total_matches,
        &mut files_scanned,
        &mut visited,
        &mut truncated,
    );

    let header = if truncated {
        format!(
            "Found {total_matches} matches (truncated at {MAX_MATCHES}) across {files_scanned} files:"
        )
    } else {
        format!("Found {total_matches} matches across {files_scanned} files:")
    };
    let body = output.join("\n");
    let out = if body.is_empty() {
        header
    } else {
        format!("{header}\n{body}")
    };
    (out, false)
}

fn parse_context_lines_arg(value: Option<&Value>) -> Result<usize, String> {
    let Some(value) = value else {
        return Ok(0);
    };
    let Some(context) = value.as_u64() else {
        return Err("Error: context_lines must be a non-negative integer".to_string());
    };
    Ok(usize::try_from(context).unwrap_or(usize::MAX))
}

struct Hit {
    line_no: usize,
    line: String,
    context_before: Vec<String>,
    context_after: Vec<String>,
}

fn grep_one(file: File, regex: &Regex, context: usize) -> std::io::Result<Vec<Hit>> {
    let meta = file.metadata()?;
    if meta.len() > MAX_FILE_BYTES {
        return Ok(Vec::new());
    }
    let mut body = String::new();
    file.take(MAX_FILE_BYTES + 1).read_to_string(&mut body)?;
    if body.len() > usize::try_from(MAX_FILE_BYTES).unwrap_or(usize::MAX) {
        return Ok(Vec::new());
    }
    let lines: Vec<&str> = body.lines().collect();
    let mut hits = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        if regex.is_match(line) {
            let line_no = idx + 1;
            let before_start = idx.saturating_sub(context);
            // crosslink #149-fix: `idx + context + 1` overflowed when
            // `context_lines` was coerced to `usize::MAX` from a huge
            // u64. Saturating arithmetic prevents the panic and still
            // yields the correct end-of-file cap via `.min(lines.len())`.
            let after_end = idx
                .saturating_add(context)
                .saturating_add(1)
                .min(lines.len());
            let context_before: Vec<String> = lines[before_start..idx]
                .iter()
                .map(|s| (*s).to_string())
                .collect();
            let context_after: Vec<String> = lines[idx + 1..after_end]
                .iter()
                .map(|s| (*s).to_string())
                .collect();
            hits.push(Hit {
                line_no,
                line: (*line).to_string(),
                context_before,
                context_after,
            });
        }
    }
    Ok(hits)
}

#[allow(clippy::too_many_arguments)]
fn grep_directory(
    dir: &secure_fs::SecureDirectory,
    relative_dir: &Path,
    regex: &Regex,
    context: usize,
    output: &mut Vec<String>,
    total_matches: &mut usize,
    files_scanned: &mut usize,
    visited: &mut usize,
    truncated: &mut bool,
) {
    if *visited >= MAX_WALK_ENTRIES || *total_matches >= MAX_MATCHES {
        *truncated = true;
        return;
    }
    let entries = match dir.entries() {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(
                dir = %relative_dir.display(),
                error = %e,
                "grep: skipping unreadable dir"
            );
            return;
        }
    };
    let mut subdirs: Vec<(secure_fs::SecureDirectory, PathBuf)> = Vec::new();
    for entry in entries {
        *visited += 1;
        if *visited >= MAX_WALK_ENTRIES {
            *truncated = true;
            return;
        }
        let name = entry.name;
        let name_str = name.to_string_lossy();
        let relative = relative_dir.join(&name);
        if entry.kind == secure_fs::SecureFileType::Directory {
            if name_str.starts_with('.') || SKIP_DIRS.contains(&name_str.as_ref()) {
                continue;
            }
            match dir.open_child_directory(&name) {
                Ok(child) => subdirs.push((child, relative)),
                Err(error) => tracing::warn!(
                    entry = %relative.display(),
                    %error,
                    "grep: directory changed before secure open"
                ),
            }
        } else if entry.kind == secure_fs::SecureFileType::Regular {
            *files_scanned += 1;
            match dir.open_child_regular(&name) {
                Ok(file) => match grep_one(file, regex, context) {
                    Ok(hits) => append_hits(
                        &relative.display().to_string(),
                        hits,
                        context,
                        output,
                        total_matches,
                        truncated,
                    ),
                    Err(error) => tracing::warn!(
                        file = %relative.display(),
                        %error,
                        "grep: confined file read failed"
                    ),
                },
                Err(error) => tracing::warn!(
                    file = %relative.display(),
                    %error,
                    "grep: file changed before secure open"
                ),
            }
            if *total_matches >= MAX_MATCHES {
                *truncated = true;
                return;
            }
        }
    }
    for (sub, relative) in subdirs {
        grep_directory(
            &sub,
            &relative,
            regex,
            context,
            output,
            total_matches,
            files_scanned,
            visited,
            truncated,
        );
        if *truncated {
            return;
        }
    }
}

fn append_hits(
    relative: &str,
    hits: Vec<Hit>,
    context: usize,
    output: &mut Vec<String>,
    total_matches: &mut usize,
    truncated: &mut bool,
) {
    for hit in hits {
        if *total_matches >= MAX_MATCHES {
            *truncated = true;
            break;
        }
        for ctx_line in hit.context_before {
            output.push(format!("{relative}-{}-{ctx_line}", hit.line_no - 1));
        }
        output.push(format!("{relative}:{}:{}", hit.line_no, hit.line));
        let mut after_no = hit.line_no;
        for ctx_line in hit.context_after {
            after_no += 1;
            output.push(format!("{relative}-{after_no}-{ctx_line}"));
        }
        if context > 0 {
            output.push("--".to_string());
        }
        *total_matches += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::fs::File;
    use std::io::Write as _;
    use tempfile::TempDir;

    fn write_file(dir: &Path, rel: &str, body: &str) {
        let p = dir.join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        File::create(&p)
            .unwrap()
            .write_all(body.as_bytes())
            .unwrap();
    }

    /// Pin: matches the requested regex and returns `file:line:match`
    /// for every hit, ignoring files that don't contain the pattern.
    #[test]
    fn grep_emits_file_line_match() {
        let dir = TempDir::new_in(".").unwrap();
        write_file(
            dir.path(),
            "a.rs",
            "fn main() {\n    println!(\"hello world\");\n}\n",
        );
        write_file(dir.path(), "b.rs", "fn other() {}\n");
        let mut args = HashMap::new();
        args.insert("pattern".to_string(), json!("hello"));
        args.insert(
            "path".to_string(),
            json!(dir.path().to_string_lossy().to_string()),
        );
        let (out, err) = execute_grep(&args);
        assert!(!err, "got error: {out}");
        assert!(out.contains("a.rs:2:"), "expected a.rs:2: in: {out}");
        assert!(out.contains("hello world"), "match body lost: {out}");
        assert!(!out.contains("b.rs:"), "b.rs leaked: {out}");
    }

    /// Pin: `context_lines` = 1 emits the surrounding line on each side.
    #[test]
    fn grep_emits_context_lines() {
        let dir = TempDir::new_in(".").unwrap();
        write_file(
            dir.path(),
            "ctx.txt",
            "line one\nline two MATCH here\nline three\n",
        );
        let mut args = HashMap::new();
        args.insert("pattern".to_string(), json!("MATCH"));
        args.insert(
            "path".to_string(),
            json!(dir.path().to_string_lossy().to_string()),
        );
        args.insert("context_lines".to_string(), json!(1));
        let (out, err) = execute_grep(&args);
        assert!(!err, "got error: {out}");
        // Before-context emitted with `-1-` delimiter style
        assert!(out.contains("ctx.txt-1-line one"), "before-ctx: {out}");
        assert!(out.contains("ctx.txt:2:"), "match line: {out}");
        assert!(out.contains("ctx.txt-3-line three"), "after-ctx: {out}");
    }

    /// Pin: an invalid regex surfaces a clean error instead of panicking.
    #[test]
    fn grep_invalid_regex_errors() {
        let dir = TempDir::new_in(".").unwrap();
        let mut args = HashMap::new();
        args.insert("pattern".to_string(), json!("[unterminated"));
        args.insert(
            "path".to_string(),
            json!(dir.path().to_string_lossy().to_string()),
        );
        let (out, err) = execute_grep(&args);
        assert!(err, "expected error, got: {out}");
        assert!(out.contains("Invalid regex"), "msg was: {out}");
    }

    /// Pin: missing pattern is a clean error.
    #[test]
    fn grep_missing_pattern_errors() {
        let args = HashMap::new();
        let (out, err) = execute_grep(&args);
        assert!(err, "missing pattern must be an error: {out}");
        assert!(out.contains("pattern"), "error must name the arg: {out}");
    }

    #[test]
    fn grep_rejects_non_string_pattern() {
        let mut args = HashMap::new();
        args.insert("pattern".to_string(), json!(["hello"]));

        let (out, err) = execute_grep(&args);

        assert!(err, "non-string pattern must be an error: {out}");
        assert_eq!(out, "Invalid 'pattern' argument: expected string");
    }

    #[test]
    fn grep_rejects_non_string_path() {
        let mut args = HashMap::new();
        args.insert("pattern".to_string(), json!("hello"));
        args.insert("path".to_string(), json!(["not", "a", "path"]));

        let (out, err) = execute_grep(&args);

        assert!(err, "non-string path must be an error: {out}");
        assert!(
            out.contains("Invalid 'path' argument: expected string"),
            "unexpected error: {out}"
        );
    }

    /// Pin: `case_insensitive=true` matches mixed-case occurrences.
    #[test]
    fn grep_case_insensitive_flag() {
        let dir = TempDir::new_in(".").unwrap();
        write_file(dir.path(), "x.txt", "HELLO world\n");
        let mut args = HashMap::new();
        args.insert("pattern".to_string(), json!("hello"));
        args.insert(
            "path".to_string(),
            json!(dir.path().to_string_lossy().to_string()),
        );
        args.insert("case_insensitive".to_string(), json!(true));
        let (out, err) = execute_grep(&args);
        assert!(!err);
        assert!(out.contains("x.txt:1:"), "case-insensitive miss: {out}");
    }

    #[test]
    fn grep_rejects_non_boolean_case_insensitive() {
        let dir = TempDir::new_in(".").unwrap();
        write_file(dir.path(), "x.txt", "hello\n");
        let mut args = HashMap::new();
        args.insert("pattern".to_string(), json!("hello"));
        args.insert(
            "path".to_string(),
            json!(dir.path().to_string_lossy().to_string()),
        );
        args.insert("case_insensitive".to_string(), json!("true"));

        let (out, err) = execute_grep(&args);

        assert!(err, "non-boolean case_insensitive must error: {out}");
        assert!(
            out.contains("Invalid 'case_insensitive' argument: expected boolean"),
            "unexpected error: {out}"
        );
    }
}
