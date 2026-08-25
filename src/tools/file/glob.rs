//! Deterministic, paginated native glob discovery.

use super::{discovery, resolve_path};
use crate::tools::args::ToolArgs as _;
use crate::tools::{ToolFailure, ToolFailureCode, ToolHandlerResult, ToolRetryability, ToolUsage};
use regex::{Regex, RegexBuilder};
use serde_json::{json, Value};
use std::collections::HashMap;

const DEFAULT_PAGE_LIMIT: usize = 100;
const MAX_PAGE_LIMIT: usize = 500;
const MAX_GLOB_PATTERN_BYTES: usize = 4 * 1024;
const MAX_REGEX_COMPILED_BYTES: usize = 2 * 1024 * 1024;

/// Typed glob execution retained through registry, provider, trace, and
/// frontend adapters.
#[allow(clippy::too_many_lines)] // Parsing, traversal, pagination, and typed rendering are one tool transaction.
pub fn execute_glob_typed(
    run: &std::sync::Arc<crate::tools::security::ToolRunContext>,
    args: &HashMap<String, Value>,
) -> ToolHandlerResult {
    let pattern = match args.arg_str_strict("pattern") {
        Ok(pattern) => pattern,
        Err(error) => return invalid_arguments(error.to_string()),
    };
    if pattern.len() > MAX_GLOB_PATTERN_BYTES {
        return invalid_arguments(format!(
            "Invalid glob pattern: maximum length is {MAX_GLOB_PATTERN_BYTES} bytes"
        ));
    }
    let regex = match glob_to_regex(pattern) {
        Ok(regex) => regex,
        Err(error) => return invalid_arguments(error),
    };
    let raw_path = match args.arg_str_or_strict("path", ".") {
        Ok(path) => path,
        Err(error) => return invalid_arguments(error.to_string()),
    };
    let root = match resolve_path(run, raw_path) {
        Ok(path) => path,
        Err(error) => return invalid_arguments(error),
    };
    let ignore_policy = if args.contains_key("path")
        && root.components().any(|component| {
            component
                .as_os_str()
                .to_str()
                .is_some_and(|name| name.starts_with('.') && name != "." && name != "..")
        }) {
        discovery::IgnorePolicy::None
    } else {
        discovery::IgnorePolicy::Standard
    };
    let limit =
        match discovery::parse_page_limit(args.get("limit"), DEFAULT_PAGE_LIMIT, MAX_PAGE_LIMIT) {
            Ok(limit) => limit,
            Err(error) => return invalid_arguments(error),
        };
    let cursor_arg = match args.arg_str_opt_strict("cursor") {
        Ok(cursor) => cursor,
        Err(error) => return invalid_arguments(error.to_string()),
    };
    let root_id = root.to_string_lossy();
    let binding = discovery::cursor_binding(&["glob", &root_id, pattern]);
    let cursor = match discovery::decode_cursor(cursor_arg, &binding) {
        Ok(None) => None,
        Ok(Some(discovery::CursorPosition::Entry { resource_id })) => Some(resource_id),
        Ok(Some(discovery::CursorPosition::Match { .. })) => {
            return invalid_arguments("Invalid cursor: expected a glob-entry position")
        }
        Err(error) => return invalid_arguments(error),
    };

    let mut resource_batch = match crate::guardrails::begin_path_resource_batch(run) {
        Ok(batch) => batch,
        Err(error) => return policy_error(error),
    };
    if let Err(error) = resource_batch.check_scope(run, &root) {
        return policy_error(error);
    }

    let mut cursor_seen = cursor.is_none();
    let mut matches = Vec::with_capacity(limit);
    let mut rendered_bytes = 0usize;
    let mut has_more = false;
    let mut output_limited = false;
    let walk = discovery::walk(
        run,
        &root,
        discovery::WalkOptions {
            recursive: true,
            visit_directories: true,
            directories_first: false,
            ignore_policy,
        },
        |entry| {
            if entry.kind == discovery::WalkEntryKind::Directory {
                resource_batch.check_scope(run, entry.absolute_path)?;
                return Ok(discovery::WalkControl::Continue);
            }
            if !cursor_seen {
                if cursor.as_deref() == Some(entry.resource_id) {
                    cursor_seen = true;
                }
                return Ok(discovery::WalkControl::Continue);
            }
            if !regex.is_match(entry.resource_id) {
                return Ok(discovery::WalkControl::Continue);
            }
            if matches.len() >= limit {
                has_more = true;
                return Ok(discovery::WalkControl::Stop);
            }
            let next_bytes = entry.resource_id.len().saturating_add(1);
            if rendered_bytes.saturating_add(next_bytes) > discovery::MAX_RENDERED_BYTES {
                has_more = true;
                output_limited = true;
                return Ok(discovery::WalkControl::Stop);
            }
            resource_batch.reserve_file(run, entry.absolute_path)?;
            rendered_bytes = rendered_bytes.saturating_add(next_bytes);
            matches.push(entry.resource_id.to_string());
            Ok(discovery::WalkControl::Continue)
        },
    );
    let report = match walk {
        Ok(report) => report,
        Err(discovery::WalkError::Visitor(error)) => return policy_error(error),
        Err(discovery::WalkError::Filesystem(error)) => {
            return ToolHandlerResult::error(ToolFailure::new(
                ToolFailureCode::External,
                format!(
                    "Failed to securely search glob root '{}': {error}",
                    root.display()
                ),
                ToolRetryability::Safe,
            ))
        }
    };

    if cursor.is_some() && !cursor_seen {
        if report.is_complete() {
            return invalid_arguments("Invalid cursor: its glob entry no longer exists");
        }
        has_more = true;
    }
    let incomplete_walk =
        !report.is_complete() && report.termination != discovery::WalkTermination::Visitor;
    let complete = !has_more && !incomplete_walk;
    let next_cursor = if complete {
        None
    } else {
        matches.last().map(|resource_id| {
            discovery::encode_cursor(
                &binding,
                discovery::CursorPosition::Entry {
                    resource_id: resource_id.clone(),
                },
            )
        })
    };
    let mut diagnostics = report
        .diagnostics
        .iter()
        .map(|diagnostic| {
            json!({
                "code": diagnostic.code,
                "resource_id": diagnostic.resource_id,
                "message": diagnostic.message,
            })
        })
        .collect::<Vec<_>>();
    if output_limited {
        diagnostics.push(json!({
            "code": "rendered_output_limit",
            "resource_id": "",
            "message": format!(
                "glob reached its {}-byte rendered-output budget",
                discovery::MAX_RENDERED_BYTES
            ),
        }));
    }
    if report.stats.diagnostics_omitted > 0 {
        diagnostics.push(json!({
            "code": "diagnostics_omitted",
            "resource_id": "",
            "message": format!(
                "{} additional diagnostics were omitted",
                report.stats.diagnostics_omitted
            ),
        }));
    }
    let ignore_policy_metadata = if ignore_policy == discovery::IgnorePolicy::Standard {
        json!({
            "mode": "standard",
            "directories": discovery::STANDARD_IGNORED_DIRECTORIES,
        })
    } else {
        json!({
            "mode": "none",
            "directories": [],
        })
    };

    let mut text = format!(
        "Found {} match{}{}:",
        matches.len(),
        if matches.len() == 1 { "" } else { "es" },
        if complete { "" } else { " (partial)" }
    );
    for resource_id in &matches {
        text.push('\n');
        text.push_str(resource_id);
    }
    append_partial_text(&mut text, &diagnostics, next_cursor.as_deref());

    let structured = json!({
        "file_discovery": {
            "schema_version": 1,
            "operation": "glob",
            "root": root_id.as_ref(),
            "pattern": pattern,
            "entries": &matches,
            "page": {
                "complete": complete,
                "next_cursor": next_cursor.as_deref(),
                "limit": limit,
            },
            "coverage": &report.stats,
            "diagnostics": &diagnostics,
            "ignore_policy": ignore_policy_metadata,
        }
    });
    resource_batch.commit();
    let mut result = if complete {
        ToolHandlerResult::success_structured(text, structured)
    } else {
        ToolHandlerResult::partial_structured(
            text,
            structured,
            report_failures(&report, output_limited),
            next_cursor.as_ref().map(|cursor| json!({"cursor": cursor})),
        )
    };
    result.usage = ToolUsage {
        output_bytes: u64::try_from(result.content().len()).unwrap_or(u64::MAX),
        elapsed_ms: report.stats.elapsed_ms,
        ..ToolUsage::default()
    };
    result
}

fn glob_to_regex(pattern: &str) -> Result<Regex, String> {
    let mut expression = String::with_capacity(pattern.len().saturating_mul(2).saturating_add(2));
    expression.push('^');
    let mut chars = pattern.chars().peekable();
    while let Some(character) = chars.next() {
        match character {
            '*' if chars.peek() == Some(&'*') => {
                let _second = chars.next();
                expression.push_str(".*");
                if chars.peek() == Some(&'/') {
                    let _slash = chars.next();
                    expression.push_str("/?");
                }
            }
            '*' => expression.push_str("[^/]*"),
            '?' => expression.push_str("[^/]"),
            '.' | '+' | '^' | '$' | '(' | ')' | '{' | '}' | '[' | ']' | '|' | '\\' => {
                expression.push('\\');
                expression.push(character);
            }
            other => expression.push(other),
        }
    }
    expression.push('$');
    RegexBuilder::new(&expression)
        .size_limit(MAX_REGEX_COMPILED_BYTES)
        .dfa_size_limit(MAX_REGEX_COMPILED_BYTES)
        .build()
        .map_err(|error| format!("Invalid glob pattern '{pattern}': {error}"))
}

fn invalid_arguments(message: impl Into<String>) -> ToolHandlerResult {
    ToolHandlerResult::error(ToolFailure::new(
        ToolFailureCode::InvalidArguments,
        message.into(),
        ToolRetryability::Never,
    ))
}

fn policy_error(message: impl Into<String>) -> ToolHandlerResult {
    ToolHandlerResult::error(ToolFailure::new(
        ToolFailureCode::PolicyDenied,
        format!("Blocked by blast radius guardrails: {}", message.into()),
        ToolRetryability::Never,
    ))
}

fn report_failures(report: &discovery::WalkReport, output_limited: bool) -> Vec<ToolFailure> {
    let mut failures = Vec::new();
    match report.termination {
        discovery::WalkTermination::Cancelled => failures.push(ToolFailure::new(
            ToolFailureCode::Cancelled,
            "Glob discovery was cancelled before coverage completed".to_string(),
            ToolRetryability::Never,
        )),
        discovery::WalkTermination::Deadline => failures.push(ToolFailure::new(
            ToolFailureCode::DeadlineExceeded,
            "Glob discovery exceeded its traversal deadline".to_string(),
            ToolRetryability::Safe,
        )),
        _ if !report.diagnostics.is_empty() => failures.push(ToolFailure::new(
            ToolFailureCode::External,
            "Glob discovery omitted entries; inspect typed diagnostics".to_string(),
            ToolRetryability::Safe,
        )),
        _ => {}
    }
    if output_limited {
        failures.push(ToolFailure::new(
            ToolFailureCode::External,
            "Glob discovery reached its rendered-output limit".to_string(),
            ToolRetryability::Safe,
        ));
    }
    failures
}

fn append_partial_text(text: &mut String, diagnostics: &[Value], next_cursor: Option<&str>) {
    if !diagnostics.is_empty() {
        text.push_str("\nPartial diagnostics:");
        for diagnostic in diagnostics.iter().take(8) {
            let code = diagnostic["code"].as_str().unwrap_or("partial");
            let resource = diagnostic["resource_id"].as_str().unwrap_or("");
            let message = diagnostic["message"]
                .as_str()
                .unwrap_or("coverage incomplete");
            text.push_str("\n- ");
            text.push_str(code);
            if !resource.is_empty() {
                text.push_str(" (");
                text.push_str(resource);
                text.push(')');
            }
            text.push_str(": ");
            text.push_str(message);
        }
    }
    if let Some(cursor) = next_cursor {
        text.push_str("\nNext cursor: ");
        text.push_str(cursor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn write_file(root: &Path, relative: &str) {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("parent");
        }
        std::fs::write(path, "x").expect("file");
    }

    #[test]
    fn glob_pages_in_stable_order_and_skips_standard_hidden_subtrees() {
        let root = tempfile::tempdir().expect("root");
        write_file(root.path(), "z.rs");
        write_file(root.path(), "src/b.rs");
        write_file(root.path(), "src/a.rs");
        write_file(root.path(), ".git/hidden.rs");
        let run = crate::tools::security::test_run_context_for(root.path());
        let first_args = HashMap::from([
            ("pattern".to_string(), json!("**/*.rs")),
            ("limit".to_string(), json!(2)),
        ]);

        let first = execute_glob_typed(&run, &first_args);

        assert!(
            matches!(&first.outcome, crate::tools::ToolOutcome::Partial { .. }),
            "{}",
            first.content()
        );
        assert!(first.content().contains("src/a.rs\nsrc/b.rs"));
        assert!(!first.content().contains("hidden.rs"));
        let cursor = match &first.outcome {
            crate::tools::ToolOutcome::Partial { content, .. } => content
                .structured
                .as_ref()
                .and_then(|value| value.pointer("/file_discovery/page/next_cursor"))
                .and_then(Value::as_str)
                .expect("cursor"),
            other => panic!("expected partial glob, got {other:?}"),
        };
        let second_args = HashMap::from([
            ("pattern".to_string(), json!("**/*.rs")),
            ("limit".to_string(), json!(2)),
            ("cursor".to_string(), json!(cursor)),
        ]);
        let second = execute_glob_typed(&run, &second_args);

        assert!(
            !matches!(&second.outcome, crate::tools::ToolOutcome::Error { .. }),
            "{}",
            second.content()
        );
        assert!(second.content().contains("z.rs"));
        assert!(!second.content().contains("src/a.rs"));
    }

    #[test]
    fn glob_rejects_oversized_pattern_before_compilation() {
        let args = HashMap::from([(
            "pattern".to_string(),
            json!("a".repeat(MAX_GLOB_PATTERN_BYTES + 1)),
        )]);

        let result = execute_glob_typed(crate::tools::security::test_run_context(), &args);

        assert!(matches!(
            &result.outcome,
            crate::tools::ToolOutcome::Error { .. }
        ));
        assert!(result.content().contains("maximum length"));
    }
}
