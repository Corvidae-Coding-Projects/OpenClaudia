use super::{discovery, resolve_path};
use crate::tools::args::ToolArgs as _;
use crate::tools::{ToolFailure, ToolFailureCode, ToolHandlerResult, ToolRetryability, ToolUsage};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashMap;

const DEFAULT_PAGE_LIMIT: usize = 200;
const MAX_PAGE_LIMIT: usize = 500;

#[derive(Serialize)]
struct ListedEntry {
    resource_id: String,
    kind: &'static str,
}

/// Typed, bounded directory listing used by every production registry path.
#[allow(clippy::too_many_lines)] // Parsing, traversal, pagination, and typed rendering are one tool transaction.
pub fn execute_list_files_typed(
    run: &std::sync::Arc<crate::tools::security::ToolRunContext>,
    args: &HashMap<String, Value>,
) -> ToolHandlerResult {
    let raw_path = match args.arg_str_or_strict("path", ".") {
        Ok(path) => path,
        Err(error) => return invalid_arguments(error.to_string()),
    };
    let root = match resolve_path(run, raw_path) {
        Ok(path) => path,
        Err(error) => return invalid_arguments(error),
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
    let binding = discovery::cursor_binding(&["list_files", &root_id]);
    let cursor = match discovery::decode_cursor(cursor_arg, &binding) {
        Ok(None) => None,
        Ok(Some(discovery::CursorPosition::Entry { resource_id })) => Some(resource_id),
        Ok(Some(discovery::CursorPosition::Match { .. })) => {
            return invalid_arguments("Invalid cursor: expected a directory-entry position")
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
    let mut entries = Vec::with_capacity(limit);
    let mut rendered_bytes = 0usize;
    let mut has_more = false;
    let mut output_limited = false;
    let walk = discovery::walk(
        run,
        &root,
        discovery::WalkOptions {
            recursive: false,
            visit_directories: true,
            directories_first: true,
            ignore_policy: discovery::IgnorePolicy::None,
        },
        |entry| {
            if !cursor_seen {
                if cursor.as_deref() == Some(entry.resource_id) {
                    cursor_seen = true;
                }
                return Ok(discovery::WalkControl::Continue);
            }
            if entries.len() >= limit {
                has_more = true;
                return Ok(discovery::WalkControl::Stop);
            }
            let suffix = if entry.kind == discovery::WalkEntryKind::Directory {
                "/"
            } else {
                ""
            };
            let next_bytes = entry
                .resource_id
                .len()
                .saturating_add(suffix.len())
                .saturating_add(1);
            if rendered_bytes.saturating_add(next_bytes) > discovery::MAX_RENDERED_BYTES {
                has_more = true;
                output_limited = true;
                return Ok(discovery::WalkControl::Stop);
            }
            if entry.kind == discovery::WalkEntryKind::Directory {
                resource_batch.check_disclosed_scope(run, entry.absolute_path)?;
            } else {
                resource_batch.reserve_file(run, entry.absolute_path)?;
            }
            rendered_bytes = rendered_bytes.saturating_add(next_bytes);
            entries.push(ListedEntry {
                resource_id: entry.resource_id.to_string(),
                kind: if entry.kind == discovery::WalkEntryKind::Directory {
                    "directory"
                } else {
                    "file"
                },
            });
            Ok(discovery::WalkControl::Continue)
        },
    );
    let report = match walk {
        Ok(report) => report,
        Err(discovery::WalkError::Visitor(error)) => return policy_error(error),
        Err(discovery::WalkError::Filesystem(error)) => {
            return ToolHandlerResult::error(ToolFailure::new(
                ToolFailureCode::External,
                format!("Failed to list directory '{}': {error}", root.display()),
                ToolRetryability::Safe,
            ))
        }
    };

    if cursor.is_some() && !cursor_seen {
        if report.is_complete() {
            return invalid_arguments(
                "Invalid cursor: its directory entry no longer exists in this listing",
            );
        }
        has_more = true;
    }

    let incomplete_walk =
        !report.is_complete() && report.termination != discovery::WalkTermination::Visitor;
    let complete = !has_more && !incomplete_walk;
    let next_cursor = if complete {
        None
    } else {
        entries.last().map(|entry| {
            discovery::encode_cursor(
                &binding,
                discovery::CursorPosition::Entry {
                    resource_id: entry.resource_id.clone(),
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
                "listing reached its {}-byte rendered-output budget",
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

    let mut text = if entries.is_empty() && complete {
        String::new()
    } else {
        format!(
            "Listed {} entr{}{}:",
            entries.len(),
            if entries.len() == 1 { "y" } else { "ies" },
            if complete { "" } else { " (partial)" }
        )
    };
    for entry in &entries {
        text.push('\n');
        text.push_str(&entry.resource_id);
        if entry.kind == "directory" {
            text.push('/');
        }
    }
    append_partial_text(&mut text, &diagnostics, next_cursor.as_deref());

    let structured = json!({
        "file_discovery": {
            "schema_version": 1,
            "operation": "list_files",
            "root": root_id.as_ref(),
            "entries": &entries,
            "page": {
                "complete": complete,
                "next_cursor": next_cursor.as_deref(),
                "limit": limit,
            },
            "coverage": &report.stats,
            "diagnostics": &diagnostics,
        }
    });
    resource_batch.commit();
    let mut result = if complete {
        ToolHandlerResult::success_structured(text, structured)
    } else {
        let continuation = next_cursor.as_ref().map(|cursor| json!({"cursor": cursor}));
        ToolHandlerResult::partial_structured(
            text,
            structured,
            report_failures(&report, output_limited),
            continuation,
        )
    };
    result.usage = ToolUsage {
        output_bytes: u64::try_from(result.content().len()).unwrap_or(u64::MAX),
        elapsed_ms: report.stats.elapsed_ms,
        ..ToolUsage::default()
    };
    result
}

/// Compatibility projection for leaf callers; registry/provider paths retain
/// the typed partial result from [`execute_list_files_typed`].
#[cfg(test)]
pub fn execute_list_files(
    run: &std::sync::Arc<crate::tools::security::ToolRunContext>,
    args: &HashMap<String, Value>,
) -> (String, bool) {
    execute_list_files_typed(run, args).into_legacy()
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
    if report.termination == discovery::WalkTermination::Cancelled {
        failures.push(ToolFailure::new(
            ToolFailureCode::Cancelled,
            "Directory listing was cancelled before coverage completed".to_string(),
            ToolRetryability::Never,
        ));
    } else if report.termination == discovery::WalkTermination::Deadline {
        failures.push(ToolFailure::new(
            ToolFailureCode::DeadlineExceeded,
            "Directory listing exceeded its traversal deadline".to_string(),
            ToolRetryability::Safe,
        ));
    } else if !report.diagnostics.is_empty() {
        failures.push(ToolFailure::new(
            ToolFailureCode::External,
            "Directory listing omitted entries; inspect typed diagnostics".to_string(),
            ToolRetryability::Safe,
        ));
    }
    if output_limited {
        failures.push(ToolFailure::new(
            ToolFailureCode::External,
            "Directory listing reached its rendered-output limit".to_string(),
            ToolRetryability::Safe,
        ));
    }
    failures
}

fn append_partial_text(text: &mut String, diagnostics: &[Value], next_cursor: Option<&str>) {
    if diagnostics.is_empty() && next_cursor.is_none() {
        return;
    }
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
    use serde_json::json;

    fn test_run(root: &std::path::Path) -> std::sync::Arc<crate::tools::ToolRunContext> {
        crate::tools::security::test_run_context_for(root)
    }

    #[test]
    fn list_files_pages_in_repeatable_directory_first_order() {
        let root = tempfile::tempdir().expect("root");
        std::fs::write(root.path().join("z-file"), "x").expect("file");
        std::fs::create_dir(root.path().join("z-dir")).expect("directory");
        std::fs::write(root.path().join("a-file"), "x").expect("file");
        std::fs::create_dir(root.path().join("a-dir")).expect("directory");
        let run = test_run(root.path());
        let first_args = HashMap::from([
            ("path".to_string(), json!(root.path())),
            ("limit".to_string(), json!(2)),
        ]);

        let first = execute_list_files_typed(&run, &first_args);
        assert!(matches!(
            &first.outcome,
            crate::tools::ToolOutcome::Partial { .. }
        ));
        assert!(first.content().contains("a-dir/\nz-dir/"));
        let structured = match &first.outcome {
            crate::tools::ToolOutcome::Partial { content, .. } => content
                .structured
                .as_ref()
                .expect("structured partial listing"),
            other => panic!("expected partial listing, got {other:?}"),
        };
        let cursor = structured
            .pointer("/file_discovery/page/next_cursor")
            .and_then(Value::as_str)
            .expect("next cursor");
        let second_args = HashMap::from([
            ("path".to_string(), json!(root.path())),
            ("limit".to_string(), json!(2)),
            ("cursor".to_string(), json!(cursor)),
        ]);
        let second = execute_list_files_typed(&run, &second_args);

        assert!(
            !matches!(&second.outcome, crate::tools::ToolOutcome::Error { .. }),
            "{}",
            second.content()
        );
        assert!(second.content().contains("a-file\nz-file"));
    }

    #[test]
    fn list_files_observes_run_cancellation() {
        let root = tempfile::tempdir().expect("root");
        std::fs::write(root.path().join("entry"), "x").expect("file");
        let run = test_run(root.path());
        let _receipt = run
            .runtime()
            .cancellation()
            .cancel(crate::runtime::CancellationReason::User);
        let args = HashMap::from([("path".to_string(), json!(root.path()))]);

        let result = execute_list_files_typed(&run, &args);

        assert!(matches!(
            &result.outcome,
            crate::tools::ToolOutcome::Partial { .. }
        ));
        assert!(result.content().contains("cancelled"));
    }
}
