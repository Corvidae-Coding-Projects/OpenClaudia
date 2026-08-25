//! Bounded streaming grep over the shared secure discovery walker.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::time::Instant;

use regex::RegexBuilder;
use serde::Serialize;
use serde_json::{json, Value};

use super::{discovery, resolve_path, secure_fs};
use crate::tools::args::ToolArgs as _;
use crate::tools::{ToolFailure, ToolFailureCode, ToolHandlerResult, ToolRetryability, ToolUsage};

const DEFAULT_PAGE_LIMIT: usize = 200;
const MAX_PAGE_LIMIT: usize = 500;
const MAX_PATTERN_BYTES: usize = 16 * 1024;
const MAX_REGEX_COMPILED_BYTES: usize = 8 * 1024 * 1024;
const MAX_CONTEXT_LINES: usize = 20;
const MAX_FILES_SCANNED: usize = 10_000;
const MAX_FILE_BYTES: usize = 5 * 1024 * 1024;
const MAX_DECODED_BYTES: usize = 64 * 1024 * 1024;
const MAX_REGEX_WORK_BYTES: usize = 64 * 1024 * 1024;
const MAX_LINE_BYTES: usize = 64 * 1024;
const MAX_RENDERED_LINE_BYTES: usize = 8 * 1024;
const MAX_SEARCH_BODY_BYTES: usize = discovery::MAX_RENDERED_BYTES - 16 * 1024;
const MAX_SEARCH_DIAGNOSTICS: usize = 32;

#[derive(Clone, Serialize)]
struct GrepMatch {
    resource_id: String,
    line: u64,
}

#[derive(Clone, Serialize)]
struct GrepOutputLine {
    resource_id: String,
    line: u64,
    kind: &'static str,
    text: String,
    truncated: bool,
}

#[derive(Clone)]
struct BufferedLine {
    line: u64,
    text: String,
    truncated: bool,
}

#[allow(clippy::struct_excessive_bools)] // Independent terminal causes remain explicit in partial-result diagnostics.
struct GrepState<'a> {
    regex: &'a regex::Regex,
    context_lines: usize,
    page_limit: usize,
    started: Instant,
    cursor_resource: Option<&'a str>,
    cursor_line: u64,
    cursor_seen: bool,
    matches: Vec<GrepMatch>,
    output_lines: Vec<GrepOutputLine>,
    rendered_bytes: usize,
    files_considered: usize,
    files_scanned: usize,
    decoded_bytes: usize,
    regex_work_bytes: usize,
    long_lines_skipped: usize,
    diagnostics: Vec<Value>,
    diagnostics_omitted: usize,
    has_more: bool,
    continuable: bool,
    output_limited: bool,
    cancelled: bool,
    deadline_exceeded: bool,
}

impl<'a> GrepState<'a> {
    fn new(
        regex: &'a regex::Regex,
        context_lines: usize,
        page_limit: usize,
        cursor: Option<(&'a str, u64)>,
    ) -> Self {
        Self {
            regex,
            context_lines,
            page_limit,
            started: Instant::now(),
            cursor_resource: cursor.map(|(resource, _)| resource),
            cursor_line: cursor.map_or(0, |(_, line)| line),
            cursor_seen: cursor.is_none(),
            matches: Vec::with_capacity(page_limit),
            output_lines: Vec::new(),
            rendered_bytes: 0,
            files_considered: 0,
            files_scanned: 0,
            decoded_bytes: 0,
            regex_work_bytes: 0,
            long_lines_skipped: 0,
            diagnostics: Vec::new(),
            diagnostics_omitted: 0,
            has_more: false,
            continuable: false,
            output_limited: false,
            cancelled: false,
            deadline_exceeded: false,
        }
    }

    fn push_diagnostic(
        &mut self,
        code: &'static str,
        resource_id: &str,
        message: impl Into<String>,
    ) {
        if self.diagnostics.len() < MAX_SEARCH_DIAGNOSTICS {
            self.diagnostics.push(json!({
                "code": code,
                "resource_id": resource_id,
                "message": message.into(),
            }));
        } else {
            self.diagnostics_omitted = self.diagnostics_omitted.saturating_add(1);
        }
    }

    #[allow(clippy::too_many_lines)] // One pinned-file read owns every admission and search budget update.
    fn visit_file(
        &mut self,
        run: &crate::tools::ToolRunContext,
        batch: &mut crate::guardrails::PathResourceBatch,
        entry: &discovery::WalkEntry<'_>,
    ) -> Result<discovery::WalkControl, String> {
        if !self.cursor_seen {
            if self.cursor_resource == Some(entry.resource_id) {
                self.cursor_seen = true;
            } else {
                return Ok(discovery::WalkControl::Continue);
            }
        }
        if self.files_considered >= MAX_FILES_SCANNED {
            self.has_more = true;
            self.continuable = true;
            self.push_diagnostic(
                "file_limit",
                entry.resource_id,
                format!("grep reached its {MAX_FILES_SCANNED}-file scan budget"),
            );
            return Ok(discovery::WalkControl::Stop);
        }
        if self.started.elapsed() >= discovery::MAX_WALK_DURATION {
            self.has_more = true;
            self.continuable = true;
            self.deadline_exceeded = true;
            self.push_diagnostic(
                "deadline_exceeded",
                entry.resource_id,
                "grep exceeded its wall-clock search budget",
            );
            return Ok(discovery::WalkControl::Stop);
        }
        if run.runtime().cancellation().is_cancelled() {
            self.has_more = true;
            self.continuable = true;
            self.cancelled = true;
            self.push_diagnostic(
                "cancelled",
                entry.resource_id,
                "grep stopped because this run was cancelled",
            );
            return Ok(discovery::WalkControl::Stop);
        }

        self.files_considered = self.files_considered.saturating_add(1);
        batch.reserve_file(run, entry.absolute_path)?;
        let mut file = match entry.open_regular() {
            Ok(file) => file,
            Err(error) => {
                self.push_diagnostic("file_open_failed", entry.resource_id, error);
                return Ok(discovery::WalkControl::Continue);
            }
        };
        let metadata = match file.metadata() {
            Ok(metadata) => metadata,
            Err(error) => {
                self.push_diagnostic(
                    "file_metadata_failed",
                    entry.resource_id,
                    format!("failed to inspect confined file: {error}"),
                );
                return Ok(discovery::WalkControl::Continue);
            }
        };
        let file_bytes = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
        if file_bytes > MAX_FILE_BYTES {
            self.push_diagnostic(
                "file_too_large",
                entry.resource_id,
                format!("file exceeds the {MAX_FILE_BYTES}-byte per-file search budget"),
            );
            return Ok(discovery::WalkControl::Continue);
        }
        if self.decoded_bytes.saturating_add(file_bytes) > MAX_DECODED_BYTES {
            self.has_more = true;
            self.continuable = true;
            self.push_diagnostic(
                "decoded_bytes_limit",
                entry.resource_id,
                format!("grep reached its {MAX_DECODED_BYTES}-byte decoded-input budget"),
            );
            return Ok(discovery::WalkControl::Stop);
        }
        let bytes = match secure_fs::read_stable_bounded_bytes(
            &mut file,
            entry.absolute_path,
            MAX_FILE_BYTES,
        ) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.push_diagnostic("file_read_failed", entry.resource_id, error);
                return Ok(discovery::WalkControl::Continue);
            }
        };
        let Ok(content) = std::str::from_utf8(&bytes) else {
            self.push_diagnostic(
                "non_utf8_file",
                entry.resource_id,
                "file omitted because native grep accepts UTF-8 text only",
            );
            return Ok(discovery::WalkControl::Continue);
        };
        self.files_scanned = self.files_scanned.saturating_add(1);
        self.decoded_bytes = self.decoded_bytes.saturating_add(bytes.len());
        let after_line = if self.cursor_resource == Some(entry.resource_id) {
            self.cursor_line
        } else {
            0
        };
        let stop = self.scan_content(run, entry.resource_id, content, after_line);
        Ok(if stop {
            discovery::WalkControl::Stop
        } else {
            discovery::WalkControl::Continue
        })
    }

    #[allow(clippy::too_many_lines)] // Match admission and bounded context selection share one streaming state machine.
    fn scan_content(
        &mut self,
        run: &crate::tools::ToolRunContext,
        resource_id: &str,
        content: &str,
        after_line: u64,
    ) -> bool {
        let mut previous = VecDeque::<Option<BufferedLine>>::with_capacity(self.context_lines);
        let mut selected = BTreeMap::<u64, GrepOutputLine>::new();
        let mut after_context_remaining = 0usize;
        let mut file_long_lines = 0usize;
        let mut stop = false;

        for (index, raw_line) in content.split_terminator('\n').enumerate() {
            if index % 256 == 0 {
                if run.runtime().cancellation().is_cancelled() {
                    self.has_more = true;
                    self.continuable = true;
                    self.cancelled = true;
                    self.push_diagnostic(
                        "cancelled",
                        resource_id,
                        "grep stopped because this run was cancelled",
                    );
                    stop = true;
                    break;
                }
                if self.started.elapsed() >= discovery::MAX_WALK_DURATION {
                    self.has_more = true;
                    self.continuable = true;
                    self.deadline_exceeded = true;
                    self.push_diagnostic(
                        "deadline_exceeded",
                        resource_id,
                        "grep exceeded its wall-clock search budget",
                    );
                    stop = true;
                    break;
                }
            }
            let line_number = u64::try_from(index).unwrap_or(u64::MAX).saturating_add(1);
            let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
            if line.len() > MAX_LINE_BYTES {
                file_long_lines = file_long_lines.saturating_add(1);
                self.long_lines_skipped = self.long_lines_skipped.saturating_add(1);
                if after_context_remaining > 0 {
                    after_context_remaining = after_context_remaining.saturating_sub(1);
                }
                if self.context_lines > 0 {
                    if previous.len() >= self.context_lines {
                        let _oldest = previous.pop_front();
                    }
                    previous.push_back(None);
                }
                continue;
            }

            let is_match = if line_number > after_line {
                if self.regex_work_bytes.saturating_add(line.len()) > MAX_REGEX_WORK_BYTES {
                    self.has_more = true;
                    self.continuable = true;
                    self.push_diagnostic(
                        "regex_work_limit",
                        resource_id,
                        format!("grep reached its {MAX_REGEX_WORK_BYTES}-byte regex-work budget"),
                    );
                    stop = true;
                    break;
                }
                self.regex_work_bytes = self.regex_work_bytes.saturating_add(line.len());
                self.regex.is_match(line)
            } else {
                false
            };
            if is_match && self.matches.len() >= self.page_limit {
                self.has_more = true;
                self.continuable = true;
                stop = true;
                break;
            }

            let buffered = bounded_line(line_number, line);
            if is_match {
                if !self.insert_line(resource_id, buffered.clone(), true, &mut selected) {
                    self.has_more = true;
                    self.continuable = true;
                    self.output_limited = true;
                    stop = true;
                    break;
                }
                self.matches.push(GrepMatch {
                    resource_id: resource_id.to_string(),
                    line: line_number,
                });
                for context_line in previous.iter().flatten() {
                    if !self.insert_line(resource_id, context_line.clone(), false, &mut selected) {
                        self.has_more = true;
                        self.continuable = true;
                        self.output_limited = true;
                        stop = true;
                        break;
                    }
                }
                if stop {
                    break;
                }
                after_context_remaining = self.context_lines;
            } else if after_context_remaining > 0 {
                if !self.insert_line(resource_id, buffered.clone(), false, &mut selected) {
                    self.has_more = true;
                    self.continuable = true;
                    self.output_limited = true;
                    stop = true;
                    break;
                }
                after_context_remaining = after_context_remaining.saturating_sub(1);
            }
            if self.context_lines > 0 {
                if previous.len() >= self.context_lines {
                    let _oldest = previous.pop_front();
                }
                previous.push_back(Some(buffered));
            }
        }

        if file_long_lines > 0 {
            self.push_diagnostic(
                "line_length_limit",
                resource_id,
                format!(
                    "{file_long_lines} line(s) exceeded the {MAX_LINE_BYTES}-byte regex line budget and were omitted"
                ),
            );
        }
        self.output_lines.extend(selected.into_values());
        stop
    }

    fn insert_line(
        &mut self,
        resource_id: &str,
        line: BufferedLine,
        is_match: bool,
        selected: &mut BTreeMap<u64, GrepOutputLine>,
    ) -> bool {
        if let Some(existing) = selected.get_mut(&line.line) {
            if is_match {
                existing.kind = "match";
            }
            return true;
        }
        let next_bytes = rendered_line_bytes(resource_id, line.line, &line.text);
        if self.rendered_bytes.saturating_add(next_bytes) > MAX_SEARCH_BODY_BYTES {
            return false;
        }
        self.rendered_bytes = self.rendered_bytes.saturating_add(next_bytes);
        selected.insert(
            line.line,
            GrepOutputLine {
                resource_id: resource_id.to_string(),
                line: line.line,
                kind: if is_match { "match" } else { "context" },
                text: line.text,
                truncated: line.truncated,
            },
        );
        true
    }
}

/// Typed grep execution used by the canonical registry.
#[allow(clippy::too_many_lines)] // Parsing, traversal, pagination, and typed rendering are one tool transaction.
pub fn execute_grep_typed(
    run: &std::sync::Arc<crate::tools::security::ToolRunContext>,
    args: &HashMap<String, Value>,
) -> ToolHandlerResult {
    let pattern = match args.arg_str_strict("pattern") {
        Ok(pattern) => pattern,
        Err(error) => return invalid_arguments(error.to_string()),
    };
    if pattern.len() > MAX_PATTERN_BYTES {
        return invalid_arguments(format!(
            "Invalid regex: maximum pattern length is {MAX_PATTERN_BYTES} bytes"
        ));
    }
    let case_insensitive = match args.arg_bool_or_strict("case_insensitive", false) {
        Ok(value) => value,
        Err(error) => return invalid_arguments(error.to_string()),
    };
    let regex = match RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .size_limit(MAX_REGEX_COMPILED_BYTES)
        .dfa_size_limit(MAX_REGEX_COMPILED_BYTES)
        .build()
    {
        Ok(regex) => regex,
        Err(error) => return invalid_arguments(format!("Invalid regex '{pattern}': {error}")),
    };
    let raw_path = match args.arg_str_or_strict("path", ".") {
        Ok(path) => path,
        Err(error) => return invalid_arguments(error.to_string()),
    };
    let root = match resolve_path(run, raw_path) {
        Ok(path) => path,
        Err(error) => return invalid_arguments(error),
    };
    let context_lines = match parse_context_lines(args.get("context_lines")) {
        Ok(context) => context,
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
    let binding = discovery::cursor_binding(&[
        "grep",
        &root_id,
        pattern,
        if case_insensitive { "true" } else { "false" },
        &context_lines.to_string(),
    ]);
    let cursor = match discovery::decode_cursor(cursor_arg, &binding) {
        Ok(None) => None,
        Ok(Some(discovery::CursorPosition::Match { resource_id, line })) if line > 0 => {
            Some((resource_id, line))
        }
        Ok(Some(discovery::CursorPosition::Match { .. })) => {
            return invalid_arguments("Invalid cursor: grep match line must be positive")
        }
        Ok(Some(discovery::CursorPosition::Entry { .. })) => {
            return invalid_arguments("Invalid cursor: expected a grep-match position")
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
    let mut search = GrepState::new(
        &regex,
        context_lines,
        limit,
        cursor
            .as_ref()
            .map(|(resource_id, line)| (resource_id.as_str(), *line)),
    );
    let walk = discovery::walk(
        run,
        &root,
        discovery::WalkOptions {
            recursive: true,
            visit_directories: true,
            directories_first: false,
            ignore_policy: discovery::IgnorePolicy::Standard,
        },
        |entry| {
            if entry.kind == discovery::WalkEntryKind::Directory {
                resource_batch.check_scope(run, entry.absolute_path)?;
                Ok(discovery::WalkControl::Continue)
            } else {
                search.visit_file(run, &mut resource_batch, &entry)
            }
        },
    );
    let report = match walk {
        Ok(report) => report,
        Err(discovery::WalkError::Visitor(error)) => return policy_error(error),
        Err(discovery::WalkError::Filesystem(error)) => {
            return ToolHandlerResult::error(ToolFailure::new(
                ToolFailureCode::External,
                format!(
                    "Failed to securely search grep root '{}': {error}",
                    root.display()
                ),
                ToolRetryability::Safe,
            ))
        }
    };

    if cursor.is_some() && !search.cursor_seen {
        if report.is_complete() {
            return invalid_arguments("Invalid cursor: its grep file no longer exists");
        }
        search.has_more = true;
        search.continuable = true;
    }
    for diagnostic in &report.diagnostics {
        search.push_diagnostic(
            diagnostic.code,
            &diagnostic.resource_id,
            diagnostic.message.clone(),
        );
    }
    search.diagnostics_omitted = search
        .diagnostics_omitted
        .saturating_add(report.stats.diagnostics_omitted);
    if search.output_limited {
        search.push_diagnostic(
            "rendered_output_limit",
            "",
            format!(
                "grep reached its {}-byte rendered-output budget",
                discovery::MAX_RENDERED_BYTES
            ),
        );
    }
    if search.diagnostics_omitted > 0 {
        let omitted = search.diagnostics_omitted;
        search.diagnostics.push(json!({
            "code": "diagnostics_omitted",
            "resource_id": "",
            "message": format!("{omitted} additional diagnostics were omitted"),
        }));
    }

    let walker_incomplete =
        !report.is_complete() && report.termination != discovery::WalkTermination::Visitor;
    let complete = !search.has_more && !walker_incomplete && search.diagnostics.is_empty();
    let next_cursor = if !complete && search.continuable {
        search.matches.last().map(|last_match| {
            discovery::encode_cursor(
                &binding,
                discovery::CursorPosition::Match {
                    resource_id: last_match.resource_id.clone(),
                    line: last_match.line,
                },
            )
        })
    } else {
        None
    };
    let text = render_text(
        &search.output_lines,
        search.matches.len(),
        search.files_scanned,
        complete,
        &search.diagnostics,
        next_cursor.as_deref(),
    );
    let structured = json!({
        "file_search": {
            "schema_version": 1,
            "operation": "grep",
            "root": root_id.as_ref(),
            "pattern": pattern,
            "case_insensitive": case_insensitive,
            "context_lines": context_lines,
            "matches": &search.matches,
            "lines": &search.output_lines,
            "page": {
                "complete": complete,
                "next_cursor": next_cursor.as_deref(),
                "limit": limit,
            },
            "coverage": {
                "entries_discovered": report.stats.entries_discovered,
                "path_bytes_discovered": report.stats.path_bytes_discovered,
                "directories_opened": report.stats.directories_opened,
                "ignored_directories": report.stats.ignored_directories,
                "files_considered": search.files_considered,
                "files_scanned": search.files_scanned,
                "decoded_bytes": search.decoded_bytes,
                "regex_work_bytes": search.regex_work_bytes,
                "long_lines_skipped": search.long_lines_skipped,
                "elapsed_ms": u64::try_from(search.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            },
            "diagnostics": &search.diagnostics,
            "ignore_policy": discovery::STANDARD_IGNORED_DIRECTORIES,
        }
    });
    resource_batch.commit();
    let mut result = if complete {
        ToolHandlerResult::success_structured(text, structured)
    } else {
        ToolHandlerResult::partial_structured(
            text,
            structured,
            search_failures(&search, &report),
            next_cursor.as_ref().map(|cursor| json!({"cursor": cursor})),
        )
    };
    result.usage = ToolUsage {
        input_bytes: u64::try_from(search.decoded_bytes).unwrap_or(u64::MAX),
        output_bytes: u64::try_from(result.content().len()).unwrap_or(u64::MAX),
        elapsed_ms: u64::try_from(search.started.elapsed().as_millis()).unwrap_or(u64::MAX),
    };
    result
}

fn parse_context_lines(value: Option<&Value>) -> Result<usize, String> {
    let Some(value) = value else {
        return Ok(0);
    };
    let Some(value) = value.as_u64() else {
        return Err("Error: context_lines must be a non-negative integer".to_string());
    };
    let Ok(value) = usize::try_from(value) else {
        return Err(format!(
            "Error: context_lines must not exceed {MAX_CONTEXT_LINES}"
        ));
    };
    if value > MAX_CONTEXT_LINES {
        return Err(format!(
            "Error: context_lines must not exceed {MAX_CONTEXT_LINES}"
        ));
    }
    Ok(value)
}

fn bounded_line(line: u64, text: &str) -> BufferedLine {
    if text.len() <= MAX_RENDERED_LINE_BYTES {
        return BufferedLine {
            line,
            text: text.to_string(),
            truncated: false,
        };
    }
    let mut boundary = MAX_RENDERED_LINE_BYTES.min(text.len());
    while !text.is_char_boundary(boundary) {
        boundary = boundary.saturating_sub(1);
    }
    let omitted = text.len().saturating_sub(boundary);
    BufferedLine {
        line,
        text: format!("{}… <{omitted} bytes omitted>", &text[..boundary]),
        truncated: true,
    }
}

fn rendered_line_bytes(resource_id: &str, line: u64, text: &str) -> usize {
    resource_id
        .len()
        .saturating_add(line.to_string().len())
        .saturating_add(text.len())
        .saturating_add(3)
}

fn render_text(
    lines: &[GrepOutputLine],
    matches: usize,
    files_scanned: usize,
    complete: bool,
    diagnostics: &[Value],
    next_cursor: Option<&str>,
) -> String {
    let mut text = format!(
        "Found {matches} match{} across {files_scanned} scanned file{}{}:",
        if matches == 1 { "" } else { "es" },
        if files_scanned == 1 { "" } else { "s" },
        if complete { "" } else { " (partial)" }
    );
    let mut previous: Option<(&str, u64)> = None;
    for line in lines {
        if previous.is_some_and(|(resource, number)| {
            resource != line.resource_id || number.saturating_add(1) < line.line
        }) {
            text.push_str("\n--");
        }
        text.push('\n');
        text.push_str(&line.resource_id);
        let delimiter = if line.kind == "match" { ':' } else { '-' };
        text.push(delimiter);
        text.push_str(&line.line.to_string());
        text.push(delimiter);
        text.push_str(&line.text);
        previous = Some((&line.resource_id, line.line));
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
    text
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

fn search_failures(search: &GrepState<'_>, report: &discovery::WalkReport) -> Vec<ToolFailure> {
    if search.cancelled || report.termination == discovery::WalkTermination::Cancelled {
        return vec![ToolFailure::new(
            ToolFailureCode::Cancelled,
            "Grep was cancelled before search coverage completed".to_string(),
            ToolRetryability::Never,
        )];
    }
    if search.deadline_exceeded || report.termination == discovery::WalkTermination::Deadline {
        return vec![ToolFailure::new(
            ToolFailureCode::DeadlineExceeded,
            "Grep exceeded its search deadline".to_string(),
            ToolRetryability::Safe,
        )];
    }
    if !search.diagnostics.is_empty() || !report.diagnostics.is_empty() {
        return vec![ToolFailure::new(
            ToolFailureCode::External,
            "Grep coverage is partial; inspect typed diagnostics".to_string(),
            ToolRetryability::Safe,
        )];
    }
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn write_file(root: &Path, relative: &str, contents: &str) {
        let path = root.join(relative);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("parent");
        }
        std::fs::write(path, contents).expect("file");
    }

    #[test]
    fn grep_paginates_matches_without_collecting_the_file() {
        let root = tempfile::tempdir().expect("root");
        write_file(root.path(), "hits.txt", "hit one\nhit two\nhit three\n");
        let run = crate::tools::security::test_run_context_for(root.path());
        let first_args = HashMap::from([
            ("path".to_string(), json!(root.path())),
            ("pattern".to_string(), json!("hit")),
            ("limit".to_string(), json!(2)),
        ]);

        let first = execute_grep_typed(&run, &first_args);

        assert!(
            matches!(&first.outcome, crate::tools::ToolOutcome::Partial { .. }),
            "{}",
            first.content()
        );
        assert!(first.content().contains("hits.txt:1:hit one"));
        assert!(first.content().contains("hits.txt:2:hit two"));
        assert!(!first.content().contains("hit three"));
        let cursor = match &first.outcome {
            crate::tools::ToolOutcome::Partial { content, .. } => content
                .structured
                .as_ref()
                .and_then(|value| value.pointer("/file_search/page/next_cursor"))
                .and_then(Value::as_str)
                .expect("cursor"),
            other => panic!("expected partial grep, got {other:?}"),
        };
        let second_args = HashMap::from([
            ("path".to_string(), json!(root.path())),
            ("pattern".to_string(), json!("hit")),
            ("limit".to_string(), json!(2)),
            ("cursor".to_string(), json!(cursor)),
        ]);
        let second = execute_grep_typed(&run, &second_args);

        assert!(
            !matches!(&second.outcome, crate::tools::ToolOutcome::Error { .. }),
            "{}",
            second.content()
        );
        assert!(second.content().contains("hits.txt:3:hit three"));
        assert!(!second.content().contains("hit one"));
    }

    #[test]
    fn grep_page_does_not_render_the_next_match_as_context() {
        let root = tempfile::tempdir().expect("root");
        write_file(root.path(), "hits.txt", "hit one\nhit two\ntail\n");
        let run = crate::tools::security::test_run_context_for(root.path());
        let args = HashMap::from([
            ("path".to_string(), json!(root.path())),
            ("pattern".to_string(), json!("hit")),
            ("context_lines".to_string(), json!(1)),
            ("limit".to_string(), json!(1)),
        ]);

        let result = execute_grep_typed(&run, &args);

        assert!(matches!(
            &result.outcome,
            crate::tools::ToolOutcome::Partial { .. }
        ));
        assert!(result.content().contains("hits.txt:1:hit one"));
        assert!(
            !result.content().contains("hit two"),
            "the next page's match must not leak into this page as context: {}",
            result.content()
        );
    }

    #[test]
    fn grep_deduplicates_overlapping_context_and_numbers_it_correctly() {
        let root = tempfile::tempdir().expect("root");
        write_file(
            root.path(),
            "context.txt",
            "zero\none hit\ntwo hit\nthree\nfour\n",
        );
        let run = crate::tools::security::test_run_context_for(root.path());
        let args = HashMap::from([
            ("path".to_string(), json!(root.path())),
            ("pattern".to_string(), json!("hit")),
            ("context_lines".to_string(), json!(2)),
        ]);

        let result = execute_grep_typed(&run, &args);

        assert!(
            !matches!(&result.outcome, crate::tools::ToolOutcome::Error { .. }),
            "{}",
            result.content()
        );
        assert_eq!(result.content().matches("context.txt-1-zero").count(), 1);
        assert_eq!(result.content().matches("context.txt:2:one hit").count(), 1);
        assert_eq!(result.content().matches("context.txt:3:two hit").count(), 1);
        assert_eq!(result.content().matches("context.txt-4-three").count(), 1);
    }

    #[test]
    fn grep_rejects_unbounded_context_request() {
        let args = HashMap::from([
            ("pattern".to_string(), json!("hit")),
            ("context_lines".to_string(), json!(u64::MAX)),
        ]);

        let result = execute_grep_typed(crate::tools::security::test_run_context(), &args);

        assert!(matches!(
            &result.outcome,
            crate::tools::ToolOutcome::Error { .. }
        ));
        assert!(result.content().contains("must not exceed"));
    }

    #[test]
    fn grep_reports_overlong_lines_as_partial_instead_of_searching_them() {
        let root = tempfile::tempdir().expect("root");
        write_file(
            root.path(),
            "long.txt",
            &("x".repeat(MAX_LINE_BYTES + 1) + "needle\n"),
        );
        let run = crate::tools::security::test_run_context_for(root.path());
        let args = HashMap::from([
            ("path".to_string(), json!(root.path())),
            ("pattern".to_string(), json!("needle")),
        ]);

        let result = execute_grep_typed(&run, &args);

        assert!(matches!(
            &result.outcome,
            crate::tools::ToolOutcome::Partial { .. }
        ));
        assert!(result.content().contains("line_length_limit"));
    }
}
