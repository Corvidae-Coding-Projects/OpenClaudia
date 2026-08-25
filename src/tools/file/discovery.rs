//! Shared bounded traversal and pagination primitives for read-side file tools.
//!
//! The walker keeps filesystem authority descriptor-relative, never follows
//! links, sorts every admitted directory before visiting it, and checks the
//! run cancellation root and wall-clock deadline between entries. Directory
//! enumeration is bounded before retaining names; aggregate discovery budgets
//! then bound the complete invocation rather than only its rendered page.

use std::collections::HashSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use super::secure_fs;
use crate::tools::security::ToolRunContext;

pub(super) const MAX_WALK_ENTRIES: usize = 50_000;
pub(super) const MAX_WALK_PATH_BYTES: usize = 8 * 1024 * 1024;
pub(super) const MAX_DIRECTORY_ENTRIES: usize = 10_000;
pub(super) const MAX_DIRECTORY_NAME_BYTES: usize = 2 * 1024 * 1024;
pub(super) const MAX_WALK_DEPTH: usize = 128;
pub(super) const MAX_WALK_DURATION: Duration = Duration::from_secs(10);
pub(super) const MAX_CURSOR_BYTES: usize = 4 * 1024;
pub(super) const MAX_RENDERED_BYTES: usize = 256 * 1024;
const MAX_DIAGNOSTICS: usize = 32;
const CURSOR_SCHEMA_VERSION: u8 = 1;

pub(super) const STANDARD_IGNORED_DIRECTORIES: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    ".cache",
    ".svelte-kit",
    ".next",
    "dist",
    "build",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum IgnorePolicy {
    None,
    Standard,
}

#[derive(Clone, Copy, Debug)]
pub(super) struct WalkOptions {
    pub(super) recursive: bool,
    pub(super) visit_directories: bool,
    pub(super) directories_first: bool,
    pub(super) ignore_policy: IgnorePolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WalkEntryKind {
    Directory,
    Regular,
}

pub(super) struct WalkEntry<'a> {
    pub(super) resource_id: &'a str,
    pub(super) absolute_path: &'a Path,
    pub(super) kind: WalkEntryKind,
    parent: &'a secure_fs::SecureDirectory,
    name: &'a std::ffi::OsStr,
}

impl WalkEntry<'_> {
    pub(super) fn open_regular(&self) -> Result<std::fs::File, String> {
        if self.kind != WalkEntryKind::Regular {
            return Err(format!(
                "'{}' is not a regular file",
                self.absolute_path.display()
            ));
        }
        self.parent.open_child_regular(self.name)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WalkControl {
    Continue,
    Stop,
}

pub(super) enum WalkError {
    Filesystem(String),
    Visitor(String),
}

#[derive(Clone, Debug, Serialize)]
pub(super) struct WalkDiagnostic {
    pub(super) code: &'static str,
    pub(super) resource_id: String,
    pub(super) message: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub(super) struct WalkStats {
    pub(super) entries_discovered: usize,
    pub(super) path_bytes_discovered: usize,
    pub(super) directories_opened: usize,
    pub(super) ignored_directories: usize,
    pub(super) skipped_non_regular_entries: usize,
    pub(super) diagnostics_omitted: usize,
    pub(super) elapsed_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WalkTermination {
    Complete,
    Visitor,
    Cancelled,
    Deadline,
    EntryBudget,
    PathBudget,
}

pub(super) struct WalkReport {
    pub(super) termination: WalkTermination,
    pub(super) diagnostics: Vec<WalkDiagnostic>,
    pub(super) stats: WalkStats,
}

impl WalkReport {
    pub(super) fn is_complete(&self) -> bool {
        self.termination == WalkTermination::Complete && self.diagnostics.is_empty()
    }
}

struct Frame {
    directory: secure_fs::SecureDirectory,
    relative: PathBuf,
    entries: Vec<secure_fs::SecureDirEntry>,
    next_entry: usize,
    depth: usize,
    terminal_after: Option<WalkTermination>,
}

struct WalkState {
    started: Instant,
    termination: WalkTermination,
    diagnostics: Vec<WalkDiagnostic>,
    stats: WalkStats,
}

impl WalkState {
    fn push_diagnostic(
        &mut self,
        code: &'static str,
        resource_id: impl Into<String>,
        message: impl Into<String>,
    ) {
        if self.diagnostics.len() < MAX_DIAGNOSTICS {
            self.diagnostics.push(WalkDiagnostic {
                code,
                resource_id: resource_id.into(),
                message: message.into(),
            });
        } else {
            self.stats.diagnostics_omitted = self.stats.diagnostics_omitted.saturating_add(1);
        }
    }

    fn finish(mut self) -> WalkReport {
        self.stats.elapsed_ms =
            u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        WalkReport {
            termination: self.termination,
            diagnostics: self.diagnostics,
            stats: self.stats,
        }
    }
}

/// Walk a securely opened tree in deterministic depth-first order.
///
/// The visitor sees only UTF-8 resource IDs because those IDs must be usable
/// in a later JSON tool call. Non-UTF-8 entries remain contained and are
/// reported as partial coverage rather than lossy-converted into collisions.
#[allow(clippy::too_many_lines)] // Traversal, containment, and terminal-budget state form one auditable loop.
pub(super) fn walk<F>(
    run: &Arc<ToolRunContext>,
    root: &Path,
    options: WalkOptions,
    mut visitor: F,
) -> Result<WalkReport, WalkError>
where
    F: FnMut(WalkEntry<'_>) -> Result<WalkControl, String>,
{
    let started = Instant::now();
    let mut state = WalkState {
        started,
        termination: WalkTermination::Complete,
        diagnostics: Vec::new(),
        stats: WalkStats::default(),
    };
    if run.runtime().cancellation().is_cancelled() {
        state.termination = WalkTermination::Cancelled;
        state.push_diagnostic(
            "cancelled",
            "",
            "file discovery stopped because this run was cancelled",
        );
        return Ok(state.finish());
    }
    let root_directory = secure_fs::open_directory(run, root).map_err(WalkError::Filesystem)?;
    let root_identity = root_directory.identity().map_err(WalkError::Filesystem)?;
    let mut identities = HashSet::from([root_identity]);
    state.stats.directories_opened = 1;
    let Some(root_frame) = load_frame(
        root_directory,
        PathBuf::new(),
        0,
        true,
        options.directories_first,
        &mut state,
    )
    .map_err(WalkError::Filesystem)?
    else {
        return Ok(state.finish());
    };
    let mut stack = vec![root_frame];

    while !stack.is_empty() {
        if run.runtime().cancellation().is_cancelled() {
            state.termination = WalkTermination::Cancelled;
            state.push_diagnostic(
                "cancelled",
                "",
                "file discovery stopped because this run was cancelled",
            );
            break;
        }
        if state.started.elapsed() >= MAX_WALK_DURATION {
            state.termination = WalkTermination::Deadline;
            state.push_diagnostic(
                "deadline_exceeded",
                "",
                format!(
                    "file discovery exceeded its {} ms wall-clock budget",
                    MAX_WALK_DURATION.as_millis()
                ),
            );
            break;
        }

        let Some(frame) = stack.last_mut() else {
            break;
        };
        if frame.next_entry >= frame.entries.len() {
            let terminal_after = frame.terminal_after;
            stack.pop();
            if let Some(termination) = terminal_after {
                state.termination = termination;
                break;
            }
            continue;
        }

        let entry = &frame.entries[frame.next_entry];
        frame.next_entry = frame.next_entry.saturating_add(1);
        let Some(name) = entry.name.to_str() else {
            state.push_diagnostic(
                "non_utf8_name",
                display_resource_id(&frame.relative),
                "entry omitted because its name cannot be represented in a JSON file-tool call",
            );
            continue;
        };
        let relative = frame.relative.join(name);
        let Some(resource_id) = relative.to_str() else {
            state.push_diagnostic(
                "non_utf8_path",
                display_resource_id(&frame.relative),
                "entry omitted because its resource ID is not valid UTF-8",
            );
            continue;
        };
        let absolute = root.join(&relative);

        match entry.kind {
            secure_fs::SecureFileType::Directory => {
                if options.ignore_policy == IgnorePolicy::Standard && should_ignore_directory(name)
                {
                    state.stats.ignored_directories =
                        state.stats.ignored_directories.saturating_add(1);
                    continue;
                }
                if options.visit_directories {
                    let visit = WalkEntry {
                        resource_id,
                        absolute_path: &absolute,
                        kind: WalkEntryKind::Directory,
                        parent: &frame.directory,
                        name: &entry.name,
                    };
                    if visitor(visit).map_err(WalkError::Visitor)? == WalkControl::Stop {
                        state.termination = WalkTermination::Visitor;
                        break;
                    }
                }
                if !options.recursive {
                    continue;
                }
                if frame.depth >= MAX_WALK_DEPTH {
                    state.push_diagnostic(
                        "depth_limit",
                        resource_id,
                        format!("directory omitted at the maximum depth of {MAX_WALK_DEPTH}"),
                    );
                    continue;
                }
                let child = match frame.directory.open_child_directory(&entry.name) {
                    Ok(child) => child,
                    Err(error) => {
                        state.push_diagnostic("directory_changed", resource_id, error);
                        continue;
                    }
                };
                let identity = match child.identity() {
                    Ok(identity) => identity,
                    Err(error) => {
                        state.push_diagnostic("directory_identity_unavailable", resource_id, error);
                        continue;
                    }
                };
                if !identities.insert(identity) {
                    state.push_diagnostic(
                        "directory_cycle",
                        resource_id,
                        "directory identity was already visited; repeated subtree omitted",
                    );
                    continue;
                }
                state.stats.directories_opened = state.stats.directories_opened.saturating_add(1);
                if let Some(child_frame) = load_frame(
                    child,
                    relative,
                    frame.depth.saturating_add(1),
                    false,
                    options.directories_first,
                    &mut state,
                )
                .map_err(WalkError::Filesystem)?
                {
                    stack.push(child_frame);
                }
            }
            secure_fs::SecureFileType::Regular => {
                let visit = WalkEntry {
                    resource_id,
                    absolute_path: &absolute,
                    kind: WalkEntryKind::Regular,
                    parent: &frame.directory,
                    name: &entry.name,
                };
                if visitor(visit).map_err(WalkError::Visitor)? == WalkControl::Stop {
                    state.termination = WalkTermination::Visitor;
                    break;
                }
            }
            secure_fs::SecureFileType::Other => {
                state.stats.skipped_non_regular_entries =
                    state.stats.skipped_non_regular_entries.saturating_add(1);
            }
        }
    }

    Ok(state.finish())
}

#[allow(clippy::too_many_lines)] // Enumeration admission and aggregate budget accounting are one transaction.
fn load_frame(
    directory: secure_fs::SecureDirectory,
    relative: PathBuf,
    depth: usize,
    root: bool,
    directories_first: bool,
    state: &mut WalkState,
) -> Result<Option<Frame>, String> {
    let resource_id = display_resource_id(&relative);
    let bounded = match directory.entries_bounded(MAX_DIRECTORY_ENTRIES, MAX_DIRECTORY_NAME_BYTES) {
        Ok(entries) => entries,
        Err(secure_fs::SecureDirectoryEntriesError::EntryLimit { limit }) => {
            let message = format!(
                "directory omitted because it exceeds the {limit}-entry enumeration budget"
            );
            if root {
                state.push_diagnostic("directory_entry_limit", resource_id, message);
                return Ok(None);
            }
            state.push_diagnostic("directory_entry_limit", resource_id, message);
            return Ok(None);
        }
        Err(secure_fs::SecureDirectoryEntriesError::NameByteLimit { limit }) => {
            let message = format!(
                "directory omitted because its names exceed the {limit}-byte enumeration budget"
            );
            state.push_diagnostic("directory_name_bytes_limit", resource_id, message);
            return Ok(None);
        }
        Err(secure_fs::SecureDirectoryEntriesError::Read(message)) if root => {
            return Err(message);
        }
        Err(secure_fs::SecureDirectoryEntriesError::Read(message)) => {
            state.push_diagnostic("directory_read_failed", resource_id, message);
            return Ok(None);
        }
    };
    if bounded.skipped_changed_entries > 0 {
        state.push_diagnostic(
            "directory_entries_changed",
            display_resource_id(&relative),
            format!(
                "{} entries changed during descriptor-relative inspection and were omitted",
                bounded.skipped_changed_entries
            ),
        );
    }

    let mut entries = bounded.entries;
    entries.sort_by(|left, right| {
        let by_kind = if directories_first {
            let left_rank = usize::from(left.kind != secure_fs::SecureFileType::Directory);
            let right_rank = usize::from(right.kind != secure_fs::SecureFileType::Directory);
            left_rank.cmp(&right_rank)
        } else {
            std::cmp::Ordering::Equal
        };
        by_kind.then_with(|| left.name.cmp(&right.name))
    });
    let remaining_entries = MAX_WALK_ENTRIES.saturating_sub(state.stats.entries_discovered);
    let remaining_path_bytes =
        MAX_WALK_PATH_BYTES.saturating_sub(state.stats.path_bytes_discovered);
    let mut admitted = Vec::with_capacity(entries.len().min(remaining_entries));
    let mut admitted_path_bytes = 0usize;
    let mut terminal_after = None;
    for entry in entries {
        if admitted.len() >= remaining_entries {
            terminal_after = Some(WalkTermination::EntryBudget);
            state.push_diagnostic(
                "entry_budget",
                display_resource_id(&relative),
                format!("file discovery reached its aggregate {MAX_WALK_ENTRIES}-entry budget"),
            );
            break;
        }
        let path_bytes = relative
            .as_os_str()
            .as_encoded_bytes()
            .len()
            .saturating_add(usize::from(!relative.as_os_str().is_empty()))
            .saturating_add(entry.name.as_encoded_bytes().len());
        let Some(next_path_bytes) = admitted_path_bytes.checked_add(path_bytes) else {
            terminal_after = Some(WalkTermination::PathBudget);
            state.push_diagnostic(
                "path_bytes_budget",
                display_resource_id(&relative),
                "file discovery path-byte accounting overflowed",
            );
            break;
        };
        if next_path_bytes > remaining_path_bytes {
            terminal_after = Some(WalkTermination::PathBudget);
            state.push_diagnostic(
                "path_bytes_budget",
                display_resource_id(&relative),
                format!(
                    "file discovery reached its aggregate {MAX_WALK_PATH_BYTES}-byte path budget"
                ),
            );
            break;
        }
        admitted_path_bytes = next_path_bytes;
        admitted.push(entry);
    }
    state.stats.entries_discovered = state
        .stats
        .entries_discovered
        .saturating_add(admitted.len());
    state.stats.path_bytes_discovered = state
        .stats
        .path_bytes_discovered
        .saturating_add(admitted_path_bytes);

    Ok(Some(Frame {
        directory,
        relative,
        entries: admitted,
        next_entry: 0,
        depth,
        terminal_after,
    }))
}

fn should_ignore_directory(name: &str) -> bool {
    name.starts_with('.') || STANDARD_IGNORED_DIRECTORIES.contains(&name)
}

fn display_resource_id(relative: &Path) -> String {
    relative.to_string_lossy().into_owned()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum CursorPosition {
    Entry {
        resource_id: String,
    },
    Match {
        resource_id: String,
        line: u64,
    },
    Read {
        resource_id: String,
        generation: String,
        byte: u64,
        line_limit: Option<u64>,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CursorEnvelope {
    version: u8,
    binding: String,
    position: CursorPosition,
}

pub(super) fn cursor_binding(parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    for part in parts {
        digest.update(part.len().to_le_bytes());
        digest.update(part.as_bytes());
    }
    let finalized = digest.finalize();
    let mut encoded = String::with_capacity(finalized.len().saturating_mul(2));
    for byte in finalized {
        write!(&mut encoded, "{byte:02x}").expect("writing into a String cannot fail");
    }
    encoded
}

pub(super) fn encode_cursor(binding: &str, position: CursorPosition) -> String {
    let encoded = serde_json::to_vec(&CursorEnvelope {
        version: CURSOR_SCHEMA_VERSION,
        binding: binding.to_string(),
        position,
    })
    .expect("discovery cursor serialization is infallible");
    URL_SAFE_NO_PAD.encode(encoded)
}

pub(super) fn decode_cursor(
    raw: Option<&str>,
    expected_binding: &str,
) -> Result<Option<CursorPosition>, String> {
    let Some(raw) = raw else {
        return Ok(None);
    };
    if raw.is_empty() || raw.len() > MAX_CURSOR_BYTES {
        return Err(format!(
            "Invalid cursor: expected 1-{MAX_CURSOR_BYTES} encoded bytes"
        ));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| "Invalid cursor: malformed encoding".to_string())?;
    if decoded.len() > MAX_CURSOR_BYTES {
        return Err("Invalid cursor: decoded payload is too large".to_string());
    }
    let envelope: CursorEnvelope = serde_json::from_slice(&decoded)
        .map_err(|_| "Invalid cursor: malformed payload".to_string())?;
    if envelope.version != CURSOR_SCHEMA_VERSION {
        return Err(format!(
            "Invalid cursor: unsupported schema version {}",
            envelope.version
        ));
    }
    if envelope.binding != expected_binding {
        return Err("Invalid cursor: it belongs to different search arguments or root".to_string());
    }
    match &envelope.position {
        CursorPosition::Entry { resource_id }
        | CursorPosition::Match { resource_id, .. }
        | CursorPosition::Read { resource_id, .. } => {
            if resource_id.is_empty() || resource_id.len() > MAX_CURSOR_BYTES {
                return Err("Invalid cursor: resource position is empty or too large".to_string());
            }
        }
    }
    if let CursorPosition::Read { generation, .. } = &envelope.position {
        generation
            .parse::<crate::runtime::ContentDigest>()
            .map_err(|_| "Invalid cursor: malformed file generation".to_string())?;
    }
    Ok(Some(envelope.position))
}

pub(super) fn parse_page_limit(
    value: Option<&Value>,
    default: usize,
    maximum: usize,
) -> Result<usize, String> {
    let Some(value) = value else {
        return Ok(default);
    };
    let Some(value) = value.as_u64() else {
        return Err("Invalid 'limit' argument: expected positive integer".to_string());
    };
    let Ok(value) = usize::try_from(value) else {
        return Err(format!("Invalid 'limit' argument: maximum is {maximum}"));
    };
    if value == 0 || value > maximum {
        return Err(format!(
            "Invalid 'limit' argument: expected an integer from 1 to {maximum}"
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_is_bound_to_exact_request() {
        let first = cursor_binding(&["glob", "/workspace", "*.rs"]);
        let second = cursor_binding(&["glob", "/workspace", "*.md"]);
        let cursor = encode_cursor(
            &first,
            CursorPosition::Entry {
                resource_id: "src/lib.rs".to_string(),
            },
        );

        assert_eq!(
            decode_cursor(Some(&cursor), &first).expect("matching cursor"),
            Some(CursorPosition::Entry {
                resource_id: "src/lib.rs".to_string(),
            })
        );
        assert!(decode_cursor(Some(&cursor), &second).is_err());
    }
}
