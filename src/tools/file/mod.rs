mod edit;
mod glob;
mod grep;
mod list;
mod notebook;
mod read;
mod secure_fs;
mod write;

pub use edit::execute_edit_file;
pub use glob::execute_glob;
pub use grep::execute_grep;
pub use list::execute_list_files;
#[cfg(test)]
pub use notebook::execute_notebook_edit;
pub use notebook::execute_notebook_edit_typed;
pub use notebook::source_to_line_array;
#[allow(unused_imports)] // used by tests in tools::mod
pub use read::{
    detect_file_type, parse_page_range, read_image_file, read_notebook_file, read_text_file,
    FileType, ImageKind,
};
pub use write::execute_write_file;

use crate::tools::args::{ToolArgError, ToolArgs as _};
use std::collections::HashMap;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, MutexGuard};

use similar::TextDiff;

const LEDGER_EXCERPT_MAX_BYTES: usize = 100_000;

/// Maximum number of entries in the read tracker, per session, before
/// the oldest write is evicted from the front of the list. Per-session so
/// a noisy run cannot evict another run's reads. Matches the
/// previous global ceiling.
const READ_TRACKER_MAX_ENTRIES: usize = 10_000;

/// Per-run bucket: canonical path → monotonic insertion counter.
///
/// Counter values are pulled from a single tracker-wide [`AtomicU64`] so
/// the smallest counter in the bucket is the least-recently-read path
/// (LRU). Lookup is O(1) on the underlying [`HashMap`]; eviction at
/// the cap scans the bucket once.
type Bucket = HashMap<PathBuf, u64>;

/// Tracks which files have been read, bucketed by exact run identity.
///
/// Each run has its own [`HashSet`]-equivalent of canonicalized paths (stored as a
/// `HashMap<PathBuf, u64>` so we can drive LRU eviction without
/// paying the per-lookup linear scan a `Vec` required). `edit_file`
/// will fail if the file hasn't been read first **in the same
/// run**. There is no ambient session lookup or shared default bucket.
///
/// crosslink #986: the previous doc-comment called this an "LRU" list,
/// which is ambiguous — true LRU bumps the entry on read too. Here, only
/// `mark_read` touches the order; `has_been_read` is read-only and does
/// not affect eviction. The naming is "write-recency" / "insertion-
/// recency" to match the actual semantics.
///
/// crosslink #363: canonicalization is now strict — a path whose
/// `canonicalize` call fails on `has_been_read` is treated as **not
/// read**. This refuses to silently fall back to the raw path (which
/// previously hid bugs where the read-before-edit gate compared a
/// canonical absolute against a raw relative). `mark_read` on a path
/// whose `canonicalize` fails logs a warning and skips the insertion.
///
/// The tracker is process-shared storage, but every bucket is keyed by the
/// exact immutable run identity passed by the caller. There is no current
/// session lookup or default bucket.
///
/// [`HashSet`]: std::collections::HashSet
pub static READ_TRACKER: LazyLock<ReadFileTracker> = LazyLock::new(ReadFileTracker::new);

pub struct ReadFileTracker {
    /// Per-run buckets. The inner map is canonical path → insertion counter
    /// (see [`Bucket`]).
    /// `has_been_read` does not promote — see crosslink #986.
    buckets: Mutex<HashMap<String, Bucket>>,
    /// Monotonic counter used to assign each successful `mark_read` a
    /// strictly increasing value. Drives LRU eviction at the cap.
    counter: std::sync::atomic::AtomicU64,
}

impl ReadFileTracker {
    fn new() -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn buckets_guard(
        &self,
        operation: &'static str,
    ) -> Option<MutexGuard<'_, HashMap<String, Bucket>>> {
        match self.buckets.lock() {
            Ok(guard) => Some(guard),
            Err(err) => {
                tracing::error!(operation, error = %err, "Read file tracker lock poisoned");
                None
            }
        }
    }

    /// Mark a file as having been read by this exact run.
    ///
    /// `path` is canonicalized first. If canonicalization fails (file
    /// does not exist, permission denied, symlink loop, etc.) the call
    /// logs a warning and does **not** insert — silently storing the
    /// raw path would let `has_been_read` succeed via the same fallback
    /// and defeat the read-before-edit gate (see crosslink #363).
    /// Other sessions' buckets are untouched.
    pub(crate) fn mark_read(&self, run: &super::security::ToolRunContext, path: &Path) {
        let anchored = if path.is_absolute() {
            path.to_path_buf()
        } else {
            run.working_directory().join(path)
        };
        let resolved = match std::fs::canonicalize(&anchored) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "READ_TRACKER.mark_read: canonicalize failed; skipping insertion"
                );
                return;
            }
        };
        if !run.permits_read(&resolved) {
            tracing::warn!(
                path = %resolved.display(),
                run_id = %run.run_id(),
                "READ_TRACKER.mark_read: path is outside the run capability"
            );
            return;
        }
        let stamp = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let key = run.run_id().to_string();
        let Some(mut buckets) = self.buckets_guard("mark_read") else {
            return;
        };
        let files = buckets.entry(key).or_default();
        // O(1) upsert: re-inserting refreshes the LRU stamp.
        files.insert(resolved, stamp);
        if files.len() > READ_TRACKER_MAX_ENTRIES {
            Self::evict_lru(files);
        }
    }

    /// Drop bucket entries until the count is back at the cap. Removes
    /// the oldest-stamped entries first (true LRU).
    fn evict_lru(files: &mut Bucket) {
        let excess = files.len().saturating_sub(READ_TRACKER_MAX_ENTRIES);
        if excess == 0 {
            return;
        }
        // Collect (stamp, path) pairs and partial-sort by stamp ascending.
        let mut stamped: Vec<(u64, PathBuf)> = files.iter().map(|(p, &s)| (s, p.clone())).collect();
        stamped.sort_by_key(|(stamp, _)| *stamp);
        for (_, p) in stamped.into_iter().take(excess) {
            files.remove(&p);
        }
    }

    /// Check whether a file has been read by this exact run.
    ///
    /// `path` is canonicalized first. If canonicalization fails (file
    /// does not exist, permission denied, symlink loop, etc.) this
    /// returns `false` — the caller must read the file before the
    /// check can pass. A read in another session does not satisfy this
    /// check.
    pub(crate) fn has_been_read(&self, run: &super::security::ToolRunContext, path: &Path) -> bool {
        let anchored = if path.is_absolute() {
            path.to_path_buf()
        } else {
            run.working_directory().join(path)
        };
        let Ok(check_path) = std::fs::canonicalize(anchored) else {
            // Strict mode: refuse to silently fall back to the raw path.
            // The agent must perform a real read first. See crosslink #363.
            return false;
        };
        if !run.permits_read(&check_path) {
            return false;
        }
        let key = run.run_id().to_string();
        let Some(buckets) = self.buckets_guard("has_been_read") else {
            return false;
        };
        buckets
            .get(&key)
            .is_some_and(|f| f.contains_key(&check_path))
    }

    /// Invalidate this exact run's read marker for a file after mutation.
    ///
    /// A successful write/edit makes the previous file observation stale. The
    /// ledger records that for prompt grounding; this keeps the live
    /// read-before-edit gate in sync so a second mutation must be preceded by a
    /// fresh read.
    pub(crate) fn mark_stale(&self, run: &super::security::ToolRunContext, path: &Path) {
        let anchored = if path.is_absolute() {
            path.to_path_buf()
        } else {
            run.working_directory().join(path)
        };
        let Ok(check_path) = std::fs::canonicalize(anchored) else {
            tracing::warn!(
                path = %path.display(),
                "READ_TRACKER.mark_stale: canonicalize failed; skipping removal"
            );
            return;
        };
        let key = run.run_id().to_string();
        let Some(mut buckets) = self.buckets_guard("mark_stale") else {
            return;
        };
        if let Some(files) = buckets.get_mut(&key) {
            files.remove(&check_path);
        }
    }

    /// Clear one exact run's bucket without invalidating other runs.
    pub(crate) fn clear_run(&self, run: &super::security::ToolRunContext) {
        let Some(mut buckets) = self.buckets_guard("clear_run") else {
            return;
        };
        buckets.remove(&run.run_id().to_string());
    }

    /// Clear every run bucket in the crate test harness.
    #[cfg(test)]
    pub(crate) fn clear_all(&self) {
        let Some(mut buckets) = self.buckets_guard("clear_all") else {
            return;
        };
        buckets.clear();
    }
}

fn project_root(run: &super::security::ToolRunContext) -> Result<PathBuf, String> {
    run.require(super::security::ToolResource::WorkspaceRead)
        .map_err(|error| error.to_string())?;
    Ok(run.project_root().to_path_buf())
}

pub fn resolve_path(run: &super::security::ToolRunContext, path: &str) -> Result<PathBuf, String> {
    run.require(super::security::ToolResource::WorkspaceRead)
        .map_err(|error| error.to_string())?;
    let security = run;
    let p = Path::new(path);
    let absolute = if p.is_absolute() {
        p.to_path_buf()
    } else {
        security.working_directory().join(p)
    };
    if absolute
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        return Err(format!("Path traversal not allowed: '{path}'"));
    }
    let canonical = if let Ok(c) = absolute.canonicalize() {
        c
    } else {
        let mut ancestor = absolute.as_path();
        let mut suffix_components: Vec<&std::ffi::OsStr> = Vec::new();
        let canonical_ancestor = loop {
            if let Ok(c) = ancestor.canonicalize() {
                break c;
            }
            let file_name = ancestor.file_name().ok_or_else(|| {
                format!("Cannot resolve any ancestor of '{path}' — reached filesystem root")
            })?;
            suffix_components.push(file_name);
            ancestor = ancestor
                .parent()
                .ok_or_else(|| format!("Cannot resolve parent while walking up '{path}'"))?;
        };
        let mut built = canonical_ancestor;
        for comp in suffix_components.iter().rev() {
            built.push(comp);
        }
        built
    };
    if !security.permits_read(&canonical) {
        return Err(format!(
            "Path '{path}' resolves to '{}' which is outside the session's granted roots \
             (project '{}', private temp '{}').",
            canonical.display(),
            security.project_root().display(),
            security.private_temp_root().display(),
        ));
    }
    Ok(canonical)
}

fn resolve_host_control_path(
    run: &super::security::ToolRunContext,
    path: &str,
) -> Result<PathBuf, String> {
    run.require(super::security::ToolResource::WorkspaceRead)
        .map_err(|error| error.to_string())?;
    let supplied = Path::new(path);
    let absolute = if supplied.is_absolute() {
        supplied.to_path_buf()
    } else {
        run.project_root().join(supplied)
    };
    if absolute
        .components()
        .any(|component| component == std::path::Component::ParentDir)
    {
        return Err(format!("Host-control path traversal not allowed: '{path}'"));
    }
    let resolved = canonicalize_or_walk_up(&absolute, path)?;
    if !resolved.starts_with(run.project_root()) || !run.is_denied_path(&resolved) {
        return Err(format!(
            "Path '{}' is not masked host-control state below run project '{}'",
            resolved.display(),
            run.project_root().display()
        ));
    }
    Ok(resolved)
}

/// Open an agent-supplied path through the same immutable capability and
/// descriptor-relative traversal used by `read_file`.
///
/// Agent-adjacent consumers such as the LSP adapter must use this rather than
/// reopening a validated path by name.
pub fn open_capability_regular_read(
    run: &super::security::ToolRunContext,
    user_path: &str,
) -> Result<(PathBuf, std::fs::File), String> {
    let resolved = resolve_path(run, user_path)?;
    let file = secure_fs::open_regular_read(run, &resolved)?;
    Ok((resolved, file))
}

/// Read one UTF-8 attachment through the exact run filesystem capability.
///
/// Frontend prompt affordances such as legacy-REPL `@file` expansion use this
/// helper so they share the file tool's descriptor-relative traversal and
/// size limit instead of reopening a path beneath the process CWD.
///
/// # Errors
///
/// Returns an error when the run lacks read authority, the path is outside or
/// masked from the run, descriptor-relative opening fails, the file exceeds
/// the attachment limit, or its bytes are not UTF-8.
pub fn read_capability_text_attachment(
    run: &super::security::ToolRunContext,
    user_path: &str,
) -> Result<(PathBuf, String), String> {
    let (resolved, file) = open_capability_regular_read(run, user_path)?;
    let mut bytes = Vec::new();
    file.take(read::MAX_FILE_SIZE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("Failed to read '{}': {error}", resolved.display()))?;
    if bytes.len() > usize::try_from(read::MAX_FILE_SIZE_BYTES).unwrap_or(usize::MAX) {
        return Err(format!(
            "File '{}' exceeds the {}-byte attachment limit",
            resolved.display(),
            read::MAX_FILE_SIZE_BYTES
        ));
    }
    let content = String::from_utf8(bytes)
        .map_err(|error| format!("File '{}' is not valid UTF-8: {error}", resolved.display()))?;
    READ_TRACKER.mark_read(run, &resolved);
    Ok((resolved, content))
}

/// Create one UTF-8 frontend-owned file without ever overwriting an existing
/// object. Parent creation and the final open use the same descriptor-relative
/// capability path as `write_file`.
///
/// # Errors
///
/// Returns an error when the run lacks write authority, the path is outside or
/// masked from the run, guardrails reject it, secure creation fails, the target
/// already exists, or the content cannot be written.
pub fn create_capability_text_file(
    run: &super::security::ToolRunContext,
    user_path: &str,
    content: &str,
) -> Result<PathBuf, String> {
    let resolved = resolve_path(run, user_path)?;
    let open_path = resolve_open_path(run, user_path)?;
    let mut effect_reservation =
        crate::guardrails::reserve_workspace_mutation(run, &resolved.to_string_lossy())?;
    let (lines_added, lines_removed) = changed_line_counts("", content);
    let mut line_reservation = crate::guardrails::reserve_changed_lines(
        run,
        u64::from(lines_added) + u64::from(lines_removed),
    )?;
    let (mut file, existed) = secure_fs::open_regular_update_or_create(run, &open_path)?;
    if existed {
        return Err(format!("File '{}' already exists", resolved.display()));
    }
    if let Err(error) = file.write_all(content.as_bytes()) {
        // `existed == false` proves the descriptor open created the target, so
        // this is a partial mutation even if zero payload bytes were durable.
        // Reconcile what can be observed and conservatively commit both
        // reservations before returning the legacy error surface.
        if let Ok(actual_content) = secure_fs::read_to_string(&mut file, &resolved) {
            let (actual_added, actual_removed) = changed_line_counts("", &actual_content);
            line_reservation
                .reconcile_and_commit(u64::from(actual_added) + u64::from(actual_removed));
            crate::guardrails::record_file_modification(
                run,
                &resolved.to_string_lossy(),
                actual_added,
                actual_removed,
            );
        } else {
            line_reservation.commit();
        }
        effect_reservation.commit();
        return Err(format!("Failed to write '{}': {error}", resolved.display()));
    }
    line_reservation.commit();
    effect_reservation.commit();
    crate::guardrails::record_file_modification(
        run,
        &resolved.to_string_lossy(),
        lines_added,
        lines_removed,
    );
    Ok(resolved)
}

/// Read host-owned control text below the exact run project.
///
/// This is a frontend lifecycle boundary, not an agent file-tool primitive:
/// it can enter masked `.openclaudia` state but cannot escape the pinned run
/// project or follow symlinks.
#[doc(hidden)]
pub fn read_run_control_text(
    run: &super::security::ToolRunContext,
    user_path: &str,
) -> Result<(PathBuf, String), String> {
    let resolved = resolve_host_control_path(run, user_path)?;
    let file = secure_fs::open_host_control_regular_read(run, &resolved)?;
    let mut bytes = Vec::new();
    file.take(read::MAX_FILE_SIZE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("Failed to read '{}': {error}", resolved.display()))?;
    if bytes.len() > usize::try_from(read::MAX_FILE_SIZE_BYTES).unwrap_or(usize::MAX) {
        return Err(format!(
            "Control file '{}' exceeds the {}-byte limit",
            resolved.display(),
            read::MAX_FILE_SIZE_BYTES
        ));
    }
    let content = String::from_utf8(bytes).map_err(|error| {
        format!(
            "Control file '{}' is not valid UTF-8: {error}",
            resolved.display()
        )
    })?;
    Ok((resolved, content))
}

/// Create one host-owned control text file without overwriting an existing
/// object, using the run's pinned project descriptor.
#[doc(hidden)]
pub fn create_run_control_text_file(
    run: &super::security::ToolRunContext,
    user_path: &str,
    content: &str,
) -> Result<PathBuf, String> {
    let resolved = resolve_host_control_path(run, user_path)?;
    let (mut file, existed) =
        secure_fs::open_host_control_regular_update_or_create(run, &resolved)?;
    if existed {
        return Err(format!("File '{}' already exists", resolved.display()));
    }
    file.write_all(content.as_bytes())
        .map_err(|error| format!("Failed to write '{}': {error}", resolved.display()))?;
    Ok(resolved)
}

/// Securely create one host-owned control directory below the run project.
#[doc(hidden)]
pub fn create_run_control_directory(
    run: &super::security::ToolRunContext,
    user_path: &str,
) -> Result<PathBuf, String> {
    let resolved = resolve_host_control_path(run, user_path)?;
    secure_fs::create_host_control_directories(run, &resolved)?;
    Ok(resolved)
}

/// Result of initializing the run's project-owned `OpenClaudia` control state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProjectInitOutcome {
    Created,
    AlreadyExists,
}

/// Initialize `.openclaudia/config.yaml` and the project skill directory
/// through the exact run's pinned host-control capability.
#[doc(hidden)]
pub fn initialize_project_for_run(
    run: &super::security::ToolRunContext,
) -> Result<ProjectInitOutcome, String> {
    let config_path = run.project_root().join(".openclaudia/config.yaml");
    match read_run_control_text(run, &config_path.to_string_lossy()) {
        Ok(_) => return Ok(ProjectInitOutcome::AlreadyExists),
        Err(error) if error.starts_with("NOT_FOUND:") => {}
        Err(error) => return Err(error),
    }
    let skills_path = run.project_root().join(".openclaudia/skills");
    create_run_control_directory(run, &skills_path.to_string_lossy())?;
    let default_config = "# OpenClaudia Configuration\nproxy:\n  port: 8080\n  host: \"127.0.0.1\"\n  target: anthropic\n\nproviders:\n  anthropic:\n    base_url: https://api.anthropic.com\n\nsession:\n  timeout_minutes: 30\n  persist_path: .openclaudia/session\n";
    match create_run_control_text_file(run, &config_path.to_string_lossy(), default_config) {
        Ok(_) => Ok(ProjectInitOutcome::Created),
        Err(error) if error.ends_with("already exists") => Ok(ProjectInitOutcome::AlreadyExists),
        Err(error) => Err(error),
    }
}

/// Canonicalise a path that may not yet exist by walking the deepest
/// canonicalisable ancestor and rejoining the remaining suffix.
///
/// crosslink #969: this used to live as inline `match canonicalize(&p) {
/// Ok(c) => c, Err(_) => match p.parent() { ... } }` blocks in
/// `write.rs`, `edit.rs::canonicalise_edit_path`, and
/// `notebook.rs::preflight_and_open` — three near-identical copies with
/// drifted error messages. Centralised here so every file tool agrees on
/// the semantics. Returns the resolved [`PathBuf`] or a stringly-typed
/// error mentioning the original user-supplied path.
pub(super) fn canonicalize_or_walk_up(p: &Path, user_path: &str) -> Result<PathBuf, String> {
    if let Ok(c) = std::fs::canonicalize(p) {
        return Ok(c);
    }
    // Walk up the ancestor chain until we find a canonicalisable directory,
    // then rejoin the missing suffix. Supports `write_file` calling
    // `create_dir_all` later: e.g. `/tmp/X/a/b/c/file.txt` where only
    // `/tmp/X` exists today.
    let mut ancestor = p;
    let mut suffix: Vec<&std::ffi::OsStr> = Vec::new();
    loop {
        let file_name = ancestor.file_name().ok_or_else(|| {
            format!("Cannot resolve any ancestor of '{user_path}' — reached filesystem root")
        })?;
        suffix.push(file_name);
        let Some(parent) = ancestor.parent() else {
            return Err(format!("Invalid path: '{user_path}'"));
        };
        if let Ok(canon_parent) = std::fs::canonicalize(parent) {
            let mut built = canon_parent;
            for comp in suffix.iter().rev() {
                built.push(comp);
            }
            return Ok(built);
        }
        ancestor = parent;
    }
}

pub fn resolve_open_path(
    run: &super::security::ToolRunContext,
    user_path: &str,
) -> Result<PathBuf, String> {
    run.require(super::security::ToolResource::WorkspaceWrite)
        .map_err(|error| error.to_string())?;
    let security = run;
    let p = Path::new(user_path);
    let absolute = if p.is_absolute() {
        p.to_path_buf()
    } else {
        security.working_directory().join(p)
    };
    if absolute
        .components()
        .any(|c| c == std::path::Component::ParentDir)
    {
        return Err(format!("Path traversal not allowed: '{user_path}'"));
    }
    let parent = absolute
        .parent()
        .ok_or_else(|| format!("Invalid path (no parent): '{user_path}'"))?;
    let leaf = absolute
        .file_name()
        .ok_or_else(|| format!("Invalid path (no leaf): '{user_path}'"))?;
    let canonical_parent = if let Ok(c) = parent.canonicalize() {
        c
    } else {
        let mut ancestor = parent;
        let mut suffix_components: Vec<&std::ffi::OsStr> = Vec::new();
        let canonical_ancestor = loop {
            if let Ok(c) = ancestor.canonicalize() {
                break c;
            }
            let name = ancestor.file_name().ok_or_else(|| {
                format!("Cannot resolve any ancestor of '{user_path}' — reached filesystem root")
            })?;
            suffix_components.push(name);
            ancestor = ancestor
                .parent()
                .ok_or_else(|| format!("Cannot resolve parent while walking up '{user_path}'"))?;
        };
        let mut built = canonical_ancestor;
        for comp in suffix_components.iter().rev() {
            built.push(comp);
        }
        built
    };
    let containment_probe = canonical_parent.join(leaf);
    if !security.permits_write(&containment_probe) {
        return Err(format!(
            "Path '{user_path}' resolves to '{}' which is outside the session's writable roots \
             (project '{}', private temp '{}').",
            containment_probe.display(),
            security.project_root().display(),
            security.private_temp_root().display(),
        ));
    }
    Ok(canonical_parent.join(leaf))
}

pub fn execute_read_file(
    run: &super::security::ToolRunContext,
    args: &std::collections::HashMap<String, serde_json::Value>,
) -> (String, bool) {
    let path = match args.arg_str_strict("path") {
        Ok(path) => path,
        Err(e) => return e.into_tool_error(),
    };

    let resolved = match resolve_path(run, path) {
        Ok(p) => p,
        Err(e) => return (e, true),
    };
    let resolved_str = resolved.to_string_lossy();

    let (content, is_error) = match detect_file_type(&resolved_str) {
        FileType::Image(kind) => read_image_file(run, &resolved_str, kind),
        FileType::Pdf => {
            let pages = match args.get("pages") {
                None => None,
                Some(serde_json::Value::String(value)) => Some(value.as_str()),
                Some(_) => {
                    return ToolArgError::WrongType {
                        key: "pages",
                        expected: "string",
                    }
                    .into_tool_error();
                }
            };
            read::read_pdf_file(run, &resolved_str, pages)
        }
        FileType::Notebook => read_notebook_file(run, &resolved_str),
        FileType::Text => read_text_file(run, &resolved_str, args),
    };

    if !is_error {
        READ_TRACKER.mark_read(run, &resolved);
        record_active_file_read_observation(run, &resolved, args, &content);
    }

    (content, is_error)
}

fn record_active_file_read_observation(
    run: &super::security::ToolRunContext,
    resolved: &Path,
    args: &std::collections::HashMap<String, serde_json::Value>,
    output: &str,
) {
    let session_key = run.session_id();
    let Some(ledger) = crate::ledger::active_ledger_for_session(session_key) else {
        return;
    };

    let bytes = match read_file_bytes_for_ledger(run, resolved) {
        Ok(bytes) => bytes,
        Err(err) => {
            tracing::warn!(
                path = %resolved.display(),
                error = %err,
                "read_file succeeded but ledger hash read failed; skipping observation"
            );
            return;
        }
    };

    let (start_line, end_line) = ledger_line_range(args, &bytes, output);
    let excerpt = super::safe_truncate(output, LEDGER_EXCERPT_MAX_BYTES).to_string();
    let mut ledger = ledger.lock().unwrap_or_else(|err| {
        tracing::error!("active reality ledger lock poisoned; recovering inner state");
        err.into_inner()
    });
    if let Err(err) = ledger.observe_file_read_bytes(
        run,
        resolved.to_string_lossy().to_string(),
        &bytes,
        start_line,
        end_line,
        excerpt,
    ) {
        tracing::warn!(
            path = %resolved.display(),
            error = %err,
            "failed to append read_file observation to reality ledger"
        );
    }
}

pub(super) fn require_fresh_file_observation_if_ledger_active(
    run: &super::security::ToolRunContext,
    path: &Path,
    action: &str,
) -> Result<(), String> {
    let session_key = run.session_id();
    let Some(ledger) = crate::ledger::active_ledger_for_session(session_key) else {
        return Ok(());
    };
    let path = path.to_string_lossy().to_string();
    let has_fresh_read = {
        let ledger = ledger.lock().unwrap_or_else(|err| {
            tracing::error!("active reality ledger lock poisoned; recovering inner state");
            err.into_inner()
        });
        ledger.observations_chronological().into_iter().any(|obs| {
            obs.provenance.trust == crate::ledger::EvidenceTrust::RuntimeObserved
                && obs.provenance.is_bound_to(run)
                && !ledger.is_stale(obs.id)
                && matches!(
                    &obs.kind,
                    crate::ledger::ObservationKind::FileRead { path: observed, .. }
                        if observed == &path
                )
        })
    };
    if has_fresh_read {
        return Ok(());
    }
    Err(format!(
        "You must read '{path}' before {action}. The active reality ledger has no fresh file read observation; use read_file first to ground the change."
    ))
}

fn read_file_bytes_for_ledger(
    run: &super::security::ToolRunContext,
    path: &Path,
) -> std::io::Result<Vec<u8>> {
    let file = secure_fs::open_regular_read(run, path).map_err(std::io::Error::other)?;
    let mut bytes = Vec::new();
    file.take(read::MAX_FILE_SIZE_BYTES)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn ledger_line_range(
    args: &std::collections::HashMap<String, serde_json::Value>,
    bytes: &[u8],
    output: &str,
) -> (usize, usize) {
    let start_line = args
        .get("offset")
        .and_then(serde_json::Value::as_u64)
        .and_then(|n| usize::try_from(n).ok())
        .filter(|n| *n > 0)
        .unwrap_or(1);

    let total_lines = std::str::from_utf8(bytes)
        .map_or_else(|_| output.lines().count().max(1), count_display_lines);
    let requested = args
        .get("limit")
        .and_then(serde_json::Value::as_u64)
        .and_then(|n| usize::try_from(n).ok())
        .filter(|n| *n > 0);
    let end_line = requested.map_or(total_lines, |limit| {
        start_line.saturating_add(limit).saturating_sub(1)
    });
    (start_line, end_line.min(total_lines.max(start_line)))
}

fn count_display_lines(text: &str) -> usize {
    if text.is_empty() {
        return 0;
    }
    text.lines().count().max(1)
}

/// Count inserted and deleted lines in the exact before/after payload.
///
/// This is shared by file writers, blast-radius reservations, diff-monitor
/// accounting, and reality-ledger output so all four boundaries use the same
/// unit instead of estimating from input fragments.
pub(super) fn changed_line_counts(before: &str, after: &str) -> (u32, u32) {
    let mut added = 0_u32;
    let mut removed = 0_u32;
    for change in TextDiff::from_lines(before, after).iter_all_changes() {
        match change.tag() {
            similar::ChangeTag::Insert => added = added.saturating_add(1),
            similar::ChangeTag::Delete => removed = removed.saturating_add(1),
            similar::ChangeTag::Equal => {}
        }
    }
    (added, removed)
}

pub(super) fn record_active_diff_observation(
    run: &super::security::ToolRunContext,
    path: &str,
    before: &str,
    after: &str,
) {
    if before == after {
        return;
    }
    READ_TRACKER.mark_stale(run, Path::new(path));
    let session_key = run.session_id();
    let Some(ledger) = crate::ledger::active_ledger_for_session(session_key) else {
        return;
    };
    let diff_patch = TextDiff::from_lines(before, after)
        .unified_diff()
        .header(&format!("a/{path}"), &format!("b/{path}"))
        .to_string();
    let mut ledger = ledger.lock().unwrap_or_else(|err| {
        tracing::error!("active reality ledger lock poisoned; recovering inner state");
        err.into_inner()
    });
    if let Err(err) = ledger.observe_diff(run, vec![path.to_string()], diff_patch) {
        tracing::warn!(
            path,
            error = %err,
            "failed to append file diff observation to reality ledger"
        );
    }
}

/// Process-wide mutex for tests that mutate the global `READ_TRACKER`.
///
/// Sibling test modules (`edit::tests`, `write::tests`) call this to
/// serialize against the tracker-internal tests here. Without a shared
/// mutex, `clear_all()` calls in one test module race with `mark_read`
/// calls in another and corrupt the `LazyLock` bucket state. See
/// crosslink #968 follow-up.
#[cfg(test)]
pub fn shared_tracker_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::MutexGuard;

    fn test_run() -> &'static std::sync::Arc<crate::tools::ToolRunContext> {
        crate::tools::security::test_run_context()
    }

    fn fresh_run() -> std::sync::Arc<crate::tools::ToolRunContext> {
        crate::tools::security::test_run_context_for(std::path::Path::new(env!(
            "CARGO_MANIFEST_DIR"
        )))
    }

    fn tracker_lock() -> MutexGuard<'static, ()> {
        // Delegate to the crate-wide lock so write::tests and
        // edit::tests can serialize against this module's tests.
        // crosslink #968 follow-up: a separate local OnceLock here
        // previously allowed concurrent corruption of READ_TRACKER
        // state across sibling test modules.
        super::shared_tracker_lock()
    }

    #[test]
    fn changed_line_counts_use_the_exact_before_after_diff() {
        assert_eq!(changed_line_counts("", "one\ntwo\n"), (2, 0));
        assert_eq!(changed_line_counts("one\ntwo\n", "one\nthree\n"), (1, 1));
        assert_eq!(changed_line_counts("same\n", "same\n"), (0, 0));
        assert_eq!(
            changed_line_counts("same\n", "same"),
            (1, 1),
            "trailing-newline changes must not disappear from line accounting"
        );
    }

    #[cfg(unix)]
    #[test]
    fn project_initialization_is_exact_run_scoped_and_control_state_stays_masked() {
        let first_root = tempfile::tempdir().expect("first project root");
        let second_root = tempfile::tempdir().expect("second project root");
        let first_run = crate::tools::security::test_run_context_for(first_root.path());
        let second_run = crate::tools::security::test_run_context_for(second_root.path());

        assert_eq!(
            initialize_project_for_run(&first_run).expect("initialize first project"),
            ProjectInitOutcome::Created
        );
        let first_config = first_root.path().join(".openclaudia/config.yaml");
        assert!(first_config.is_file());
        assert!(first_root.path().join(".openclaudia/skills").is_dir());
        assert!(!second_root.path().join(".openclaudia").exists());
        assert!(
            read_capability_text_attachment(&first_run, &first_config.to_string_lossy()).is_err(),
            "agent attachment reads must not inherit host-control authority"
        );
        assert!(
            read_run_control_text(&first_run, &first_config.to_string_lossy()).is_ok(),
            "the exact frontend run must retain host-control access"
        );

        std::fs::create_dir_all(second_root.path().join(".openclaudia"))
            .expect("second control directory");
        std::fs::write(
            second_root.path().join(".openclaudia/config.yaml"),
            "SECOND-RUN-SENTINEL",
        )
        .expect("second config sentinel");
        assert_eq!(
            initialize_project_for_run(&second_run).expect("inspect second project"),
            ProjectInitOutcome::AlreadyExists
        );
        assert_eq!(
            std::fs::read_to_string(second_root.path().join(".openclaudia/config.yaml"))
                .expect("preserved second config"),
            "SECOND-RUN-SENTINEL"
        );
    }

    fn two_temp_paths() -> (
        tempfile::NamedTempFile,
        tempfile::NamedTempFile,
        PathBuf,
        PathBuf,
    ) {
        let a = tempfile::NamedTempFile::new_in(".").expect("tempfile a");
        let b = tempfile::NamedTempFile::new_in(".").expect("tempfile b");
        let pa = a.path().canonicalize().expect("canonicalize a");
        let pb = b.path().canonicalize().expect("canonicalize b");
        (a, b, pa, pb)
    }

    /// A read marked by run A is not visible to run B even though the backing
    /// tracker is process-shared.
    #[test]
    fn read_tracker_isolates_marks_between_runs() {
        let _lock = tracker_lock();
        READ_TRACKER.clear_all();
        let (_keep_a, _keep_b, path_a, path_b) = two_temp_paths();
        let run_a = fresh_run();
        let run_b = fresh_run();

        READ_TRACKER.mark_read(&run_a, &path_a);
        assert!(READ_TRACKER.has_been_read(&run_a, &path_a));
        assert!(!READ_TRACKER.has_been_read(&run_b, &path_a));

        READ_TRACKER.mark_read(&run_b, &path_b);
        assert!(READ_TRACKER.has_been_read(&run_b, &path_b));
        assert!(!READ_TRACKER.has_been_read(&run_b, &path_a));
        assert!(READ_TRACKER.has_been_read(&run_a, &path_a));
        assert!(!READ_TRACKER.has_been_read(&run_a, &path_b));
    }

    /// crosslink #440 phase 1: same-session mark-then-check round-trip.
    #[test]
    fn read_tracker_same_session_round_trip() {
        let _lock = tracker_lock();
        READ_TRACKER.clear_all();
        let (_keep, _keep_b, path_a, _path_b) = two_temp_paths();
        assert!(
            !READ_TRACKER.has_been_read(test_run(), &path_a),
            "fresh run sees nothing"
        );
        READ_TRACKER.mark_read(test_run(), &path_a);
        assert!(
            READ_TRACKER.has_been_read(test_run(), &path_a),
            "round-trip works inside one run"
        );
        READ_TRACKER.mark_read(test_run(), &path_a);
        assert!(
            READ_TRACKER.has_been_read(test_run(), &path_a),
            "re-mark stays visible"
        );
    }

    #[test]
    fn read_tracker_mark_stale_only_clears_exact_run() {
        let _lock = tracker_lock();
        READ_TRACKER.clear_all();
        let (_keep_a, _keep_b, path_a, _path_b) = two_temp_paths();
        let run_a = fresh_run();
        let run_b = fresh_run();
        READ_TRACKER.mark_read(&run_a, &path_a);
        READ_TRACKER.mark_read(&run_b, &path_a);
        READ_TRACKER.mark_stale(&run_a, &path_a);
        assert!(!READ_TRACKER.has_been_read(&run_a, &path_a));
        assert!(READ_TRACKER.has_been_read(&run_b, &path_a));
    }

    /// Clearing one run never invalidates another run's observation.
    #[test]
    fn read_tracker_clear_run_preserves_other_buckets() {
        let _lock = tracker_lock();
        READ_TRACKER.clear_all();
        let (_keep_a, _keep_b, path_a, path_b) = two_temp_paths();
        let run_a = fresh_run();
        let run_b = fresh_run();
        READ_TRACKER.mark_read(&run_a, &path_a);
        READ_TRACKER.mark_read(&run_b, &path_b);
        READ_TRACKER.clear_run(&run_a);
        assert!(!READ_TRACKER.has_been_read(&run_a, &path_a));
        assert!(READ_TRACKER.has_been_read(&run_b, &path_b));
    }

    #[test]
    fn dropping_last_run_handle_clears_only_its_tracker_bucket() {
        let _lock = tracker_lock();
        READ_TRACKER.clear_all();
        let (_keep_a, _keep_b, path_a, path_b) = two_temp_paths();
        let run_a = fresh_run();
        let run_b = fresh_run();
        let dropped_run_key = run_a.run_id().to_string();
        let retained_run_key = run_b.run_id().to_string();
        READ_TRACKER.mark_read(&run_a, &path_a);
        READ_TRACKER.mark_read(&run_b, &path_b);

        drop(run_a);

        let buckets = READ_TRACKER
            .buckets_guard("drop lifecycle test")
            .expect("tracker lock");
        assert!(!buckets.contains_key(&dropped_run_key));
        assert!(buckets.contains_key(&retained_run_key));
        drop(buckets);
    }

    // ---------------------------------------------------------------
    // crosslink #363: strict canonicalize + HashSet/HashMap migration
    // ---------------------------------------------------------------

    /// crosslink #363 (1): `mark_read` + `has_been_read` for the same
    /// canonical path returns true.
    #[test]
    fn read_tracker_363_canonical_round_trip_returns_true() {
        let _lock = tracker_lock();
        READ_TRACKER.clear_all();
        let (_keep, _keep_b, path_a, _path_b) = two_temp_paths();
        READ_TRACKER.mark_read(test_run(), &path_a);
        assert!(
            READ_TRACKER.has_been_read(test_run(), &path_a),
            "canonical mark must satisfy canonical check"
        );
    }

    /// crosslink #363 (2): `mark_read` with a relative path, then
    /// `has_been_read` with the absolute canonical path, resolves to
    /// the same key (because both calls canonicalize internally).
    #[test]
    fn read_tracker_363_relative_then_absolute_resolves() {
        let _lock = tracker_lock();
        READ_TRACKER.clear_all();

        let dir = tempfile::tempdir_in(".").expect("tempdir");
        let canon_dir = dir.path().canonicalize().expect("canonicalize dir");
        let abs_file = canon_dir.join("rel_target.txt");
        std::fs::write(&abs_file, b"hello").expect("write file");

        // Build a relative path from the explicit run working directory.
        let rel_file = pathdiff_relative(test_run().working_directory(), &abs_file)
            .expect("relative path between cwd and tempdir target exists");
        assert!(
            rel_file.is_relative(),
            "test precondition: derived path must be relative"
        );

        READ_TRACKER.mark_read(test_run(), &rel_file);
        assert!(
            READ_TRACKER.has_been_read(test_run(), &abs_file),
            "relative mark must be visible via the canonical absolute path"
        );
        assert!(
            READ_TRACKER.has_been_read(test_run(), &rel_file),
            "relative path query must also succeed (it canonicalizes to the same key)"
        );
    }

    /// crosslink #363 (3): `has_been_read` for a nonexistent path
    /// returns false (canonicalize fails → treat as not read).
    #[test]
    fn read_tracker_363_nonexistent_path_returns_false() {
        let _lock = tracker_lock();
        READ_TRACKER.clear_all();

        // Path under a real tempdir but with a leaf that does not exist
        // on disk: canonicalize on the leaf will fail.
        let dir = tempfile::tempdir_in(".").expect("tempdir");
        let ghost = dir.path().join("does_not_exist_12345.txt");
        assert!(
            !ghost.exists(),
            "test precondition: ghost path must not exist"
        );

        assert!(
            !READ_TRACKER.has_been_read(test_run(), &ghost),
            "nonexistent path must NOT be considered read (strict canonicalize)"
        );

        // mark_read on a nonexistent path must also be a no-op (warning
        // logged inside); a subsequent has_been_read still returns false
        // even if we later create the file, because no insertion happened.
        READ_TRACKER.mark_read(test_run(), &ghost);
        assert!(
            !READ_TRACKER.has_been_read(test_run(), &ghost),
            "mark_read on a nonexistent path must NOT silently store the raw path"
        );

        // Sanity: once the file exists and is marked, the gate works.
        std::fs::write(&ghost, b"materialized").expect("write ghost");
        let canon = ghost.canonicalize().expect("now canonicalizable");
        READ_TRACKER.mark_read(test_run(), &canon);
        assert!(
            READ_TRACKER.has_been_read(test_run(), &canon),
            "after real read on an existing file, the gate must pass"
        );
    }

    /// crosslink #363 (4): 100 concurrent `mark_read` calls all succeed;
    /// the final set contains every path. Guards against a race in the
    /// `HashMap` upsert + LRU stamp interaction.
    #[test]
    fn read_tracker_363_concurrent_mark_read_no_loss() {
        const N: usize = 100;

        let _lock = tracker_lock();
        READ_TRACKER.clear_all();

        let dir = tempfile::tempdir_in(".").expect("tempdir");
        let canon_dir = dir.path().canonicalize().expect("canonicalize dir");

        let mut paths: Vec<PathBuf> = Vec::with_capacity(N);
        for i in 0..N {
            let p = canon_dir.join(format!("race_{i}.txt"));
            std::fs::write(&p, format!("contents-{i}")).expect("write race file");
            paths.push(p);
        }

        // Hand each path to a fresh thread. Every worker uses the same exact
        // immutable run capability, so all marks land in one bucket.
        let mut handles = Vec::with_capacity(N);
        for p in &paths {
            let p = p.clone();
            handles.push(std::thread::spawn(move || {
                READ_TRACKER.mark_read(test_run(), &p);
            }));
        }
        for h in handles {
            h.join().expect("worker thread panicked");
        }

        for p in &paths {
            assert!(
                READ_TRACKER.has_been_read(test_run(), p),
                "concurrent mark must not drop path {}",
                p.display()
            );
        }
    }

    /// crosslink #363 (5): LRU eviction still works at the cap.
    /// Bypasses `READ_TRACKER_MAX_ENTRIES` for the test by calling
    /// `evict_lru` directly with a small over-cap bucket; verifies
    /// the oldest stamps go first.
    #[test]
    fn read_tracker_363_lru_eviction_drops_oldest() {
        // No tracker_lock needed: this test operates on a local bucket.
        let mut bucket: Bucket = Bucket::new();
        // Insert (cap + 3) entries with strictly increasing stamps so
        // we can predict which three get evicted.
        let cap = READ_TRACKER_MAX_ENTRIES;
        for i in 0..(cap + 3) {
            bucket.insert(PathBuf::from(format!("/virtual/path/{i}")), i as u64);
        }
        assert_eq!(bucket.len(), cap + 3);

        ReadFileTracker::evict_lru(&mut bucket);

        assert_eq!(bucket.len(), cap, "post-eviction size must match cap");
        // The three oldest (stamps 0, 1, 2) must be gone.
        for i in 0..3 {
            assert!(
                !bucket.contains_key(&PathBuf::from(format!("/virtual/path/{i}"))),
                "oldest entry /virtual/path/{i} should be evicted"
            );
        }
        // The newest (stamp cap+2) must remain.
        let newest = PathBuf::from(format!("/virtual/path/{}", cap + 2));
        assert!(
            bucket.contains_key(&newest),
            "most-recently-stamped entry must survive eviction"
        );
    }

    /// Minimal pathdiff: compute a relative path from `base` to `target`
    /// when `target` is absolute and `base` is absolute. Returns `None`
    /// only if either input is relative.
    fn pathdiff_relative(base: &Path, target: &Path) -> Option<PathBuf> {
        if !base.is_absolute() || !target.is_absolute() {
            return None;
        }
        let base_comps: Vec<_> = base.components().collect();
        let target_comps: Vec<_> = target.components().collect();
        let mut shared = 0;
        while shared < base_comps.len()
            && shared < target_comps.len()
            && base_comps[shared] == target_comps[shared]
        {
            shared += 1;
        }
        let mut out = PathBuf::new();
        for _ in shared..base_comps.len() {
            out.push("..");
        }
        for c in &target_comps[shared..] {
            out.push(c.as_os_str());
        }
        if out.as_os_str().is_empty() {
            out.push(".");
        }
        Some(out)
    }
}
