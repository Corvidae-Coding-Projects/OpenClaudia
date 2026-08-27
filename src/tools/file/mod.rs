mod discovery;
mod edit;
mod glob;
mod grep;
mod list;
mod notebook;
mod read;
pub mod secure_fs;
pub mod workspace_projection;
mod write;

pub use edit::execute_edit_file;
pub use glob::execute_glob_typed;
pub use grep::execute_grep_typed;
#[cfg(test)]
pub use list::execute_list_files;
pub use list::execute_list_files_typed;
#[cfg(test)]
pub use notebook::execute_notebook_edit;
pub use notebook::execute_notebook_edit_typed;
pub use notebook::source_to_line_array;
pub use read::{detect_file_type, FileType};
#[cfg(test)]
pub use read::{parse_page_range, read_notebook_file, ImageKind};
pub use write::execute_write_file;

use crate::tools::args::ToolArgs as _;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex, MutexGuard};

use similar::TextDiff;

const LEDGER_EXCERPT_MAX_BYTES: usize = 100_000;
const MAX_DERIVED_READ_OUTPUT_BYTES: usize = 100_000;
const MAX_IMAGE_EDGE_PIXELS: u32 = 32_768;
const MAX_IMAGE_PIXELS: u64 = 100_000_000;
pub(super) const MAX_MUTATION_BYTES: usize = 10 * 1024 * 1024;
const MAX_DIFF_LINES_PER_GENERATION: usize = 100_000;
const MAX_RETAINED_DIFF_BYTES: usize = 64 * 1024;

/// Maximum number of entries in the read tracker, per session, before
/// the oldest write is evicted from the front of the list. Per-session so
/// a noisy run cannot evict another run's reads. Matches the
/// previous global ceiling.
const READ_TRACKER_MAX_ENTRIES: usize = 10_000;

/// Immutable generation captured from the exact bytes used by `read_file`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct FileSnapshot {
    generation: crate::runtime::ContentDigest,
    byte_len: u64,
}

impl FileSnapshot {
    #[must_use]
    pub(super) const fn generation(self) -> crate::runtime::ContentDigest {
        self.generation
    }

    #[must_use]
    pub(super) const fn byte_len(self) -> u64 {
        self.byte_len
    }
}

#[derive(Clone, Copy)]
struct TrackedSnapshot {
    snapshot: FileSnapshot,
    stamp: u64,
}

/// Per-run bucket: canonical resource identity → immutable read generation.
type Bucket = HashMap<PathBuf, TrackedSnapshot>;

/// Tracks which files have been read, bucketed by exact run identity.
///
/// Each run has its own map of canonical resource identities to the exact
/// content digest and byte length observed by `read_file`. `edit_file` and
/// existing-file `write_file` require the caller to name that generation and
/// revalidate it before publication. There is no ambient session lookup or
/// shared default bucket.
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
    /// Per-run buckets. The inner map is canonical resource identity →
    /// immutable snapshot plus insertion counter (see [`Bucket`]).
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
    #[cfg(test)]
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
        let mut file = match secure_fs::open_regular_read(run, &resolved) {
            Ok(file) => file,
            Err(error) => {
                tracing::warn!(
                    path = %resolved.display(),
                    error,
                    "READ_TRACKER.mark_read: secure read failed; skipping insertion"
                );
                return;
            }
        };
        let maximum = usize::try_from(read::MAX_FILE_SIZE_BYTES).unwrap_or(usize::MAX);
        let bytes = match secure_fs::read_stable_bounded_bytes(&mut file, &resolved, maximum) {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::warn!(
                    path = %resolved.display(),
                    error,
                    "READ_TRACKER.mark_read: stable snapshot failed; skipping insertion"
                );
                return;
            }
        };
        self.mark_snapshot(run, &resolved, &bytes);
    }

    /// Record the digest of the same stable bytes used to produce a successful
    /// read result. The canonical path is already resolved by the caller, so
    /// this does not reopen or canonicalize the resource.
    pub(super) fn mark_snapshot(
        &self,
        run: &super::security::ToolRunContext,
        resolved: &Path,
        bytes: &[u8],
    ) -> FileSnapshot {
        self.mark_generation(
            run,
            resolved,
            crate::runtime::ContentDigest::sha256(bytes),
            u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        )
    }

    /// Record an already-streamed complete generation without retaining the
    /// source bytes in memory.
    pub(super) fn mark_generation(
        &self,
        run: &super::security::ToolRunContext,
        resolved: &Path,
        generation: crate::runtime::ContentDigest,
        byte_len: u64,
    ) -> FileSnapshot {
        let snapshot = FileSnapshot {
            generation,
            byte_len,
        };
        if !resolved.is_absolute() || !run.permits_read(resolved) {
            tracing::warn!(
                path = %resolved.display(),
                run_id = %run.run_id(),
                "READ_TRACKER.mark_snapshot: unresolved or unauthorized resource identity"
            );
            return snapshot;
        }
        let stamp = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let key = run.run_id().to_string();
        let Some(mut buckets) = self.buckets_guard("mark_read") else {
            return snapshot;
        };
        let files = buckets.entry(key).or_default();
        // O(1) upsert: re-inserting refreshes the LRU stamp.
        files.insert(resolved.to_path_buf(), TrackedSnapshot { snapshot, stamp });
        if files.len() > READ_TRACKER_MAX_ENTRIES {
            Self::evict_lru(files);
        }
        snapshot
    }

    /// Drop bucket entries until the count is back at the cap. Removes
    /// the oldest-stamped entries first (true LRU).
    fn evict_lru(files: &mut Bucket) {
        let excess = files.len().saturating_sub(READ_TRACKER_MAX_ENTRIES);
        if excess == 0 {
            return;
        }
        // Collect (stamp, path) pairs and partial-sort by stamp ascending.
        let mut stamped: Vec<(u64, PathBuf)> = files
            .iter()
            .map(|(path, tracked)| (tracked.stamp, path.clone()))
            .collect();
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
        self.snapshot_for(run, path).is_some()
    }

    /// Return the latest immutable generation read by this exact run.
    pub(super) fn snapshot_for(
        &self,
        run: &super::security::ToolRunContext,
        path: &Path,
    ) -> Option<FileSnapshot> {
        let anchored = if path.is_absolute() {
            path.to_path_buf()
        } else {
            run.working_directory().join(path)
        };
        let Ok(check_path) = std::fs::canonicalize(anchored) else {
            // Strict mode: refuse to silently fall back to the raw path.
            // The agent must perform a real read first. See crosslink #363.
            return None;
        };
        if !run.permits_read(&check_path) {
            return None;
        }
        let key = run.run_id().to_string();
        let buckets = self.buckets_guard("has_been_read")?;
        buckets
            .get(&key)
            .and_then(|files| files.get(&check_path))
            .map(|tracked| tracked.snapshot)
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

/// Resolve a caller-supplied path through one immutable run capability.
///
/// Relative paths are anchored to the run working directory, existing path
/// components are canonicalized, and successful results remain inside a root
/// for which the run has read authority.
///
/// # Errors
///
/// Returns an error when workspace reads are not granted, the input contains a
/// parent traversal component, no existing ancestor can be resolved, or the
/// normalized path is outside every root granted to the run.
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
    if !super::security::path_is_within(&resolved, run.project_root())
        || !run.is_denied_path(&resolved)
    {
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
    let (resolved, mut file) = open_capability_regular_read(run, user_path)?;
    let bytes = secure_fs::read_stable_bounded_bytes(
        &mut file,
        &resolved,
        usize::try_from(read::MAX_FILE_SIZE_BYTES).unwrap_or(usize::MAX),
    )?;
    let content = String::from_utf8(bytes)
        .map_err(|error| format!("File '{}' is not valid UTF-8: {error}", resolved.display()))?;
    READ_TRACKER.mark_snapshot(run, &resolved, content.as_bytes());
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
    let diff_permit = crate::guardrails::admit_file_change(run, &resolved, content.as_bytes())?;
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
            diff_permit.reconcile_live();
            crate::guardrails::record_file_modification(
                run,
                &resolved.to_string_lossy(),
                actual_added,
                actual_removed,
            );
        } else {
            line_reservation.commit();
            diff_permit.reconcile_live();
        }
        effect_reservation.commit();
        return Err(format!("Failed to write '{}': {error}", resolved.display()));
    }
    line_reservation.commit();
    diff_permit.commit();
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

fn read_sensitivity(
    run: &super::security::ToolRunContext,
    resolved: &Path,
) -> crate::tools::ToolSensitivity {
    if resolved.starts_with(run.project_root()) {
        crate::tools::ToolSensitivity::Workspace
    } else {
        crate::tools::ToolSensitivity::Private
    }
}

fn provider_accepts_attachment(provider: &str, media_type: &str) -> bool {
    let normalized = provider.to_ascii_lowercase();
    let provider = match normalized.as_str() {
        "gemini" => "google",
        other => other,
    };
    if provider == "google" {
        return true;
    }
    media_type.starts_with("image/") && matches!(provider, "anthropic" | "openai" | "ollama")
}

fn incompatible_read_option(
    args: &HashMap<String, serde_json::Value>,
    allowed: &[&str],
) -> Option<&'static str> {
    ["offset", "limit", "cursor", "pages"]
        .into_iter()
        .find(|option| args.contains_key(*option) && !allowed.contains(option))
}

fn incompatible_read_result(option: &str, kind: &str) -> crate::tools::ToolHandlerResult {
    crate::tools::ToolHandlerResult::error(crate::tools::ToolFailure::new(
        crate::tools::ToolFailureCode::InvalidArguments,
        format!("'{option}' is not supported when reading {kind} content"),
        crate::tools::ToolRetryability::Never,
    ))
}

fn read_artifact(
    resolved: &Path,
    generation: crate::runtime::ContentDigest,
    byte_len: u64,
    mime_type: &str,
    encoding: Option<&str>,
    sensitivity: crate::tools::ToolSensitivity,
) -> crate::tools::ToolArtifact {
    crate::tools::ToolArtifact {
        id: format!("file:{generation}"),
        kind: "file_snapshot".to_string(),
        label: resolved.to_string_lossy().into_owned(),
        metadata: serde_json::json!({
            "generation": generation,
            "byte_len": byte_len,
            "mime_type": mime_type,
            "encoding": encoding,
        }),
        sensitivity,
    }
}

fn finish_typed_read(
    run: &super::security::ToolRunContext,
    resolved: &Path,
    mut result: crate::tools::ToolHandlerResult,
    generation: crate::runtime::ContentDigest,
    total_bytes: u64,
    start_line: usize,
    end_line: usize,
) -> crate::tools::ToolHandlerResult {
    READ_TRACKER.mark_generation(run, resolved, generation, total_bytes);
    run.record_skill_path_touch(resolved);
    let excerpt = super::safe_truncate(result.content(), LEDGER_EXCERPT_MAX_BYTES).to_string();
    record_active_file_read_observation_digest(
        run, resolved, generation, start_line, end_line, excerpt,
    );
    result.usage.input_bytes = total_bytes;
    result.usage.output_bytes = u64::try_from(result.content().len()).unwrap_or(u64::MAX);
    result
}

fn text_page_result(
    run: &super::security::ToolRunContext,
    resolved: &Path,
    page: read::StableReadPage,
) -> crate::tools::ToolHandlerResult {
    let read::StablePageContent::Text {
        text,
        start_line,
        start_column_bytes,
        end_line,
        end_column_bytes,
    } = page.content
    else {
        unreachable!("text_page_result requires text content")
    };
    let sensitivity = read_sensitivity(run, resolved);
    let mut rendered = if text.is_empty() && page.total_bytes > 0 {
        "(no lines at or after requested offset)".to_string()
    } else {
        read::render_numbered_text_page(&text, start_line, start_column_bytes)
    };
    let _ = write!(
        rendered,
        "\n\nFile snapshot: generation={}, bytes={}. Byte range: {}..{}.",
        page.generation, page.total_bytes, page.byte_start, page.byte_end
    );
    let continuation = page
        .next_cursor
        .as_ref()
        .map(|cursor| serde_json::json!({"cursor": cursor}));
    if let Some(cursor) = page.next_cursor.as_ref() {
        let _ = write!(
            rendered,
            " Read is partial; continue with cursor={cursor:?} (do not also pass offset)."
        );
    }
    let structured = serde_json::json!({
        "kind": "text",
        "path": resolved,
        "encoding": "utf-8",
        "mime_type": "text/plain; charset=utf-8",
        "sensitivity": sensitivity,
        "artifact": {
            "generation": page.generation,
            "byte_len": page.total_bytes,
        },
        "range": {
            "byte_start": page.byte_start,
            "byte_end": page.byte_end,
            "start_line": start_line,
            "start_column_bytes": start_column_bytes,
            "end_line": end_line,
            "end_column_bytes": end_column_bytes,
        },
        "partial": continuation.is_some(),
        "eof": continuation.is_none(),
        "continuation": continuation,
    });
    let mut result = if let Some(continuation) = continuation {
        crate::tools::ToolHandlerResult::partial_truncated_structured(
            rendered,
            structured,
            page.total_bytes.saturating_sub(page.byte_end),
            Some(continuation),
        )
    } else {
        crate::tools::ToolHandlerResult::success_structured(rendered, structured)
    };
    result.sensitivity = sensitivity;
    result = result.with_artifact(read_artifact(
        resolved,
        page.generation,
        page.total_bytes,
        "text/plain; charset=utf-8",
        Some("utf-8"),
        sensitivity,
    ));
    let ledger_end = if end_column_bytes == 0 && end_line > start_line {
        end_line.saturating_sub(1)
    } else {
        end_line
    };
    finish_typed_read(
        run,
        resolved,
        result,
        page.generation,
        page.total_bytes,
        usize::try_from(start_line).unwrap_or(usize::MAX),
        usize::try_from(ledger_end).unwrap_or(usize::MAX),
    )
}

fn binary_page_result(
    run: &super::security::ToolRunContext,
    resolved: &Path,
    page: read::StableReadPage,
) -> crate::tools::ToolHandlerResult {
    let read::StablePageContent::Binary(bytes) = page.content else {
        unreachable!("binary_page_result requires binary content")
    };
    let media_type = "application/octet-stream";
    if !provider_accepts_attachment(run.provider_id(), media_type) {
        return crate::tools::ToolHandlerResult::error(crate::tools::ToolFailure::new(
            crate::tools::ToolFailureCode::Unavailable,
            format!(
                "Provider '{}' does not support typed binary tool-result attachments; use a text/domain-specific reader for '{}'",
                run.provider_id(),
                resolved.display()
            ),
            crate::tools::ToolRetryability::Never,
        ));
    }
    let sensitivity = read_sensitivity(run, resolved);
    let attachment =
        match crate::tools::register_transient_attachment(media_type, bytes, sensitivity) {
            Ok(attachment) => attachment,
            Err(message) => {
                return crate::tools::ToolHandlerResult::error(crate::tools::ToolFailure::new(
                    crate::tools::ToolFailureCode::Unavailable,
                    message,
                    crate::tools::ToolRetryability::Safe,
                ))
            }
        };
    let continuation = page
        .next_cursor
        .as_ref()
        .map(|cursor| serde_json::json!({"cursor": cursor}));
    let text = format!(
        "Binary file page attached as {media_type}: '{}' bytes {}..{} of {} (generation={}).",
        resolved.display(),
        page.byte_start,
        page.byte_end,
        page.total_bytes,
        page.generation
    );
    let structured = serde_json::json!({
        "kind": "binary",
        "path": resolved,
        "encoding": "binary",
        "mime_type": media_type,
        "sensitivity": sensitivity,
        "artifact": {"generation": page.generation, "byte_len": page.total_bytes},
        "range": {"byte_start": page.byte_start, "byte_end": page.byte_end},
        "partial": continuation.is_some(),
        "eof": continuation.is_none(),
        "continuation": continuation,
    });
    let mut result = if let Some(continuation) = continuation {
        crate::tools::ToolHandlerResult::partial_truncated_structured(
            text,
            structured,
            page.total_bytes.saturating_sub(page.byte_end),
            Some(continuation),
        )
    } else {
        crate::tools::ToolHandlerResult::success_structured(text, structured)
    };
    result.sensitivity = sensitivity;
    result = result
        .with_artifact(read_artifact(
            resolved,
            page.generation,
            page.total_bytes,
            media_type,
            None,
            sensitivity,
        ))
        .with_attachment(attachment);
    finish_typed_read(
        run,
        resolved,
        result,
        page.generation,
        page.total_bytes,
        1,
        1,
    )
}

fn media_result(
    run: &super::security::ToolRunContext,
    resolved: &Path,
    bytes: Vec<u8>,
    kind: read::ImageKind,
) -> crate::tools::ToolHandlerResult {
    let sensitivity = read_sensitivity(run, resolved);
    let generation = crate::runtime::ContentDigest::sha256(&bytes);
    let total_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let media_type = kind.mime();
    let Some(dimensions) = kind.dimensions(&bytes) else {
        return crate::tools::ToolHandlerResult::error(crate::tools::ToolFailure::new(
            crate::tools::ToolFailureCode::InvalidInput,
            format!(
                "Image '{}' does not contain a valid {media_type} header and non-zero dimensions matching its extension",
                resolved.display()
            ),
            crate::tools::ToolRetryability::Never,
        ));
    };
    let pixels = u64::from(dimensions.width).saturating_mul(u64::from(dimensions.height));
    if dimensions.width > MAX_IMAGE_EDGE_PIXELS
        || dimensions.height > MAX_IMAGE_EDGE_PIXELS
        || pixels > MAX_IMAGE_PIXELS
    {
        return crate::tools::ToolHandlerResult::error(crate::tools::ToolFailure::new(
            crate::tools::ToolFailureCode::InvalidInput,
            format!(
                "Image '{}' declares unsupported dimensions {}x{} (maximum edge {MAX_IMAGE_EDGE_PIXELS}, maximum pixels {MAX_IMAGE_PIXELS})",
                resolved.display(), dimensions.width, dimensions.height
            ),
            crate::tools::ToolRetryability::Never,
        ));
    }
    if !provider_accepts_attachment(run.provider_id(), media_type) {
        return crate::tools::ToolHandlerResult::error(crate::tools::ToolFailure::new(
            crate::tools::ToolFailureCode::Unavailable,
            format!(
                "Provider '{}' does not support typed {media_type} tool-result attachments",
                run.provider_id()
            ),
            crate::tools::ToolRetryability::Never,
        ));
    }
    let mut attachment =
        match crate::tools::register_transient_attachment(media_type, bytes, sensitivity) {
            Ok(attachment) => attachment,
            Err(message) => {
                return crate::tools::ToolHandlerResult::error(crate::tools::ToolFailure::new(
                    crate::tools::ToolFailureCode::Unavailable,
                    message,
                    crate::tools::ToolRetryability::Safe,
                ))
            }
        };
    if let Some(metadata) = attachment.data.as_object_mut() {
        metadata.insert("width".to_string(), serde_json::json!(dimensions.width));
        metadata.insert("height".to_string(), serde_json::json!(dimensions.height));
    }
    let text = format!(
        "Image attached natively: '{}' ({}x{}, {total_bytes} bytes, {media_type}, generation={generation}).",
        resolved.display(), dimensions.width, dimensions.height
    );
    let structured = serde_json::json!({
        "kind": "image",
        "path": resolved,
        "encoding": "binary",
        "mime_type": media_type,
        "sensitivity": sensitivity,
        "artifact": {"generation": generation, "byte_len": total_bytes},
        "dimensions": {"width": dimensions.width, "height": dimensions.height},
        "partial": false,
        "eof": true,
    });
    let mut result = crate::tools::ToolHandlerResult::success_structured(text, structured)
        .with_artifact(read_artifact(
            resolved,
            generation,
            total_bytes,
            media_type,
            None,
            sensitivity,
        ))
        .with_attachment(attachment);
    result.sensitivity = sensitivity;
    result.usage.input_bytes = total_bytes;
    result.usage.output_bytes = u64::try_from(result.content().len()).unwrap_or(u64::MAX);
    READ_TRACKER.mark_generation(run, resolved, generation, total_bytes);
    run.record_skill_path_touch(resolved);
    record_active_file_read_observation_digest(
        run,
        resolved,
        generation,
        1,
        1,
        result.content().to_string(),
    );
    result
}

fn read_text_or_binary_typed(
    run: &super::security::ToolRunContext,
    args: &HashMap<String, serde_json::Value>,
    resolved: &Path,
    file: &mut std::fs::File,
) -> crate::tools::ToolHandlerResult {
    if let Some(option) = incompatible_read_option(args, &["offset", "limit", "cursor"]) {
        return incompatible_read_result(option, "text or binary");
    }
    match read::read_stable_page(run, file, resolved, args) {
        Ok(
            page @ read::StableReadPage {
                content: read::StablePageContent::Text { .. },
                ..
            },
        ) => text_page_result(run, resolved, page),
        Ok(page) => binary_page_result(run, resolved, page),
        Err(failure) => crate::tools::ToolHandlerResult::error(failure),
    }
}

fn read_image_typed(
    run: &super::security::ToolRunContext,
    args: &HashMap<String, serde_json::Value>,
    resolved: &Path,
    file: &mut std::fs::File,
    kind: read::ImageKind,
) -> crate::tools::ToolHandlerResult {
    if let Some(option) = incompatible_read_option(args, &[]) {
        return incompatible_read_result(option, "image");
    }
    let bytes = match secure_fs::read_stable_bounded_bytes(
        file,
        resolved,
        usize::try_from(read::MAX_FILE_SIZE_BYTES).unwrap_or(usize::MAX),
    ) {
        Ok(bytes) => bytes,
        Err(message) => {
            return crate::tools::ToolHandlerResult::error(crate::tools::ToolFailure::new(
                crate::tools::ToolFailureCode::InvalidInput,
                message,
                crate::tools::ToolRetryability::Never,
            ));
        }
    };
    media_result(run, resolved, bytes, kind)
}

fn render_derived_content(
    run: &super::security::ToolRunContext,
    args: &HashMap<String, serde_json::Value>,
    resolved: &Path,
    bytes: &[u8],
    file_type: read::FileType,
) -> Result<(String, &'static str, &'static str), crate::tools::ToolFailure> {
    let (content, is_error, mime_type, representation) = match file_type {
        FileType::Pdf => {
            let pages = match args.get("pages") {
                None => None,
                Some(serde_json::Value::String(value)) => Some(value.as_str()),
                Some(_) => {
                    return Err(crate::tools::ToolFailure::new(
                        crate::tools::ToolFailureCode::InvalidArguments,
                        "'pages' must be a string".to_string(),
                        crate::tools::ToolRetryability::Never,
                    ));
                }
            };
            let (content, is_error) =
                read::render_pdf_bytes(run, &resolved.to_string_lossy(), pages, bytes);
            (content, is_error, "application/pdf", "extracted_text")
        }
        FileType::Notebook => {
            let (content, is_error) =
                read::render_notebook_bytes(&resolved.to_string_lossy(), bytes);
            (
                content,
                is_error,
                "application/x-ipynb+json",
                "rendered_notebook",
            )
        }
        _ => unreachable!("derived file type was matched before rendering"),
    };
    if is_error {
        Err(crate::tools::ToolFailure::new(
            crate::tools::ToolFailureCode::External,
            content,
            crate::tools::ToolRetryability::Never,
        ))
    } else {
        Ok((content, mime_type, representation))
    }
}

fn build_derived_result(
    run: &super::security::ToolRunContext,
    resolved: &Path,
    content: String,
    mime_type: &str,
    representation: &str,
    generation: crate::runtime::ContentDigest,
    total_bytes: u64,
) -> crate::tools::ToolHandlerResult {
    let sensitivity = read_sensitivity(run, resolved);
    let derived_bytes = content.len();
    let truncated = derived_bytes > MAX_DERIVED_READ_OUTPUT_BYTES;
    let content = if truncated {
        format!(
            "{}\n[derived representation truncated at {MAX_DERIVED_READ_OUTPUT_BYTES} bytes; narrow the document read]",
            super::safe_truncate(&content, MAX_DERIVED_READ_OUTPUT_BYTES)
        )
    } else {
        content
    };
    let structured = serde_json::json!({
        "kind": "document",
        "path": resolved,
        "encoding": "utf-8",
        "mime_type": mime_type,
        "representation": representation,
        "sensitivity": sensitivity,
        "artifact": {"generation": generation, "byte_len": total_bytes},
        "partial": truncated,
        "eof": true,
        "truncation": truncated.then(|| serde_json::json!({
            "output_bytes": derived_bytes,
            "kept_bytes": MAX_DERIVED_READ_OUTPUT_BYTES,
            "continuation": null,
        })),
    });
    let result = if truncated {
        crate::tools::ToolHandlerResult::partial_truncated_structured(
            content,
            structured,
            u64::try_from(derived_bytes.saturating_sub(MAX_DERIVED_READ_OUTPUT_BYTES))
                .unwrap_or(u64::MAX),
            None,
        )
    } else {
        crate::tools::ToolHandlerResult::success_structured(content, structured)
    };
    let mut result = result.with_artifact(read_artifact(
        resolved,
        generation,
        total_bytes,
        mime_type,
        Some("utf-8"),
        sensitivity,
    ));
    result.sensitivity = sensitivity;
    finish_typed_read(run, resolved, result, generation, total_bytes, 1, 1)
}

fn read_derived_document_typed(
    run: &super::security::ToolRunContext,
    args: &HashMap<String, serde_json::Value>,
    resolved: &Path,
    file: &mut std::fs::File,
    file_type: read::FileType,
) -> crate::tools::ToolHandlerResult {
    let allowed = if matches!(file_type, FileType::Pdf) {
        &["pages"][..]
    } else {
        &[][..]
    };
    if let Some(option) = incompatible_read_option(args, allowed) {
        return incompatible_read_result(option, "derived document");
    }
    let bytes = match secure_fs::read_stable_bounded_bytes(
        file,
        resolved,
        usize::try_from(read::MAX_FILE_SIZE_BYTES).unwrap_or(usize::MAX),
    ) {
        Ok(bytes) => bytes,
        Err(message) => {
            return crate::tools::ToolHandlerResult::error(crate::tools::ToolFailure::new(
                crate::tools::ToolFailureCode::InvalidInput,
                message,
                crate::tools::ToolRetryability::Never,
            ));
        }
    };
    let generation = crate::runtime::ContentDigest::sha256(&bytes);
    let total_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    let (content, mime_type, representation) =
        match render_derived_content(run, args, resolved, &bytes, file_type) {
            Ok(rendered) => rendered,
            Err(failure) => return crate::tools::ToolHandlerResult::error(failure),
        };
    build_derived_result(
        run,
        resolved,
        content,
        mime_type,
        representation,
        generation,
        total_bytes,
    )
}

pub fn execute_read_file_typed(
    run: &super::security::ToolRunContext,
    args: &HashMap<String, serde_json::Value>,
) -> crate::tools::ToolHandlerResult {
    let path = match args.arg_str_strict("path") {
        Ok(path) => path,
        Err(error) => {
            return crate::tools::ToolHandlerResult::error(crate::tools::ToolFailure::new(
                crate::tools::ToolFailureCode::InvalidArguments,
                error.to_string(),
                crate::tools::ToolRetryability::Never,
            ))
        }
    };
    let resolved = match resolve_path(run, path) {
        Ok(resolved) => resolved,
        Err(message) => {
            return crate::tools::ToolHandlerResult::error(crate::tools::ToolFailure::new(
                crate::tools::ToolFailureCode::PermissionDenied,
                message,
                crate::tools::ToolRetryability::Never,
            ))
        }
    };
    let mut file = match secure_fs::open_regular_read(run, &resolved) {
        Ok(file) => file,
        Err(message) => {
            return crate::tools::ToolHandlerResult::error(crate::tools::ToolFailure::new(
                crate::tools::ToolFailureCode::PermissionDenied,
                message,
                crate::tools::ToolRetryability::Never,
            ))
        }
    };
    let file_type = detect_file_type(&resolved.to_string_lossy());
    match file_type {
        FileType::Text => read_text_or_binary_typed(run, args, &resolved, &mut file),
        FileType::Image(kind) => read_image_typed(run, args, &resolved, &mut file, kind),
        FileType::Pdf | FileType::Notebook => {
            read_derived_document_typed(run, args, &resolved, &mut file, file_type)
        }
    }
}

fn record_active_file_read_observation_digest(
    run: &super::security::ToolRunContext,
    resolved: &Path,
    generation: crate::runtime::ContentDigest,
    start_line: usize,
    end_line: usize,
    excerpt: String,
) {
    let Some(ledger) = crate::ledger::active_ledger_for_session(run.evidence_session_key()) else {
        return;
    };
    let digest = generation.to_string();
    let sha256 = digest.strip_prefix("sha256:").unwrap_or(&digest);
    let mut ledger = ledger.lock().unwrap_or_else(|error| {
        tracing::error!("active reality ledger lock poisoned; recovering inner state");
        error.into_inner()
    });
    if let Err(error) = ledger.observe_file_read_digest(
        run,
        resolved.to_string_lossy().to_string(),
        sha256,
        start_line,
        end_line,
        excerpt,
    ) {
        tracing::warn!(
            path = %resolved.display(),
            error = %error,
            "failed to append streamed read_file observation to reality ledger"
        );
    }
}

pub(super) fn require_fresh_file_observation_if_ledger_active(
    run: &super::security::ToolRunContext,
    path: &Path,
    action: &str,
) -> Result<(), String> {
    let session_key = run.evidence_session_key();
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

pub(super) fn require_expected_snapshot(
    run: &super::security::ToolRunContext,
    path: &Path,
    supplied: Option<&serde_json::Value>,
) -> Result<FileSnapshot, crate::tools::ToolFailure> {
    use crate::tools::{ToolFailure, ToolFailureCode, ToolRetryability};

    let Some(snapshot) = READ_TRACKER.snapshot_for(run, path) else {
        return Err(ToolFailure::new(
            ToolFailureCode::Conflict,
            format!(
                "No current snapshot exists for '{}'. Call read_file and pass the returned generation as expected_snapshot.",
                path.display()
            ),
            ToolRetryability::Safe,
        ));
    };
    let supplied = supplied.and_then(serde_json::Value::as_str).ok_or_else(|| {
        ToolFailure::new(
            ToolFailureCode::InvalidArguments,
            format!(
                "expected_snapshot is required for '{}'. Pass the generation returned by read_file.",
                path.display()
            ),
            ToolRetryability::Never,
        )
    })?;
    let expected = supplied
        .parse::<crate::runtime::ContentDigest>()
        .map_err(|error| {
            ToolFailure::new(
                ToolFailureCode::InvalidArguments,
                format!("Invalid expected_snapshot '{supplied}': {error}"),
                ToolRetryability::Never,
            )
        })?;
    if expected != snapshot.generation() {
        let mut failure = ToolFailure::new(
            ToolFailureCode::Conflict,
            format!(
                "Snapshot generation for '{}' is stale (requested {expected}, latest read {}). Read the file again before retrying.",
                path.display(),
                snapshot.generation()
            ),
            ToolRetryability::Safe,
        );
        failure.recovery = Some(serde_json::json!({
            "action": "read_file",
            "path": path,
            "latest_read_snapshot": snapshot.generation().to_string(),
        }));
        return Err(failure);
    }
    Ok(snapshot)
}

pub(super) fn read_expected_snapshot_bytes(
    run: &super::security::ToolRunContext,
    path: &Path,
    snapshot: FileSnapshot,
) -> Result<Vec<u8>, crate::tools::ToolFailure> {
    use crate::tools::{ToolFailure, ToolFailureCode, ToolRetryability};

    let mut file = secure_fs::open_regular_read(run, path).map_err(|error| {
        ToolFailure::new(
            ToolFailureCode::Conflict,
            format!(
                "File '{}' is no longer available at the reviewed snapshot: {error}",
                path.display()
            ),
            ToolRetryability::Safe,
        )
    })?;
    let bytes = secure_fs::read_stable_bounded_bytes(&mut file, path, MAX_MUTATION_BYTES).map_err(
        |error| {
            ToolFailure::new(
                ToolFailureCode::Conflict,
                format!(
                    "File '{}' could not be revalidated against the reviewed snapshot: {error}",
                    path.display()
                ),
                ToolRetryability::Safe,
            )
        },
    )?;
    let observed = crate::runtime::ContentDigest::sha256(&bytes);
    if observed != snapshot.generation()
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) != snapshot.byte_len()
    {
        READ_TRACKER.mark_stale(run, path);
        let mut failure = ToolFailure::new(
            ToolFailureCode::Conflict,
            format!(
                "File '{}' changed after it was read (expected {}, observed {observed}). Read it again before retrying.",
                path.display(),
                snapshot.generation()
            ),
            ToolRetryability::Safe,
        );
        failure.recovery = Some(serde_json::json!({
            "action": "read_file",
            "path": path,
            "expected_snapshot": snapshot.generation().to_string(),
            "observed_snapshot": observed.to_string(),
        }));
        return Err(failure);
    }
    Ok(bytes)
}

pub(super) struct PreparedFileDiff {
    pub(super) lines_added: u32,
    pub(super) lines_removed: u32,
    patch: String,
}

struct BoundedDiffWriter {
    text: String,
    maximum_bytes: usize,
    truncated: bool,
}

impl std::fmt::Write for BoundedDiffWriter {
    fn write_str(&mut self, value: &str) -> std::fmt::Result {
        let remaining = self.maximum_bytes.saturating_sub(self.text.len());
        if value.len() <= remaining {
            self.text.push_str(value);
            return Ok(());
        }
        let mut boundary = remaining.min(value.len());
        while boundary > 0 && !value.is_char_boundary(boundary) {
            boundary -= 1;
        }
        self.text.push_str(&value[..boundary]);
        self.truncated = true;
        Err(std::fmt::Error)
    }
}

/// Compute line accounting and a bounded, secret-sanitized evidence patch
/// before any file publication occurs.
pub(super) fn prepare_file_diff(
    run: &super::security::ToolRunContext,
    path: &str,
    before: &str,
    after: &str,
) -> Result<PreparedFileDiff, String> {
    let before_lines = before.bytes().filter(|byte| *byte == b'\n').count();
    let after_lines = after.bytes().filter(|byte| *byte == b'\n').count();
    if before_lines > MAX_DIFF_LINES_PER_GENERATION || after_lines > MAX_DIFF_LINES_PER_GENERATION {
        return Err(format!(
            "Diff for '{path}' exceeds the {MAX_DIFF_LINES_PER_GENERATION}-line computation budget; use a narrower file operation"
        ));
    }
    let diff = TextDiff::from_lines(before, after);
    let mut lines_added = 0_u32;
    let mut lines_removed = 0_u32;
    for change in diff.iter_all_changes() {
        match change.tag() {
            similar::ChangeTag::Insert => lines_added = lines_added.saturating_add(1),
            similar::ChangeTag::Delete => lines_removed = lines_removed.saturating_add(1),
            similar::ChangeTag::Equal => {}
        }
    }
    let mut writer = BoundedDiffWriter {
        text: String::with_capacity(
            MAX_RETAINED_DIFF_BYTES.min(before.len().saturating_add(after.len())),
        ),
        maximum_bytes: MAX_RETAINED_DIFF_BYTES,
        truncated: false,
    };
    let _ = write!(
        writer,
        "{}",
        diff.unified_diff()
            .header(&format!("a/{path}"), &format!("b/{path}"))
    );
    if writer.truncated {
        writer.text.push_str("\n[diff truncated at 65536 bytes]\n");
    }
    let sanitized_patch = run.sanitize_diagnostic(&writer.text).to_string();
    Ok(PreparedFileDiff {
        lines_added,
        lines_removed,
        patch: sanitized_patch,
    })
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

pub(super) fn record_prepared_diff_observation(
    run: &super::security::ToolRunContext,
    path: &str,
    committed_bytes: &[u8],
    prepared: &PreparedFileDiff,
) -> FileSnapshot {
    let resolved = Path::new(path);
    let snapshot = READ_TRACKER.mark_snapshot(run, resolved, committed_bytes);
    append_prepared_diff_observation(run, path, prepared);
    snapshot
}

fn append_prepared_diff_observation(
    run: &super::security::ToolRunContext,
    path: &str,
    prepared: &PreparedFileDiff,
) {
    let session_key = run.session_id();
    let Some(ledger) = crate::ledger::active_ledger_for_session(session_key) else {
        return;
    };
    let mut ledger = ledger.lock().unwrap_or_else(|err| {
        tracing::error!("active reality ledger lock poisoned; recovering inner state");
        err.into_inner()
    });
    if let Err(err) = ledger.observe_diff(run, vec![path.to_string()], prepared.patch.clone()) {
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
    use base64::Engine as _;
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

    fn tiny_png() -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=")
            .expect("valid embedded PNG fixture")
    }

    #[test]
    fn typed_text_page_exposes_matching_gap_free_continuation_metadata() {
        let root = tempfile::tempdir().expect("text project root");
        let path = root.path().join("large.txt");
        std::fs::write(&path, "line\n".repeat(20_000)).expect("write paged text fixture");
        let run = crate::tools::security::test_run_context_for_provider(root.path(), "anthropic");
        let args = HashMap::from([("path".to_string(), serde_json::json!(path))]);
        let first = execute_read_file_typed(&run, &args);

        let crate::tools::ToolOutcome::Partial {
            content,
            continuation,
            ..
        } = &first.outcome
        else {
            panic!("large typed text read must be partial")
        };
        let structured = content.structured.as_ref().expect("structured text result");
        assert_eq!(structured["kind"], "text");
        assert_eq!(structured["encoding"], "utf-8");
        assert_eq!(structured["mime_type"], "text/plain; charset=utf-8");
        assert_eq!(structured["partial"], true);
        assert_eq!(structured["eof"], false);
        assert_eq!(structured["continuation"], serde_json::json!(continuation));
        let crate::tools::ToolCompleteness::Truncated {
            continuation: completeness_continuation,
            omitted_bytes,
        } = &content.completeness
        else {
            panic!("partial result must report typed truncation")
        };
        assert_eq!(completeness_continuation, continuation);
        assert!(*omitted_bytes > 0);
        let first_end = structured["range"]["byte_end"]
            .as_u64()
            .expect("first byte end");
        let cursor = continuation
            .as_ref()
            .and_then(|value| value.get("cursor"))
            .and_then(serde_json::Value::as_str)
            .expect("opaque continuation cursor");

        let next_args = HashMap::from([
            ("path".to_string(), serde_json::json!(path)),
            ("cursor".to_string(), serde_json::json!(cursor)),
        ]);
        let next = execute_read_file_typed(&run, &next_args);
        let next_structured = match &next.outcome {
            crate::tools::ToolOutcome::Success { content }
            | crate::tools::ToolOutcome::Partial { content, .. } => {
                content.structured.as_ref().expect("next structured result")
            }
            crate::tools::ToolOutcome::Error { failure } => {
                panic!("continuation failed: {}", failure.message)
            }
        };
        assert_eq!(next_structured["range"]["byte_start"], first_end);
        assert_eq!(next_structured["artifact"], structured["artifact"]);
    }

    #[test]
    fn typed_binary_page_is_bounded_native_data_not_serialized_prose() {
        let root = tempfile::tempdir().expect("binary project root");
        let path = root.path().join("payload.bin");
        let bytes = (0_u8..64)
            .map(|byte| byte.wrapping_add(0x80))
            .collect::<Vec<_>>();
        std::fs::write(&path, &bytes).expect("write binary fixture");
        let run = crate::tools::security::test_run_context_for_provider(root.path(), "google");
        let args = HashMap::from([("path".to_string(), serde_json::json!(path))]);
        let handler_result = execute_read_file_typed(&run, &args);

        let crate::tools::ToolOutcome::Success { content } = &handler_result.outcome else {
            panic!("small Google binary read must succeed")
        };
        let structured = content
            .structured
            .as_ref()
            .expect("structured binary result");
        assert_eq!(structured["kind"], "binary");
        assert_eq!(structured["encoding"], "binary");
        assert_eq!(structured["mime_type"], "application/octet-stream");
        assert_eq!(structured["range"]["byte_start"], 0);
        assert_eq!(structured["range"]["byte_end"], bytes.len());
        assert_eq!(structured["eof"], true);
        assert_eq!(handler_result.attachments.len(), 1);

        let call = crate::tools::ToolCall {
            id: "binary-call".to_string(),
            call_type: "function".to_string(),
            function: crate::tools::FunctionCall {
                name: "read_file".to_string(),
                arguments: serde_json::to_string(&serde_json::json!({"path": path}))
                    .expect("serialize arguments"),
            },
        };
        let result = crate::tools::ToolResult::bind(&call, "read_file", handler_result);
        let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
        assert!(!serde_json::to_string(&result)
            .expect("serialize typed binary result")
            .contains(&encoded));
        assert!(!result.provider_content().contains(&encoded));
        let message = result.openai_message();
        let resolved = crate::tools::resolve_tool_attachments(
            message.get(crate::tools::TOOL_ATTACHMENTS_MESSAGE_KEY),
        )
        .expect("resolve transient binary attachment");
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].bytes.as_ref(), bytes.as_slice());
    }

    #[test]
    fn typed_image_read_keeps_raw_media_out_of_the_serialized_result() {
        let root = tempfile::tempdir().expect("image project root");
        let path = root.path().join("pixel.png");
        let bytes = tiny_png();
        std::fs::write(&path, &bytes).expect("write image fixture");
        let run = crate::tools::security::test_run_context_for_provider(root.path(), "anthropic");
        let args = HashMap::from([("path".to_string(), serde_json::json!(path))]);
        let handler_result = execute_read_file_typed(&run, &args);

        let crate::tools::ToolOutcome::Success { content } = &handler_result.outcome else {
            panic!("valid PNG must produce a successful typed result")
        };
        let structured = content
            .structured
            .as_ref()
            .expect("structured image result");
        assert_eq!(structured["dimensions"]["width"], 1);
        assert_eq!(structured["dimensions"]["height"], 1);
        assert_eq!(structured["eof"], true);
        assert_eq!(handler_result.attachments.len(), 1);
        assert_eq!(handler_result.attachments[0].media_type, "image/png");
        assert_eq!(handler_result.attachments[0].data["width"], 1);
        assert_eq!(handler_result.attachments[0].data["height"], 1);
        let call = crate::tools::ToolCall {
            id: "image-call".to_string(),
            call_type: "function".to_string(),
            function: crate::tools::FunctionCall {
                name: "read_file".to_string(),
                arguments: serde_json::to_string(&serde_json::json!({"path": path}))
                    .expect("serialize arguments"),
            },
        };
        let result = crate::tools::ToolResult::bind(&call, "read_file", handler_result);
        let encoded_media = base64::engine::general_purpose::STANDARD.encode(&bytes);
        let serialized = serde_json::to_string(&result).expect("serialize typed result");
        assert!(!serialized.contains(&encoded_media));
        assert!(!result.provider_content().contains(&encoded_media));
        assert!(result
            .openai_message()
            .get(crate::tools::TOOL_ATTACHMENTS_MESSAGE_KEY)
            .is_some());
    }

    #[test]
    fn image_read_reports_typed_unavailable_for_unsupported_provider() {
        let root = tempfile::tempdir().expect("image project root");
        let path = root.path().join("pixel.png");
        std::fs::write(&path, tiny_png()).expect("write image fixture");
        let run = crate::tools::security::test_run_context_for_provider(root.path(), "deepseek");
        let args = HashMap::from([("path".to_string(), serde_json::json!(path))]);
        let result = execute_read_file_typed(&run, &args);

        let crate::tools::ToolOutcome::Error { failure } = &result.outcome else {
            panic!("unsupported provider must return a typed error")
        };
        assert_eq!(failure.code, crate::tools::ToolFailureCode::Unavailable);
        assert!(result.attachments.is_empty());
    }

    #[test]
    fn image_read_rejects_excessive_declared_dimensions() {
        let root = tempfile::tempdir().expect("image project root");
        let path = root.path().join("oversized.png");
        let mut bytes = vec![0_u8; 24];
        bytes[..8].copy_from_slice(b"\x89PNG\r\n\x1a\n");
        bytes[12..16].copy_from_slice(b"IHDR");
        bytes[16..20].copy_from_slice(&(MAX_IMAGE_EDGE_PIXELS + 1).to_be_bytes());
        bytes[20..24].copy_from_slice(&1_u32.to_be_bytes());
        std::fs::write(&path, bytes).expect("write declared-dimension fixture");
        let run = crate::tools::security::test_run_context_for_provider(root.path(), "anthropic");
        let args = HashMap::from([("path".to_string(), serde_json::json!(path))]);
        let result = execute_read_file_typed(&run, &args);

        let crate::tools::ToolOutcome::Error { failure } = &result.outcome else {
            panic!("excessive image dimensions must fail before provider delivery")
        };
        assert_eq!(failure.code, crate::tools::ToolFailureCode::InvalidInput);
        assert!(failure.message.contains("dimensions"));
        assert!(result.attachments.is_empty());
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
            bucket.insert(
                PathBuf::from(format!("/virtual/path/{i}")),
                TrackedSnapshot {
                    snapshot: FileSnapshot {
                        generation: crate::runtime::ContentDigest::sha256(i.to_le_bytes()),
                        byte_len: 0,
                    },
                    stamp: i as u64,
                },
            );
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
