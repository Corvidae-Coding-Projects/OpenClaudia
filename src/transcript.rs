//! Claude Code-compatible session transcript persistence.
//!
//! Port of `utils/sessionStorage.ts` and `utils/sessionStoragePortable.ts`.
//! Transcripts are append-only JSONL files, one message per line. Layout:
//!
//! ```text
//! $CLAUDE_CONFIG_HOME_DIR/projects/<sanitized-cwd>/<session-id>.jsonl
//! ```
//!
//! `CLAUDE_CONFIG_HOME_DIR` defaults to `~/.claude`. `sanitized-cwd`
//! replaces every non-alphanumeric byte in the absolute path with `-`
//! (e.g. `/home/doll/OpenClaudia` → `-home-doll-OpenClaudia`), so
//! sessions created here are readable by Claude Code and vice versa.
//!
//! Each line is a [`SerializedMessage`] — the underlying chat message
//! plus envelope fields (`cwd`, `sessionId`, `timestamp`, `version`,
//! optional `gitBranch`). Appends use `O_APPEND` semantics via Rust's
//! [`OpenOptions`], which is atomic for small writes on POSIX.

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{LazyLock, Mutex, MutexGuard};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::state::{StateEvent, StateStore, StateSubscription};

/// Crate version baked in by Cargo. Matches Claude Code's `version`
/// field on each serialized message.
pub const TRANSCRIPT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Absolute, PATH-independent location of `git` for transcript metadata.
static GIT_BIN: LazyLock<Result<PathBuf, String>> =
    LazyLock::new(|| which::which("git").map_err(|e| format!("git binary not found on PATH: {e}")));

fn git_bin() -> Result<&'static Path, String> {
    match &*GIT_BIN {
        Ok(path) => Ok(path.as_path()),
        Err(msg) => Err(msg.clone()),
    }
}

fn git_command() -> Result<Command, String> {
    Ok(Command::new(git_bin()?))
}

/// Per-cwd cache entry: last-observed git `HEAD` mtime + last branch
/// result. `mtime = None` is a sentinel for "no git HEAD could be
/// stat'd", which still memoises the negative answer so a non-repo
/// directory does not pay a subprocess on every line.
type BranchCacheEntry = (Option<SystemTime>, Option<String>);
type BranchCache = std::collections::HashMap<PathBuf, BranchCacheEntry>;

static GIT_BRANCH_CACHE: Mutex<Option<BranchCache>> = Mutex::new(None);

fn git_branch_cache_guard(
    operation: &'static str,
) -> Option<MutexGuard<'static, Option<BranchCache>>> {
    match GIT_BRANCH_CACHE.lock() {
        Ok(guard) => Some(guard),
        Err(err) => {
            tracing::error!(operation, error = %err, "Git branch cache lock poisoned");
            None
        }
    }
}

/// On-disk envelope around a raw chat message. Field names match
/// Claude Code's `SerializedMessage` type (camelCase over the wire).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedMessage {
    /// Message kind — one of `user`, `assistant`, `system`, `summary`,
    /// `custom-title`, etc. Kept as a free-form string so new Claude
    /// Code metadata entry types round-trip without a code change.
    #[serde(rename = "type")]
    pub kind: String,
    /// UUID assigned to this message. Generated at append time if the
    /// caller doesn't provide one.
    pub uuid: String,
    /// ISO-8601 UTC timestamp.
    pub timestamp: String,
    /// Absolute working directory the message was generated in.
    pub cwd: String,
    /// Session UUID this message belongs to.
    #[serde(rename = "sessionId")]
    pub session_id: String,
    /// Harness version that wrote the line.
    pub version: String,
    /// Git branch at write time, if inside a repo.
    #[serde(rename = "gitBranch", skip_serializing_if = "Option::is_none")]
    pub git_branch: Option<String>,
    /// Underlying chat message payload. For `user`/`assistant`/`system`
    /// this is typically `{ role, content }`. Metadata entry types
    /// (`summary`, `custom-title`, …) carry the payload directly in the
    /// outer object — we preserve it here under `message`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<Value>,
}

/// Resolve `$CLAUDE_CONFIG_HOME_DIR`. Matches Claude Code's
/// `getClaudeConfigHomeDir()`: env var wins, else `~/.claude`.
#[must_use]
pub fn claude_config_home_dir() -> PathBuf {
    if let Ok(explicit) = std::env::var("CLAUDE_CONFIG_HOME_DIR") {
        if !explicit.is_empty() {
            return PathBuf::from(explicit);
        }
    }
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".claude")
}

/// `<claude_config_home>/projects`.
#[must_use]
pub fn projects_dir() -> PathBuf {
    claude_config_home_dir().join("projects")
}

/// Sanitize a filesystem path for use as a project-directory name.
///
/// Claude Code's regex: `/[^a-zA-Z0-9]/g` → `-`. The naive form collapses
/// `/home/doll/Open-Claudia`, `/home/doll/Open Claudia`, and
/// `/home/doll/Open/Claudia` to the same string, sharing the on-disk
/// project directory between distinct projects and leaking transcript
/// metadata across them.
///
/// Crosslink #777: append a short hex digest of the *original* input so the
/// human-readable prefix can collide freely without sharing a directory.
/// The dash-replaced prefix is capped at 200 bytes so the digest-suffixed
/// total (`-<200>-<16>`) stays well under the 255-byte ext4 path-component
/// limit. The hash is taken with SHA-256 (already a dependency) and
/// truncated to 16 hex chars (64 bits) — well above the
/// `sqrt(50e3)` collision-resistance threshold for the per-machine
/// project counts this directory ever sees.
#[must_use]
pub fn sanitize_path(name: &str) -> String {
    use sha2::{Digest, Sha256};

    const PREFIX_CAP: usize = 200;
    const DIGEST_HEX_LEN: usize = 16;

    let mut sanitized: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    if sanitized.len() > PREFIX_CAP {
        sanitized.truncate(PREFIX_CAP);
    }

    // sha2 0.11 returns `hybrid_array::Array<u8, _>` which does not impl
    // `LowerHex` (unlike 0.10's `GenericArray`). Hex-encode the bytes
    // explicitly to keep the wire format byte-identical across the upgrade.
    let digest = Sha256::digest(name.as_bytes());
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in &digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    let suffix = &hex[..DIGEST_HEX_LEN];

    format!("{sanitized}-{suffix}")
}

/// Absolute projects-dir path for `cwd` (e.g.
/// `~/.claude/projects/-home-doll-OpenClaudia`).
#[must_use]
pub fn project_dir_for(cwd: &Path) -> PathBuf {
    let key = cwd.to_string_lossy();
    projects_dir().join(sanitize_path(&key))
}

/// Absolute transcript path for `(cwd, session_id)`.
#[must_use]
pub fn transcript_path(cwd: &Path, session_id: &str) -> PathBuf {
    project_dir_for(cwd).join(format!("{session_id}.jsonl"))
}

fn git_head_mtime(cwd: &Path) -> Option<SystemTime> {
    let git_path = cwd.join(".git");
    let direct_head = git_path.join("HEAD");
    if let Ok(mtime) = std::fs::metadata(&direct_head).and_then(|m| m.modified()) {
        return Some(mtime);
    }

    let git_file = std::fs::read_to_string(&git_path).ok()?;
    let git_dir = git_file.strip_prefix("gitdir:")?.trim();
    let git_dir_path = Path::new(git_dir);
    let resolved_git_dir = if git_dir_path.is_absolute() {
        git_dir_path.to_path_buf()
    } else {
        cwd.join(git_dir_path)
    };

    std::fs::metadata(resolved_git_dir.join("HEAD"))
        .and_then(|m| m.modified())
        .ok()
}

/// Best-effort git branch lookup via `git rev-parse --abbrev-ref HEAD`.
/// Returns `None` when git isn't available or `cwd` isn't a repo.
///
/// Crosslink #781: previously spawned a blocking `git` subprocess on every
/// transcript-line append, hitting the tokio executor thread for 5-50 ms
/// per call (and indefinitely on a wedged git lock — there is no timeout
/// on `std::process::Command::output()`). Now memoises the answer per
/// `(cwd, .git/HEAD mtime)` so the steady-state cost on a session that
/// stays on one branch is a single subprocess call followed by hash-map
/// hits, and a `git checkout` invalidates the entry naturally on the next
/// call.
#[must_use]
pub fn current_git_branch(cwd: &Path) -> Option<String> {
    let head_mtime = git_head_mtime(cwd);

    {
        let guard = git_branch_cache_guard("current_git_branch.read");
        if let Some(map) = guard.as_ref().and_then(|g| g.as_ref()) {
            if let Some((cached_mtime, cached_branch)) = map.get(cwd) {
                if *cached_mtime == head_mtime {
                    return cached_branch.clone();
                }
            }
        }
    }

    let branch = match git_command().and_then(|mut cmd| {
        cmd.args(["rev-parse", "--abbrev-ref", "HEAD"])
            .current_dir(cwd)
            .output()
            .map_err(|e| e.to_string())
    }) {
        Ok(out) if out.status.success() => {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if s.is_empty() || s == "HEAD" {
                None
            } else {
                Some(s)
            }
        }
        _ => None,
    };

    if let Some(mut guard) = git_branch_cache_guard("current_git_branch.write") {
        let map = guard.get_or_insert_with(BranchCache::new);
        map.insert(cwd.to_path_buf(), (head_mtime, branch.clone()));
    }

    branch
}

/// Build a [`SerializedMessage`] for `message` using the current time,
/// a fresh UUID, and a best-effort git-branch lookup.
#[must_use]
pub fn envelope_for(
    kind: &str,
    cwd: &Path,
    session_id: &str,
    message: Option<Value>,
) -> SerializedMessage {
    SerializedMessage {
        kind: kind.to_string(),
        uuid: uuid::Uuid::new_v4().to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        cwd: cwd.to_string_lossy().into_owned(),
        session_id: session_id.to_string(),
        version: TRANSCRIPT_VERSION.to_string(),
        git_branch: current_git_branch(cwd),
        message,
    }
}

/// Append one JSONL line to the transcript for `(cwd, session_id)`,
/// creating the project directory on first use. Mode `0o600` on the
/// file, `0o700` on the directory — matches Claude Code's permissions.
///
/// On Unix the file and the project directory are *born* with the
/// restricted mode via [`OpenOptionsExt::mode`] /
/// [`DirBuilderExt::mode`]. The previous implementation
/// `create_dir_all` + `OpenOptions::create` + post-create `chmod`
/// briefly exposed the path at the umask-default permissions (typically
/// `0o755` / `0o644`) between the `open(2)` and the `chmod(2)`. For a
/// transcript that includes prompt context or tool-result snippets,
/// that race let a concurrent reader on the same host see one line of
/// session content (crosslink #948, same shape as #801).
///
/// # Errors
///
/// Returns an error if the filesystem is inaccessible. The caller
/// should log-and-continue rather than crash: transcript writes are
/// best-effort and must not fail the user-visible turn.
pub fn append_entry(
    cwd: &Path,
    session_id: &str,
    entry: &SerializedMessage,
) -> std::io::Result<()> {
    let path = transcript_path(cwd, session_id);
    if let Some(parent) = path.parent() {
        create_dir_all_secure(parent)?;
    }
    let line = serde_json::to_string(entry).map_err(std::io::Error::other)?;
    let mut file = open_append_secure(&path)?;
    writeln!(file, "{line}")?;
    Ok(())
}

/// Event-driven writer for the canonical session transcript tail.
///
/// Multiple queued message events are coalesced into one snapshot and one
/// tail flush. If the bounded event channel lags, the writer reconciles from
/// the canonical watermark so skipped notifications cannot drop messages.
pub struct TranscriptStateSubscriber {
    state: StateStore,
    subscription: StateSubscription,
}

impl TranscriptStateSubscriber {
    #[must_use]
    pub fn new(state: StateStore) -> Self {
        let subscription = state.subscribe_log_lag();
        Self {
            state,
            subscription,
        }
    }

    /// Drain queued events and flush once when any message may have changed.
    pub fn drain_pending(&mut self) -> usize {
        let mut should_flush = false;
        while let Some(event) = self.subscription.try_recv() {
            if matches!(
                event,
                StateEvent::MessageAppended { .. } | StateEvent::SnapshotReplaced
            ) {
                should_flush = true;
            }
        }
        should_flush |= self.subscription.take_lagged();
        if should_flush {
            self.flush_now()
        } else {
            0
        }
    }

    /// Reconcile the on-disk transcript with the canonical watermark now.
    ///
    /// Save and shutdown boundaries call this even without a fresh event so a
    /// previously failed append gets another chance. The watermark advances
    /// only across entries that were actually persisted.
    pub fn flush_now(&mut self) -> usize {
        let (cwd, session_id, watermark, messages) = self.state.inspect(|state| {
            (
                state.transcript.transcript_cwd.clone(),
                state.identity.session_id.clone(),
                state.transcript.watermark,
                state.conversation.messages.clone(),
            )
        });
        let total = messages.len();
        let start = watermark.min(total);
        let mut appended = 0;
        for message in &messages[start..] {
            let kind = message
                .get("role")
                .and_then(Value::as_str)
                .unwrap_or("system");
            let entry = envelope_for(kind, &cwd, session_id.as_str(), Some(message.clone()));
            match append_entry(&cwd, session_id.as_str(), &entry) {
                Ok(()) => appended += 1,
                Err(err) => {
                    let remaining = total - start - appended;
                    tracing::warn!(
                        error = %err,
                        appended,
                        remaining,
                        "transcript append failed; watermark advanced only over persisted entries"
                    );
                    break;
                }
            }
        }

        self.state.update(|state, _| {
            if state.identity.session_id == session_id {
                state.transcript.watermark = start + appended;
            } else {
                tracing::warn!(
                    flushed_session_id = %session_id,
                    active_session_id = %state.identity.session_id,
                    "session switched during transcript flush; discarded stale watermark"
                );
            }
        });
        appended
    }
}

/// Open `path` for append, creating it with mode `0o600` on Unix so the
/// file never exists at a wider permission than its final mode. On
/// non-Unix targets the open is the standard append-create — NTFS ACLs
/// handle confidentiality and there is no umask to defeat.
#[cfg(unix)]
fn open_append_secure(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_append_secure(path: &Path) -> std::io::Result<std::fs::File> {
    OpenOptions::new().create(true).append(true).open(path)
}

/// Create `path` (recursively) with mode `0o700` on Unix so the project
/// directory is never observable at the default `0o755` between its
/// creation and a follow-up `chmod`. Re-creating an existing directory
/// is a no-op; the mode is enforced on first creation only, which
/// matches Claude Code's behaviour and avoids paying a `chmod` syscall
/// on every transcript append.
#[cfg(unix)]
fn create_dir_all_secure(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
}

#[cfg(not(unix))]
fn create_dir_all_secure(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)
}

/// Sentinel content prefix used by
/// [`crate::compaction::build_compact_boundary_message`]. Re-declared
/// here to avoid a circular import — keep in sync with the canonical
/// constant in `src/compaction.rs`.
const COMPACT_BOUNDARY_MARKER: &str = "[openclaudia:compact_boundary]";

/// True when a serialized message carries the compact-boundary marker
/// in its text content. Looks at the nested `message.content` shape
/// used by normal user/assistant/system entries.
fn is_compact_boundary(entry: &SerializedMessage) -> bool {
    if entry.kind != "system" {
        return false;
    }
    let Some(msg) = entry.message.as_ref() else {
        return false;
    };
    let Some(content) = msg.get("content") else {
        return false;
    };
    if let Some(s) = content.as_str() {
        return s.starts_with(COMPACT_BOUNDARY_MARKER);
    }
    if let Some(arr) = content.as_array() {
        return arr.iter().any(|block| {
            block
                .get("text")
                .and_then(|t| t.as_str())
                .is_some_and(|t| t.starts_with(COMPACT_BOUNDARY_MARKER))
        });
    }
    false
}

/// Return the subset of `entries` starting from the last compact-boundary marker onward.
///
/// When no boundary exists, returns `entries` unchanged. Used by `--resume` to
/// avoid re-feeding the model content that was already summarized away.
#[must_use]
pub fn entries_after_last_boundary(entries: &[SerializedMessage]) -> &[SerializedMessage] {
    entries
        .iter()
        .rposition(is_compact_boundary)
        .map_or(entries, |idx| &entries[idx..])
}

/// Read every JSONL line in `path` as a [`SerializedMessage`]. Lines
/// that fail to parse are skipped (and logged via `tracing::warn`) so a
/// partial/corrupt tail doesn't break resume.
#[must_use]
pub fn load_transcript(path: &Path) -> Vec<SerializedMessage> {
    let Ok(file) = std::fs::File::open(path) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (idx, line) in BufReader::new(file).lines().enumerate() {
        let Ok(line) = line else { continue };
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<SerializedMessage>(&line) {
            Ok(msg) => out.push(msg),
            Err(err) => tracing::warn!(
                path = %path.display(),
                line = idx + 1,
                error = %err,
                "skipping unparseable transcript line"
            ),
        }
    }
    out
}

/// Summary of a transcript on disk, used by `--resume` pickers.
#[derive(Debug, Clone)]
pub struct TranscriptInfo {
    pub session_id: String,
    pub path: PathBuf,
    pub first_prompt: Option<String>,
    pub message_count: usize,
    pub modified: std::time::SystemTime,
}

/// List every transcript for the project rooted at `cwd`, newest first.
/// Non-JSONL files and files we can't read are silently skipped.
#[must_use]
pub fn list_transcripts(cwd: &Path) -> Vec<TranscriptInfo> {
    let dir = project_dir_for(cwd);
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    let mut out: Vec<TranscriptInfo> = entries
        .flatten()
        .filter_map(|e| {
            let path = e.path();
            if path.extension()?.to_str()? != "jsonl" {
                return None;
            }
            let session_id = path.file_stem()?.to_str()?.to_string();
            let modified = e.metadata().ok()?.modified().ok()?;
            let messages = load_transcript(&path);
            let first_prompt = messages
                .iter()
                .find(|m| m.kind == "user")
                .and_then(|m| m.message.as_ref())
                .and_then(extract_text_content);
            Some(TranscriptInfo {
                session_id,
                path,
                first_prompt,
                message_count: messages.len(),
                modified,
            })
        })
        .collect();
    out.sort_by_key(|t| std::cmp::Reverse(t.modified));
    out
}

/// Pull plain text out of a `{ role, content }` payload where `content`
/// is either a string or an Anthropic-style block array.
fn extract_text_content(message: &Value) -> Option<String> {
    let content = message.get("content")?;
    if let Some(s) = content.as_str() {
        return Some(s.to_string());
    }
    if let Some(arr) = content.as_array() {
        let joined: String = arr
            .iter()
            .filter_map(|block| block.get("text").and_then(|t| t.as_str()))
            .collect::<Vec<_>>()
            .join("");
        if joined.is_empty() {
            return None;
        }
        return Some(joined);
    }
    None
}

/// Locate a transcript anywhere under `projects_dir()` by session ID.
/// Used by `--resume <session-id>` when the user doesn't pass `--cwd`.
#[must_use]
pub fn find_transcript_by_id(session_id: &str) -> Option<PathBuf> {
    let projects = projects_dir();
    let entries = std::fs::read_dir(&projects).ok()?;
    for project_entry in entries.flatten() {
        let project_path = project_entry.path();
        if !project_path.is_dir() {
            continue;
        }
        let candidate = project_path.join(format!("{session_id}.jsonl"));
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Serialize every test (across modules) that touches the shared
/// `CLAUDE_CONFIG_HOME_DIR` env var. Cargo's default parallel test
/// runner otherwise races between tests that point the var at
/// different `TempDir`s, producing flaky path / `list_transcripts`
/// assertions. Crosslink #709 promoted this lock to crate-visible so
/// the TUI transcript-subscriber tests can share the same gate as
/// the transcript module's own tests rather than ship a second mutex
/// for the same global.
#[cfg(test)]
pub(crate) fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    struct EnvGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            unsafe {
                std::env::set_var(key, value);
            }
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            unsafe {
                match &self.previous {
                    Some(v) => std::env::set_var(self.key, v),
                    None => std::env::remove_var(self.key),
                }
            }
        }
    }

    #[test]
    fn current_git_branch_uses_resolved_git_binary_path() {
        let git = git_bin().expect("transcript tests require git on PATH");
        assert!(
            git.is_absolute(),
            "git_bin must resolve git to an absolute path, got {}",
            git.display()
        );

        let src = include_str!("transcript.rs");
        let cfg_test = src
            .find("#[cfg(test)]")
            .expect("test module marker must be present");
        let production = &src[..cfg_test];

        for (idx, raw_line) in production.lines().enumerate() {
            let code = raw_line.split("//").next().unwrap_or("");
            assert!(
                !code.contains("Command::new(\"git\")")
                    && !code.contains("std::process::Command::new(\"git\")"),
                "production transcript code must not invoke bare git; line {n}: {raw_line}",
                n = idx + 1,
            );
        }
    }

    #[test]
    fn git_head_mtime_reads_worktree_gitdir_file() {
        let tmp = TempDir::new().unwrap();
        let worktree = tmp.path().join("worktree");
        let git_dir = tmp.path().join("repo/.git/worktrees/worktree");
        std::fs::create_dir_all(&worktree).unwrap();
        std::fs::create_dir_all(&git_dir).unwrap();
        std::fs::write(
            worktree.join(".git"),
            "gitdir: ../repo/.git/worktrees/worktree\n",
        )
        .unwrap();
        std::fs::write(git_dir.join("HEAD"), "ref: refs/heads/feature\n").unwrap();

        assert!(
            git_head_mtime(&worktree).is_some(),
            "worktree .git file should resolve to the real gitdir HEAD"
        );
    }

    #[test]
    fn sanitize_path_appends_stable_digest() {
        // Crosslink #777: sanitize_path now appends a 16-hex SHA-256
        // suffix so collisions on the dash-replaced prefix are
        // vanishingly rare. The prefix remains human-readable.
        let out = sanitize_path("/home/doll/OpenClaudia");
        assert!(
            out.starts_with("-home-doll-OpenClaudia-"),
            "expected human-readable prefix, got: {out}"
        );
        // Suffix is deterministic for a given input.
        assert_eq!(out, sanitize_path("/home/doll/OpenClaudia"));
        // Last 16 chars after the trailing `-` are lowercase hex.
        let (_, suffix) = out.rsplit_once('-').expect("suffix present");
        assert_eq!(suffix.len(), 16);
        assert!(
            suffix
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "suffix must be lowercase hex: {suffix}"
        );

        // Every non-alphanumeric char still becomes a dash in the prefix.
        let win = sanitize_path("C:\\Users\\Foo");
        assert!(win.starts_with("C--Users-Foo-"));
        assert!(sanitize_path("plain").starts_with("plain-"));
    }

    #[test]
    fn sanitize_path_distinguishes_collision_targets_777() {
        // Crosslink #777 regression: the three inputs all collapse to the
        // same dash-string under the old implementation. Distinct inputs
        // must now produce distinct sanitized directory names.
        let dashed = sanitize_path("/home/doll/Open-Claudia");
        let spaced = sanitize_path("/home/doll/Open Claudia");
        let nested = sanitize_path("/home/doll/Open/Claudia");
        assert_ne!(
            dashed, spaced,
            "Open-Claudia vs Open Claudia must differ ({dashed} == {spaced})"
        );
        assert_ne!(
            dashed, nested,
            "Open-Claudia vs Open/Claudia must differ ({dashed} == {nested})"
        );
        assert_ne!(
            spaced, nested,
            "Open Claudia vs Open/Claudia must differ ({spaced} == {nested})"
        );

        // /foo/bar vs /foo-bar — the example from the issue body.
        let slash = sanitize_path("/foo/bar");
        let hyphen = sanitize_path("/foo-bar");
        assert_ne!(
            slash, hyphen,
            "/foo/bar vs /foo-bar must differ ({slash} == {hyphen})"
        );
    }

    #[test]
    fn sanitize_path_caps_prefix_for_long_inputs_777() {
        // Crosslink #777: the prefix component is capped at 200 bytes so
        // the digest-suffixed total fits inside the 255-byte ext4 limit,
        // even for absurdly long input paths.
        let long = "/".to_string() + &"a".repeat(1000);
        let out = sanitize_path(&long);
        // 200 (prefix cap) + 1 (dash) + 16 (digest) = 217 ≤ 255.
        assert!(out.len() <= 255, "out is {} bytes", out.len());
        assert!(
            out.len() >= 200,
            "prefix should fill the cap, got {}",
            out.len()
        );
    }

    #[test]
    fn env_overrides_home_dir() {
        let _lock = env_lock();
        let tmp = TempDir::new().unwrap();
        let _g = EnvGuard::set("CLAUDE_CONFIG_HOME_DIR", tmp.path().to_str().unwrap());
        assert_eq!(claude_config_home_dir(), tmp.path());
        assert_eq!(projects_dir(), tmp.path().join("projects"));
    }

    #[test]
    fn append_and_load_roundtrip() {
        let _lock = env_lock();
        let tmp = TempDir::new().unwrap();
        let _g = EnvGuard::set("CLAUDE_CONFIG_HOME_DIR", tmp.path().to_str().unwrap());
        let cwd = PathBuf::from("/home/doll/OpenClaudia");
        let session_id = "11111111-2222-3333-4444-555555555555";

        let entry = envelope_for(
            "user",
            &cwd,
            session_id,
            Some(json!({"role": "user", "content": "hello"})),
        );
        append_entry(&cwd, session_id, &entry).unwrap();

        let loaded = load_transcript(&transcript_path(&cwd, session_id));
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].kind, "user");
        assert_eq!(loaded[0].session_id, session_id);
        assert_eq!(loaded[0].cwd, "/home/doll/OpenClaudia");
        assert_eq!(
            loaded[0]
                .message
                .as_ref()
                .unwrap()
                .get("content")
                .and_then(|c| c.as_str()),
            Some("hello"),
        );
    }

    #[test]
    fn list_transcripts_sorts_newest_first() {
        let _lock = env_lock();
        let tmp = TempDir::new().unwrap();
        let _g = EnvGuard::set("CLAUDE_CONFIG_HOME_DIR", tmp.path().to_str().unwrap());
        let cwd = PathBuf::from("/tmp/proj");
        for id in ["aaa", "bbb"] {
            let entry = envelope_for("user", &cwd, id, Some(json!({"content": id})));
            append_entry(&cwd, id, &entry).unwrap();
            // Sleep briefly so mtime differs.
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let infos = list_transcripts(&cwd);
        assert_eq!(infos.len(), 2);
        assert_eq!(infos[0].session_id, "bbb");
        assert_eq!(infos[1].session_id, "aaa");
    }

    #[test]
    fn entries_after_last_boundary_slices_correctly() {
        // Build a mixed transcript: pre-boundary messages, boundary,
        // post-boundary messages. Resume must only feed the last slice.
        let make = |kind: &str, content: &str| SerializedMessage {
            kind: kind.to_string(),
            uuid: "u".to_string(),
            timestamp: "t".to_string(),
            cwd: "/x".to_string(),
            session_id: "s".to_string(),
            version: "v".to_string(),
            git_branch: None,
            message: Some(json!({"role": kind, "content": content})),
        };
        let entries = vec![
            make("user", "old question"),
            make("assistant", "old answer"),
            make(
                "system",
                &format!("{COMPACT_BOUNDARY_MARKER} {{}}\nsummary"),
            ),
            make("user", "new question"),
            make("assistant", "new answer"),
        ];
        let after = entries_after_last_boundary(&entries);
        assert_eq!(after.len(), 3, "boundary + 2 post-boundary messages kept");
        assert_eq!(after[0].kind, "system");
        assert_eq!(after[1].kind, "user");
        assert!(after[1]
            .message
            .as_ref()
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .unwrap()
            .contains("new"));
    }

    #[test]
    fn entries_after_last_boundary_is_identity_without_boundary() {
        let entry = SerializedMessage {
            kind: "user".to_string(),
            uuid: "u".to_string(),
            timestamp: "t".to_string(),
            cwd: "/x".to_string(),
            session_id: "s".to_string(),
            version: "v".to_string(),
            git_branch: None,
            message: Some(json!({"role": "user", "content": "hi"})),
        };
        let entries = vec![entry];
        let after = entries_after_last_boundary(&entries);
        assert_eq!(after.len(), 1);
    }

    #[test]
    fn find_by_id_searches_all_projects() {
        let _lock = env_lock();
        let tmp = TempDir::new().unwrap();
        let _g = EnvGuard::set("CLAUDE_CONFIG_HOME_DIR", tmp.path().to_str().unwrap());
        let cwd = PathBuf::from("/tmp/elsewhere");
        let session_id = "needle-id";
        let entry = envelope_for("user", &cwd, session_id, None);
        append_entry(&cwd, session_id, &entry).unwrap();
        let found = find_transcript_by_id(session_id).unwrap();
        assert!(found.ends_with(format!("{session_id}.jsonl")));
    }
}
