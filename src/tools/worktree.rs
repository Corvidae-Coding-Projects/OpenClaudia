//! Git worktree isolation for agent operations.
//!
//! Provides tools to create and manage isolated git worktrees so agents can
//! work on branches without affecting the main working tree.
//!
//! # Run-bound isolation (crosslink #345, S-074)
//!
//! Earlier revisions called [`std::env::set_current_dir`] inside the enter
//! and exit handlers. That is process-wide global state: any other thread
//! (proxy, TUI, concurrent tool executor) doing a relative-path operation
//! races against the mutation and sees an inconsistent view of the working
//! directory. POSIX, Rust, and Go all document `chdir` as fundamentally
//! unsafe for concurrent processes.
//!
//! The compatibility leaf functions retain the original explicit-path API:
//!
//! * `execute_enter_worktree` never mutates the process CWD. The registry's
//!   capability-bearing adapter creates an immutable replacement run rooted
//!   at the new worktree.
//! * `execute_exit_worktree` no longer reads CWD to discover which worktree
//!   to clean up. It requires an explicit `path` argument naming the
//!   worktree to remove.
//! * All `git` invocations take an explicit `cwd` and pass it to
//!   `Command::current_dir`, so no `git` subprocess depends on the parent's
//!   CWD either.
//!
//! Application frontends must apply the trusted in-memory transition emitted
//! by the registry result; serialized/provider-originated output cannot mint
//! that authority.

use crate::tools::args::ToolArgError;
use crate::tools::args::ToolArgs as _;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

/// Maximum time to wait for a git command (seconds).
const GIT_TIMEOUT_SECS: u64 = 30;

/// Maximum number of paths that one exact worktree transaction may inspect.
/// Refusing an oversized transaction preserves the worktree for a narrower,
/// human-reviewed operation instead of truncating the generation silently.
const MAX_TRANSACTION_PATHS: usize = 4_096;

/// Maximum aggregate UTF-8 bytes retained across one path category.
const MAX_TRANSACTION_PATH_BYTES: usize = 2 * 1024 * 1024;

/// Filesystem-state bound for an exact worktree generation. Fingerprinting is
/// streaming, so this limits I/O rather than resident memory. Refusal leaves
/// the worktree untouched for manual or narrower recovery.
const MAX_FINGERPRINT_ENTRIES: u64 = 200_000;
const MAX_FINGERPRINT_BYTES: u64 = 16 * 1024 * 1024 * 1024;

/// Maximum commit-message bytes accepted by the worktree transaction tool.
const MAX_COMMIT_MESSAGE_BYTES: usize = 4_096;

const WORKTREE_TRANSACTION_SCHEMA_VERSION: u16 = 1;

/// Resolve `git` through the immutable executable search path captured for the
/// exact run that owns the worktree operation.
fn git_bin(run: &crate::tools::ToolRunContext) -> Result<PathBuf, String> {
    run.resolve_executable("git")
        .map_err(|error| error.to_string())
}

/// Process-wide set of worktree paths currently held by the agent harness.
///
/// Populated by [`execute_enter_worktree`] on success and consulted on every
/// subsequent call so a duplicate enter is short-circuited into a no-op
/// instead of racing with itself (crosslink #624). Entries are removed by
/// [`execute_exit_worktree`] when the worktree is successfully torn down.
///
/// Stored under a `Mutex` (not a `DashSet`) because contention is per-call
/// and each call already issues several `git` subprocesses; a single lock
/// roundtrip is negligible next to that.
fn active_worktrees() -> &'static Mutex<HashSet<PathBuf>> {
    static SET: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();
    SET.get_or_init(|| Mutex::new(HashSet::new()))
}

fn active_worktrees_guard(
    operation: &'static str,
) -> Option<MutexGuard<'static, HashSet<PathBuf>>> {
    match active_worktrees().lock() {
        Ok(guard) => Some(guard),
        Err(err) => {
            tracing::error!(operation, error = %err, "Active worktree set lock poisoned");
            None
        }
    }
}

fn workspace_capability_lifecycle() -> &'static Mutex<()> {
    static GATE: OnceLock<Mutex<()>> = OnceLock::new();
    GATE.get_or_init(|| Mutex::new(()))
}

fn active_workspace_capabilities(
) -> &'static Mutex<HashMap<PathBuf, crate::runtime::IsolatedWorkspaceDescriptor>> {
    static CAPABILITIES: OnceLock<
        Mutex<HashMap<PathBuf, crate::runtime::IsolatedWorkspaceDescriptor>>,
    > = OnceLock::new();
    CAPABILITIES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Best-effort canonicalisation that falls back to the original path. Used
/// for *comparison* keys in [`active_worktrees`] so two equivalent spellings
/// of the same path collide on the duplicate-guard check (crosslink #624).
fn canonical_or_self(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Monotonic generation counter bumped whenever the active-worktree set
/// changes. This is the harness-wide signal that any cwd/canonicalize-keyed
/// cache must invalidate (crosslink #624). Callers that *do* cache such
/// state can stash the generation alongside the cached value and reload
/// when [`cwd_cache_generation`] advances.
///
/// The harness today does not own a long-lived realpath cache (Phase 1 of
/// #345 retired the `set_current_dir` calls that would have required one),
/// but exposing the generation now means a future cache only needs to
/// subscribe — it won't need a parallel invalidation mechanism wired in.
static CWD_CACHE_GENERATION: AtomicU64 = AtomicU64::new(0);
static NEXT_WORKSPACE_CAPABILITY_GENERATION: AtomicU64 = AtomicU64::new(1);

fn next_workspace_capability_generation() -> Result<crate::runtime::WorkspaceGeneration, String> {
    let generation = NEXT_WORKSPACE_CAPABILITY_GENERATION
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| "isolated workspace generation space exhausted".to_string())?;
    crate::runtime::WorkspaceGeneration::new(generation)
        .ok_or_else(|| "isolated workspace generation must be non-zero".to_string())
}

/// Current generation of the cwd/canonicalize invalidation token. Bumped by
/// every successful [`execute_enter_worktree`] / [`execute_exit_worktree`]
/// call that mutates the active-worktree set.
#[must_use]
pub fn cwd_cache_generation() -> u64 {
    CWD_CACHE_GENERATION.load(Ordering::Acquire)
}

/// Bump [`CWD_CACHE_GENERATION`] so subscribers see the change. The store
/// uses `Release` so subscribers using `Acquire` observe a happens-before
/// ordering with respect to the path-set mutation that preceded the bump.
fn bump_cwd_cache_generation() {
    CWD_CACHE_GENERATION.fetch_add(1, Ordering::AcqRel);
}

/// Record `worktree_dir` as active and bump the cache generation. Returns
/// `true` if the entry was newly inserted (i.e. the duplicate-guard was
/// satisfied), `false` if it was already present — callers that have
/// already short-circuited on the duplicate-guard should never observe
/// the `false` return, but it keeps the helper total.
fn register_active_worktree(worktree_dir: &Path) -> bool {
    let key = canonical_or_self(worktree_dir);
    let inserted =
        active_worktrees_guard("register_active_worktree").is_some_and(|mut set| set.insert(key));
    if inserted {
        bump_cwd_cache_generation();
    }
    inserted
}

/// Symmetric to [`register_active_worktree`]: drop a worktree from the
/// active set and bump the cache generation if a removal actually
/// happened. Called by [`execute_exit_worktree`] on successful teardown.
fn unregister_active_worktree(worktree_dir: &Path) {
    let key = canonical_or_self(worktree_dir);
    let removed = active_worktrees_guard("unregister_active_worktree")
        .is_some_and(|mut set| set.remove(&key));
    if removed {
        bump_cwd_cache_generation();
    }
}

/// Validate a user-supplied branch name before it reaches any other `git`
/// invocation (crosslink #408).
///
/// `git worktree add -b <name>` historically refused option-looking arguments
/// (those starting with `-`) only on git >= 2.17, and even modern git accepts
/// shell-metacharacters like `;` or `&` inside ref names — which is fine for
/// git itself, but inside the agent harness those characters then flow into
/// log lines, prompt context, and `worktree_dir.join(&branch)` path joins.
///
/// This validator is intentionally stricter than git's own check:
///
/// 1. **Layered character rejection** runs *before* we shell out, so we never
///    rely on the installed git version to catch dangerous inputs:
///    * empty name → rejected
///    * leading `-` → rejected (option-injection)
///    * any of `;`, `&`, `|`, `` ` ``, `$`, `<`, `>`, `(`, `)`, `'`, `"`,
///      `\n`, `\r`, `\t`, or any ASCII control character (< 0x20 or 0x7F) →
///      rejected (shell-metacharacter / control-char hardening)
///    * `..`, `:`, `\\`, `~`, `?`, `*`, `[` anywhere in the name → rejected
///      (matches git's own ref rules; pinned here so we don't depend on
///      `git check-ref-format`'s exact behavior across versions)
///    * trailing `.` → rejected (git rule: ref must not end in `.`)
/// 2. **`git check-ref-format --branch <name>`** then makes the final call on
///    anything that survived the local checks. Its exit status decides
///    accept/reject; its stderr is surfaced verbatim.
///
/// Both layers are required: the first guarantees we never spawn a git
/// subprocess with an unsafe argument, the second guarantees we honor
/// every git rule (e.g. `foo.lock`, `@`, `a@{b`) without re-implementing them.
/// Validate a proposed worktree branch without creating a branch or worktree.
///
/// # Errors
///
/// Returns a descriptive error when the name could enable option injection,
/// shell interpretation, path traversal, or violates Git ref syntax.
pub fn validate_branch_name(
    run: &crate::tools::security::ToolRunContext,
    name: &str,
) -> Result<(), String> {
    if name.is_empty() {
        return Err("branch name is required".to_string());
    }

    if name.starts_with('-') {
        return Err(format!(
            "invalid branch name '{name}': must not start with '-' (option-injection guard)"
        ));
    }

    if name.ends_with('.') {
        return Err(format!(
            "invalid branch name '{name}': must not end with '.'"
        ));
    }

    for ch in name.chars() {
        if ch.is_control() {
            return Err(format!(
                "invalid branch name: contains ASCII control character U+{:04X}",
                ch as u32
            ));
        }
        // Two categories of forbidden characters, merged into a single arm
        // because the error rendering is identical:
        //   * shell metacharacters:  ; & | ` $ < > ( ) ' " <space>
        //   * git ref-syntax chars:  : \ ~ ? * [
        // Both are surfaced with the same "forbidden character" message so the
        // caller doesn't need to distinguish the category — the *fact* of
        // rejection is what matters at the tool boundary.
        if matches!(
            ch,
            ';' | '&'
                | '|'
                | '`'
                | '$'
                | '<'
                | '>'
                | '('
                | ')'
                | '\''
                | '"'
                | ' '
                | ':'
                | '\\'
                | '~'
                | '?'
                | '*'
                | '['
        ) {
            return Err(format!(
                "invalid branch name '{name}': contains forbidden character '{ch}'"
            ));
        }
    }

    if name.contains("..") {
        return Err(format!(
            "invalid branch name '{name}': must not contain '..'"
        ));
    }

    // Defer the remaining ref-format rules (foo.lock, @, a@{b, leading '/',
    // empty path segments, etc.) to git itself. Although this invocation does
    // not inspect a repository, its argument is model-controlled, so keep it
    // inside the common subprocess boundary.
    let output = crate::tools::run_sandboxed_with_timeout_with_env(
        run,
        crate::tools::SandboxProfile::StaticAnalyzer,
        &git_bin(run)?,
        &["check-ref-format", "--branch", name],
        run.working_directory(),
        std::time::Duration::from_secs(GIT_TIMEOUT_SECS),
        &HashMap::new(),
    )
    .map_err(|err| match err {
        crate::tools::command::CommandError::SpawnFailed { source, .. } => {
            format!("failed to spawn git check-ref-format: {source}")
        }
        crate::tools::command::CommandError::TimedOut { .. } => {
            format!("git check-ref-format timed out after {GIT_TIMEOUT_SECS}s")
        }
        crate::tools::command::CommandError::WaitFailed { source, .. } => {
            format!("git check-ref-format wait failed: {source}")
        }
        error @ (crate::tools::command::CommandError::InputTooLarge { .. }
        | crate::tools::command::CommandError::Cancelled { .. }
        | crate::tools::command::CommandError::RuntimeFailed { .. }
        | crate::tools::command::CommandError::WorkspaceReconciliationFailed { .. }) => {
            error.to_string()
        }
    })?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.is_empty() {
            Err(format!(
                "invalid branch name '{name}': rejected by git check-ref-format"
            ))
        } else {
            Err(format!("invalid branch name '{name}': {stderr}"))
        }
    }
}

/// Run a git command in a specified working directory with a timeout.
///
/// `cwd` is mandatory: every call site must say *where* the git command runs.
/// This is the contract that lets us remove `set_current_dir` from this
/// module entirely (crosslink #345).
///
/// Crosslink #836: subprocess spawning, timeout/backoff, and reaping
/// are delegated to [`crate::tools::command::run_with_timeout`] so the
/// pdf reader, the git worktree path, and any future tool share one
/// implementation. The exponential-backoff schedule (1→2→5→10→25→50→100 ms,
/// then sustained 100 ms) lives in that helper; the crosslink #956 latency
/// fix is preserved unchanged.
fn git_in(
    run: &crate::tools::security::ToolRunContext,
    cwd: &Path,
    args: &[&str],
) -> Result<std::process::Output, String> {
    let git = git_bin(run)?;
    // Crosslink #836: route through the shared [`run_with_timeout`]
    // helper so git, pdftotext, and any future tool subprocess share
    // one timeout/backoff implementation. The git-specific timeout
    // and argv-tail formatting are kept here so the caller-visible
    // error string is unchanged.
    let mut hardened_args = vec![
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "diff.external=",
        "-c",
        "core.pager=cat",
        "-c",
        "credential.helper=",
        "-c",
        "protocol.file.allow=never",
        "-c",
        "protocol.ext.allow=never",
    ];
    hardened_args.extend_from_slice(args);
    let env = HashMap::from([
        ("GIT_CONFIG_GLOBAL".to_string(), "/dev/null".to_string()),
        ("GIT_CONFIG_NOSYSTEM".to_string(), "1".to_string()),
        ("GIT_TERMINAL_PROMPT".to_string(), "0".to_string()),
        ("GIT_OPTIONAL_LOCKS".to_string(), "0".to_string()),
    ]);
    crate::tools::run_sandboxed_with_timeout_with_env(
        run,
        crate::tools::SandboxProfile::GitWorktree,
        &git,
        &hardened_args,
        cwd,
        std::time::Duration::from_secs(GIT_TIMEOUT_SECS),
        &env,
    )
    .map_err(|err| match err {
        crate::tools::command::CommandError::SpawnFailed { source, .. } => {
            format!("Failed to spawn git: {source}")
        }
        crate::tools::command::CommandError::TimedOut { .. } => format!(
            "Git command timed out after {GIT_TIMEOUT_SECS}s: git {}",
            args.join(" ")
        ),
        crate::tools::command::CommandError::WaitFailed { source, .. } => {
            format!("Git wait failed: {source}")
        }
        error @ (crate::tools::command::CommandError::InputTooLarge { .. }
        | crate::tools::command::CommandError::Cancelled { .. }
        | crate::tools::command::CommandError::RuntimeFailed { .. }
        | crate::tools::command::CommandError::WorkspaceReconciliationFailed { .. }) => {
            error.to_string()
        }
    })
}

/// Create a new git worktree for isolated agent work.
///
/// **Phase 1 (#345) behavior**: this function does NOT change the process
/// CWD. It only invokes git to create the worktree directory and returns the
/// resulting path in its success message. The caller is responsible for
/// recording the active worktree on the session and threading the path into
/// subsequent tool calls (Phase 2).
#[must_use]
pub fn execute_enter_worktree<S: std::hash::BuildHasher>(
    run: &crate::tools::security::ToolRunContext,
    args: &HashMap<String, Value, S>,
) -> (String, bool) {
    let branch = match args.get("branch") {
        None => "",
        Some(Value::String(branch)) => branch,
        Some(_) => {
            return ToolArgError::WrongType {
                key: "branch",
                expected: "string",
            }
            .into_tool_error();
        }
    };

    if branch.is_empty() {
        return ("Error: branch name is required".to_string(), true);
    }

    // Crosslink #408: validate the branch name BEFORE any other git call.
    // This rejects shell-metacharacters, control chars, option-injection
    // prefixes, and forwards remaining rules to `git check-ref-format`.
    if let Err(e) = validate_branch_name(run, branch) {
        return (format!("Error: {e}"), true);
    }

    let cwd = run.working_directory().to_path_buf();

    match git_in(run, &cwd, &["rev-parse", "--is-inside-work-tree"]) {
        Ok(output) if output.status.success() => {}
        _ => return ("Error: not inside a git repository".to_string(), true),
    }

    let git_root = git_in(run, &cwd, &["rev-parse", "--show-toplevel"])
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map_or_else(|| cwd.clone(), |s| PathBuf::from(s.trim()));

    let worktree_dir = git_root.join(".worktrees").join(branch);

    // Crosslink #624: duplicate-session guard. If this exact worktree path
    // is already tracked as active (by canonical equality), return a no-op
    // success so re-issuing the call doesn't race with itself or leave a
    // half-created git worktree behind. The branch -> worktree_dir mapping
    // above is deterministic, so two callers asking for the same branch
    // both land here.
    let dup_key = canonical_or_self(&worktree_dir);
    if let Some(set) = active_worktrees_guard("execute_enter_worktree.duplicate_check") {
        if set.contains(&dup_key) {
            return (
                format!(
                    "already in worktree at {} (branch '{}'). No-op — use exit_worktree to leave it.",
                    worktree_dir.display(),
                    branch
                ),
                false,
            );
        }
    }

    let base_branch = get_current_branch_at(run, &cwd).unwrap_or_else(|| "HEAD".to_string());
    create_worktree_on_disk(run, &cwd, &worktree_dir, branch, &base_branch)
}

/// Create an isolated worktree and bind it to an opaque, owner-specific host
/// transition.
///
/// The legacy tuple entry point remains available for compatibility, while
/// application registries use this capability-bearing path.
#[must_use]
#[allow(clippy::too_many_lines)] // Creation, inspection, ownership, and publication are one transaction.
pub fn execute_enter_worktree_bound<S: std::hash::BuildHasher>(
    run: &crate::tools::security::ToolRunContext,
    args: &HashMap<String, Value, S>,
) -> crate::tools::ToolHandlerResult {
    if run.isolated_workspace().is_some() {
        return crate::tools::ToolHandlerResult::error(crate::tools::ToolFailure::new(
            crate::tools::ToolFailureCode::Conflict,
            "The active run is already bound to an isolated workspace; exit it before entering another"
                .to_string(),
            crate::tools::ToolRetryability::Never,
        ));
    }
    let _lifecycle = match workspace_capability_lifecycle().lock() {
        Ok(guard) => guard,
        Err(error) => {
            return crate::tools::ToolHandlerResult::error(crate::tools::ToolFailure::new(
                crate::tools::ToolFailureCode::Unavailable,
                format!("Worktree capability lifecycle is unavailable: {error}"),
                crate::tools::ToolRetryability::Safe,
            ));
        }
    };
    let branch = match args.get("branch") {
        Some(Value::String(branch)) if !branch.is_empty() => branch.as_str(),
        _ => {
            let (message, is_error) = execute_enter_worktree(run, args);
            return crate::tools::ToolHandlerResult::legacy(message, is_error);
        }
    };
    let (message, is_error) = execute_enter_worktree(run, args);
    if is_error {
        return crate::tools::ToolHandlerResult::error(crate::tools::ToolFailure::new(
            crate::tools::ToolFailureCode::InvalidInput,
            message,
            crate::tools::ToolRetryability::Never,
        ));
    }
    let expected_path = run.project_root().join(".worktrees").join(branch);
    let snapshot = match inspect_worktree(run, &expected_path) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return crate::tools::ToolHandlerResult::partial_text(
                "The Git worktree was created, but its workspace capability could not be pinned",
                vec![crate::tools::ToolFailure::new(
                    crate::tools::ToolFailureCode::Conflict,
                    error,
                    crate::tools::ToolRetryability::Safe,
                )],
            );
        }
    };
    let mut active = match active_workspace_capabilities().lock() {
        Ok(active) => active,
        Err(error) => {
            return crate::tools::ToolHandlerResult::partial_text(
                "The Git worktree exists, but its owner registry is unavailable",
                vec![crate::tools::ToolFailure::new(
                    crate::tools::ToolFailureCode::Unavailable,
                    error.to_string(),
                    crate::tools::ToolRetryability::Safe,
                )],
            );
        }
    };
    let descriptor = if let Some(existing) = active.get(&snapshot.worktree_path) {
        if existing.owner_session().as_str() != run.session_id()
            || existing.owner_run() != run.run_id()
            || existing.owner_actor() != run.runtime().descriptor().actor.id
        {
            return crate::tools::ToolHandlerResult::error(crate::tools::ToolFailure::new(
                crate::tools::ToolFailureCode::Conflict,
                "The requested worktree is already owned by another run capability".to_string(),
                crate::tools::ToolRetryability::Never,
            ));
        }
        existing.clone()
    } else {
        let base_commit = match git_text(
            run,
            &snapshot.worktree_path,
            &[
                "merge-base",
                &snapshot.view.worktree_head,
                &snapshot.view.target_head,
            ],
        ) {
            Ok(base) => base,
            Err(error) => {
                return crate::tools::ToolHandlerResult::partial_text(
                    "The Git worktree exists, but its base commit could not be pinned",
                    vec![crate::tools::ToolFailure::new(
                        crate::tools::ToolFailureCode::Conflict,
                        error,
                        crate::tools::ToolRetryability::Safe,
                    )],
                );
            }
        };
        let repository_id = match snapshot
            .view
            .repository_id
            .parse::<crate::runtime::ContentDigest>()
        {
            Ok(identity) => identity,
            Err(error) => {
                return crate::tools::ToolHandlerResult::partial_text(
                    "The Git worktree exists, but its repository identity is malformed",
                    vec![crate::tools::ToolFailure::new(
                        crate::tools::ToolFailureCode::Internal,
                        error.to_string(),
                        crate::tools::ToolRetryability::Never,
                    )],
                );
            }
        };
        let worktree_id = match snapshot
            .view
            .worktree_id
            .parse::<crate::runtime::ContentDigest>()
        {
            Ok(identity) => identity,
            Err(error) => {
                return crate::tools::ToolHandlerResult::partial_text(
                    "The Git worktree exists, but its worktree identity is malformed",
                    vec![crate::tools::ToolFailure::new(
                        crate::tools::ToolFailureCode::Internal,
                        error.to_string(),
                        crate::tools::ToolRetryability::Never,
                    )],
                );
            }
        };
        let descriptor = match crate::runtime::IsolatedWorkspaceDescriptor::new(
            crate::runtime::WorkspaceHandleId::new(),
            repository_id,
            worktree_id,
            snapshot.repository_root_id,
            snapshot.worktree_root_id,
            snapshot.main_path.clone(),
            snapshot.worktree_path.clone(),
            base_commit,
            snapshot.view.target_head.clone(),
            snapshot.view.branch.clone(),
            run.runtime().descriptor().session_id.clone(),
            run.process_owner().to_string(),
            run.run_id(),
            run.runtime().descriptor().actor.id,
            match next_workspace_capability_generation() {
                Ok(generation) => generation,
                Err(error) => {
                    return crate::tools::ToolHandlerResult::partial_text(
                        "The Git worktree exists, but no workspace generation was available",
                        vec![crate::tools::ToolFailure::new(
                            crate::tools::ToolFailureCode::Internal,
                            error,
                            crate::tools::ToolRetryability::Never,
                        )],
                    );
                }
            },
        ) {
            Ok(descriptor) => descriptor,
            Err(error) => {
                return crate::tools::ToolHandlerResult::partial_text(
                    "The Git worktree exists, but its capability descriptor was rejected",
                    vec![crate::tools::ToolFailure::new(
                        crate::tools::ToolFailureCode::Internal,
                        error.to_string(),
                        crate::tools::ToolRetryability::Never,
                    )],
                );
            }
        };
        active.insert(snapshot.worktree_path.clone(), descriptor.clone());
        descriptor
    };
    drop(active);
    crate::tools::ToolHandlerResult::success_structured(
        format!(
            "Entered isolated workspace on branch '{}'",
            descriptor.branch()
        ),
        json!({
            "workspace_handle": descriptor.handle_id().to_string(),
            "generation": descriptor.generation().get(),
            "branch": descriptor.branch(),
            "path": descriptor.workspace_root(),
            "lifecycle": "active",
        }),
    )
    .with_workspace_transition(crate::tools::WorkspaceTransition::enter(
        run.run_id(),
        run.generation(),
        descriptor,
    ))
}

pub(crate) fn rebind_workspace_descriptor(
    run: &crate::tools::ToolRunContext,
    persisted: &crate::runtime::IsolatedWorkspaceDescriptor,
) -> Result<crate::runtime::IsolatedWorkspaceDescriptor, String> {
    let _lifecycle = workspace_capability_lifecycle()
        .lock()
        .map_err(|error| format!("worktree capability lifecycle is unavailable: {error}"))?;
    persisted.validate().map_err(|error| error.to_string())?;
    if persisted.owner_session().as_str() != run.session_id()
        || persisted.repository_root() != run.project_root()
    {
        return Err("persisted workspace belongs to another session or repository".to_string());
    }
    let snapshot = inspect_worktree(run, persisted.workspace_root())?;
    let repository_id = snapshot
        .view
        .repository_id
        .parse::<crate::runtime::ContentDigest>()
        .map_err(|error| error.to_string())?;
    let worktree_id = snapshot
        .view
        .worktree_id
        .parse::<crate::runtime::ContentDigest>()
        .map_err(|error| error.to_string())?;
    if repository_id != persisted.repository_id()
        || worktree_id != persisted.worktree_id()
        || snapshot.repository_root_id != persisted.repository_root_id()
        || snapshot.worktree_root_id != persisted.workspace_root_id()
        || snapshot.main_path != persisted.repository_root()
        || snapshot.worktree_path != persisted.workspace_root()
        || snapshot.view.branch != persisted.branch()
    {
        return Err("persisted isolated workspace identity changed".to_string());
    }
    for commit in [persisted.base_commit(), persisted.target_commit()] {
        git_success(
            run,
            persisted.repository_root(),
            &["cat-file", "-e", &format!("{commit}^{{commit}}")],
        )?;
    }
    let mut active = active_workspace_capabilities()
        .lock()
        .map_err(|error| format!("worktree owner registry is unavailable: {error}"))?;
    if let Some(existing) = active.get(persisted.workspace_root()) {
        if existing.owner_run() != run.run_id() {
            return Err("isolated workspace is still owned by another live run".to_string());
        }
    }
    let rebound = crate::runtime::IsolatedWorkspaceDescriptor::new(
        persisted.handle_id(),
        repository_id,
        worktree_id,
        snapshot.repository_root_id,
        snapshot.worktree_root_id,
        snapshot.main_path,
        snapshot.worktree_path.clone(),
        persisted.base_commit().to_string(),
        persisted.target_commit().to_string(),
        persisted.branch().to_string(),
        run.runtime().descriptor().session_id.clone(),
        run.process_owner().to_string(),
        run.run_id(),
        run.runtime().descriptor().actor.id,
        next_workspace_capability_generation()?,
    )
    .map_err(|error| error.to_string())?;
    active.insert(snapshot.worktree_path, rebound.clone());
    drop(active);
    Ok(rebound)
}

pub(crate) fn release_workspace_descriptor_owner(
    run: &crate::tools::ToolRunContext,
) -> Result<(), String> {
    let Some(descriptor) = run.isolated_workspace() else {
        return Ok(());
    };
    let _lifecycle = workspace_capability_lifecycle()
        .lock()
        .map_err(|error| format!("worktree capability lifecycle is unavailable: {error}"))?;
    let mut active = active_workspace_capabilities()
        .lock()
        .map_err(|error| format!("worktree owner registry is unavailable: {error}"))?;
    if active.get(descriptor.workspace_root()) != Some(descriptor) {
        return Err("cannot release a workspace owned by another generation".to_string());
    }
    active.remove(descriptor.workspace_root());
    drop(active);
    Ok(())
}

/// Run `git worktree add` (with the existing-branch retry path) and surface
/// the resulting `(message, is_error)` tuple. Extracted from
/// [`execute_enter_worktree`] so the orchestrator stays under the
/// `clippy::too_many_lines` ceiling. Records the new worktree in the active
/// set on success (crosslink #624).
fn create_worktree_on_disk(
    run: &crate::tools::security::ToolRunContext,
    cwd: &Path,
    worktree_dir: &Path,
    branch: &str,
    base_branch: &str,
) -> (String, bool) {
    let result = git_in(
        run,
        cwd,
        &[
            "worktree",
            "add",
            "-b",
            branch,
            worktree_dir.to_str().unwrap_or(""),
            base_branch,
        ],
    );

    match result {
        Ok(output) if output.status.success() => {
            register_active_worktree(worktree_dir);
            (
                format!(
                    "Created worktree at {} on branch '{branch}' (based on '{base_branch}').\n\
                     The process CWD has NOT been changed. Pass path={} to exit_worktree, \
                     or use `bash` with explicit working directories when running commands \
                     inside the worktree.\nOriginal directory: {}",
                    worktree_dir.display(),
                    worktree_dir.display(),
                    cwd.display()
                ),
                false,
            )
        }
        Ok(output) => {
            retry_worktree_add_for_existing_branch(run, cwd, worktree_dir, branch, &output)
        }
        Err(e) => (format!("Failed to run git: {e}"), true),
    }
}

/// Helper for [`create_worktree_on_disk`]: if the initial `git worktree add
/// -b` failed because the branch already exists, retry without `-b` so the
/// existing branch is checked out into the new worktree. Returns the final
/// `(message, is_error)` tuple to surface to the caller.
fn retry_worktree_add_for_existing_branch(
    run: &crate::tools::security::ToolRunContext,
    cwd: &Path,
    worktree_dir: &Path,
    branch: &str,
    failed_output: &std::process::Output,
) -> (String, bool) {
    let stderr = String::from_utf8_lossy(&failed_output.stderr);
    if !stderr.contains("already exists") {
        return (
            format!("Failed to create worktree: {}", stderr.trim()),
            true,
        );
    }
    let retry = git_in(
        run,
        cwd,
        &[
            "worktree",
            "add",
            worktree_dir.to_str().unwrap_or(""),
            branch,
        ],
    );
    match retry {
        Ok(o) if o.status.success() => {
            register_active_worktree(worktree_dir);
            (
                format!(
                    "Created worktree (existing branch) at {} on branch '{branch}'.\n\
                     The process CWD has NOT been changed. Pass path={} to exit_worktree.",
                    worktree_dir.display(),
                    worktree_dir.display()
                ),
                false,
            )
        }
        _ => (
            format!("Failed to create worktree: {}", stderr.trim()),
            true,
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorktreeOperation {
    Preview,
    Stage,
    Commit,
    Merge,
    Discard,
    Remove,
    LegacyApply,
    LegacyDiscard,
}

impl WorktreeOperation {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Preview => "preview",
            Self::Stage => "stage",
            Self::Commit => "commit",
            Self::Merge => "merge",
            Self::Discard => "discard",
            Self::Remove => "remove",
            Self::LegacyApply => "legacy_apply",
            Self::LegacyDiscard => "legacy_discard",
        }
    }

    const fn effect(self) -> crate::tools::effect::ToolEffect {
        use crate::tools::effect::ToolEffect;
        match self {
            Self::Preview => ToolEffect::ReadOnly,
            Self::Stage | Self::Commit | Self::Merge => ToolEffect::WorkspaceMutation,
            Self::Discard | Self::Remove | Self::LegacyApply | Self::LegacyDiscard => {
                ToolEffect::Destructive
            }
        }
    }
}

fn parse_operation_name(value: &str) -> Result<WorktreeOperation, String> {
    match value {
        "preview" => Ok(WorktreeOperation::Preview),
        "stage" => Ok(WorktreeOperation::Stage),
        "commit" => Ok(WorktreeOperation::Commit),
        "merge" => Ok(WorktreeOperation::Merge),
        "discard" => Ok(WorktreeOperation::Discard),
        "remove" => Ok(WorktreeOperation::Remove),
        _ => Err(format!(
            "invalid worktree operation '{value}'; expected preview, stage, commit, merge, discard, or remove"
        )),
    }
}

fn parse_worktree_operation<S: std::hash::BuildHasher>(
    args: &HashMap<String, Value, S>,
) -> Result<WorktreeOperation, String> {
    let apply = args
        .arg_bool_or_strict("apply_changes", false)
        .map_err(|error| error.to_string())?;
    let discard = args
        .arg_bool_or_strict("discard_changes", false)
        .map_err(|error| error.to_string())?;
    match args.get("operation") {
        Some(Value::String(operation)) => {
            if apply || discard {
                return Err(
                    "'operation' cannot be combined with deprecated apply_changes/discard_changes flags"
                        .to_string(),
                );
            }
            parse_operation_name(operation)
        }
        Some(_) => Err("Invalid 'operation' argument: expected string".to_string()),
        None if apply => Ok(WorktreeOperation::LegacyApply),
        None if discard => Ok(WorktreeOperation::LegacyDiscard),
        None => Ok(WorktreeOperation::Preview),
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
struct ChangeState {
    staged: BTreeSet<String>,
    unstaged: BTreeSet<String>,
    untracked: BTreeSet<String>,
    ignored: BTreeSet<String>,
    conflicted: BTreeSet<String>,
}

impl ChangeState {
    fn reviewable_paths(&self) -> BTreeSet<String> {
        self.staged
            .iter()
            .chain(&self.unstaged)
            .chain(&self.untracked)
            .chain(&self.conflicted)
            .cloned()
            .collect()
    }

    fn tracked_and_untracked_clean(&self) -> bool {
        self.staged.is_empty()
            && self.unstaged.is_empty()
            && self.untracked.is_empty()
            && self.conflicted.is_empty()
    }

    fn completely_clean(&self) -> bool {
        self.tracked_and_untracked_clean() && self.ignored.is_empty()
    }
}

struct GitStatusObservation {
    branch: String,
    head: String,
    changes: ChangeState,
}

#[derive(Debug, Clone, Serialize)]
struct WorktreeSnapshotView {
    schema_version: u16,
    repository_id: String,
    worktree_id: String,
    generation: String,
    path: String,
    branch: String,
    worktree_head: String,
    target_path: String,
    target_branch: String,
    target_head: String,
    worktree_content_digest: String,
    worktree_index_digest: String,
    target_change_digest: String,
    changes: ChangeState,
    target_changes: ChangeState,
}

struct WorktreeSnapshot {
    view: WorktreeSnapshotView,
    worktree_path: PathBuf,
    main_path: PathBuf,
    repository_root_id: crate::persistence::StorageRootId,
    worktree_root_id: crate::persistence::StorageRootId,
}

/// Narrow read-only projection used by supervised-worker handoff.
///
/// S-087 consumes the same byte-bound observation as the transactional
/// worktree tool instead of reimplementing Git status parsing in subagent
/// cleanup. The projection deliberately exposes no mutation capability.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)] // Direct projection of independent porcelain-v2 state categories.
pub(crate) struct WorkerArtifactObservation {
    pub generation: String,
    pub staged: bool,
    pub unstaged: bool,
    pub untracked: bool,
    pub ignored: bool,
    pub conflicted: bool,
    pub committed: bool,
}

impl WorkerArtifactObservation {
    /// Removal is safe only when neither the worktree bytes/index nor its
    /// branch contain state that has not reached the target branch.
    #[must_use]
    pub const fn cleanup_allowed(&self) -> bool {
        !self.staged && !self.unstaged && !self.untracked && !self.conflicted && !self.committed
    }
}

/// Inspect one linked worktree using the canonical S-074 observation path.
///
/// # Errors
/// Returns the same fail-closed errors as transactional preview. Callers must
/// preserve the linked worktree when inspection fails.
pub(crate) fn inspect_worker_artifacts(
    run: &crate::tools::security::ToolRunContext,
    path: &Path,
) -> Result<WorkerArtifactObservation, String> {
    let snapshot = inspect_worktree(run, path)?;
    let committed = if snapshot.view.worktree_head == snapshot.view.target_head {
        false
    } else {
        !is_ancestor(
            run,
            &snapshot.worktree_path,
            &snapshot.view.worktree_head,
            &snapshot.view.target_head,
        )?
    };
    Ok(WorkerArtifactObservation {
        generation: snapshot.view.generation,
        staged: !snapshot.view.changes.staged.is_empty(),
        unstaged: !snapshot.view.changes.unstaged.is_empty(),
        untracked: !snapshot.view.changes.untracked.is_empty(),
        ignored: !snapshot.view.changes.ignored.is_empty(),
        conflicted: !snapshot.view.changes.conflicted.is_empty(),
        committed,
    })
}

#[derive(Serialize)]
struct SnapshotGeneration<'a> {
    schema_version: u16,
    repository_id: &'a str,
    worktree_id: &'a str,
    path: &'a str,
    branch: &'a str,
    worktree_head: &'a str,
    target_path: &'a str,
    target_branch: &'a str,
    target_head: &'a str,
    worktree_content_digest: &'a str,
    worktree_index_digest: &'a str,
    target_change_digest: &'a str,
    changes: &'a ChangeState,
    target_changes: &'a ChangeState,
}

fn git_success(
    run: &crate::tools::security::ToolRunContext,
    cwd: &Path,
    args: &[&str],
) -> Result<std::process::Output, String> {
    let output = git_in(run, cwd, args)?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn git_text(
    run: &crate::tools::security::ToolRunContext,
    cwd: &Path,
    args: &[&str],
) -> Result<String, String> {
    let output = git_success(run, cwd, args)?;
    String::from_utf8(output.stdout)
        .map(|text| text.trim().to_string())
        .map_err(|_| format!("git {} returned non-UTF-8 output", args.join(" ")))
}

fn resolve_git_path(base: &Path, raw: &str, label: &str) -> Result<PathBuf, String> {
    let candidate = Path::new(raw);
    let candidate = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        base.join(candidate)
    };
    std::fs::canonicalize(&candidate)
        .map_err(|error| format!("Cannot resolve {label} '{}': {error}", candidate.display()))
}

fn record_status_path(
    observed: &mut BTreeSet<String>,
    total_bytes: &mut usize,
    raw: &[u8],
) -> Result<String, String> {
    let path = std::str::from_utf8(raw)
        .map_err(|_| "git status reported a non-UTF-8 path; refusing mutation".to_string())?;
    if observed.insert(path.to_string()) {
        *total_bytes = total_bytes.saturating_add(path.len());
    }
    if observed.len() > MAX_TRANSACTION_PATHS || *total_bytes > MAX_TRANSACTION_PATH_BYTES {
        return Err(format!(
            "Worktree inspection exceeds the transaction limit of {MAX_TRANSACTION_PATHS} paths or {MAX_TRANSACTION_PATH_BYTES} path bytes"
        ));
    }
    Ok(path.to_string())
}

fn record_xy(state: &mut ChangeState, path: String, xy: &str) -> Result<(), String> {
    let bytes = xy.as_bytes();
    if bytes.len() != 2 {
        return Err(format!("Malformed Git status code '{xy}'"));
    }
    if bytes[0] != b'.' {
        state.staged.insert(path.clone());
    }
    if bytes[1] != b'.' {
        state.unstaged.insert(path.clone());
    }
    if bytes.contains(&b'U') {
        state.conflicted.insert(path);
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // Porcelain-v2 record variants share one bounded parser.
fn parse_porcelain_v2(bytes: &[u8], include_ignored: bool) -> Result<GitStatusObservation, String> {
    let records = bytes.split(|byte| *byte == 0).collect::<Vec<_>>();
    let mut state = ChangeState::default();
    let mut branch = None;
    let mut head = None;
    let mut observed = BTreeSet::new();
    let mut total_bytes = 0_usize;
    let mut index = 0_usize;
    while index < records.len() {
        let raw = records[index];
        index = index.saturating_add(1);
        if raw.is_empty() {
            continue;
        }
        if let Some(value) = raw.strip_prefix(b"# branch.oid ") {
            head = Some(
                std::str::from_utf8(value)
                    .map_err(|_| "Git branch OID is not UTF-8".to_string())?
                    .to_string(),
            );
            continue;
        }
        if let Some(value) = raw.strip_prefix(b"# branch.head ") {
            branch = Some(
                std::str::from_utf8(value)
                    .map_err(|_| "Git branch name is not UTF-8".to_string())?
                    .to_string(),
            );
            continue;
        }
        if raw.starts_with(b"# ") {
            continue;
        }
        if let Some(path) = raw.strip_prefix(b"? ") {
            let path = record_status_path(&mut observed, &mut total_bytes, path)?;
            state.untracked.insert(path);
            continue;
        }
        if let Some(path) = raw.strip_prefix(b"! ") {
            if include_ignored {
                let path = record_status_path(&mut observed, &mut total_bytes, path)?;
                state.ignored.insert(path);
            }
            continue;
        }
        let text = std::str::from_utf8(raw)
            .map_err(|_| "git status reported non-UTF-8 metadata".to_string())?;
        if text.starts_with("1 ") {
            let fields = text.splitn(9, ' ').collect::<Vec<_>>();
            if fields.len() != 9 {
                return Err(format!("Malformed ordinary Git status record: {text}"));
            }
            let path = record_status_path(&mut observed, &mut total_bytes, fields[8].as_bytes())?;
            record_xy(&mut state, path, fields[1])?;
            continue;
        }
        if text.starts_with("2 ") {
            let fields = text.splitn(10, ' ').collect::<Vec<_>>();
            if fields.len() != 10 || index >= records.len() {
                return Err(format!("Malformed renamed Git status record: {text}"));
            }
            let current =
                record_status_path(&mut observed, &mut total_bytes, fields[9].as_bytes())?;
            let original = record_status_path(&mut observed, &mut total_bytes, records[index])?;
            index = index.saturating_add(1);
            record_xy(&mut state, current, fields[1])?;
            record_xy(&mut state, original, fields[1])?;
            continue;
        }
        if text.starts_with("u ") {
            let fields = text.splitn(11, ' ').collect::<Vec<_>>();
            if fields.len() != 11 {
                return Err(format!("Malformed unmerged Git status record: {text}"));
            }
            let path = record_status_path(&mut observed, &mut total_bytes, fields[10].as_bytes())?;
            state.conflicted.insert(path);
            continue;
        }
        return Err(format!("Unsupported Git status record: {text}"));
    }
    let branch = branch.ok_or_else(|| "Git status omitted branch identity".to_string())?;
    let head = head.ok_or_else(|| "Git status omitted HEAD identity".to_string())?;
    if head == "(initial)" {
        return Err("Worktree transaction requires an existing HEAD".to_string());
    }
    Ok(GitStatusObservation {
        branch,
        head,
        changes: state,
    })
}

fn inspect_changes(
    run: &crate::tools::security::ToolRunContext,
    cwd: &Path,
    include_ignored: bool,
) -> Result<GitStatusObservation, String> {
    let mut args = vec![
        "status",
        "--porcelain=v2",
        "-z",
        "--branch",
        "--untracked-files=all",
    ];
    if include_ignored {
        args.push("--ignored=matching");
    }
    let output = git_success(run, cwd, &args)?;
    parse_porcelain_v2(&output.stdout, include_ignored)
}

#[derive(Default)]
struct FingerprintBudget {
    entries: u64,
    bytes: u64,
}

fn hash_framed(hasher: &mut Sha256, label: &[u8], bytes: &[u8]) {
    hasher.update(label.len().to_le_bytes());
    hasher.update(label);
    hasher.update(bytes.len().to_le_bytes());
    hasher.update(bytes);
}

#[cfg(unix)]
fn hash_platform_metadata(hasher: &mut Sha256, metadata: &std::fs::Metadata) {
    use std::os::unix::fs::MetadataExt as _;
    hasher.update(metadata.mode().to_le_bytes());
}

#[cfg(not(unix))]
fn hash_platform_metadata(hasher: &mut Sha256, metadata: &std::fs::Metadata) {
    hasher.update([u8::from(metadata.permissions().readonly())]);
}

fn stable_file_metadata(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    if before.len() != after.len()
        || before.file_type() != after.file_type()
        || before.modified().ok() != after.modified().ok()
    {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        before.dev() == after.dev() && before.ino() == after.ino()
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn fingerprint_entry(
    root: &Path,
    relative: &Path,
    hasher: &mut Sha256,
    budget: &mut FingerprintBudget,
) -> Result<(), String> {
    budget.entries = budget.entries.saturating_add(1);
    if budget.entries > MAX_FINGERPRINT_ENTRIES {
        return Err(format!(
            "Worktree fingerprint exceeds {MAX_FINGERPRINT_ENTRIES} filesystem entries"
        ));
    }
    hash_framed(hasher, b"path", relative.as_os_str().as_encoded_bytes());
    let path = root.join(relative);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            hash_framed(hasher, b"type", b"missing");
            return Ok(());
        }
        Err(error) => {
            return Err(format!(
                "Cannot inspect worktree path '{}': {error}",
                path.display()
            ));
        }
    };
    hash_platform_metadata(hasher, &metadata);
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        hash_framed(hasher, b"type", b"symlink");
        let target = std::fs::read_link(&path)
            .map_err(|error| format!("Cannot read symlink '{}': {error}", path.display()))?;
        hash_framed(hasher, b"target", target.as_os_str().as_encoded_bytes());
        return Ok(());
    }
    if file_type.is_file() {
        hash_framed(hasher, b"type", b"file");
        hasher.update(metadata.len().to_le_bytes());
        budget.bytes = budget.bytes.saturating_add(metadata.len());
        if budget.bytes > MAX_FINGERPRINT_BYTES {
            return Err(format!(
                "Worktree fingerprint exceeds {MAX_FINGERPRINT_BYTES} file bytes"
            ));
        }
        let mut file = std::fs::File::open(&path)
            .map_err(|error| format!("Cannot open worktree file '{}': {error}", path.display()))?;
        let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
        loop {
            let read = file.read(&mut buffer).map_err(|error| {
                format!("Cannot read worktree file '{}': {error}", path.display())
            })?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        let after = std::fs::symlink_metadata(&path).map_err(|error| {
            format!(
                "Cannot re-inspect worktree file '{}': {error}",
                path.display()
            )
        })?;
        if !stable_file_metadata(&metadata, &after) {
            return Err(format!(
                "Worktree file changed during inspection: {}",
                path.display()
            ));
        }
        return Ok(());
    }
    if file_type.is_dir() {
        hash_framed(hasher, b"type", b"directory");
        let mut children = std::fs::read_dir(&path)
            .map_err(|error| {
                format!(
                    "Cannot list worktree directory '{}': {error}",
                    path.display()
                )
            })?
            .map(|entry| {
                entry
                    .map(|entry| entry.file_name())
                    .map_err(|error| format!("Cannot enumerate '{}': {error}", path.display()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        children.sort_unstable();
        for child in children {
            fingerprint_entry(root, &relative.join(child), hasher, budget)?;
        }
        return Ok(());
    }
    Err(format!(
        "Unsupported special filesystem entry in worktree: {}",
        path.display()
    ))
}

fn fingerprint_paths<'a>(
    root: &Path,
    paths: impl IntoIterator<Item = &'a Path>,
) -> Result<String, String> {
    let mut hasher = Sha256::new();
    hash_framed(&mut hasher, b"domain", b"openclaudia-worktree-state-v1");
    let mut budget = FingerprintBudget::default();
    for path in paths {
        fingerprint_entry(root, path, &mut hasher, &mut budget)?;
    }
    let digest: [u8; 32] = hasher.finalize().into();
    Ok(crate::runtime::ContentDigest::from_sha256_bytes(digest).to_string())
}

fn fingerprint_changed_paths(root: &Path, changes: &ChangeState) -> Result<String, String> {
    let paths = changes.reviewable_paths();
    fingerprint_paths(root, paths.iter().map(Path::new))
}

fn identity_digest<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(crate::runtime::ContentDigest::sha256)
        .map(|digest| digest.to_string())
        .map_err(|error| format!("Cannot encode worktree identity: {error}"))
}

fn storage_identity(path: &Path, label: &str) -> Result<crate::persistence::StorageRootId, String> {
    crate::persistence::PersistentStorage::open(path)
        .map(|storage| storage.root_id())
        .map_err(|error| format!("Cannot pin {label} '{}': {error}", path.display()))
}

#[allow(clippy::too_many_lines)] // One observation must bind both linked worktree and target state.
fn inspect_worktree(
    run: &crate::tools::security::ToolRunContext,
    requested_path: &Path,
) -> Result<WorktreeSnapshot, String> {
    let worktree_path = std::fs::canonicalize(requested_path).map_err(|error| {
        format!(
            "Cannot resolve worktree path '{}': {error}",
            requested_path.display()
        )
    })?;
    let geometry = git_text(
        run,
        &worktree_path,
        &[
            "rev-parse",
            "--git-common-dir",
            "--git-dir",
            "--show-object-format",
        ],
    )?;
    let mut geometry = geometry.lines();
    let common_raw = geometry
        .next()
        .ok_or_else(|| "Git omitted its common directory".to_string())?;
    let git_dir_raw = geometry
        .next()
        .ok_or_else(|| "Git omitted its linked-worktree directory".to_string())?;
    let object_format = geometry
        .next()
        .ok_or_else(|| "Git omitted its object format".to_string())?;
    if geometry.next().is_some() {
        return Err("Git returned unexpected repository geometry".to_string());
    }
    let common_dir = resolve_git_path(&worktree_path, common_raw, "Git common directory")?;
    let git_dir = resolve_git_path(&worktree_path, git_dir_raw, "linked-worktree Git directory")?;
    if git_dir == common_dir {
        return Err(
            "Not in an isolated worktree. Use this tool only on a linked worktree.".to_string(),
        );
    }
    let main_path = common_dir
        .parent()
        .ok_or_else(|| "Git common directory has no repository parent".to_string())?;
    let main_path = std::fs::canonicalize(main_path)
        .map_err(|error| format!("Cannot resolve main worktree: {error}"))?;
    if main_path == worktree_path {
        return Err("Refusing to transact against the main worktree".to_string());
    }

    // S-108 deliberately publishes Git metadata through transactional
    // projections, so the common-dir and linked-admin directory inode may
    // change after a successful sandboxed Git command. Bind repository and
    // worktree identity to the stable descriptor-pinned content roots plus
    // the canonical metadata paths; binding to projected metadata inodes
    // would make every read-only preview invalidate itself.
    let repository_root_id = storage_identity(&main_path, "main worktree root")?;
    let worktree_root_id = storage_identity(&worktree_path, "worktree root")?;
    let repository_id = identity_digest(&(
        repository_root_id,
        common_dir.to_string_lossy(),
        object_format,
    ))?;
    let worktree_id =
        identity_digest(&(worktree_root_id, git_dir.to_string_lossy(), &repository_id))?;

    let worktree_status = inspect_changes(run, &worktree_path, true)?;
    if worktree_status.branch == "(detached)" {
        return Err(
            "Worktree transaction requires the linked worktree to have an attached branch"
                .to_string(),
        );
    }
    // Ignored files in the merge target are not touched by any S-073 phase.
    // Traversing target/, .worktrees/, and other ignored caches would make a
    // small worktree transaction proportional to unrelated build artifacts.
    let target_status = inspect_changes(run, &main_path, false)?;
    let mut target_changes = target_status.changes;
    if let Ok(relative_worktree) = worktree_path.strip_prefix(&main_path) {
        let retain_outside_managed_worktree = |path: &String| {
            let path = Path::new(path);
            path != relative_worktree && !path.starts_with(relative_worktree)
        };
        target_changes
            .staged
            .retain(retain_outside_managed_worktree);
        target_changes
            .unstaged
            .retain(retain_outside_managed_worktree);
        target_changes
            .untracked
            .retain(retain_outside_managed_worktree);
        target_changes
            .ignored
            .retain(retain_outside_managed_worktree);
        target_changes
            .conflicted
            .retain(retain_outside_managed_worktree);
    }
    let path = worktree_path
        .to_str()
        .ok_or_else(|| "Worktree path is not valid UTF-8; refusing mutation".to_string())?
        .to_string();
    let target_path = main_path
        .to_str()
        .ok_or_else(|| "Main worktree path is not valid UTF-8; refusing mutation".to_string())?
        .to_string();
    let branch = worktree_status.branch;
    let worktree_head = worktree_status.head;
    let changes = worktree_status.changes;
    let target_branch = target_status.branch;
    let target_head = target_status.head;
    // Bind approvals to bytes, not only status categories. This prevents a
    // same-path edit from reusing an older destructive approval. The linked
    // worktree tree includes untracked, ignored, and empty directories; the
    // separate index digest distinguishes staged content from working bytes.
    let worktree_content_digest =
        fingerprint_paths(&worktree_path, std::iter::once(Path::new("")))?;
    let worktree_index_digest = fingerprint_paths(&git_dir, std::iter::once(Path::new("index")))?;
    let target_change_digest = fingerprint_changed_paths(&main_path, &target_changes)?;
    let material = SnapshotGeneration {
        schema_version: WORKTREE_TRANSACTION_SCHEMA_VERSION,
        repository_id: &repository_id,
        worktree_id: &worktree_id,
        path: &path,
        branch: &branch,
        worktree_head: &worktree_head,
        target_path: &target_path,
        target_branch: &target_branch,
        target_head: &target_head,
        worktree_content_digest: &worktree_content_digest,
        worktree_index_digest: &worktree_index_digest,
        target_change_digest: &target_change_digest,
        changes: &changes,
        target_changes: &target_changes,
    };
    let generation = identity_digest(&material)?;
    Ok(WorktreeSnapshot {
        view: WorktreeSnapshotView {
            schema_version: WORKTREE_TRANSACTION_SCHEMA_VERSION,
            repository_id,
            worktree_id,
            generation,
            path,
            branch,
            worktree_head,
            target_path,
            target_branch,
            target_head,
            worktree_content_digest,
            worktree_index_digest,
            target_change_digest,
            changes,
            target_changes,
        },
        worktree_path,
        main_path,
        repository_root_id,
        worktree_root_id,
    })
}

fn snapshot_payload(operation: WorktreeOperation, snapshot: &WorktreeSnapshot) -> Value {
    json!({
        "schema_version": WORKTREE_TRANSACTION_SCHEMA_VERSION,
        "operation": operation.as_str(),
        "transaction": snapshot.view,
    })
}

fn failure_with_snapshot(
    code: crate::tools::ToolFailureCode,
    message: impl Into<String>,
    retryability: crate::tools::ToolRetryability,
    operation: WorktreeOperation,
    snapshot: Option<&WorktreeSnapshot>,
    next_action: &str,
) -> crate::tools::ToolHandlerResult {
    let mut failure = crate::tools::ToolFailure::new(code, message.into(), retryability);
    failure.recovery = Some(json!({
        "next_action": next_action,
        "state": snapshot.map(|state| snapshot_payload(operation, state)),
    }));
    crate::tools::ToolHandlerResult::error(failure)
}

fn partial_with_snapshot(
    message: impl Into<String>,
    operation: WorktreeOperation,
    snapshot: Option<&WorktreeSnapshot>,
    next_action: &str,
) -> crate::tools::ToolHandlerResult {
    let failure = crate::tools::ToolFailure {
        code: crate::tools::ToolFailureCode::External,
        message: message.into(),
        source: Some("git".to_string()),
        retryability: crate::tools::ToolRetryability::Safe,
        recovery: Some(json!({"next_action": next_action})),
    };
    let structured = snapshot.map_or_else(
        || json!({"operation": operation.as_str()}),
        |state| snapshot_payload(operation, state),
    );
    crate::tools::ToolHandlerResult::partial_structured(
        "Worktree operation changed state but did not reach its terminal postcondition",
        structured,
        vec![failure],
        None,
    )
}

fn required_string<'a, S: std::hash::BuildHasher>(
    args: &'a HashMap<String, Value, S>,
    key: &'static str,
) -> Result<&'a str, String> {
    match args.get(key) {
        Some(Value::String(value)) if !value.is_empty() => Ok(value),
        Some(Value::String(_)) | None => Err(format!("'{key}' is required")),
        Some(_) => Err(format!("Invalid '{key}' argument: expected string")),
    }
}

fn expected_generation<S: std::hash::BuildHasher>(
    args: &HashMap<String, Value, S>,
) -> Result<&str, String> {
    let generation = required_string(args, "expected_generation")?;
    generation
        .parse::<crate::runtime::ContentDigest>()
        .map_err(|error| format!("Invalid expected_generation: {error}"))?;
    Ok(generation)
}

fn requested_paths<S: std::hash::BuildHasher>(
    args: &HashMap<String, Value, S>,
) -> Result<BTreeSet<String>, String> {
    let values = args
        .get("paths")
        .and_then(Value::as_array)
        .ok_or_else(|| "'paths' must be a non-empty array of relative paths".to_string())?;
    if values.is_empty() || values.len() > MAX_TRANSACTION_PATHS {
        return Err(format!(
            "'paths' must contain between 1 and {MAX_TRANSACTION_PATHS} entries"
        ));
    }
    let mut paths = BTreeSet::new();
    let mut total_bytes = 0_usize;
    for value in values {
        let path = value
            .as_str()
            .ok_or_else(|| "Every 'paths' entry must be a string".to_string())?;
        let parsed = Path::new(path);
        if path.is_empty()
            || parsed.is_absolute()
            || parsed
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(format!("Invalid transaction path '{path}'"));
        }
        total_bytes = total_bytes.saturating_add(path.len());
        if total_bytes > MAX_TRANSACTION_PATH_BYTES {
            return Err(format!(
                "Transaction path bytes exceed {MAX_TRANSACTION_PATH_BYTES}"
            ));
        }
        if !paths.insert(path.to_string()) {
            return Err(format!("Duplicate transaction path '{path}'"));
        }
    }
    Ok(paths)
}

fn generation_matches(expected: &str, snapshot: &WorktreeSnapshot) -> bool {
    expected == snapshot.view.generation
}

fn recovery_ref(expected: &str) -> Result<String, String> {
    let suffix = expected
        .strip_prefix("sha256:")
        .ok_or_else(|| "expected_generation has no sha256 prefix".to_string())?;
    Ok(format!("refs/openclaudia/worktree-recovery/{suffix}"))
}

fn cleanup_ref(expected: &str, worktree_path: &str) -> Result<String, String> {
    let generation = expected
        .strip_prefix("sha256:")
        .ok_or_else(|| "expected_generation has no sha256 prefix".to_string())?;
    let path_digest = identity_digest(&worktree_path)?;
    let path = path_digest
        .strip_prefix("sha256:")
        .ok_or_else(|| "worktree path digest has no sha256 prefix".to_string())?;
    Ok(format!(
        "refs/openclaudia/worktree-cleanup/{generation}/{path}"
    ))
}

fn ensure_recovery_ref(
    run: &crate::tools::security::ToolRunContext,
    snapshot: &WorktreeSnapshot,
    expected: &str,
    commit: &str,
) -> Result<String, String> {
    let reference = recovery_ref(expected)?;
    if let Ok(observed) = git_text(
        run,
        &snapshot.worktree_path,
        &["rev-parse", "--verify", &reference],
    ) {
        return if observed == commit {
            Ok(reference)
        } else {
            Err(format!(
                "Recovery ref {reference} resolved to {observed}, expected {commit}"
            ))
        };
    }
    git_success(
        run,
        &snapshot.worktree_path,
        &["update-ref", &reference, commit, ""],
    )?;
    let observed = git_text(
        run,
        &snapshot.worktree_path,
        &["rev-parse", "--verify", &reference],
    )?;
    if observed != commit {
        return Err(format!(
            "Recovery ref {reference} resolved to {observed}, expected {commit}"
        ));
    }
    Ok(reference)
}

fn ensure_cleanup_ref(
    run: &crate::tools::security::ToolRunContext,
    snapshot: &WorktreeSnapshot,
    expected: &str,
) -> Result<String, String> {
    let reference = cleanup_ref(expected, &snapshot.view.path)?;
    if let Ok(observed) = git_text(
        run,
        &snapshot.main_path,
        &["rev-parse", "--verify", &reference],
    ) {
        return if observed == snapshot.view.worktree_head {
            Ok(reference)
        } else {
            Err(format!(
                "cleanup ref {reference} resolved to {observed}, expected {}",
                snapshot.view.worktree_head
            ))
        };
    }
    git_success(
        run,
        &snapshot.main_path,
        &["update-ref", &reference, &snapshot.view.worktree_head, ""],
    )?;
    let observed = git_text(
        run,
        &snapshot.main_path,
        &["rev-parse", "--verify", &reference],
    )?;
    if observed != snapshot.view.worktree_head {
        return Err(format!(
            "cleanup ref {reference} resolved to {observed}, expected {}",
            snapshot.view.worktree_head
        ));
    }
    Ok(reference)
}

fn worktree_is_registered(
    run: &crate::tools::security::ToolRunContext,
    main_path: &Path,
    worktree_path: &str,
) -> Result<bool, String> {
    let output = git_success(run, main_path, &["worktree", "list", "--porcelain", "-z"])?;
    let expected = worktree_path.as_bytes();
    Ok(output.stdout.split(|byte| *byte == 0).any(|record| {
        record
            .strip_prefix(b"worktree ")
            .is_some_and(|path| path == expected)
    }))
}

fn validate_cleanup_target(provided: &str, snapshot: &WorktreeSnapshot) -> Result<(), String> {
    let canonical = std::fs::canonicalize(provided)
        .map_err(|error| format!("Cannot resolve target_path '{provided}': {error}"))?;
    if canonical != snapshot.main_path {
        return Err(format!(
            "target_path does not match the reviewed target (expected {})",
            snapshot.main_path.display()
        ));
    }
    Ok(())
}

fn reconcile_absent_cleanup(
    run: &crate::tools::security::ToolRunContext,
    operation: WorktreeOperation,
    worktree_path: &str,
    target_path: &str,
    expected: &str,
) -> crate::tools::ToolHandlerResult {
    let main_path = match std::fs::canonicalize(target_path) {
        Ok(path) => path,
        Err(error) => {
            return failure_with_snapshot(
                crate::tools::ToolFailureCode::InvalidArguments,
                format!("Cannot resolve target_path '{target_path}': {error}"),
                crate::tools::ToolRetryability::Never,
                operation,
                None,
                "Pass the exact target_path returned by the approved preview",
            );
        }
    };
    let reference = match cleanup_ref(expected, worktree_path) {
        Ok(reference) => reference,
        Err(error) => {
            return failure_with_snapshot(
                crate::tools::ToolFailureCode::InvalidArguments,
                error,
                crate::tools::ToolRetryability::Never,
                operation,
                None,
                "Pass the exact generation returned by the approved cleanup call",
            );
        }
    };
    if git_text(run, &main_path, &["rev-parse", "--verify", &reference]).is_err() {
        return failure_with_snapshot(
            crate::tools::ToolFailureCode::Conflict,
            "The worktree path is absent but this repository has no matching durable cleanup receipt",
            crate::tools::ToolRetryability::Never,
            operation,
            None,
            "Inspect the target repository and worktree metadata manually; no cleanup was attempted",
        );
    }
    match worktree_is_registered(run, &main_path, worktree_path) {
        Ok(false) => crate::tools::ToolHandlerResult::success_structured(
            "Cleanup retry was already satisfied and verified by its repository-bound receipt",
            json!({
                "schema_version": WORKTREE_TRANSACTION_SCHEMA_VERSION,
                "operation": operation.as_str(),
                "terminal": "already_absent",
                "generation": expected,
                "path": worktree_path,
                "target_path": main_path,
                "cleanup_ref": reference,
            }),
        ),
        Ok(true) => partial_with_snapshot(
            "Worktree files are absent but Git still registers the linked worktree",
            operation,
            None,
            "Keep the cleanup receipt and repair the stale Git worktree registration manually",
        ),
        Err(error) => partial_with_snapshot(
            format!("Could not verify cleanup retry against Git worktree metadata: {error}"),
            operation,
            None,
            "Do not assume cleanup completed; inspect the target repository and retained cleanup ref",
        ),
    }
}

fn is_ancestor(
    run: &crate::tools::security::ToolRunContext,
    cwd: &Path,
    ancestor: &str,
    descendant: &str,
) -> Result<bool, String> {
    let output = git_in(
        run,
        cwd,
        &["merge-base", "--is-ancestor", ancestor, descendant],
    )?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => Err(format!(
            "git merge-base --is-ancestor failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )),
    }
}

fn inspect_after(
    run: &crate::tools::security::ToolRunContext,
    path: &Path,
) -> Option<WorktreeSnapshot> {
    inspect_worktree(run, path).ok()
}

#[allow(clippy::too_many_lines)] // Keep one auditable stage state machine and its postconditions.
fn execute_stage<S: std::hash::BuildHasher>(
    run: &crate::tools::security::ToolRunContext,
    args: &HashMap<String, Value, S>,
    snapshot: &WorktreeSnapshot,
) -> crate::tools::ToolHandlerResult {
    let expected = match expected_generation(args) {
        Ok(value) => value,
        Err(error) => {
            return failure_with_snapshot(
                crate::tools::ToolFailureCode::InvalidArguments,
                error,
                crate::tools::ToolRetryability::Never,
                WorktreeOperation::Stage,
                Some(snapshot),
                "Run operation=preview and pass its exact generation and path list",
            );
        }
    };
    let paths = match requested_paths(args) {
        Ok(paths) => paths,
        Err(error) => {
            return failure_with_snapshot(
                crate::tools::ToolFailureCode::InvalidArguments,
                error,
                crate::tools::ToolRetryability::Never,
                WorktreeOperation::Stage,
                Some(snapshot),
                "Run operation=preview and review every returned non-ignored path",
            );
        }
    };
    if !generation_matches(expected, snapshot) {
        return failure_with_snapshot(
            crate::tools::ToolFailureCode::Conflict,
            "Worktree generation changed before stage",
            crate::tools::ToolRetryability::Safe,
            WorktreeOperation::Stage,
            Some(snapshot),
            "Review the returned state and request stage again with its new generation",
        );
    }
    if !snapshot.view.changes.conflicted.is_empty() {
        return failure_with_snapshot(
            crate::tools::ToolFailureCode::Conflict,
            "Cannot stage a worktree with unresolved conflicts",
            crate::tools::ToolRetryability::Safe,
            WorktreeOperation::Stage,
            Some(snapshot),
            "Resolve conflicts, preview the resulting generation, and retry",
        );
    }
    let observed_paths = snapshot.view.changes.reviewable_paths();
    if paths != observed_paths {
        return failure_with_snapshot(
            crate::tools::ToolFailureCode::Conflict,
            "Stage paths do not exactly match the reviewed worktree generation",
            crate::tools::ToolRetryability::Safe,
            WorktreeOperation::Stage,
            Some(snapshot),
            "Use exactly the non-ignored paths returned by preview; ignored data requires an explicit discard or manual preservation decision",
        );
    }
    let mut owned = vec!["add", "-A", "--"];
    owned.extend(paths.iter().map(String::as_str));
    let result = git_in(run, &snapshot.worktree_path, &owned);
    let after = inspect_after(run, &snapshot.worktree_path);
    match result {
        Ok(output) if output.status.success() => {
            let Some(after) = after else {
                return partial_with_snapshot(
                    "Stage completed but the resulting worktree state could not be inspected",
                    WorktreeOperation::Stage,
                    None,
                    "Do not clean up; inspect the worktree manually, then run preview",
                );
            };
            let reached = after.view.changes.staged == paths
                && after.view.changes.unstaged.is_empty()
                && after.view.changes.untracked.is_empty()
                && after.view.changes.conflicted.is_empty();
            let reviewed_inputs_unchanged = after.view.repository_id == snapshot.view.repository_id
                && after.view.worktree_id == snapshot.view.worktree_id
                && after.view.path == snapshot.view.path
                && after.view.branch == snapshot.view.branch
                && after.view.worktree_head == snapshot.view.worktree_head
                && after.view.target_path == snapshot.view.target_path
                && after.view.target_branch == snapshot.view.target_branch
                && after.view.target_head == snapshot.view.target_head
                && after.view.worktree_content_digest == snapshot.view.worktree_content_digest
                && after.view.target_change_digest == snapshot.view.target_change_digest
                && after.view.target_changes == snapshot.view.target_changes;
            if !reached || !reviewed_inputs_unchanged {
                return partial_with_snapshot(
                    "Git stage changed state without reaching the exact reviewed postcondition",
                    WorktreeOperation::Stage,
                    Some(&after),
                    "Keep the worktree; review the returned generation before another operation",
                );
            }
            crate::tools::ToolHandlerResult::success_structured(
                "Staged the exact reviewed worktree paths",
                snapshot_payload(WorktreeOperation::Stage, &after),
            )
        }
        Ok(output) => {
            let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
            if after
                .as_ref()
                .is_some_and(|state| state.view.generation != snapshot.view.generation)
            {
                partial_with_snapshot(
                    format!("Git stage failed after changing the index: {detail}"),
                    WorktreeOperation::Stage,
                    after.as_ref(),
                    "The worktree was retained; preview and review the partially staged state",
                )
            } else {
                failure_with_snapshot(
                    crate::tools::ToolFailureCode::External,
                    format!("Git stage failed without changing the reviewed generation: {detail}"),
                    crate::tools::ToolRetryability::Safe,
                    WorktreeOperation::Stage,
                    after.as_ref().or(Some(snapshot)),
                    "Fix the reported Git/filter condition; the worktree remains intact",
                )
            }
        }
        Err(error) => partial_with_snapshot(
            format!("Git stage did not reach a confirmed terminal result: {error}"),
            WorktreeOperation::Stage,
            after.as_ref(),
            "The worktree was retained; preview before retrying",
        ),
    }
}

#[allow(clippy::too_many_lines)] // Keep commit, ambiguity reconciliation, and recovery-ref checks together.
fn execute_commit<S: std::hash::BuildHasher>(
    run: &crate::tools::security::ToolRunContext,
    args: &HashMap<String, Value, S>,
    snapshot: &WorktreeSnapshot,
) -> crate::tools::ToolHandlerResult {
    let expected = match expected_generation(args) {
        Ok(value) => value,
        Err(error) => {
            return failure_with_snapshot(
                crate::tools::ToolFailureCode::InvalidArguments,
                error,
                crate::tools::ToolRetryability::Never,
                WorktreeOperation::Commit,
                Some(snapshot),
                "Stage first, then pass that exact generation to commit",
            );
        }
    };
    let message = match required_string(args, "message") {
        Ok(message) if message.len() <= MAX_COMMIT_MESSAGE_BYTES => message,
        Ok(_) => {
            return failure_with_snapshot(
                crate::tools::ToolFailureCode::InvalidArguments,
                format!("Commit message exceeds {MAX_COMMIT_MESSAGE_BYTES} bytes"),
                crate::tools::ToolRetryability::Never,
                WorktreeOperation::Commit,
                Some(snapshot),
                "Provide a bounded commit message",
            );
        }
        Err(error) => {
            return failure_with_snapshot(
                crate::tools::ToolFailureCode::InvalidArguments,
                error,
                crate::tools::ToolRetryability::Never,
                WorktreeOperation::Commit,
                Some(snapshot),
                "Provide the exact reviewed commit message",
            );
        }
    };
    let reference = match recovery_ref(expected) {
        Ok(reference) => reference,
        Err(error) => {
            return failure_with_snapshot(
                crate::tools::ToolFailureCode::InvalidArguments,
                error,
                crate::tools::ToolRetryability::Never,
                WorktreeOperation::Commit,
                Some(snapshot),
                "Use the generation returned by stage",
            );
        }
    };
    if !generation_matches(expected, snapshot) {
        if let Ok(commit) = git_text(
            run,
            &snapshot.worktree_path,
            &["rev-parse", "--verify", &reference],
        ) {
            if commit == snapshot.view.worktree_head {
                return crate::tools::ToolHandlerResult::success_structured(
                    "Commit retry was already satisfied; the recovery ref and branch still name the commit",
                    json!({
                        "operation": "commit",
                        "recovery_ref": reference,
                        "transaction": snapshot.view,
                    }),
                );
            }
        }
        return failure_with_snapshot(
            crate::tools::ToolFailureCode::Conflict,
            "Worktree generation changed before commit",
            crate::tools::ToolRetryability::Safe,
            WorktreeOperation::Commit,
            Some(snapshot),
            "Preview and review the new generation; no cleanup was attempted",
        );
    }
    if snapshot.view.changes.staged.is_empty()
        || !snapshot.view.changes.unstaged.is_empty()
        || !snapshot.view.changes.untracked.is_empty()
        || !snapshot.view.changes.conflicted.is_empty()
    {
        return failure_with_snapshot(
            crate::tools::ToolFailureCode::Conflict,
            "Commit requires a non-empty, fully staged, conflict-free reviewed generation",
            crate::tools::ToolRetryability::Safe,
            WorktreeOperation::Commit,
            Some(snapshot),
            "Preview and stage the exact non-ignored path set before commit",
        );
    }
    let commit_result = git_in(
        run,
        &snapshot.worktree_path,
        &["commit", "--no-verify", "-m", message],
    );
    let after = inspect_after(run, &snapshot.worktree_path);
    let Some(after) = after else {
        return partial_with_snapshot(
            "Commit attempt completed but its resulting state could not be inspected",
            WorktreeOperation::Commit,
            None,
            "Do not remove the worktree; inspect its branch and index manually",
        );
    };
    let head_changed = after.view.worktree_head != snapshot.view.worktree_head;
    if !commit_result
        .as_ref()
        .is_ok_and(|output| output.status.success())
        || !head_changed
    {
        let detail = match commit_result {
            Ok(output) => String::from_utf8_lossy(&output.stderr).trim().to_string(),
            Err(error) => error,
        };
        return if head_changed {
            partial_with_snapshot(
                format!("Commit changed HEAD but did not report an unambiguous success: {detail}"),
                WorktreeOperation::Commit,
                Some(&after),
                "The branch retains the commit; preview and verify it before any merge",
            )
        } else {
            failure_with_snapshot(
                crate::tools::ToolFailureCode::External,
                format!("Git commit failed; staged work was retained: {detail}"),
                crate::tools::ToolRetryability::Safe,
                WorktreeOperation::Commit,
                Some(&after),
                "Fix identity, signing, filter, or lock configuration and retry this exact staged generation",
            )
        };
    }
    match ensure_recovery_ref(run, &after, expected, &after.view.worktree_head) {
        Ok(reference) => crate::tools::ToolHandlerResult::success_structured(
            "Committed the exact staged generation and pinned a recovery ref",
            json!({
                "operation": "commit",
                "recovery_ref": reference,
                "transaction": after.view,
            }),
        ),
        Err(error) => partial_with_snapshot(
            format!("Commit succeeded but its recovery ref could not be verified: {error}"),
            WorktreeOperation::Commit,
            Some(&after),
            "The branch still retains the commit; repair or create a recovery ref before merge",
        ),
    }
}

#[allow(clippy::too_many_lines)] // Merge success, conflict abort, and retained-ref recovery are one state machine.
fn execute_merge<S: std::hash::BuildHasher>(
    run: &crate::tools::security::ToolRunContext,
    args: &HashMap<String, Value, S>,
    snapshot: &WorktreeSnapshot,
) -> crate::tools::ToolHandlerResult {
    let expected = match expected_generation(args) {
        Ok(value) => value,
        Err(error) => {
            return failure_with_snapshot(
                crate::tools::ToolFailureCode::InvalidArguments,
                error,
                crate::tools::ToolRetryability::Never,
                WorktreeOperation::Merge,
                Some(snapshot),
                "Commit first, then pass its exact generation to merge",
            );
        }
    };
    if !generation_matches(expected, snapshot) {
        if let Ok(reference) = recovery_ref(expected) {
            if let Ok(approved_commit) = git_text(
                run,
                &snapshot.main_path,
                &["rev-parse", "--verify", &reference],
            ) {
                if is_ancestor(
                    run,
                    &snapshot.main_path,
                    &approved_commit,
                    &snapshot.view.target_head,
                )
                .unwrap_or(false)
                {
                    return crate::tools::ToolHandlerResult::success_structured(
                        "Merge retry was already satisfied; the target contains the receipt-bound approved commit",
                        json!({
                            "operation": "merge",
                            "recovery_ref": reference,
                            "approved_commit": approved_commit,
                            "transaction": snapshot.view,
                        }),
                    );
                }
            }
        }
        return failure_with_snapshot(
            crate::tools::ToolFailureCode::Conflict,
            "Worktree or target generation changed before merge",
            crate::tools::ToolRetryability::Safe,
            WorktreeOperation::Merge,
            Some(snapshot),
            "Review both returned generations before authorizing another merge",
        );
    }
    if snapshot.view.target_branch == "(detached)" {
        return failure_with_snapshot(
            crate::tools::ToolFailureCode::Conflict,
            "Merge requires the target worktree to have an attached branch",
            crate::tools::ToolRetryability::Safe,
            WorktreeOperation::Merge,
            Some(snapshot),
            "Attach the target HEAD to the intended branch, then preview and review the new generation",
        );
    }
    if !snapshot.view.changes.tracked_and_untracked_clean() {
        return failure_with_snapshot(
            crate::tools::ToolFailureCode::Conflict,
            "Merge requires a committed, conflict-free worktree",
            crate::tools::ToolRetryability::Safe,
            WorktreeOperation::Merge,
            Some(snapshot),
            "Stage and commit all reviewed non-ignored paths first",
        );
    }
    if !snapshot.view.target_changes.tracked_and_untracked_clean() {
        return failure_with_snapshot(
            crate::tools::ToolFailureCode::Conflict,
            "Target worktree changed or is dirty; merge refused",
            crate::tools::ToolRetryability::Safe,
            WorktreeOperation::Merge,
            Some(snapshot),
            "Preserve or finish the target work, then preview a new exact generation",
        );
    }
    let reference = match ensure_recovery_ref(run, snapshot, expected, &snapshot.view.worktree_head)
    {
        Ok(reference) => reference,
        Err(error) => {
            return failure_with_snapshot(
                crate::tools::ToolFailureCode::External,
                format!("Cannot establish recovery ref before merge: {error}"),
                crate::tools::ToolRetryability::Safe,
                WorktreeOperation::Merge,
                Some(snapshot),
                "The worktree and branch remain intact; repair ref storage and retry",
            );
        }
    };
    let merge = git_in(
        run,
        &snapshot.main_path,
        &["merge", "--no-edit", &snapshot.view.branch],
    );
    let after = inspect_after(run, &snapshot.worktree_path);
    if let Some(after) = &after {
        if is_ancestor(
            run,
            &after.main_path,
            &snapshot.view.worktree_head,
            &after.view.target_head,
        )
        .unwrap_or(false)
            && after.view.repository_id == snapshot.view.repository_id
            && after.view.worktree_id == snapshot.view.worktree_id
            && after.view.worktree_head == snapshot.view.worktree_head
            && after.view.target_path == snapshot.view.target_path
            && after.view.target_branch == snapshot.view.target_branch
            && after.view.worktree_content_digest == snapshot.view.worktree_content_digest
            && after.view.changes.tracked_and_untracked_clean()
            && after.view.target_changes.tracked_and_untracked_clean()
        {
            return crate::tools::ToolHandlerResult::success_structured(
                "Merged the committed worktree generation into the exact target",
                json!({
                    "operation": "merge",
                    "recovery_ref": reference,
                    "transaction": after.view,
                }),
            );
        }
    }
    let merge_detail = match merge {
        Ok(output) => String::from_utf8_lossy(&output.stderr).trim().to_string(),
        Err(error) => error,
    };
    let merge_in_progress = git_in(
        run,
        &snapshot.main_path,
        &["rev-parse", "--quiet", "--verify", "MERGE_HEAD"],
    )
    .is_ok_and(|output| output.status.success());
    if merge_in_progress {
        let abort = git_in(run, &snapshot.main_path, &["merge", "--abort"]);
        if !abort.is_ok_and(|output| output.status.success()) {
            return partial_with_snapshot(
                format!("Merge failed and merge --abort did not restore the target: {merge_detail}"),
                WorktreeOperation::Merge,
                after.as_ref(),
                "Do not remove either worktree; recover the target merge state manually using the recovery ref",
            );
        }
    }
    let restored = inspect_after(run, &snapshot.worktree_path);
    if restored
        .as_ref()
        .is_none_or(|state| state.view.generation != snapshot.view.generation)
    {
        partial_with_snapshot(
            format!(
                "Merge did not complete and the exact pre-merge generation was not restored: {merge_detail}"
            ),
            WorktreeOperation::Merge,
            restored.as_ref().or(after.as_ref()),
            "Do not remove either worktree; inspect the target and retained recovery ref before retrying",
        )
    } else {
        failure_with_snapshot(
            crate::tools::ToolFailureCode::Conflict,
            format!(
                "Merge did not complete; the pre-merge generation and recovery ref were retained: {merge_detail}"
            ),
            crate::tools::ToolRetryability::Safe,
            WorktreeOperation::Merge,
            restored.as_ref(),
            "Resolve the target/branch conflict without deleting the worktree, then preview and retry",
        )
    }
}

#[allow(clippy::too_many_lines)] // Cleanup receipt creation and terminal reconciliation must remain adjacent.
fn execute_remove(
    run: &crate::tools::security::ToolRunContext,
    expected: &str,
    target_path: &str,
    snapshot: &WorktreeSnapshot,
    force: bool,
) -> crate::tools::ToolHandlerResult {
    let operation = if force {
        WorktreeOperation::Discard
    } else {
        WorktreeOperation::Remove
    };
    if !generation_matches(expected, snapshot) {
        return failure_with_snapshot(
            crate::tools::ToolFailureCode::Conflict,
            format!(
                "Worktree generation changed before cleanup (expected {expected}, observed {})",
                snapshot.view.generation
            ),
            crate::tools::ToolRetryability::Safe,
            operation,
            Some(snapshot),
            "Review the returned state and explicitly approve its exact generation",
        );
    }
    if let Err(error) = validate_cleanup_target(target_path, snapshot) {
        return failure_with_snapshot(
            crate::tools::ToolFailureCode::Conflict,
            error,
            crate::tools::ToolRetryability::Safe,
            operation,
            Some(snapshot),
            "Pass the exact canonical target_path returned by the approved preview",
        );
    }
    if !force && !snapshot.view.changes.completely_clean() {
        return failure_with_snapshot(
            crate::tools::ToolFailureCode::Conflict,
            "Remove requires a completely clean worktree, including no ignored files",
            crate::tools::ToolRetryability::Safe,
            operation,
            Some(snapshot),
            "Preserve or explicitly discard the returned exact generation",
        );
    }
    let cleanup_reference = match ensure_cleanup_ref(run, snapshot, expected) {
        Ok(reference) => reference,
        Err(error) => {
            return failure_with_snapshot(
                crate::tools::ToolFailureCode::External,
                format!("Cannot establish durable cleanup receipt: {error}"),
                crate::tools::ToolRetryability::Safe,
                operation,
                Some(snapshot),
                "The worktree remains intact; repair ref storage before retrying cleanup",
            );
        }
    };
    let path = snapshot.view.path.as_str();
    let args = if force {
        vec!["worktree", "remove", path, "--force"]
    } else {
        vec!["worktree", "remove", path]
    };
    let result = git_in(run, &snapshot.main_path, &args);
    let path_absent = !snapshot.worktree_path.exists();
    let registered = worktree_is_registered(run, &snapshot.main_path, path);
    if path_absent && matches!(registered, Ok(false)) {
        unregister_active_worktree(&snapshot.worktree_path);
        return crate::tools::ToolHandlerResult::success_structured(
            if force {
                "Discarded the exact approved worktree generation"
            } else {
                "Removed the verified clean worktree without force"
            },
            json!({
                "schema_version": WORKTREE_TRANSACTION_SCHEMA_VERSION,
                "operation": operation.as_str(),
                "terminal": "removed",
                "repository_id": snapshot.view.repository_id,
                "worktree_id": snapshot.view.worktree_id,
                "generation": snapshot.view.generation,
                "target_path": snapshot.view.target_path,
                "cleanup_ref": cleanup_reference,
                "branch_retained": snapshot.view.branch,
                "worktree_head": snapshot.view.worktree_head,
                "target_head": snapshot.view.target_head,
            }),
        );
    }
    let detail = match result {
        Ok(output) => String::from_utf8_lossy(&output.stderr).trim().to_string(),
        Err(error) => error,
    };
    let registration_detail = match registered {
        Ok(true) => "Git still registers the worktree".to_string(),
        Ok(false) => "Git no longer registers the worktree".to_string(),
        Err(error) => format!("Git registration could not be verified: {error}"),
    };
    let after = inspect_after(run, &snapshot.worktree_path);
    partial_with_snapshot(
        format!(
            "Worktree cleanup failed or was interrupted: {detail}; {registration_detail}; durable receipt {cleanup_reference} was retained"
        ),
        operation,
        after.as_ref(),
        "Do not retry destructively until preview confirms the exact retained state",
    )
}

/// Execute one generation-bound worktree transaction operation.
///
/// Mutations are deliberately split across calls. The canonical permission
/// receipt hashes the full argument object, so an approval covers one exact
/// path, operation, observed generation, reviewed path set, and commit message.
#[must_use]
#[allow(clippy::too_many_lines)] // Dispatch keeps all terminal operation choices auditable together.
pub fn execute_exit_worktree<S: std::hash::BuildHasher>(
    run: &crate::tools::security::ToolRunContext,
    args: &HashMap<String, Value, S>,
) -> crate::tools::ToolHandlerResult {
    let operation = match parse_worktree_operation(args) {
        Ok(operation) => operation,
        Err(error) => {
            return failure_with_snapshot(
                crate::tools::ToolFailureCode::InvalidArguments,
                error,
                crate::tools::ToolRetryability::Never,
                WorktreeOperation::Preview,
                None,
                "Use one explicit operation and no deprecated composite flags",
            );
        }
    };
    if matches!(
        operation,
        WorktreeOperation::LegacyApply | WorktreeOperation::LegacyDiscard
    ) {
        return failure_with_snapshot(
            crate::tools::ToolFailureCode::InvalidArguments,
            "Composite apply_changes/discard_changes calls are deprecated because they cannot bind each destructive transition to an exact reviewed generation",
            crate::tools::ToolRetryability::Never,
            operation,
            None,
            "Call operation=preview, then authorize stage, commit, merge, and remove separately; use operation=discard only for an exact reviewed generation",
        );
    }
    let path_argument = match required_string(args, "path") {
        Ok(path) => path,
        Err(error) => {
            return failure_with_snapshot(
                crate::tools::ToolFailureCode::InvalidArguments,
                error,
                crate::tools::ToolRetryability::Never,
                operation,
                None,
                "Pass the absolute path returned by enter_worktree",
            );
        }
    };
    let path = PathBuf::from(path_argument);
    if !path.exists()
        && matches!(
            operation,
            WorktreeOperation::Remove | WorktreeOperation::Discard
        )
    {
        let expected = match expected_generation(args) {
            Ok(expected) => expected,
            Err(error) => {
                return failure_with_snapshot(
                    crate::tools::ToolFailureCode::InvalidArguments,
                    error,
                    crate::tools::ToolRetryability::Never,
                    operation,
                    None,
                    "Pass the exact generation and target_path returned by the cleanup transaction",
                );
            }
        };
        let target_path = match required_string(args, "target_path") {
            Ok(target_path) => target_path,
            Err(error) => {
                return failure_with_snapshot(
                    crate::tools::ToolFailureCode::InvalidArguments,
                    error,
                    crate::tools::ToolRetryability::Never,
                    operation,
                    None,
                    "Pass the exact target_path returned by the approved preview",
                );
            }
        };
        return reconcile_absent_cleanup(run, operation, path_argument, target_path, expected);
    }
    let snapshot = match inspect_worktree(run, &path) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return failure_with_snapshot(
                crate::tools::ToolFailureCode::Conflict,
                format!("Worktree inspection failed; no cleanup was attempted: {error}"),
                crate::tools::ToolRetryability::Safe,
                operation,
                None,
                "Preserve the path and repair inspection before retrying",
            );
        }
    };
    if operation != WorktreeOperation::Preview && path_argument != snapshot.view.path {
        return failure_with_snapshot(
            crate::tools::ToolFailureCode::Conflict,
            format!(
                "Mutation path is not the exact canonical worktree path (use {})",
                snapshot.view.path
            ),
            crate::tools::ToolRetryability::Safe,
            operation,
            Some(&snapshot),
            "Repeat the operation with the canonical path returned by preview",
        );
    }
    match operation {
        WorktreeOperation::Preview => crate::tools::ToolHandlerResult::success_structured(
            "Reviewed the exact worktree and target generations; no mutation was performed",
            snapshot_payload(operation, &snapshot),
        ),
        WorktreeOperation::Stage => execute_stage(run, args, &snapshot),
        WorktreeOperation::Commit => execute_commit(run, args, &snapshot),
        WorktreeOperation::Merge => execute_merge(run, args, &snapshot),
        WorktreeOperation::Discard | WorktreeOperation::Remove => {
            let expected = match expected_generation(args) {
                Ok(expected) => expected,
                Err(error) => {
                    return failure_with_snapshot(
                        crate::tools::ToolFailureCode::InvalidArguments,
                        error,
                        crate::tools::ToolRetryability::Never,
                        operation,
                        Some(&snapshot),
                        "Preview first and pass its exact generation",
                    );
                }
            };
            let target_path = match required_string(args, "target_path") {
                Ok(target_path) => target_path,
                Err(error) => {
                    return failure_with_snapshot(
                        crate::tools::ToolFailureCode::InvalidArguments,
                        error,
                        crate::tools::ToolRetryability::Never,
                        operation,
                        Some(&snapshot),
                        "Pass the exact target_path returned by the approved preview",
                    );
                }
            };
            execute_remove(
                run,
                expected,
                target_path,
                &snapshot,
                operation == WorktreeOperation::Discard,
            )
        }
        WorktreeOperation::LegacyApply | WorktreeOperation::LegacyDiscard => {
            unreachable!("legacy operations returned before inspection")
        }
    }
}

/// Execute worktree transactions through the active opaque workspace
/// capability. Calls outside an isolated generation retain the existing
/// path-based compatibility behavior.
#[must_use]
#[allow(clippy::too_many_lines)] // Authenticate, inject trusted roots, execute, and publish together.
pub fn execute_exit_worktree_bound<S: std::hash::BuildHasher>(
    run: &crate::tools::security::ToolRunContext,
    args: &HashMap<String, Value, S>,
) -> crate::tools::ToolHandlerResult {
    let Some(descriptor) = run.isolated_workspace() else {
        if let Some(Value::String(path)) = args.get("path") {
            let key = canonical_or_self(Path::new(path));
            let active = match active_workspace_capabilities().lock() {
                Ok(active) => active,
                Err(error) => {
                    return crate::tools::ToolHandlerResult::error(crate::tools::ToolFailure::new(
                        crate::tools::ToolFailureCode::Unavailable,
                        format!("Worktree owner registry is unavailable: {error}"),
                        crate::tools::ToolRetryability::Safe,
                    ));
                }
            };
            if let Some(owner) = active.get(&key) {
                return crate::tools::ToolHandlerResult::error(crate::tools::ToolFailure::new(
                    crate::tools::ToolFailureCode::Conflict,
                    format!(
                        "Worktree '{}' is owned by isolated workspace capability {}; exit it from that bound run",
                        owner.workspace_root().display(),
                        owner.handle_id()
                    ),
                    crate::tools::ToolRetryability::Never,
                ));
            }
        }
        return execute_exit_worktree(run, args);
    };
    let supplied_handle = match required_string(args, "workspace_handle") {
        Ok(handle) => handle,
        Err(error) => {
            return crate::tools::ToolHandlerResult::error(crate::tools::ToolFailure::new(
                crate::tools::ToolFailureCode::InvalidArguments,
                error,
                crate::tools::ToolRetryability::Never,
            ));
        }
    };
    let supplied_handle = match uuid::Uuid::parse_str(supplied_handle) {
        Ok(handle) => crate::runtime::WorkspaceHandleId::from_uuid(handle),
        Err(_) => {
            return crate::tools::ToolHandlerResult::error(crate::tools::ToolFailure::new(
                crate::tools::ToolFailureCode::InvalidArguments,
                "'workspace_handle' must be a UUID returned by enter_worktree".to_string(),
                crate::tools::ToolRetryability::Never,
            ));
        }
    };
    if supplied_handle != descriptor.handle_id() {
        return crate::tools::ToolHandlerResult::error(crate::tools::ToolFailure::new(
            crate::tools::ToolFailureCode::Conflict,
            "The supplied workspace handle does not own this run generation".to_string(),
            crate::tools::ToolRetryability::Never,
        ));
    }
    if let Some(Value::String(path)) = args.get("path") {
        if Path::new(path) != descriptor.workspace_root() {
            return crate::tools::ToolHandlerResult::error(crate::tools::ToolFailure::new(
                crate::tools::ToolFailureCode::Conflict,
                "The supplied path differs from the active workspace capability".to_string(),
                crate::tools::ToolRetryability::Never,
            ));
        }
    }
    if let Some(Value::String(path)) = args.get("target_path") {
        if Path::new(path) != descriptor.repository_root() {
            return crate::tools::ToolHandlerResult::error(crate::tools::ToolFailure::new(
                crate::tools::ToolFailureCode::Conflict,
                "The supplied target path differs from the active repository capability"
                    .to_string(),
                crate::tools::ToolRetryability::Never,
            ));
        }
    }
    let _lifecycle = match workspace_capability_lifecycle().lock() {
        Ok(guard) => guard,
        Err(error) => {
            return crate::tools::ToolHandlerResult::error(crate::tools::ToolFailure::new(
                crate::tools::ToolFailureCode::Unavailable,
                format!("Worktree capability lifecycle is unavailable: {error}"),
                crate::tools::ToolRetryability::Safe,
            ));
        }
    };
    let active = match active_workspace_capabilities().lock() {
        Ok(active) => active,
        Err(error) => {
            return crate::tools::ToolHandlerResult::error(crate::tools::ToolFailure::new(
                crate::tools::ToolFailureCode::Unavailable,
                format!("Worktree owner registry is unavailable: {error}"),
                crate::tools::ToolRetryability::Safe,
            ));
        }
    };
    if active.get(descriptor.workspace_root()) != Some(descriptor) {
        return crate::tools::ToolHandlerResult::error(crate::tools::ToolFailure::new(
            crate::tools::ToolFailureCode::Conflict,
            "The active worktree owner record is missing or belongs to another generation"
                .to_string(),
            crate::tools::ToolRetryability::Never,
        ));
    }
    drop(active);

    let mut bound_args = args
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<HashMap<_, _>>();
    bound_args.insert(
        "path".to_string(),
        Value::String(descriptor.workspace_root().to_string_lossy().into_owned()),
    );
    bound_args.insert(
        "target_path".to_string(),
        Value::String(descriptor.repository_root().to_string_lossy().into_owned()),
    );
    let terminal = parse_worktree_operation(&bound_args).is_ok_and(|operation| {
        matches!(
            operation,
            WorktreeOperation::Remove | WorktreeOperation::Discard
        )
    });
    let mut result = execute_exit_worktree(run.workspace_control_run(), &bound_args);
    if terminal
        && !descriptor.workspace_root().exists()
        && matches!(&result.outcome, crate::tools::ToolOutcome::Success { .. })
    {
        if let Ok(mut active) = active_workspace_capabilities().lock() {
            active.remove(descriptor.workspace_root());
        }
        result = result.with_workspace_transition(crate::tools::WorkspaceTransition::exit(
            run.run_id(),
            run.generation(),
            descriptor.clone(),
        ));
    }
    result
}

/// List active worktrees.
///
/// Runs `git worktree list` from the process CWD (read-only) — this queries
/// git but does not mutate any state.
#[must_use]
pub fn execute_list_worktrees(run: &crate::tools::security::ToolRunContext) -> (String, bool) {
    let cwd = run.working_directory().to_path_buf();
    let output = git_in(run, &cwd, &["worktree", "list", "--porcelain"]);

    match output {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let mut worktrees = Vec::new();
            let mut current: HashMap<String, String> = HashMap::new();

            for line in stdout.lines() {
                if line.is_empty() {
                    if !current.is_empty() {
                        let path = current.get("worktree").cloned().unwrap_or_default();
                        let branch = current
                            .get("branch")
                            .cloned()
                            .unwrap_or_else(|| "detached".to_string());
                        let branch = branch
                            .strip_prefix("refs/heads/")
                            .unwrap_or(&branch)
                            .to_string();
                        worktrees.push(format!("  {path} ({branch})"));
                        current.clear();
                    }
                } else if let Some((key, value)) = line.split_once(' ') {
                    current.insert(key.to_string(), value.to_string());
                } else {
                    current.insert(line.to_string(), String::new());
                }
            }
            if !current.is_empty() {
                let path = current.get("worktree").cloned().unwrap_or_default();
                let branch = current
                    .get("branch")
                    .cloned()
                    .unwrap_or_else(|| "detached".to_string());
                let branch = branch
                    .strip_prefix("refs/heads/")
                    .unwrap_or(&branch)
                    .to_string();
                worktrees.push(format!("  {path} ({branch})"));
            }

            if worktrees.is_empty() {
                ("No active worktrees.".to_string(), false)
            } else {
                (
                    format!("Active worktrees:\n{}", worktrees.join("\n")),
                    false,
                )
            }
        }
        Ok(o) => (
            format!(
                "git worktree list failed: {}",
                String::from_utf8_lossy(&o.stderr)
            ),
            true,
        ),
        Err(e) => (format!("Failed to run git: {e}"), true),
    }
}

fn get_current_branch_at(
    run: &crate::tools::security::ToolRunContext,
    cwd: &Path,
) -> Option<String> {
    git_in(run, cwd, &["rev-parse", "--abbrev-ref", "HEAD"])
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
}

/// Classify one `exit_worktree` invocation before authorization (S-016).
///
/// `exit_worktree` multiplexes six explicit transaction operations behind one
/// wire-level name. Preview is read-only; stage, commit, and merge mutate Git
/// state; discard and removal retain the destructive ceiling because they
/// remove a filesystem tree. Deprecated composite flags are also classified
/// destructive before execution rejects them, so an old call can never evade
/// authorization while receiving its migration error.
///
/// Classification reads only the typed argument shape, so it completes before
/// the handler runs and before any filesystem access.
///
/// # Errors
///
/// Returns `Err` when a flag is present but is not a boolean. An invocation
/// whose effect cannot be established is denied rather than executed under an
/// assumed-safe default.
pub fn classify_exit_worktree(
    args: &serde_json::Value,
) -> Result<crate::tools::effect::TypedEffect, String> {
    use crate::tools::effect::TypedEffect;

    let flag = |key: &str| -> Result<bool, String> {
        match args.get(key) {
            None | Some(serde_json::Value::Null) => Ok(false),
            Some(serde_json::Value::Bool(value)) => Ok(*value),
            Some(other) => Err(format!(
                "'{key}' must be a boolean, got {}",
                match other {
                    serde_json::Value::String(_) => "string",
                    serde_json::Value::Number(_) => "number",
                    serde_json::Value::Array(_) => "array",
                    serde_json::Value::Object(_) => "object",
                    serde_json::Value::Bool(_) | serde_json::Value::Null => unreachable!(),
                }
            )),
        }
    };

    // The path is the resource the user is authorizing against. It is
    // required by the schema; a missing or non-string path cannot be
    // classified, so it denies rather than matching an empty pattern.
    let path = match args.get("path") {
        Some(serde_json::Value::String(path)) if !path.is_empty() => path.clone(),
        _ => return Err("'path' must be a non-empty string".to_string()),
    };

    let apply = flag("apply_changes")?;
    let discard = flag("discard_changes")?;
    let operation = match args.get("operation") {
        Some(Value::String(operation)) => {
            if apply || discard {
                return Err(
                    "'operation' cannot be combined with deprecated apply_changes/discard_changes flags"
                        .to_string(),
                );
            }
            parse_operation_name(operation)?
        }
        Some(_) => return Err("'operation' must be a string".to_string()),
        None if apply => WorktreeOperation::LegacyApply,
        None if discard => WorktreeOperation::LegacyDiscard,
        None => WorktreeOperation::Preview,
    };

    Ok(TypedEffect::new(
        operation.effect(),
        operation.as_str(),
        path,
    ))
}

/// Every operation `exit_worktree` can resolve to, for the generated matrix.
#[must_use]
pub fn exit_worktree_operations() -> Vec<(&'static str, crate::tools::effect::ToolEffect)> {
    vec![
        ("preview", WorktreeOperation::Preview.effect()),
        ("stage", WorktreeOperation::Stage.effect()),
        ("commit", WorktreeOperation::Commit.effect()),
        ("merge", WorktreeOperation::Merge.effect()),
        ("discard", WorktreeOperation::Discard.effect()),
        ("remove", WorktreeOperation::Remove.effect()),
        ("legacy_apply", WorktreeOperation::LegacyApply.effect()),
        ("legacy_discard", WorktreeOperation::LegacyDiscard.effect()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::testutil::process_cwd_lock;
    use std::sync::MutexGuard;

    #[test]
    fn worker_cleanup_requires_clean_bytes_index_and_branch() {
        let clean = WorkerArtifactObservation {
            generation: "sha256:clean".to_string(),
            staged: false,
            unstaged: false,
            untracked: false,
            ignored: false,
            conflicted: false,
            committed: false,
        };
        assert!(clean.cleanup_allowed());

        let ignored_cache_only = WorkerArtifactObservation {
            ignored: true,
            ..clean.clone()
        };
        let committed = WorkerArtifactObservation {
            committed: true,
            ..clean
        };
        assert!(ignored_cache_only.cleanup_allowed());
        assert!(!committed.cleanup_allowed());
    }

    fn test_run() -> &'static std::sync::Arc<crate::tools::ToolRunContext> {
        crate::tools::security::test_run_context()
    }

    fn isolated_git_fixture() -> (
        tempfile::TempDir,
        std::sync::Arc<crate::tools::ToolRunContext>,
    ) {
        let root = tempfile::tempdir().expect("isolated Git fixture");
        let git = which::which("git").expect("git test dependency");
        for args in [
            vec!["init", "-q"],
            vec!["config", "user.name", "OpenClaudia Test"],
            vec!["config", "user.email", "openclaudia@example.invalid"],
        ] {
            let output = std::process::Command::new(&git)
                .args(args)
                .current_dir(root.path())
                .output()
                .expect("run fixture Git");
            assert!(
                output.status.success(),
                "fixture Git failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::fs::write(root.path().join("tracked.txt"), "baseline\n").expect("tracked fixture");
        std::fs::write(root.path().join(".gitignore"), ".worktrees/\n")
            .expect("worktree fixture ignore");
        for args in [
            vec!["add", "tracked.txt", ".gitignore"],
            vec!["commit", "-qm", "fixture"],
        ] {
            let output = std::process::Command::new(&git)
                .args(args)
                .current_dir(root.path())
                .output()
                .expect("commit fixture");
            assert!(
                output.status.success(),
                "fixture Git failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let run = crate::tools::security::test_run_context_for(root.path());
        (root, run)
    }

    fn bound_enter_result(
        run: &std::sync::Arc<crate::tools::ToolRunContext>,
        branch: &str,
    ) -> crate::tools::ToolResult {
        let call = crate::tools::ToolCall {
            id: format!("enter-{branch}"),
            call_type: "function".to_string(),
            function: crate::tools::FunctionCall {
                name: "enter_worktree".to_string(),
                arguments: json!({"branch": branch}).to_string(),
            },
        };
        let args = HashMap::from([("branch".to_string(), Value::String(branch.to_string()))]);
        crate::tools::ToolResult::bind(
            &call,
            "enter_worktree",
            execute_enter_worktree_bound(run, &args),
        )
    }

    #[test]
    fn s074_bound_enter_replaces_root_and_rejects_stale_source_generation() {
        let (_root, source) = isolated_git_fixture();
        let result = bound_enter_result(&source, "s074-bound-root");
        assert!(
            !result.is_error(),
            "bound enter failed: {}",
            result.content()
        );
        let transition = result.workspace_transition().expect("host transition");
        let isolated =
            crate::tools::ToolRunContext::apply_workspace_transition(&source, transition)
                .expect("publish isolated run");

        assert_eq!(
            isolated.project_root(),
            transition.descriptor().workspace_root()
        );
        assert_eq!(isolated.working_directory(), isolated.project_root());
        assert!(isolated.permits_write(&isolated.project_root().join("new.txt")));
        let write_args = HashMap::from([
            ("path".to_string(), Value::String("new.txt".to_string())),
            (
                "content".to_string(),
                Value::String("isolated workspace\n".to_string()),
            ),
        ]);
        let (write_output, write_failed) =
            crate::tools::file::execute_write_file(&isolated, &write_args).into_legacy();
        assert!(
            !write_failed,
            "isolated relative write failed: {write_output}"
        );
        assert_eq!(
            std::fs::read_to_string(isolated.project_root().join("new.txt"))
                .expect("worktree-relative write"),
            "isolated workspace\n"
        );
        assert!(
            !source.project_root().join("new.txt").exists(),
            "relative write escaped into the repository root"
        );
        let process_args =
            HashMap::from([("command".to_string(), Value::String("pwd".to_string()))]);
        let (process_output, process_failed) =
            crate::tools::bash::execute_bash(&isolated, &process_args);
        assert!(
            !process_failed,
            "isolated relative process failed: {process_output}"
        );
        assert!(
            process_output.contains(&isolated.project_root().to_string_lossy().into_owned()),
            "process did not run in the isolated root: {process_output}"
        );
        assert!(matches!(
            source.require(crate::tools::ToolResource::WorkspaceRead),
            Err(crate::tools::ToolCapabilityError::InactiveWorkspaceGeneration { .. })
        ));
    }

    #[test]
    fn s074_bound_enter_rejects_cross_owner_for_same_worktree() {
        let (_root, first) = isolated_git_fixture();
        let second = crate::tools::security::test_run_context_for(first.project_root());
        let first_result = bound_enter_result(&first, "s074-cross-owner");
        assert!(!first_result.is_error());

        let second_result = bound_enter_result(&second, "s074-cross-owner");
        assert!(second_result.is_error());
        assert!(second_result.content().contains("owned by another run"));
    }

    #[test]
    fn s074_registered_workspace_rejects_cross_owner_exit() {
        let (_root, owner) = isolated_git_fixture();
        let other = crate::tools::security::test_run_context_for(owner.project_root());
        let enter = bound_enter_result(&owner, "s074-cross-owner-exit");
        let descriptor = enter
            .workspace_transition()
            .expect("owner transition")
            .descriptor();
        let args = HashMap::from([
            (
                "path".to_string(),
                Value::String(descriptor.workspace_root().to_string_lossy().into_owned()),
            ),
            (
                "operation".to_string(),
                Value::String("preview".to_string()),
            ),
        ]);

        let result = execute_exit_worktree_bound(&other, &args);

        assert!(matches!(
            result.outcome,
            crate::tools::ToolOutcome::Error { .. }
        ));
        assert!(result
            .content()
            .contains("owned by isolated workspace capability"));
        assert!(descriptor.workspace_root().is_dir());
    }

    #[test]
    fn s074_isolated_run_rejects_nested_enter_before_creating_a_tree() {
        let (_root, source) = isolated_git_fixture();
        let enter = bound_enter_result(&source, "s074-parent-workspace");
        let isolated = crate::tools::ToolRunContext::apply_workspace_transition(
            &source,
            enter.workspace_transition().expect("parent transition"),
        )
        .expect("publish parent workspace");
        let nested_path = isolated
            .project_root()
            .join(".worktrees")
            .join("s074-nested-workspace");

        let nested = bound_enter_result(&isolated, "s074-nested-workspace");

        assert!(nested.is_error());
        assert!(nested.content().contains("already bound"));
        assert!(
            !nested_path.exists(),
            "nested worktree was created before refusal"
        );
    }

    #[test]
    fn s074_concurrent_publication_allows_only_one_workspace_generation() {
        let (_root, source) = isolated_git_fixture();
        let result = bound_enter_result(&source, "s074-concurrent-enter");
        let transition = result
            .workspace_transition()
            .expect("host transition")
            .clone();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let source = std::sync::Arc::clone(&source);
            let transition = transition.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                crate::tools::ToolRunContext::apply_workspace_transition(&source, &transition)
            }));
        }
        barrier.wait();
        let outcomes = workers
            .into_iter()
            .map(|worker| worker.join().expect("transition worker"))
            .collect::<Vec<_>>();
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes.iter().filter(|outcome| outcome.is_err()).count(),
            1
        );
    }

    #[test]
    fn s074_removed_isolated_tree_invalidates_the_live_capability() {
        let (_root, source) = isolated_git_fixture();
        let result = bound_enter_result(&source, "s074-removed-root");
        let isolated = crate::tools::ToolRunContext::apply_workspace_transition(
            &source,
            result.workspace_transition().expect("host transition"),
        )
        .expect("publish isolated run");
        std::fs::remove_dir_all(isolated.project_root()).expect("remove isolated root fixture");

        assert!(matches!(
            isolated.require(crate::tools::ToolResource::WorkspaceRead),
            Err(crate::tools::ToolCapabilityError::StaleWorkspace { .. })
        ));
    }

    #[test]
    fn s074_resume_rebinds_the_persisted_handle_to_a_fresh_run() {
        let (_root, source) = isolated_git_fixture();
        let result = bound_enter_result(&source, "s074-resume");
        let isolated = crate::tools::ToolRunContext::apply_workspace_transition(
            &source,
            result.workspace_transition().expect("host transition"),
        )
        .expect("publish isolated run");
        let persisted: crate::runtime::IsolatedWorkspaceDescriptor = serde_json::from_value(
            serde_json::to_value(isolated.isolated_workspace().expect("descriptor"))
                .expect("serialize descriptor"),
        )
        .expect("deserialize descriptor");
        release_workspace_descriptor_owner(&isolated).expect("release prior process owner");

        let session_id = crate::state::SessionId::from_raw(source.session_id())
            .expect("source session identifier");
        let fresh_base = crate::tools::ToolRunContext::builder(session_id, source.project_root())
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::new())
            .workspace_access(crate::tools::WorkspaceAccess::ReadWrite)
            .process(true)
            .network(true)
            .secrets(true)
            .provider("unit-test")
            .build()
            .expect("fresh resume base run");
        let resumed =
            crate::tools::ToolRunContext::resume_isolated_workspace(&fresh_base, &persisted)
                .expect("resume isolated workspace");
        let rebound = resumed.isolated_workspace().expect("rebound descriptor");

        assert_eq!(rebound.handle_id(), persisted.handle_id());
        assert_ne!(rebound.owner_run(), persisted.owner_run());
        assert!(rebound.generation() > persisted.generation());
        assert_eq!(resumed.project_root(), persisted.workspace_root());
        assert!(fresh_base
            .require(crate::tools::ToolResource::WorkspaceRead)
            .is_err());
    }

    #[test]
    fn s074_bound_exit_restores_parent_and_retires_isolated_generation() {
        let (_root, source) = isolated_git_fixture();
        let enter = bound_enter_result(&source, "s074-bound-exit");
        let isolated = crate::tools::ToolRunContext::apply_workspace_transition(
            &source,
            enter.workspace_transition().expect("enter transition"),
        )
        .expect("publish isolated run");
        let ledger_path =
            crate::ledger::project_session_ledger_path_for_run(&isolated, isolated.session_id())
                .expect("isolated ledger path");
        assert!(
            !ledger_path.starts_with(isolated.project_root()),
            "run ledger would contaminate the removable worktree: {}",
            ledger_path.display()
        );
        let descriptor = isolated.isolated_workspace().expect("descriptor").clone();
        let preview_args = HashMap::from([
            (
                "workspace_handle".to_string(),
                Value::String(descriptor.handle_id().to_string()),
            ),
            (
                "path".to_string(),
                Value::String(descriptor.workspace_root().to_string_lossy().into_owned()),
            ),
            (
                "operation".to_string(),
                Value::String("preview".to_string()),
            ),
        ]);
        let preview = execute_exit_worktree_bound(&isolated, &preview_args);
        let crate::tools::ToolOutcome::Success { content } = &preview.outcome else {
            panic!("bound preview failed: {}", preview.content());
        };
        let transaction = content
            .structured
            .as_ref()
            .and_then(|value| value.get("transaction"))
            .expect("preview transaction");
        let generation = transaction["generation"]
            .as_str()
            .expect("preview generation")
            .to_string();
        let cleanup_args = HashMap::from([
            (
                "workspace_handle".to_string(),
                Value::String(descriptor.handle_id().to_string()),
            ),
            (
                "path".to_string(),
                Value::String(descriptor.workspace_root().to_string_lossy().into_owned()),
            ),
            ("operation".to_string(), Value::String("remove".to_string())),
            ("expected_generation".to_string(), Value::String(generation)),
        ]);
        let call = crate::tools::ToolCall {
            id: "exit-s074-bound-exit".to_string(),
            call_type: "function".to_string(),
            function: crate::tools::FunctionCall {
                name: "exit_worktree".to_string(),
                arguments: serde_json::to_string(&cleanup_args).expect("cleanup arguments"),
            },
        };
        let exit = crate::tools::ToolResult::bind(
            &call,
            "exit_worktree",
            execute_exit_worktree_bound(&isolated, &cleanup_args),
        );
        assert!(!exit.is_error(), "bound cleanup failed: {}", exit.content());
        let restored = crate::tools::ToolRunContext::apply_workspace_transition(
            &isolated,
            exit.workspace_transition().expect("exit transition"),
        )
        .expect("restore parent run");
        assert_eq!(restored.run_id(), source.run_id());
        assert!(restored
            .require(crate::tools::ToolResource::WorkspaceRead)
            .is_ok());
        assert!(matches!(
            isolated.require(crate::tools::ToolResource::WorkspaceRead),
            Err(crate::tools::ToolCapabilityError::InactiveWorkspaceGeneration { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn s074_symlink_replacement_invalidates_the_live_capability() {
        use std::os::unix::fs::symlink;

        let (root, source) = isolated_git_fixture();
        let result = bound_enter_result(&source, "s074-symlink-root");
        let isolated = crate::tools::ToolRunContext::apply_workspace_transition(
            &source,
            result.workspace_transition().expect("host transition"),
        )
        .expect("publish isolated run");
        let original = isolated.project_root().to_path_buf();
        let moved = root.path().join("moved-worktree");
        std::fs::rename(&original, &moved).expect("move isolated root fixture");
        symlink(root.path(), &original).expect("replace isolated root with symlink");

        assert!(matches!(
            isolated.require(crate::tools::ToolResource::WorkspaceRead),
            Err(crate::tools::ToolCapabilityError::StaleWorkspace { .. })
        ));
    }

    fn preview_transaction(run: &crate::tools::ToolRunContext, path: &Path) -> Value {
        let args = HashMap::from([
            (
                "path".to_string(),
                Value::String(path.to_string_lossy().into_owned()),
            ),
            (
                "operation".to_string(),
                Value::String("preview".to_string()),
            ),
        ]);
        let result = execute_exit_worktree(run, &args);
        let crate::tools::ToolOutcome::Success { content } = &result.outcome else {
            panic!("preview failed: {}", result.content());
        };
        content
            .structured
            .as_ref()
            .and_then(|value| value.get("transaction"))
            .expect("preview transaction")
            .clone()
    }

    fn transact_cleanup(
        run: &crate::tools::ToolRunContext,
        path: &Path,
        operation: &str,
    ) -> crate::tools::ToolHandlerResult {
        let transaction = preview_transaction(run, path);
        let generation = transaction
            .get("generation")
            .and_then(Value::as_str)
            .expect("preview generation")
            .to_string();
        let target_path = transaction
            .get("target_path")
            .and_then(Value::as_str)
            .expect("preview target path")
            .to_string();
        let args = HashMap::from([
            (
                "path".to_string(),
                Value::String(path.to_string_lossy().into_owned()),
            ),
            (
                "operation".to_string(),
                Value::String(operation.to_string()),
            ),
            ("expected_generation".to_string(), Value::String(generation)),
            ("target_path".to_string(), Value::String(target_path)),
        ]);
        execute_exit_worktree(run, &args)
    }

    fn handler_is_error(result: &crate::tools::ToolHandlerResult) -> bool {
        matches!(&result.outcome, crate::tools::ToolOutcome::Error { .. })
    }

    /// Local alias preserving call-site readability while delegating to the
    /// shared process-wide CWD lock in [`crate::tools::testutil`]. The
    /// previous implementation kept a private `static LOCK` here — that
    /// did NOT serialise against the matching helper in `cron.rs` because
    /// they were two distinct `OnceLock<Mutex<()>>` instances
    /// (crosslink #945). Routing through `process_cwd_lock` collapses
    /// them onto a single mutex so every CWD-mutating test in the
    /// workspace is mutually exclusive.
    fn cwd_lock() -> MutexGuard<'static, ()> {
        process_cwd_lock()
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn git_worktree_profile_reconciles_repository_metadata_and_files() {
        let _lock = cwd_lock();
        let root = tempfile::tempdir_in(".").expect("Git projection root");
        let git = which::which("git").expect("git test dependency");
        let run_host_git = |args: &[&str]| {
            let output = std::process::Command::new(&git)
                .args(args)
                .current_dir(root.path())
                .output()
                .expect("run fixture git");
            assert!(
                output.status.success(),
                "fixture git failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        run_host_git(&["init", "-q"]);
        run_host_git(&["config", "user.name", "OpenClaudia Test"]);
        run_host_git(&["config", "user.email", "openclaudia@example.invalid"]);
        std::fs::write(root.path().join("tracked.txt"), "baseline\n").expect("tracked fixture");
        run_host_git(&["add", "tracked.txt"]);
        run_host_git(&["commit", "-qm", "fixture"]);

        let run = crate::tools::security::test_run_context_for(root.path());
        let branch = "s108-transactional-worktree";
        let mut enter_args = HashMap::new();
        enter_args.insert("branch".to_string(), Value::String(branch.to_string()));
        let (message, is_error) = execute_enter_worktree(&run, &enter_args);
        assert!(!is_error, "enter worktree failed: {message}");
        let worktree = std::fs::canonicalize(root.path().join(".worktrees").join(branch))
            .expect("canonical fixture worktree");
        assert!(worktree.join("tracked.txt").exists());

        let result = transact_cleanup(&run, &worktree, "discard");
        assert!(
            !handler_is_error(&result),
            "exit worktree failed: {}",
            result.content()
        );
        assert!(!worktree.exists());
    }

    #[test]
    fn test_get_current_branch_at_cwd() {
        let _lock = cwd_lock();
        let (_root, run) = isolated_git_fixture();
        let branch = get_current_branch_at(&run, run.working_directory());
        assert!(branch.is_some());
    }

    #[test]
    fn test_enter_worktree_requires_branch() {
        let _lock = cwd_lock();
        let args = HashMap::new();
        let (msg, is_err) = execute_enter_worktree(test_run(), &args);
        assert!(is_err);
        assert!(msg.contains("branch name is required"));
    }

    #[test]
    fn enter_worktree_rejects_wrong_type_branch() {
        let mut args = HashMap::new();
        args.insert("branch".to_string(), serde_json::json!(42));
        let (msg, is_err) = execute_enter_worktree(test_run(), &args);
        assert!(is_err);
        assert!(msg.contains("Invalid 'branch' argument: expected string"));
    }

    #[test]
    fn test_list_worktrees() {
        let _lock = cwd_lock();
        let (_root, run) = isolated_git_fixture();
        let (msg, is_err) = execute_list_worktrees(&run);
        assert!(!is_err);
        assert!(msg.contains("worktree") || msg.contains("Active"));
    }

    // ─── Spec §5: Worktree enter/exit updates session working directory ────────

    #[test]
    fn enter_worktree_empty_branch_is_error() {
        let _lock = cwd_lock();
        let mut args = HashMap::new();
        args.insert(
            "branch".to_string(),
            serde_json::Value::String(String::new()),
        );
        let (msg, is_err) = execute_enter_worktree(test_run(), &args);
        assert!(is_err, "empty branch must produce is_error=true");
        assert!(
            msg.contains("branch name is required"),
            "error message must mention branch; got: {msg}"
        );
    }

    /// Contract: `enter_worktree` outside a git repo returns `is_error=true`
    /// with a repo-not-found message.
    ///
    /// The test supplies an isolated run rooted at a non-git directory; no
    /// process CWD mutation or ambient session registration is involved.
    #[test]
    fn enter_worktree_outside_git_repo_is_error() {
        let _lock = cwd_lock();
        let tmp = tempfile::tempdir().expect("temp dir");
        let run = crate::tools::security::test_run_context_for(tmp.path());

        let mut args = HashMap::new();
        args.insert(
            "branch".to_string(),
            serde_json::Value::String("test-branch".to_string()),
        );
        let (msg, is_err) = execute_enter_worktree(&run, &args);

        assert!(is_err, "must error outside a git repo");
        assert!(
            msg.contains("not inside a git repository"),
            "error must say 'not inside a git repository'; got: {msg}"
        );
    }

    /// Contract: `exit_worktree` with no `path` arg returns `is_error=true`.
    /// The old behavior — falling back to the process CWD — is exactly the
    /// global-state bug fixed by #345.
    #[test]
    fn exit_worktree_without_path_is_error() {
        let _lock = cwd_lock();
        let args = HashMap::new();
        let (msg, is_err) = execute_exit_worktree(test_run(), &args).into_legacy();
        assert!(is_err, "missing path must produce is_error=true");
        assert!(
            msg.contains("'path' is required"),
            "error message must mention required path; got: {msg}"
        );
    }

    #[test]
    fn exit_worktree_rejects_wrong_type_path() {
        let mut args = HashMap::new();
        args.insert("path".to_string(), serde_json::json!(42));
        let (msg, is_err) = execute_exit_worktree(test_run(), &args).into_legacy();
        assert!(is_err);
        assert!(msg.contains("Invalid 'path' argument: expected string"));
    }

    #[test]
    fn exit_worktree_rejects_non_boolean_control_flags() {
        let tmp = tempfile::tempdir().expect("temp dir");
        let mut args = HashMap::new();
        args.insert(
            "path".to_string(),
            serde_json::Value::String(tmp.path().display().to_string()),
        );
        args.insert(
            "apply_changes".to_string(),
            serde_json::Value::String("true".to_string()),
        );

        let (msg, is_err) = execute_exit_worktree(test_run(), &args).into_legacy();
        assert!(is_err, "non-boolean apply_changes must error: {msg}");
        assert!(
            msg.contains("Invalid 'apply_changes' argument: expected boolean"),
            "unexpected error: {msg}"
        );

        args.insert("apply_changes".to_string(), serde_json::Value::Bool(false));
        args.insert(
            "discard_changes".to_string(),
            serde_json::Value::String("true".to_string()),
        );

        let (msg, is_err) = execute_exit_worktree(test_run(), &args).into_legacy();
        assert!(is_err, "non-boolean discard_changes must error: {msg}");
        assert!(
            msg.contains("Invalid 'discard_changes' argument: expected boolean"),
            "unexpected error: {msg}"
        );
    }

    /// Contract: `exit_worktree` called with a path that is the main
    /// worktree (or otherwise unsafe to destroy) returns `is_error=true`
    /// with a clear message — regardless of process CWD.
    ///
    /// The disposable repository root is a valid Git workspace but is not an
    /// isolated worktree, so the refusal must identify that exact condition.
    #[test]
    fn exit_worktree_with_main_tree_path_is_error() {
        let _lock = cwd_lock();
        let (_root, run) = isolated_git_fixture();
        let main = run.project_root();
        let mut args = HashMap::new();
        args.insert(
            "path".to_string(),
            serde_json::Value::String(main.display().to_string()),
        );
        let (msg, is_err) = execute_exit_worktree(&run, &args).into_legacy();
        assert!(is_err, "exit on main worktree must produce is_error=true");
        assert!(
            msg.contains("Not in an isolated worktree"),
            "error must identify the main-worktree refusal; got: {msg}"
        );
    }

    /// #624: a second `enter_worktree` call with the same branch (which
    /// maps to the same `worktree_dir`) returns a no-op success after the
    /// duplicate-session guard fires. Pins the *fix* — the previous gap
    /// test asserted the *absence* of this guard.
    #[test]
    fn enter_worktree_duplicate_call_is_no_op_624() {
        let _lock = cwd_lock();
        let (_root, run) = isolated_git_fixture();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let branch = format!("dup-guard-624-{nanos}");

        let mut args = HashMap::new();
        args.insert(
            "branch".to_string(),
            serde_json::Value::String(branch.clone()),
        );
        let (first_msg, first_err) = execute_enter_worktree(&run, &args);
        assert!(!first_err, "first call must succeed; got: {first_msg}");

        let (second_msg, second_err) = execute_enter_worktree(&run, &args);
        assert!(!second_err, "duplicate call must be a no-op (not error)");
        assert!(
            second_msg.contains("already in worktree") && second_msg.contains("No-op"),
            "duplicate call must surface the no-op message; got: {second_msg}"
        );

        // Cleanup.
        let cwd = run.project_root().to_path_buf();
        let wt = cwd.join(".worktrees").join(&branch);
        let _ = transact_cleanup(&run, &wt, "discard");
        let _ = git_in(&run, &cwd, &["branch", "-D", &branch]);
    }

    /// #624: the cwd-cache generation counter advances when a worktree is
    /// created and again when it is destroyed. Subscribers (future
    /// realpath caches) can poll this counter to know when to invalidate.
    #[test]
    fn enter_and_exit_worktree_bump_cwd_cache_generation_624() {
        let _lock = cwd_lock();
        let (_root, run) = isolated_git_fixture();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let branch = format!("cache-gen-624-{nanos}");
        let before = cwd_cache_generation();

        let mut args = HashMap::new();
        args.insert(
            "branch".to_string(),
            serde_json::Value::String(branch.clone()),
        );
        let (msg, is_err) = execute_enter_worktree(&run, &args);
        assert!(!is_err, "enter must succeed; got: {msg}");
        let after_enter = cwd_cache_generation();
        assert!(
            after_enter > before,
            "cwd_cache_generation must advance on enter (before={before}, after={after_enter})"
        );

        let cwd = run.project_root().to_path_buf();
        let wt = cwd.join(".worktrees").join(&branch);
        let result = transact_cleanup(&run, &wt, "discard");
        assert!(
            !handler_is_error(&result),
            "exit must succeed; got: {}",
            result.content()
        );
        let after_exit = cwd_cache_generation();
        assert!(
            after_exit > after_enter,
            "cwd_cache_generation must advance on exit (after_enter={after_enter}, after_exit={after_exit})"
        );

        let _ = git_in(&run, &cwd, &["branch", "-D", &branch]);
    }

    /// #623: with the worktree dirty and `discard_changes` omitted (or
    /// `false`), `exit_worktree` must refuse with a clear safety message
    /// instead of silently running `git worktree remove --force`.
    #[test]
    fn exit_worktree_refuses_to_destroy_dirty_worktree_without_discard_623() {
        let _lock = cwd_lock();
        let (_root, run) = isolated_git_fixture();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let branch = format!("dirty-623-{nanos}");

        let mut args = HashMap::new();
        args.insert(
            "branch".to_string(),
            serde_json::Value::String(branch.clone()),
        );
        let (msg, is_err) = execute_enter_worktree(&run, &args);
        assert!(!is_err, "enter must succeed; got: {msg}");

        let cwd = run.project_root().to_path_buf();
        let wt = cwd.join(".worktrees").join(&branch);
        // Dirty the worktree by writing an untracked file.
        std::fs::write(wt.join("dirty.txt"), "uncommitted work\n").expect("write dirty");

        // A read-only preview never destroys work, and clean removal must
        // refuse this exact dirty generation.
        let transaction = preview_transaction(&run, &wt);
        let generation = transaction
            .get("generation")
            .and_then(Value::as_str)
            .expect("preview generation")
            .to_string();
        let target_path = transaction
            .get("target_path")
            .and_then(Value::as_str)
            .expect("preview target path")
            .to_string();
        let exit_args = HashMap::from([
            (
                "path".to_string(),
                serde_json::Value::String(wt.display().to_string()),
            ),
            (
                "operation".to_string(),
                serde_json::Value::String("remove".to_string()),
            ),
            (
                "expected_generation".to_string(),
                serde_json::Value::String(generation),
            ),
            (
                "target_path".to_string(),
                serde_json::Value::String(target_path),
            ),
        ]);
        let (msg, is_err) = execute_exit_worktree(&run, &exit_args).into_legacy();
        assert!(is_err, "dirty remove must error");
        assert!(
            msg.contains("completely clean"),
            "safety message must name the clean-state requirement; got: {msg}"
        );
        // Worktree still exists because we refused to destroy it.
        assert!(
            wt.exists(),
            "refused exit must leave the worktree on disk: {}",
            wt.display()
        );

        // Now authorize discard against a fresh exact generation.
        let result = transact_cleanup(&run, &wt, "discard");
        assert!(
            !handler_is_error(&result),
            "discard must succeed: {}",
            result.content()
        );
        assert!(!wt.exists(), "successful exit must remove the worktree");

        let _ = git_in(&run, &cwd, &["branch", "-D", &branch]);
    }

    /// #623: a *clean* worktree exits successfully without needing the
    /// opt-in. The safety gate must not raise the bar for the common case.
    #[test]
    fn exit_worktree_clean_worktree_exits_without_discard_flag_623() {
        let _lock = cwd_lock();
        let (_root, run) = isolated_git_fixture();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let branch = format!("clean-623-{nanos}");

        let mut args = HashMap::new();
        args.insert(
            "branch".to_string(),
            serde_json::Value::String(branch.clone()),
        );
        let (msg, is_err) = execute_enter_worktree(&run, &args);
        assert!(!is_err, "enter must succeed; got: {msg}");

        let cwd = run.project_root().to_path_buf();
        let wt = cwd.join(".worktrees").join(&branch);
        // No mutations: worktree is clean.

        let result = transact_cleanup(&run, &wt, "remove");
        assert!(
            !handler_is_error(&result),
            "clean remove must succeed: {}",
            result.content()
        );
        assert!(!wt.exists(), "clean exit must remove the worktree");

        let _ = git_in(&run, &cwd, &["branch", "-D", &branch]);
    }

    struct TransactionFixture {
        _root: tempfile::TempDir,
        run: std::sync::Arc<crate::tools::ToolRunContext>,
        git: PathBuf,
        main: PathBuf,
        worktree: PathBuf,
    }

    impl TransactionFixture {
        fn new(with_identity: bool) -> Self {
            let root = tempfile::tempdir().expect("transaction fixture");
            let main = root.path().to_path_buf();
            let git = which::which("git").expect("git test dependency");
            fixture_git(&git, &main, &["init", "-q"]);
            std::fs::write(main.join("tracked.txt"), "baseline\n").expect("baseline fixture");
            std::fs::write(main.join(".gitignore"), ".worktrees/\n")
                .expect("worktree fixture ignore");
            fixture_git(&git, &main, &["add", "tracked.txt", ".gitignore"]);
            fixture_git(
                &git,
                &main,
                &[
                    "-c",
                    "user.name=OpenClaudia Test",
                    "-c",
                    "user.email=openclaudia@example.invalid",
                    "commit",
                    "-qm",
                    "baseline",
                ],
            );
            if with_identity {
                fixture_git(&git, &main, &["config", "user.name", "OpenClaudia Test"]);
                fixture_git(
                    &git,
                    &main,
                    &["config", "user.email", "openclaudia@example.invalid"],
                );
            } else {
                fixture_git(&git, &main, &["config", "user.useConfigOnly", "true"]);
            }
            let run = crate::tools::security::test_run_context_for(&main);
            let branch = "s073-transaction";
            let enter = HashMap::from([("branch".to_string(), Value::String(branch.to_string()))]);
            let (message, error) = execute_enter_worktree(&run, &enter);
            assert!(!error, "fixture worktree creation failed: {message}");
            let worktree = main.join(".worktrees").join(branch);
            Self {
                _root: root,
                run,
                git,
                main,
                worktree,
            }
        }

        fn restarted_run(&self) -> std::sync::Arc<crate::tools::ToolRunContext> {
            crate::tools::security::test_run_context_for(&self.main)
        }
    }

    fn fixture_git(git: &Path, cwd: &Path, args: &[&str]) -> std::process::Output {
        let output = std::process::Command::new(git)
            .args(args)
            .current_dir(cwd)
            .output()
            .expect("run fixture git");
        assert!(
            output.status.success(),
            "fixture git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    fn structured_result(result: &crate::tools::ToolHandlerResult) -> &Value {
        match &result.outcome {
            crate::tools::ToolOutcome::Success { content }
            | crate::tools::ToolOutcome::Partial { content, .. } => content
                .structured
                .as_ref()
                .expect("transaction result must be structured"),
            crate::tools::ToolOutcome::Error { failure } => {
                panic!("expected structured result, got error: {}", failure.message)
            }
        }
    }

    fn result_generation(result: &crate::tools::ToolHandlerResult) -> String {
        structured_result(result)
            .pointer("/transaction/generation")
            .and_then(Value::as_str)
            .expect("transaction generation")
            .to_string()
    }

    fn result_target_path(result: &crate::tools::ToolHandlerResult) -> String {
        structured_result(result)
            .pointer("/transaction/target_path")
            .and_then(Value::as_str)
            .expect("transaction target path")
            .to_string()
    }

    fn result_reviewable_paths(result: &crate::tools::ToolHandlerResult) -> Vec<Value> {
        let transaction = structured_result(result)
            .get("transaction")
            .expect("transaction payload");
        let mut paths = BTreeSet::new();
        for category in ["staged", "unstaged", "untracked", "conflicted"] {
            for path in transaction
                .pointer(&format!("/changes/{category}"))
                .and_then(Value::as_array)
                .expect("change path array")
            {
                paths.insert(path.as_str().expect("change path string").to_string());
            }
        }
        paths.into_iter().map(Value::String).collect()
    }

    fn invoke_phase(
        run: &crate::tools::ToolRunContext,
        worktree: &Path,
        operation: &str,
        generation: &str,
        paths: Option<Vec<Value>>,
        message: Option<&str>,
        target_path: Option<&str>,
    ) -> crate::tools::ToolHandlerResult {
        let mut args = HashMap::from([
            (
                "path".to_string(),
                Value::String(worktree.to_string_lossy().into_owned()),
            ),
            (
                "operation".to_string(),
                Value::String(operation.to_string()),
            ),
            (
                "expected_generation".to_string(),
                Value::String(generation.to_string()),
            ),
        ]);
        if let Some(paths) = paths {
            args.insert("paths".to_string(), Value::Array(paths));
        }
        if let Some(message) = message {
            args.insert("message".to_string(), Value::String(message.to_string()));
        }
        if let Some(target_path) = target_path {
            args.insert(
                "target_path".to_string(),
                Value::String(target_path.to_string()),
            );
        }
        execute_exit_worktree(run, &args)
    }

    fn preview_result(
        run: &crate::tools::ToolRunContext,
        worktree: &Path,
    ) -> crate::tools::ToolHandlerResult {
        let args = HashMap::from([
            (
                "path".to_string(),
                Value::String(worktree.to_string_lossy().into_owned()),
            ),
            (
                "operation".to_string(),
                Value::String("preview".to_string()),
            ),
        ]);
        execute_exit_worktree(run, &args)
    }

    #[test]
    fn detached_target_allows_exact_cleanup_but_refuses_merge() {
        let fixture = TransactionFixture::new(true);
        fixture_git(
            &fixture.git,
            &fixture.main,
            &["checkout", "--detach", "-q", "HEAD"],
        );
        let target_head_before = fixture_git(
            &fixture.git,
            &fixture.main,
            &["rev-parse", "--verify", "HEAD"],
        )
        .stdout;

        let preview = preview_result(&fixture.run, &fixture.worktree);
        assert!(
            !handler_is_error(&preview),
            "detached target preview failed: {}",
            preview.content()
        );
        assert_eq!(
            structured_result(&preview)
                .pointer("/transaction/target_branch")
                .and_then(Value::as_str),
            Some("(detached)")
        );

        let merge = invoke_phase(
            &fixture.run,
            &fixture.worktree,
            "merge",
            &result_generation(&preview),
            None,
            None,
            None,
        );
        assert!(handler_is_error(&merge), "detached target merge must fail");
        assert!(
            merge.content().contains("attached branch"),
            "merge failure must explain recovery: {}",
            merge.content()
        );
        assert_eq!(
            fixture_git(
                &fixture.git,
                &fixture.main,
                &["rev-parse", "--verify", "HEAD"],
            )
            .stdout,
            target_head_before,
            "refused merge must not move detached target HEAD"
        );

        let cleanup = transact_cleanup(&fixture.run, &fixture.worktree, "remove");
        assert!(
            !handler_is_error(&cleanup),
            "exact clean removal must work with a detached target: {}",
            cleanup.content()
        );
        assert!(!fixture.worktree.exists());
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One end-to-end test keeps every fresh-run boundary visible.
    fn transactional_apply_survives_fresh_run_boundaries_and_is_idempotent() {
        let fixture = TransactionFixture::new(true);
        std::fs::write(fixture.worktree.join("tracked.txt"), "changed\n")
            .expect("change tracked file");
        std::fs::write(fixture.worktree.join("new.txt"), "new\n").expect("create untracked file");

        let preview = preview_result(&fixture.run, &fixture.worktree);
        let paths = result_reviewable_paths(&preview);
        assert_eq!(paths.len(), 2, "preview must enumerate both changed paths");
        let staged = invoke_phase(
            &fixture.run,
            &fixture.worktree,
            "stage",
            &result_generation(&preview),
            Some(paths),
            None,
            None,
        );
        assert!(
            !handler_is_error(&staged),
            "stage failed: {}",
            staged.content()
        );

        let restarted = fixture.restarted_run();
        let committed = invoke_phase(
            &restarted,
            &fixture.worktree,
            "commit",
            &result_generation(&staged),
            None,
            Some("transactional worktree fixture"),
            None,
        );
        assert!(
            !handler_is_error(&committed),
            "commit failed: {}",
            committed.content()
        );
        let recovery_ref = structured_result(&committed)
            .get("recovery_ref")
            .and_then(Value::as_str)
            .expect("commit recovery ref");
        let branch_head = fixture_git(
            &fixture.git,
            &fixture.worktree,
            &["rev-parse", "--verify", "HEAD"],
        );
        let recovery_head = fixture_git(
            &fixture.git,
            &fixture.worktree,
            &["rev-parse", "--verify", recovery_ref],
        );
        assert_eq!(branch_head.stdout, recovery_head.stdout);

        let restarted = fixture.restarted_run();
        let merged = invoke_phase(
            &restarted,
            &fixture.worktree,
            "merge",
            &result_generation(&committed),
            None,
            None,
            None,
        );
        assert!(
            !handler_is_error(&merged),
            "merge failed: {}",
            merged.content()
        );
        assert_eq!(
            std::fs::read_to_string(fixture.main.join("tracked.txt")).expect("merged tracked"),
            "changed\n"
        );
        assert_eq!(
            std::fs::read_to_string(fixture.main.join("new.txt")).expect("merged untracked"),
            "new\n"
        );

        let restarted = fixture.restarted_run();
        let merge_retry = invoke_phase(
            &restarted,
            &fixture.worktree,
            "merge",
            &result_generation(&committed),
            None,
            None,
            None,
        );
        assert!(
            !handler_is_error(&merge_retry),
            "merge retry failed: {}",
            merge_retry.content()
        );

        let restarted = fixture.restarted_run();
        let generation = result_generation(&merge_retry);
        let target_path = result_target_path(&merge_retry);
        let removed = invoke_phase(
            &restarted,
            &fixture.worktree,
            "remove",
            &generation,
            None,
            None,
            Some(&target_path),
        );
        assert!(
            !handler_is_error(&removed),
            "remove failed: {}",
            removed.content()
        );
        assert!(!fixture.worktree.exists());
        let restarted = fixture.restarted_run();
        let retry = invoke_phase(
            &restarted,
            &fixture.worktree,
            "remove",
            &generation,
            None,
            None,
            Some(&target_path),
        );
        assert!(
            !handler_is_error(&retry),
            "remove retry failed: {}",
            retry.content()
        );
        assert_eq!(
            structured_result(&retry)
                .get("terminal")
                .and_then(Value::as_str),
            Some("already_absent")
        );
    }

    #[test]
    fn commit_identity_failure_retains_staged_work_and_worktree() {
        let fixture = TransactionFixture::new(false);
        std::fs::write(fixture.worktree.join("tracked.txt"), "identity failure\n")
            .expect("change fixture");
        let preview = preview_result(&fixture.run, &fixture.worktree);
        let staged = invoke_phase(
            &fixture.run,
            &fixture.worktree,
            "stage",
            &result_generation(&preview),
            Some(result_reviewable_paths(&preview)),
            None,
            None,
        );
        assert!(
            !handler_is_error(&staged),
            "stage failed: {}",
            staged.content()
        );
        let before_head = fixture_git(&fixture.git, &fixture.worktree, &["rev-parse", "HEAD"]);
        let committed = invoke_phase(
            &fixture.run,
            &fixture.worktree,
            "commit",
            &result_generation(&staged),
            None,
            Some("must fail without identity"),
            None,
        );
        assert!(handler_is_error(&committed));
        assert!(committed.content().contains("staged work was retained"));
        assert!(fixture.worktree.exists());
        let after_head = fixture_git(&fixture.git, &fixture.worktree, &["rev-parse", "HEAD"]);
        assert_eq!(before_head.stdout, after_head.stdout);
        let staged_diff = fixture_git(
            &fixture.git,
            &fixture.worktree,
            &["diff", "--cached", "--name-only"],
        );
        assert!(
            !staged_diff.stdout.is_empty(),
            "staged work must remain recoverable"
        );
        let cleanup = transact_cleanup(&fixture.run, &fixture.worktree, "discard");
        assert!(
            !handler_is_error(&cleanup),
            "cleanup failed: {}",
            cleanup.content()
        );
    }

    #[test]
    fn required_clean_filter_failure_never_triggers_cleanup() {
        let fixture = TransactionFixture::new(true);
        fixture_git(
            &fixture.git,
            &fixture.main,
            &["config", "filter.reject.clean", "false"],
        );
        fixture_git(
            &fixture.git,
            &fixture.main,
            &["config", "filter.reject.required", "true"],
        );
        std::fs::write(
            fixture.worktree.join(".gitattributes"),
            "*.filterme filter=reject\n",
        )
        .expect("attributes fixture");
        std::fs::write(fixture.worktree.join("data.filterme"), "must survive\n")
            .expect("filtered fixture");
        let preview = preview_result(&fixture.run, &fixture.worktree);
        let stage = invoke_phase(
            &fixture.run,
            &fixture.worktree,
            "stage",
            &result_generation(&preview),
            Some(result_reviewable_paths(&preview)),
            None,
            None,
        );
        assert!(
            handler_is_error(&stage)
                || matches!(stage.outcome, crate::tools::ToolOutcome::Partial { .. }),
            "required clean filter must prevent a false stage success"
        );
        assert!(fixture.worktree.exists());
        assert_eq!(
            std::fs::read_to_string(fixture.worktree.join("data.filterme"))
                .expect("filtered data retained"),
            "must survive\n"
        );
        let cleanup = transact_cleanup(&fixture.run, &fixture.worktree, "discard");
        assert!(
            !handler_is_error(&cleanup),
            "cleanup failed: {}",
            cleanup.content()
        );
    }

    #[test]
    fn merge_conflict_aborts_target_and_retains_recovery_ref() {
        let fixture = TransactionFixture::new(true);
        std::fs::write(fixture.worktree.join("tracked.txt"), "worktree version\n")
            .expect("worktree change");
        let preview = preview_result(&fixture.run, &fixture.worktree);
        let staged = invoke_phase(
            &fixture.run,
            &fixture.worktree,
            "stage",
            &result_generation(&preview),
            Some(result_reviewable_paths(&preview)),
            None,
            None,
        );
        let committed = invoke_phase(
            &fixture.run,
            &fixture.worktree,
            "commit",
            &result_generation(&staged),
            None,
            Some("conflicting worktree commit"),
            None,
        );
        assert!(
            !handler_is_error(&committed),
            "commit failed: {}",
            committed.content()
        );
        let recovery_ref = structured_result(&committed)
            .get("recovery_ref")
            .and_then(Value::as_str)
            .expect("recovery ref")
            .to_string();

        std::fs::write(fixture.main.join("tracked.txt"), "target version\n")
            .expect("target change");
        fixture_git(&fixture.git, &fixture.main, &["add", "tracked.txt"]);
        fixture_git(
            &fixture.git,
            &fixture.main,
            &["commit", "-qm", "target conflict"],
        );
        let merge_preview = preview_result(&fixture.run, &fixture.worktree);
        let merged = invoke_phase(
            &fixture.run,
            &fixture.worktree,
            "merge",
            &result_generation(&merge_preview),
            None,
            None,
            None,
        );
        assert!(
            handler_is_error(&merged),
            "conflicting merge must not succeed"
        );
        assert!(fixture.worktree.exists());
        let main_status = fixture_git(&fixture.git, &fixture.main, &["status", "--porcelain"]);
        assert!(
            main_status.stdout.is_empty(),
            "merge abort must restore clean target; status: {}",
            String::from_utf8_lossy(&main_status.stdout)
        );
        assert_eq!(
            std::fs::read_to_string(fixture.main.join("tracked.txt")).expect("target retained"),
            "target version\n"
        );
        let recovery = fixture_git(
            &fixture.git,
            &fixture.main,
            &["rev-parse", "--verify", &recovery_ref],
        );
        assert!(!recovery.stdout.is_empty());
        let cleanup = transact_cleanup(&fixture.run, &fixture.worktree, "remove");
        assert!(
            !handler_is_error(&cleanup),
            "cleanup failed: {}",
            cleanup.content()
        );
    }

    #[test]
    fn stale_discard_generation_preserves_newer_work() {
        let fixture = TransactionFixture::new(true);
        std::fs::write(fixture.worktree.join("tracked.txt"), "first\n").expect("first generation");
        let preview = preview_result(&fixture.run, &fixture.worktree);
        let generation = result_generation(&preview);
        std::fs::write(fixture.worktree.join("tracked.txt"), "newer\n").expect("newer generation");
        let discard = invoke_phase(
            &fixture.run,
            &fixture.worktree,
            "discard",
            &generation,
            None,
            None,
            Some(&result_target_path(&preview)),
        );
        assert!(handler_is_error(&discard));
        assert!(discard.content().contains("generation changed"));
        assert!(fixture.worktree.exists());
        assert_eq!(
            std::fs::read_to_string(fixture.worktree.join("tracked.txt"))
                .expect("newer work retained"),
            "newer\n"
        );
        let cleanup = transact_cleanup(&fixture.run, &fixture.worktree, "discard");
        assert!(
            !handler_is_error(&cleanup),
            "cleanup failed: {}",
            cleanup.content()
        );
    }

    #[test]
    fn porcelain_parser_preserves_ordinary_rename_untracked_ignored_and_conflict_paths() {
        let ordinary = concat!(
            "# branch.oid 0123456789012345678901234567890123456789\0",
            "# branch.head topic\0",
            "1 .M N... 100644 100644 100644 0000000000000000000000000000000000000000 0000000000000000000000000000000000000000 tracked file\0",
            "2 R. N... 100644 100644 100644 0000000000000000000000000000000000000000 0000000000000000000000000000000000000000 R100 renamed\0original\0",
            "? untracked\0",
            "! target/\0",
            "u UU N... 100644 100644 100644 100644 0000000000000000000000000000000000000000 0000000000000000000000000000000000000000 0000000000000000000000000000000000000000 conflict\0"
        );
        let parsed = parse_porcelain_v2(ordinary.as_bytes(), true).expect("parse fixture");
        assert_eq!(parsed.branch, "topic");
        assert_eq!(parsed.head, "0123456789012345678901234567890123456789");
        assert!(parsed.changes.unstaged.contains("tracked file"));
        assert!(parsed.changes.staged.contains("renamed"));
        assert!(parsed.changes.staged.contains("original"));
        assert!(parsed.changes.untracked.contains("untracked"));
        assert!(parsed.changes.ignored.contains("target/"));
        assert!(parsed.changes.conflicted.contains("conflict"));
    }

    // ─── #408 regression tests: branch-name validation ────────────────────────

    /// Valid, ordinary branch names must pass validation.
    #[test]
    fn validate_branch_name_accepts_ordinary_names_408() {
        for ok in &[
            "feature/foo",
            "main",
            "release-1.2.3",
            "topic_42",
            "user/alice/work",
        ] {
            assert!(
                validate_branch_name(test_run(), ok).is_ok(),
                "expected '{ok}' to validate; got: {:?}",
                validate_branch_name(test_run(), ok)
            );
        }
    }

    /// `..` is the classic path-traversal vector. The validator must reject
    /// it before `worktree_dir = git_root.join('.worktrees').join(&branch)`
    /// can escape the worktree root.
    #[test]
    fn validate_branch_name_rejects_double_dot_408() {
        let cases = ["..", "a..b", "../escape", "foo/..", "./..", "..foo"];
        for name in &cases {
            let r = validate_branch_name(test_run(), name);
            assert!(r.is_err(), "expected '{name}' to be rejected; got Ok");
        }
    }

    /// Leading `-` would let a malicious model smuggle a flag into
    /// `git worktree add -b <name>`. Must be rejected at the validator,
    /// not relied upon git >=2.17's own guard.
    #[test]
    fn validate_branch_name_rejects_leading_dash_408() {
        for name in &["-foo", "-rf", "--upload-pack=evil", "-"] {
            let r = validate_branch_name(test_run(), name);
            assert!(r.is_err(), "expected '{name}' to be rejected; got Ok");
            let msg = r.unwrap_err();
            assert!(
                msg.contains('-') || msg.contains("option"),
                "error must mention '-' or option-injection; got: {msg}"
            );
        }
    }

    /// Shell metacharacters like `;` and `&` are valid git refs but unsafe
    /// to surface back into agent logs and prompts. The validator rejects
    /// them even though `git check-ref-format --branch` accepts them.
    #[test]
    fn validate_branch_name_rejects_shell_metacharacters_408() {
        for name in &[
            "foo;rm -rf /",
            "a&b",
            "a|b",
            "a`b`",
            "a$b",
            "a>b",
            "a<b",
            "a 'b",
            "a\"b",
        ] {
            let r = validate_branch_name(test_run(), name);
            assert!(
                r.is_err(),
                "expected '{name}' to be rejected as shell metacharacter; got Ok"
            );
        }
    }

    /// Newlines, carriage returns, tabs, and other ASCII control characters
    /// must be rejected — they corrupt log lines and can split arguments
    /// inside the agent's prompt-rendering layer.
    #[test]
    fn validate_branch_name_rejects_control_chars_408() {
        let cases = ["a\nb", "a\rb", "a\tb", "a\x01b", "a\x07b", "\x7fhello"];
        for name in &cases {
            let r = validate_branch_name(test_run(), name);
            assert!(
                r.is_err(),
                "expected control-char name {name:?} to be rejected; got Ok"
            );
            let msg = r.unwrap_err();
            assert!(
                msg.contains("control") || msg.contains("forbidden"),
                "error must mention control / forbidden char; got: {msg}"
            );
        }
    }

    /// Characters explicitly forbidden by the issue's mandated refactor:
    /// `:`, `\\`, `~`, `?`, `*`, `[`. Also pin trailing `.`.
    #[test]
    fn validate_branch_name_rejects_git_special_chars_408() {
        let cases = ["a:b", "a\\b", "a~b", "a?b", "a*b", "a[b", "trailing."];
        for name in &cases {
            assert!(
                validate_branch_name(test_run(), name).is_err(),
                "expected '{name}' to be rejected; got Ok"
            );
        }
    }

    /// End-to-end: `execute_enter_worktree` must reject a path-traversal
    /// branch arg with `is_error=true` *without* invoking `git worktree add`.
    /// We can't directly assert "no subprocess spawned", but if the function
    /// short-circuits on validation we observe the validator error message,
    /// not git's own "worktree" error.
    #[test]
    fn enter_worktree_rejects_path_traversal_branch_408() {
        let _lock = cwd_lock();
        let mut args = HashMap::new();
        args.insert(
            "branch".to_string(),
            serde_json::Value::String("../escape".to_string()),
        );
        let (msg, is_err) = execute_enter_worktree(test_run(), &args);
        assert!(is_err, "path-traversal branch must produce is_error=true");
        assert!(
            msg.contains("invalid branch name") || msg.contains("'..'"),
            "must surface validator rejection (not a git worktree-add error); got: {msg}"
        );
    }

    /// End-to-end: `-rf` as a branch name must be rejected before reaching
    /// `git worktree add -b -rf ...`.
    #[test]
    fn enter_worktree_rejects_leading_dash_branch_408() {
        let _lock = cwd_lock();
        let mut args = HashMap::new();
        args.insert(
            "branch".to_string(),
            serde_json::Value::String("-rf".to_string()),
        );
        let (msg, is_err) = execute_enter_worktree(test_run(), &args);
        assert!(is_err, "leading-dash branch must produce is_error=true");
        assert!(
            msg.contains("invalid branch name"),
            "must surface validator rejection; got: {msg}"
        );
    }

    // ─── #345 regression tests: CWD must not be mutated ───────────────────────

    /// `execute_enter_worktree` must NOT change the process CWD, even on the
    /// happy path that creates a worktree. This is the core invariant of
    /// crosslink #345 — every other thread doing relative-path work must
    /// continue to see the same CWD.
    #[test]
    fn enter_worktree_does_not_mutate_process_cwd() {
        let _lock = cwd_lock();
        let before = std::env::current_dir().expect("cwd before");
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let branch = format!("test-345-{nanos}");

        let mut args = HashMap::new();
        args.insert(
            "branch".to_string(),
            serde_json::Value::String(branch.clone()),
        );
        let (msg, _is_err) = execute_enter_worktree(test_run(), &args);

        let after = std::env::current_dir().expect("cwd after");
        assert_eq!(
            before, after,
            "execute_enter_worktree must not mutate process CWD; \
             before={before:?} after={after:?} msg={msg}"
        );

        // Best-effort cleanup if we did succeed.
        if !msg.contains("Failed") && !msg.contains("Error") {
            let wt = before.join(".worktrees").join(&branch);
            let _ = git_in(
                test_run(),
                &before,
                &["worktree", "remove", wt.to_str().unwrap_or(""), "--force"],
            );
            let _ = git_in(test_run(), &before, &["branch", "-D", &branch]);
        }
    }

    /// `execute_exit_worktree` must NOT change the process CWD on any error
    /// path — including the new "missing path" error introduced in #345.
    #[test]
    fn exit_worktree_does_not_mutate_process_cwd_on_error() {
        let _lock = cwd_lock();
        let before = std::env::current_dir().expect("cwd before");

        let (_, is_err) = execute_exit_worktree(test_run(), &HashMap::new()).into_legacy();
        assert!(is_err);
        let after_missing = std::env::current_dir().expect("cwd after missing-path");
        assert_eq!(before, after_missing, "CWD changed on missing-path error");

        let mut args = HashMap::new();
        args.insert(
            "path".to_string(),
            serde_json::Value::String("/nonexistent/path/for/345".to_string()),
        );
        let (_, is_err) = execute_exit_worktree(test_run(), &args).into_legacy();
        assert!(is_err);
        let after_nonexistent = std::env::current_dir().expect("cwd after nonexistent");
        assert_eq!(
            before, after_nonexistent,
            "CWD changed on nonexistent-path error"
        );

        let mut args = HashMap::new();
        args.insert(
            "path".to_string(),
            serde_json::Value::String(before.display().to_string()),
        );
        let (_, is_err) = execute_exit_worktree(test_run(), &args).into_legacy();
        assert!(is_err);
        let after_main = std::env::current_dir().expect("cwd after main");
        assert_eq!(before, after_main, "CWD changed on main-worktree error");
    }

    /// Forensic anti-regression: this module must not *call*
    /// `set_current_dir` in any production function. Test code is allowed
    /// to call it (the "outside git repo" test deliberately sets CWD to a
    /// temp dir to simulate that environment), so the assertion is scoped
    /// to the production region of the file — everything before
    /// `#[cfg(test)]`.
    ///
    /// We grep for the call-site pattern `set_current_dir(` to ignore
    /// docstring mentions of the symbol, then strip line comments so that
    /// a `// set_current_dir(...)` comment never trips the regression.
    #[test]
    fn production_code_contains_no_set_current_dir_calls_345() {
        let src = include_str!("worktree.rs");
        let cfg_test = src
            .find("#[cfg(test)]")
            .expect("test module marker must be present");
        let production = &src[..cfg_test];

        for (idx, raw_line) in production.lines().enumerate() {
            // Drop everything after `//` so a line like
            // `// don't call set_current_dir(...)` does not trigger.
            let code = raw_line.split("//").next().unwrap_or("");
            assert!(
                !code.contains("set_current_dir("),
                "crosslink #345: production code in src/tools/worktree.rs must \
                 not call set_current_dir (process-wide global mutation); \
                 line {n}: {raw_line}",
                n = idx + 1,
            );
        }
    }

    #[test]
    fn production_git_invocations_use_resolved_binary_path() {
        let git = git_bin(test_run()).expect("worktree tests require git on the run-bound PATH");
        assert!(
            git.is_absolute(),
            "git_bin must resolve git to an absolute path, got {}",
            git.display()
        );

        let src = include_str!("worktree.rs");
        let cfg_test = src
            .find("#[cfg(test)]")
            .expect("test module marker must be present");
        let production = &src[..cfg_test];

        for (idx, raw_line) in production.lines().enumerate() {
            let code = raw_line.split("//").next().unwrap_or("");
            assert!(
                !code.contains("Command::new(\"git\")"),
                "production worktree code must not invoke bare git; line {n}: {raw_line}",
                n = idx + 1,
            );
            assert!(
                !code.contains("run_with_timeout(\"git\""),
                "production worktree code must not pass bare git to run_with_timeout; \
                 line {n}: {raw_line}",
                n = idx + 1,
            );
            assert!(
                !code.contains("Command::new("),
                "production worktree subprocesses must use run_with_timeout; \
                 line {n}: {raw_line}",
                n = idx + 1,
            );
        }
    }
}
