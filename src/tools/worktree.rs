//! Git worktree isolation for agent operations.
//!
//! Provides tools to create and manage isolated git worktrees so agents can
//! work on branches without affecting the main working tree.
//!
//! # Phase 1: no CWD mutation (crosslink #345)
//!
//! Earlier revisions called [`std::env::set_current_dir`] inside the enter
//! and exit handlers. That is process-wide global state: any other thread
//! (proxy, TUI, concurrent tool executor) doing a relative-path operation
//! races against the mutation and sees an inconsistent view of the working
//! directory. POSIX, Rust, and Go all document `chdir` as fundamentally
//! unsafe for concurrent processes.
//!
//! In Phase 1 of the fix:
//!
//! * `execute_enter_worktree` never mutates the process CWD. It creates the
//!   git worktree and returns the new path in its success message. The
//!   caller (REPL / session layer) is responsible for tracking the active
//!   worktree on the session.
//! * `execute_exit_worktree` no longer reads CWD to discover which worktree
//!   to clean up. It requires an explicit `path` argument naming the
//!   worktree to remove.
//! * All `git` invocations take an explicit `cwd` and pass it to
//!   `Command::current_dir`, so no `git` subprocess depends on the parent's
//!   CWD either.
//!
//! Phase 2 (passing the active worktree through `ToolContext` to bash /
//! file / lsp tool calls) is tracked separately — see the follow-up issue
//! filed against #345.

use crate::tools::args::ToolArgError;
use crate::tools::args::ToolArgs as _;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};

/// Maximum time to wait for a git command (seconds).
const GIT_TIMEOUT_SECS: u64 = 30;

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

/// Resolved geometry of a worktree-exit request.
///
/// Computed by [`validate_exit_request`] before any mutating git command runs
/// so the orchestration in [`execute_exit_worktree`] stays a flat sequence of
/// helpers rather than a deeply nested function.
struct ExitContext {
    worktree_path: PathBuf,
    main_path: PathBuf,
    current_branch: String,
    apply_changes: bool,
    /// `true` iff the caller explicitly passed `discard_changes=true` and is
    /// willing to lose uncommitted work in the worktree (crosslink #623).
    discard_changes: bool,
}

/// Inspect the worktree for uncommitted changes using `git status --porcelain`.
///
/// Returns `Ok(true)` if the worktree has tracked or untracked dirty files,
/// `Ok(false)` if it is clean, and `Err(msg)` if the porcelain status command
/// itself failed.
fn worktree_has_uncommitted_changes(
    run: &crate::tools::security::ToolRunContext,
    worktree_path: &Path,
) -> Result<bool, String> {
    match git_in(run, worktree_path, &["status", "--porcelain"]) {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            Ok(stdout.lines().any(|l| !l.trim().is_empty()))
        }
        Ok(o) => Err(format!(
            "git status --porcelain failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Err(e) => Err(e),
    }
}

/// Parse and validate the arguments to `exit_worktree`. Returns either a
/// resolved [`ExitContext`] or an error tuple ready to bubble back to the
/// caller.
fn validate_exit_request<S: std::hash::BuildHasher>(
    run: &crate::tools::security::ToolRunContext,
    args: &HashMap<String, Value, S>,
) -> Result<ExitContext, (String, bool)> {
    let path_arg = match args.get("path") {
        None => "",
        Some(Value::String(path)) => path,
        Some(_) => {
            return Err(ToolArgError::WrongType {
                key: "path",
                expected: "string",
            }
            .into_tool_error());
        }
    };
    if path_arg.is_empty() {
        return Err((
            "Error: 'path' is required — exit_worktree no longer reads the \
             process CWD. Pass the path returned by enter_worktree."
                .to_string(),
            true,
        ));
    }
    let worktree_path = PathBuf::from(path_arg);
    if !worktree_path.exists() {
        return Err((
            format!(
                "Error: worktree path does not exist: {}",
                worktree_path.display()
            ),
            true,
        ));
    }

    let apply_changes = args
        .arg_bool_or_strict("apply_changes", false)
        .map_err(crate::tools::args::ToolArgError::into_tool_error)?;

    // Crosslink #623: opt-in flag that lets the caller acknowledge the loss
    // of uncommitted work. Defaults to `false`, which causes the safety
    // gate in `execute_exit_worktree` to refuse destructive removal when
    // the worktree is dirty.
    let discard_changes = args
        .arg_bool_or_strict("discard_changes", false)
        .map_err(crate::tools::args::ToolArgError::into_tool_error)?;

    let common_dir = match git_in(run, &worktree_path, &["rev-parse", "--git-common-dir"]) {
        Ok(output) if output.status.success() => {
            String::from_utf8_lossy(&output.stdout).trim().to_string()
        }
        _ => {
            return Err((
                format!(
                    "Error: path is not inside a git worktree: {}",
                    worktree_path.display()
                ),
                true,
            ));
        }
    };

    // crosslink #983: refuse to proceed if `git rev-parse --git-dir` itself
    // failed. Previously this branch silently fell through to an empty
    // string, which then *did not equal* the (non-empty) common_dir — so a
    // corrupted `.git` was misclassified as an isolated worktree and the
    // function would happily call `git worktree remove --force` on the
    // user's main repository. Surface the underlying git failure instead.
    let git_dir = match git_in(run, &worktree_path, &["rev-parse", "--git-dir"]) {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        Ok(o) => {
            return Err((
                format!(
                    "Error: failed to resolve git directory for '{}': {}",
                    worktree_path.display(),
                    String::from_utf8_lossy(&o.stderr).trim()
                ),
                true,
            ));
        }
        Err(e) => {
            return Err((
                format!(
                    "Error: failed to run git rev-parse --git-dir on '{}': {e}",
                    worktree_path.display()
                ),
                true,
            ));
        }
    };

    if git_dir == common_dir || git_dir == ".git" {
        return Err((
            "Not in an isolated worktree. Use this tool only on a worktree \
             created by enter_worktree."
                .to_string(),
            true,
        ));
    }

    let current_branch = get_current_branch_at(run, &worktree_path).unwrap_or_default();
    let main_path = Path::new(&common_dir)
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();

    Ok(ExitContext {
        worktree_path,
        main_path,
        current_branch,
        apply_changes,
        discard_changes,
    })
}

/// Render a git error from `git_in`'s `Result<Output, String>`.
fn render_git_failure(res: &Result<std::process::Output, String>) -> String {
    match res {
        Ok(o) => String::from_utf8_lossy(&o.stderr).trim().to_string(),
        Err(e) => e.clone(),
    }
}

/// Outcome of [`merge_into_main`] — distinguishes the three relevant states
/// the orchestrator must react to (crosslink #858).
pub(crate) enum MergeOutcome {
    /// Branch merged cleanly into the main worktree.
    Merged(String),
    /// Worktree had no changes to commit; nothing to merge.
    NothingToMerge,
    /// A git command produced an error the caller must surface. The message
    /// already encodes whether `git merge --abort` succeeded — the orchestrator
    /// only needs to forward the text to the user.
    Failed { message: String },
}

/// Stage + commit + merge the worktree branch into the main worktree.
///
/// crosslink #858: each git step is now error-propagated rather than
/// swallowed by `let _ = …`. On merge conflict the function runs
/// `git merge --abort` in the main worktree so the user is left in a clean
/// state instead of a half-merged HEAD that the next `worktree remove
/// --force` would silently throw away.
fn merge_into_main(
    run: &crate::tools::security::ToolRunContext,
    ctx: &ExitContext,
) -> MergeOutcome {
    match git_in(run, &ctx.worktree_path, &["add", "-A"]) {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            return MergeOutcome::Failed {
                message: format!(
                    "git add -A failed in worktree: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                ),
            };
        }
        Err(e) => {
            return MergeOutcome::Failed {
                message: format!("git add -A failed in worktree: {e}"),
            };
        }
    }

    let commit = git_in(
        run,
        &ctx.worktree_path,
        &[
            "commit",
            "-m",
            &format!("Worktree changes from branch '{}'", ctx.current_branch),
        ],
    );
    // A failed commit here is the *expected* signal that there are no staged
    // changes — git exits non-zero with stderr "nothing to commit, working
    // tree clean". Treat that as "nothing to merge" rather than a hard error.
    let committed = commit.as_ref().is_ok_and(|o| o.status.success());
    if !committed {
        return MergeOutcome::NothingToMerge;
    }

    match git_in(
        run,
        &ctx.main_path,
        &["merge", &ctx.current_branch, "--no-edit"],
    ) {
        Ok(o) if o.status.success() => MergeOutcome::Merged(format!(
            "Merged branch '{}' into main worktree.",
            ctx.current_branch
        )),
        Ok(o) => {
            // crosslink #858: leaving the main worktree mid-merge is the
            // worst possible failure mode — `worktree remove --force` would
            // then discard the user's uncommitted (conflict-resolution)
            // edits. Abort the merge first so HEAD is clean again.
            let stderr = String::from_utf8_lossy(&o.stderr).trim().to_string();
            let abort = git_in(run, &ctx.main_path, &["merge", "--abort"]);
            let aborted = abort.is_ok_and(|out| out.status.success());
            MergeOutcome::Failed {
                message: format!(
                    "Merge had conflicts: {stderr}{}",
                    if aborted {
                        " (merge aborted; main worktree restored)"
                    } else {
                        " (warning: git merge --abort also failed; main worktree may be in a half-merged state)"
                    }
                ),
            }
        }
        Err(e) => MergeOutcome::Failed {
            message: format!("Merge failed: {e}"),
        },
    }
}

/// Issue `git worktree remove --force` from the main worktree and return
/// `(removed_ok, detail_string)`. On success, drop the worktree from the
/// active set and bump the cwd-cache generation (crosslink #624).
fn remove_worktree(
    run: &crate::tools::security::ToolRunContext,
    ctx: &ExitContext,
) -> (bool, String) {
    let removed = git_in(
        run,
        &ctx.main_path,
        &[
            "worktree",
            "remove",
            ctx.worktree_path.to_str().unwrap_or(""),
            "--force",
        ],
    );
    let ok = removed.as_ref().is_ok_and(|o| o.status.success());
    if ok {
        unregister_active_worktree(&ctx.worktree_path);
    }
    (ok, render_git_failure(&removed))
}

/// Exit (remove) an isolated git worktree.
///
/// **Phase 1 (#345) behavior**: this function does NOT read or mutate the
/// process CWD. The caller must pass `path` naming the worktree to remove.
/// All git commands run against that path explicitly via `current_dir`.
///
/// Arguments:
/// * `path` (string, required) — absolute path to the worktree that
///   [`execute_enter_worktree`] previously created.
/// * `apply_changes` (bool, optional, default `false`) — if true, commit
///   uncommitted changes inside the worktree and merge the worktree branch
///   into the main worktree before removing the worktree.
/// * `discard_changes` (bool, optional, default `false`) — opt-in safety
///   gate (crosslink #623). When `apply_changes=false`, the worktree is
///   destroyed by `git worktree remove --force`. The previous behaviour
///   silently destroyed uncommitted work; the gate now refuses removal
///   unless `discard_changes=true` is set explicitly. Ignored when
///   `apply_changes=true` because the merge path commits the work first.
#[must_use]
pub fn execute_exit_worktree<S: std::hash::BuildHasher>(
    run: &crate::tools::security::ToolRunContext,
    args: &HashMap<String, Value, S>,
) -> (String, bool) {
    let ctx = match validate_exit_request(run, args) {
        Ok(ctx) => ctx,
        Err(err) => return err,
    };

    // Crosslink #623: refuse silent destruction of uncommitted work. The
    // gate fires only on the discard path; `apply_changes=true` commits
    // work before removal so dirty state is not lost there.
    if !ctx.apply_changes && !ctx.discard_changes {
        match worktree_has_uncommitted_changes(run, &ctx.worktree_path) {
            Ok(true) => {
                return (
                    format!(
                        "worktree has uncommitted changes; pass discard_changes=true to force \
                         removal of {} (or apply_changes=true to merge them first)",
                        ctx.worktree_path.display()
                    ),
                    true,
                );
            }
            Ok(false) => {}
            Err(e) => {
                return (
                    format!(
                        "Refusing to remove worktree {}: could not verify clean state ({e})",
                        ctx.worktree_path.display()
                    ),
                    true,
                );
            }
        }
    }

    if ctx.apply_changes {
        let merge_result = merge_into_main(run, &ctx);

        // crosslink #858: on merge conflict, refuse the destructive
        // `worktree remove --force` and surface the conflict to the caller.
        // The conflicting branch is still present; the user can resolve it
        // manually or invoke exit_worktree again with `discard_changes=true`.
        if let MergeOutcome::Failed { message, .. } = &merge_result {
            return (
                format!(
                    "Exit worktree at {} aborted: {}\nMain worktree: {}\n\
                     The worktree was NOT removed; resolve the conflict and \
                     retry, or pass `discard_changes:true` to discard the \
                     branch.",
                    ctx.worktree_path.display(),
                    message,
                    ctx.main_path.display()
                ),
                true,
            );
        }

        let summary = match &merge_result {
            MergeOutcome::Merged(msg) => msg.clone(),
            MergeOutcome::NothingToMerge => "No changes to commit.".to_string(),
            MergeOutcome::Failed { .. } => unreachable!("returned above"),
        };

        let (removed_ok, detail) = remove_worktree(run, &ctx);
        let warning = if removed_ok {
            String::new()
        } else {
            format!(" WARNING: worktree removal failed: {detail}")
        };
        return (
            format!(
                "Exited worktree at {}. {}{}\nMain worktree: {}",
                ctx.worktree_path.display(),
                summary,
                warning,
                ctx.main_path.display()
            ),
            !removed_ok,
        );
    }

    let (removed_ok, detail) = remove_worktree(run, &ctx);
    if removed_ok {
        (
            format!(
                "Discarded worktree on branch '{}' at {}. Main worktree: {}",
                ctx.current_branch,
                ctx.worktree_path.display(),
                ctx.main_path.display()
            ),
            false,
        )
    } else {
        (
            format!(
                "Failed to remove worktree at {}: {}",
                ctx.worktree_path.display(),
                detail
            ),
            true,
        )
    }
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
/// `exit_worktree` multiplexes three operations with materially different
/// blast radii behind one wire-level name, and F-001 records that it declared
/// no permission target at all:
///
/// * `discard_changes: true` knowingly throws away uncommitted work;
/// * `apply_changes: true` commits and merges non-ignored work first;
/// * neither flag refuses when ordinary `git status --porcelain` reports a
///   dirty worktree.
///
/// All three are classified [`ToolEffect::Destructive`]. Execution ultimately
/// calls `git worktree remove --force`, and classification is deliberately
/// argument-only: it cannot inspect the filesystem to prove that the worktree
/// contains no ignored files that `git status --porcelain` omitted. Such files
/// can be irreversibly deleted even on the nominally clean or apply paths, so a
/// lower pre-authorization effect would be an optimistic lie. S-073 owns
/// replacing that executor behavior with a transactional, ignored-file-aware
/// workflow; until then the honest ceiling is destructive.
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
    use crate::tools::effect::{ToolEffect, TypedEffect};

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

    let discard = flag("discard_changes")?;
    let apply = flag("apply_changes")?;

    // Execution gives apply_changes precedence and explicitly ignores
    // discard_changes on that path. Classification must mirror that order: a
    // call with both flags set commits/merges, it does not discard.
    let operation = if apply {
        "apply"
    } else if discard {
        "discard"
    } else {
        "remove_clean"
    };

    Ok(TypedEffect::new(ToolEffect::Destructive, operation, path))
}

/// Every operation `exit_worktree` can resolve to, for the generated matrix.
#[must_use]
pub fn exit_worktree_operations() -> Vec<(&'static str, crate::tools::effect::ToolEffect)> {
    use crate::tools::effect::ToolEffect;
    vec![
        ("discard", ToolEffect::Destructive),
        ("apply", ToolEffect::Destructive),
        ("remove_clean", ToolEffect::Destructive),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::testutil::process_cwd_lock;
    use std::sync::MutexGuard;

    fn test_run() -> &'static std::sync::Arc<crate::tools::ToolRunContext> {
        crate::tools::security::test_run_context()
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
    fn test_get_current_branch_at_cwd() {
        let _lock = cwd_lock();
        let cwd = std::env::current_dir().unwrap();
        let branch = get_current_branch_at(test_run(), &cwd);
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
        let (msg, is_err) = execute_list_worktrees(test_run());
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
        let (msg, is_err) = execute_exit_worktree(test_run(), &args);
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
        let (msg, is_err) = execute_exit_worktree(test_run(), &args);
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

        let (msg, is_err) = execute_exit_worktree(test_run(), &args);
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

        let (msg, is_err) = execute_exit_worktree(test_run(), &args);
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
    /// Three valid rejection messages exist after crosslink #623:
    ///
    /// 1. "Not in an isolated worktree" (path is the repo root).
    /// 2. "not inside a git worktree" (path is not a git workspace).
    /// 3. "uncommitted changes ... `discard_changes=true`" (#623 safety
    ///    gate — fires when the path *is* a worktree but it is dirty,
    ///    which is the common case when tests run inside the harness's
    ///    own agent worktree).
    ///
    /// All three are legitimate refusals and must produce `is_error=true`.
    #[test]
    fn exit_worktree_with_main_tree_path_is_error() {
        let _lock = cwd_lock();
        let main = std::env::current_dir().unwrap();
        let mut args = HashMap::new();
        args.insert(
            "path".to_string(),
            serde_json::Value::String(main.display().to_string()),
        );
        let (msg, is_err) = execute_exit_worktree(test_run(), &args);
        assert!(is_err, "exit on main worktree must produce is_error=true");
        assert!(
            msg.contains("Not in an isolated worktree")
                || msg.contains("not inside a git worktree")
                || msg.contains("uncommitted changes"),
            "error must indicate a legitimate refusal reason; got: {msg}"
        );
    }

    /// #624: a second `enter_worktree` call with the same branch (which
    /// maps to the same `worktree_dir`) returns a no-op success after the
    /// duplicate-session guard fires. Pins the *fix* — the previous gap
    /// test asserted the *absence* of this guard.
    #[test]
    fn enter_worktree_duplicate_call_is_no_op_624() {
        let _lock = cwd_lock();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let branch = format!("dup-guard-624-{nanos}");

        let mut args = HashMap::new();
        args.insert(
            "branch".to_string(),
            serde_json::Value::String(branch.clone()),
        );
        let (first_msg, first_err) = execute_enter_worktree(test_run(), &args);
        assert!(!first_err, "first call must succeed; got: {first_msg}");

        let (second_msg, second_err) = execute_enter_worktree(test_run(), &args);
        assert!(!second_err, "duplicate call must be a no-op (not error)");
        assert!(
            second_msg.contains("already in worktree") && second_msg.contains("No-op"),
            "duplicate call must surface the no-op message; got: {second_msg}"
        );

        // Cleanup.
        let cwd = std::env::current_dir().unwrap();
        let wt = cwd.join(".worktrees").join(&branch);
        let mut exit_args = HashMap::new();
        exit_args.insert(
            "path".to_string(),
            serde_json::Value::String(wt.display().to_string()),
        );
        exit_args.insert("discard_changes".to_string(), serde_json::Value::Bool(true));
        let _ = execute_exit_worktree(test_run(), &exit_args);
        let _ = git_in(test_run(), &cwd, &["branch", "-D", &branch]);
    }

    /// #624: the cwd-cache generation counter advances when a worktree is
    /// created and again when it is destroyed. Subscribers (future
    /// realpath caches) can poll this counter to know when to invalidate.
    #[test]
    fn enter_and_exit_worktree_bump_cwd_cache_generation_624() {
        let _lock = cwd_lock();
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
        let (msg, is_err) = execute_enter_worktree(test_run(), &args);
        assert!(!is_err, "enter must succeed; got: {msg}");
        let after_enter = cwd_cache_generation();
        assert!(
            after_enter > before,
            "cwd_cache_generation must advance on enter (before={before}, after={after_enter})"
        );

        let cwd = std::env::current_dir().unwrap();
        let wt = cwd.join(".worktrees").join(&branch);
        let mut exit_args = HashMap::new();
        exit_args.insert(
            "path".to_string(),
            serde_json::Value::String(wt.display().to_string()),
        );
        exit_args.insert("discard_changes".to_string(), serde_json::Value::Bool(true));
        let (msg, is_err) = execute_exit_worktree(test_run(), &exit_args);
        assert!(!is_err, "exit must succeed; got: {msg}");
        let after_exit = cwd_cache_generation();
        assert!(
            after_exit > after_enter,
            "cwd_cache_generation must advance on exit (after_enter={after_enter}, after_exit={after_exit})"
        );

        let _ = git_in(test_run(), &cwd, &["branch", "-D", &branch]);
    }

    /// #623: with the worktree dirty and `discard_changes` omitted (or
    /// `false`), `exit_worktree` must refuse with a clear safety message
    /// instead of silently running `git worktree remove --force`.
    #[test]
    fn exit_worktree_refuses_to_destroy_dirty_worktree_without_discard_623() {
        let _lock = cwd_lock();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let branch = format!("dirty-623-{nanos}");

        let mut args = HashMap::new();
        args.insert(
            "branch".to_string(),
            serde_json::Value::String(branch.clone()),
        );
        let (msg, is_err) = execute_enter_worktree(test_run(), &args);
        assert!(!is_err, "enter must succeed; got: {msg}");

        let cwd = std::env::current_dir().unwrap();
        let wt = cwd.join(".worktrees").join(&branch);
        // Dirty the worktree by writing an untracked file.
        std::fs::write(wt.join("dirty.txt"), "uncommitted work\n").expect("write dirty");

        // Default `discard_changes=false` must refuse.
        let mut exit_args = HashMap::new();
        exit_args.insert(
            "path".to_string(),
            serde_json::Value::String(wt.display().to_string()),
        );
        let (msg, is_err) = execute_exit_worktree(test_run(), &exit_args);
        assert!(is_err, "dirty exit without discard must error");
        assert!(
            msg.contains("uncommitted changes") && msg.contains("discard_changes=true"),
            "safety message must name the gap & the override; got: {msg}"
        );
        // Worktree still exists because we refused to destroy it.
        assert!(
            wt.exists(),
            "refused exit must leave the worktree on disk: {}",
            wt.display()
        );

        // Now opt in: discard_changes=true must succeed.
        exit_args.insert("discard_changes".to_string(), serde_json::Value::Bool(true));
        let (msg, is_err) = execute_exit_worktree(test_run(), &exit_args);
        assert!(!is_err, "discard_changes=true must succeed; got: {msg}");
        assert!(!wt.exists(), "successful exit must remove the worktree");

        let _ = git_in(test_run(), &cwd, &["branch", "-D", &branch]);
    }

    /// #623: a *clean* worktree exits successfully without needing the
    /// opt-in. The safety gate must not raise the bar for the common case.
    #[test]
    fn exit_worktree_clean_worktree_exits_without_discard_flag_623() {
        let _lock = cwd_lock();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let branch = format!("clean-623-{nanos}");

        let mut args = HashMap::new();
        args.insert(
            "branch".to_string(),
            serde_json::Value::String(branch.clone()),
        );
        let (msg, is_err) = execute_enter_worktree(test_run(), &args);
        assert!(!is_err, "enter must succeed; got: {msg}");

        let cwd = std::env::current_dir().unwrap();
        let wt = cwd.join(".worktrees").join(&branch);
        // No mutations: worktree is clean.

        let mut exit_args = HashMap::new();
        exit_args.insert(
            "path".to_string(),
            serde_json::Value::String(wt.display().to_string()),
        );
        let (msg, is_err) = execute_exit_worktree(test_run(), &exit_args);
        assert!(
            !is_err,
            "clean exit without discard_changes must succeed; got: {msg}"
        );
        assert!(!wt.exists(), "clean exit must remove the worktree");

        let _ = git_in(test_run(), &cwd, &["branch", "-D", &branch]);
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

        let (_, is_err) = execute_exit_worktree(test_run(), &HashMap::new());
        assert!(is_err);
        let after_missing = std::env::current_dir().expect("cwd after missing-path");
        assert_eq!(before, after_missing, "CWD changed on missing-path error");

        let mut args = HashMap::new();
        args.insert(
            "path".to_string(),
            serde_json::Value::String("/nonexistent/path/for/345".to_string()),
        );
        let (_, is_err) = execute_exit_worktree(test_run(), &args);
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
        let (_, is_err) = execute_exit_worktree(test_run(), &args);
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
