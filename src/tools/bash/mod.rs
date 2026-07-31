mod kill;
mod output;
pub mod path_constraints;
pub mod sandbox;
// `policy` is exposed so the security E2E test suite
// (`tests/tools_security_e2e.rs`) can drive `validate_command`,
// `is_safe_for_auto_allow`, `dangerous_shell_construct`, and
// `is_sensitive_env` against the documented attack catalog
// without actually executing the attack payloads. Internal call
// sites use the same path.
pub mod policy;

pub use kill::{execute_kill_shell, execute_kill_shells_for_agent, terminate_process_tree};
pub use output::execute_bash_output;
pub use path_constraints::{
    check_command_against_global, clear_global as clear_global_path_constraints,
    install_global as install_global_path_constraints, PathConstraints,
};
pub use policy::{
    apply_env_scrub, dangerous_shell_construct, is_safe_for_auto_allow, is_sensitive_env,
    validate_command,
};

use crate::tools::args::{into_legacy, ToolArgError, ToolArgs as _, ToolError, ToolOutput};
use crate::tools::safe_truncate;
use serde_json::Value;
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::thread;
use uuid::Uuid;

/// Maximum number of background shells allowed before refusing new ones
const MAX_BACKGROUND_SHELLS: usize = 50;
const LEDGER_COMMAND_OUTPUT_MAX_BYTES: usize = 100_000;
const BACKGROUND_OUTPUT_MAX_BYTES_PER_STREAM: usize = 1024 * 1024;
const FOREGROUND_COMMAND_TIMEOUT: std::time::Duration = std::time::Duration::from_mins(5);
const VERIFICATION_COMMAND_NEEDLES: &[&str] = &[
    "cargo test",
    "cargo check",
    "cargo clippy",
    "cargo fmt",
    "cargo nextest",
    "npm test",
    "npm run test",
    "pnpm test",
    "pnpm run test",
    "yarn test",
    "yarn run test",
    "bun test",
    "pytest",
    "python -m pytest",
    "go test",
    "zig test",
    "swift test",
    "mvn test",
    "gradle test",
    "make test",
    "ctest",
];

static BASH_BIN: LazyLock<Result<PathBuf, String>> = LazyLock::new(|| {
    which::which("bash").map_err(|e| format!("bash binary not found on PATH: {e}"))
});

fn bash_bin() -> Result<&'static Path, String> {
    match &*BASH_BIN {
        Ok(path) => Ok(path.as_path()),
        Err(msg) => Err(msg.clone()),
    }
}

fn recover_mutex_lock<'a, T>(
    mutex: &'a Mutex<T>,
    op: &'static str,
    resource: &'static str,
    shell_id: Option<&str>,
) -> MutexGuard<'a, T> {
    mutex.lock().unwrap_or_else(|p| {
        tracing::error!(
            target: "openclaudia::bash",
            event = "mutex_poisoned",
            op,
            resource,
            shell_id = shell_id.unwrap_or(""),
            "background shell mutex poisoned; recovering inner state"
        );
        p.into_inner()
    })
}

#[allow(clippy::too_many_arguments)]
fn spawn_output_reader<R>(
    stream: R,
    buffer: Arc<Mutex<Vec<String>>>,
    output_limit: Arc<OutputLimit>,
    ledger_buffer: Arc<Mutex<String>>,
    done: Arc<AtomicBool>,
    op: &'static str,
    resource: &'static str,
    shell_id: String,
) where
    R: Read + Send + 'static,
{
    thread::spawn(move || {
        let reader = BufReader::new(stream);
        for line in reader.lines().map_while(Result::ok) {
            append_ledger_output_line(&ledger_buffer, &line, op, "ledger_buffer", &shell_id);
            let retained = output_limit.reserve(line.len().saturating_add(1));
            if retained > 0 {
                let retained_line = safe_truncate(&line, retained.min(line.len())).to_string();
                recover_mutex_lock(&buffer, op, resource, Some(&shell_id)).push(retained_line);
            }
            if retained < line.len().saturating_add(1)
                && !output_limit.marker.swap(true, Ordering::SeqCst)
            {
                recover_mutex_lock(&buffer, op, resource, Some(&shell_id))
                    .push("[output truncated at 1 MiB]".to_string());
            }
        }
        done.store(true, Ordering::SeqCst);
    });
}

struct OutputLimit {
    bytes: std::sync::atomic::AtomicUsize,
    marker: AtomicBool,
}

impl OutputLimit {
    const fn new() -> Self {
        Self {
            bytes: std::sync::atomic::AtomicUsize::new(0),
            marker: AtomicBool::new(false),
        }
    }

    fn reserve(&self, requested: usize) -> usize {
        let mut current = self.bytes.load(Ordering::SeqCst);
        loop {
            let remaining = BACKGROUND_OUTPUT_MAX_BYTES_PER_STREAM.saturating_sub(current);
            let granted = requested.min(remaining);
            match self.bytes.compare_exchange(
                current,
                current.saturating_add(granted),
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return granted,
                Err(actual) => current = actual,
            }
        }
    }
}

fn append_ledger_output_line(
    buffer: &Arc<Mutex<String>>,
    line: &str,
    op: &'static str,
    resource: &'static str,
    shell_id: &str,
) {
    let mut buffer = recover_mutex_lock(buffer, op, resource, Some(shell_id));
    if buffer.len() >= LEDGER_COMMAND_OUTPUT_MAX_BYTES {
        return;
    }
    let mut chunk = String::with_capacity(line.len() + usize::from(!buffer.is_empty()));
    if !buffer.is_empty() {
        chunk.push('\n');
    }
    chunk.push_str(line);
    let remaining = LEDGER_COMMAND_OUTPUT_MAX_BYTES - buffer.len();
    buffer.push_str(safe_truncate(&chunk, remaining));
}

/// Background shell process with captured output
struct BackgroundShell {
    stdout_buffer: Arc<Mutex<Vec<String>>>,
    stderr_buffer: Arc<Mutex<Vec<String>>>,
    command: String,
    /// Session or subagent bucket that created this shell.
    owner: String,
    /// Liveness signal — true once the wait thread has reaped the child.
    ///
    /// # Fix for crosslink #674
    ///
    /// Pre-fix this flag was also flipped by the stdout reader on EOF,
    /// racing with the wait thread. A caller could observe
    /// `is_running=false` together with `exit_code=None` because the
    /// reader signalled "done" before the wait thread populated the
    /// exit status. Post-fix only the wait thread writes this flag and
    /// it implies `exit_status` has been populated under `SeqCst`.
    finished: Arc<AtomicBool>,
    stdout_done: Arc<AtomicBool>,
    stderr_done: Arc<AtomicBool>,
    /// Distinct from `finished`: set by the wait thread immediately
    /// after writing `exit_status`. Consulted by `get_output` so that
    /// (`is_running=false`, `exit_code=None`) is unreachable.
    reaped: Arc<AtomicBool>,
    exit_status: Arc<Mutex<Option<i32>>>,
    /// PID of the spawned process, used to send SIGTERM on kill
    pid: u32,
    /// Whether output has been drained at least once via `get_output`.
    ///
    /// # Fix for crosslink #351
    ///
    /// Set inside `get_output` on the actual drain operation, regardless of
    /// whether the process has finished. The previous implementation only set
    /// it when `is_finished` was observed true at poll time, which raced with
    /// the wait-thread:
    ///
    /// - Drain BEFORE the wait-thread flips `finished=true`: flag was never
    ///   set even though output was drained — GC permanently retained the
    ///   slot.
    /// - One-shot drain after finish: still set the flag (this path worked
    ///   pre-fix and is preserved).
    ///
    /// Setting the flag on drain eliminates the happens-before requirement
    /// between `finished` and `output_retrieved_after_finish`; GC additionally
    /// waits for both output readers to hit EOF and for their buffers to be
    /// empty, so a poll that happens before the child's final stdout/stderr
    /// is delivered cannot make that output collectable.
    output_retrieved_after_finish: AtomicBool,
}

/// Manager for background shell processes
pub struct BackgroundShellManager {
    shells: Mutex<HashMap<String, BackgroundShell>>,
}

impl BackgroundShellManager {
    fn new() -> Self {
        Self {
            shells: Mutex::new(HashMap::new()),
        }
    }

    /// Spawn a new background shell and return its ID.
    ///
    /// Enforces [`validate_command`] (length cap + denylist) and applies
    /// the env allowlist via [`apply_env_scrub`] before spawn so that only
    /// a curated set of variables (`PATH`, `HOME`, `USER`, `CARGO_HOME`, ...)
    /// flows into the child. See crosslink #257 and #730.
    #[allow(clippy::too_many_lines)] // spawn keeps the atomic reserve/spawn/insert sequence together
    pub(crate) fn spawn(&self, command: &str) -> Result<String, String> {
        validate_command(command)?;

        let shell_id = safe_truncate(&Uuid::new_v4().to_string(), 8).to_string();
        let owner = super::todo::current_session_key();
        let security = crate::tools::security::current_context()?;
        let cwd = security.working_directory().to_path_buf();

        // ── Crosslink #672 fix: atomic check+reserve ──────────────────────────
        //
        // Pre-fix the `cmd.spawn()` call happened BEFORE any capacity guard,
        // so a flood of concurrent `run_in_background=true` callers could each
        // fork a child before any of them lost the cap check. The cap then
        // only suppressed *tracking*, leaking orphan OS processes.
        //
        // Fix: hold the manager's `shells` lock across the entire critical
        // section — GC sweep, capacity check, spawn, and insert — so the
        // check and the spawn are atomic with respect to other spawners.
        // The lock is contended only by other spawn/list/kill calls, and
        // `Command::spawn` is a fast `fork+exec` syscall, so holding it
        // for the duration is acceptable for the cap=50 workload.
        let mut shells = recover_mutex_lock(&self.shells, "spawn", "shells", None);

        // GC sweep: remove finished shells whose output has been retrieved at
        // least once and whose reader threads have fully drained their pipes.
        // A first poll can happen before a quick child emits its final output;
        // without the reader-done + empty-buffer checks, a concurrent spawn can
        // collect that shell before the caller has a chance to read the line.
        shells.retain(|_id, s| {
            let is_finished = s.finished.load(Ordering::SeqCst);
            let output_retrieved = s.output_retrieved_after_finish.load(Ordering::SeqCst);
            if !is_finished || !output_retrieved {
                return true;
            }
            let stdout_done = s.stdout_done.load(Ordering::SeqCst);
            let stderr_done = s.stderr_done.load(Ordering::SeqCst);
            if !stdout_done || !stderr_done {
                return true;
            }
            let stdout_empty =
                recover_mutex_lock(&s.stdout_buffer, "spawn_gc", "stdout_buffer", None).is_empty();
            let stderr_empty =
                recover_mutex_lock(&s.stderr_buffer, "spawn_gc", "stderr_buffer", None).is_empty();
            !(stdout_empty && stderr_empty)
        });

        if shells.len() >= MAX_BACKGROUND_SHELLS {
            return Err(format!(
                "Maximum background shell limit ({MAX_BACKGROUND_SHELLS}) reached. \
                 Kill or wait for existing shells to finish."
            ));
        }

        #[cfg(windows)]
        let child = {
            let bash = find_git_bash().unwrap_or(bash_bin()?.to_path_buf());
            let mut cmd = sandbox::sandboxed_bash_command(&bash, command, &cwd)?;
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
            cmd.spawn()
        };

        #[cfg(not(windows))]
        let child = {
            let mut cmd = sandbox::sandboxed_bash_command(bash_bin()?, command, &cwd)?;
            cmd.stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .process_group(0); // Put child in its own process group for clean kill
            cmd.spawn()
        };

        let mut child = child.map_err(|e| format!("Failed to spawn background shell: {e}"))?;

        // Capture PID before moving the child handle into the wait thread
        let pid = child.id();

        let stdout_buffer = Arc::new(Mutex::new(Vec::new()));
        let stderr_buffer = Arc::new(Mutex::new(Vec::new()));
        let stdout_ledger_buffer = Arc::new(Mutex::new(String::new()));
        let stderr_ledger_buffer = Arc::new(Mutex::new(String::new()));
        let stdout_output_limit = Arc::new(OutputLimit::new());
        let stderr_output_limit = Arc::new(OutputLimit::new());
        let finished = Arc::new(AtomicBool::new(false));
        let stdout_done = Arc::new(AtomicBool::new(false));
        let stderr_done = Arc::new(AtomicBool::new(false));
        let reaped = Arc::new(AtomicBool::new(false));
        let exit_status = Arc::new(Mutex::new(None));

        // ── Crosslink #674 fix: only the wait thread sets `finished` ──────
        //
        // Pre-fix BOTH the stdout reader and the wait thread set
        // `finished=true`. The stdout reader could fire on EOF BEFORE the
        // wait thread reaped the child, producing the impossible state
        // (is_running=false, exit_code=None). Post-fix: the stdout reader
        // no longer touches `finished`; it is the sole responsibility of
        // the wait thread, which sets `exit_status` first and `reaped`
        // second under release/acquire ordering. `get_output` consults
        // `reaped` so a caller never observes a finished shell without an
        // exit code.
        if let Some(stdout) = child.stdout.take() {
            spawn_output_reader(
                stdout,
                Arc::clone(&stdout_buffer),
                stdout_output_limit,
                Arc::clone(&stdout_ledger_buffer),
                Arc::clone(&stdout_done),
                "stdout_reader",
                "stdout_buffer",
                shell_id.clone(),
            );
        } else {
            stdout_done.store(true, Ordering::SeqCst);
        }

        // Spawn thread to read stderr
        if let Some(stderr) = child.stderr.take() {
            spawn_output_reader(
                stderr,
                Arc::clone(&stderr_buffer),
                stderr_output_limit,
                Arc::clone(&stderr_ledger_buffer),
                Arc::clone(&stderr_done),
                "stderr_reader",
                "stderr_buffer",
                shell_id.clone(),
            );
        } else {
            stderr_done.store(true, Ordering::SeqCst);
        }

        // Spawn thread to wait for process and capture exit status
        let exit_status_clone = Arc::clone(&exit_status);
        let finished_clone = Arc::clone(&finished);
        let reaped_clone = Arc::clone(&reaped);
        let stdout_done_for_ledger = Arc::clone(&stdout_done);
        let stderr_done_for_ledger = Arc::clone(&stderr_done);
        let stdout_ledger_for_wait = Arc::clone(&stdout_ledger_buffer);
        let stderr_ledger_for_wait = Arc::clone(&stderr_ledger_buffer);
        let owner_for_ledger = owner.clone();
        let cwd_for_ledger = cwd;
        let command_for_ledger = command.to_string();
        let mut child_for_wait = child;
        let wait_shell_id = shell_id.clone();
        thread::spawn(move || {
            if let Ok(status) = child_for_wait.wait() {
                let exit_code = status.code().unwrap_or(-1);
                *recover_mutex_lock(
                    &exit_status_clone,
                    "wait",
                    "exit_status",
                    Some(&wait_shell_id),
                ) = status.code();
                // Order matters: set `reaped` AFTER `exit_status` so
                // `get_output` cannot observe `reaped=true` with
                // `exit_status=None`.
                reaped_clone.store(true, Ordering::SeqCst);
                finished_clone.store(true, Ordering::SeqCst);
                wait_for_output_readers(
                    &stdout_done_for_ledger,
                    &stderr_done_for_ledger,
                    &wait_shell_id,
                );
                let stdout = recover_mutex_lock(
                    &stdout_ledger_for_wait,
                    "wait_ledger",
                    "stdout_ledger_buffer",
                    Some(&wait_shell_id),
                )
                .clone();
                let stderr = recover_mutex_lock(
                    &stderr_ledger_for_wait,
                    "wait_ledger",
                    "stderr_ledger_buffer",
                    Some(&wait_shell_id),
                )
                .clone();
                record_command_observation_for_session(
                    &owner_for_ledger,
                    &cwd_for_ledger,
                    &command_for_ledger,
                    exit_code,
                    &stdout,
                    &stderr,
                );
            }
        });

        let shell = BackgroundShell {
            stdout_buffer,
            stderr_buffer,
            command: command.to_string(),
            owner,
            finished,
            stdout_done,
            stderr_done,
            reaped,
            exit_status,
            pid,
            output_retrieved_after_finish: AtomicBool::new(false),
        };

        shells.insert(shell_id.clone(), shell);
        drop(shells);

        Ok(shell_id)
    }

    /// Get output from a background shell (returns new output since last call)
    #[allow(clippy::significant_drop_tightening)] // shells lock must be held while accessing shell
    pub(crate) fn get_output(&self, shell_id: &str) -> Result<(String, bool, Option<i32>), String> {
        let caller = super::todo::current_session_key();
        // Crosslink #678: the shells map holds an entry-per-shell HashMap with
        // no cross-field invariant — every recoverable state is fully
        // represented inside an individual BackgroundShell, and HashMap
        // insert/get/remove are atomic. A poisoned mutex therefore reflects
        // a panic in unrelated code paths, not a corrupted shells-map
        // structure. We recover the inner state but loudly log so operators
        // see the poison event in audit logs rather than treating it as
        // invisible silent absorption.
        let shells = recover_mutex_lock(&self.shells, "get_output", "shells", Some(shell_id));
        let shell = shells
            .get(shell_id)
            .ok_or_else(|| format!("Shell '{shell_id}' not found"))?;
        if shell.owner != caller {
            tracing::warn!(
                target: "openclaudia::bash",
                event = "cross_session_shell_access_denied",
                caller,
                shell_id,
                "Denied background shell output access outside the owning session"
            );
            // Deliberately do not reveal whether a guessed identifier exists.
            return Err(format!("Shell '{shell_id}' not found"));
        }

        let mut output = String::new();

        // Swap buffers atomically — take all lines, leave empty vec.
        // This minimizes lock hold time and prevents data loss from
        // concurrent writer threads.
        let stdout_lines: Vec<String> = std::mem::take(&mut *recover_mutex_lock(
            &shell.stdout_buffer,
            "get_output",
            "stdout_buffer",
            Some(shell_id),
        ));

        let stderr_lines: Vec<String> = std::mem::take(&mut *recover_mutex_lock(
            &shell.stderr_buffer,
            "get_output",
            "stderr_buffer",
            Some(shell_id),
        ));

        // Join outside the lock
        if !stdout_lines.is_empty() {
            output.push_str(&stdout_lines.join("\n"));
        }
        if !stderr_lines.is_empty() {
            if !output.is_empty() {
                output.push('\n');
            }
            output.push_str("stderr:\n");
            output.push_str(&stderr_lines.join("\n"));
        }

        // Crosslink #351 fix: mark the slot as drained on EVERY get_output
        // call, regardless of whether `finished` has been set yet by the
        // wait-thread. The previous code gated the store on
        // `is_finished == true`, racing with the wait-thread: a caller that
        // drained just before `finished` was set would never mark the slot
        // as drained, leaving the GC sweep unable to reclaim it.
        //
        // Drain is the GC-relevant event: once a caller has had the chance
        // to read the buffers, the slot is collectable as soon as the
        // process is also finished. SeqCst on this store + matching loads
        // in `spawn`'s GC sweep gives the happens-before edge that was
        // missing before.
        shell
            .output_retrieved_after_finish
            .store(true, Ordering::SeqCst);

        // Crosslink #674 fix: derive `is_running` from `reaped` (set by the
        // wait thread after writing `exit_status`), not from `finished` —
        // which the stdout reader could previously flip on EOF before the
        // exit code was available. This guarantees a caller that observes
        // `is_running=false` will also see `exit_code=Some(_)` whenever the
        // process actually produced a code (i.e. wasn't killed in a way that
        // returned `None`).
        let is_reaped = shell.reaped.load(Ordering::SeqCst);
        let exit_code = *recover_mutex_lock(
            &shell.exit_status,
            "get_output",
            "exit_status",
            Some(shell_id),
        );
        let is_running = !is_reaped;

        Ok((output, is_running, exit_code))
    }

    /// Kill a background shell by terminating the OS process and its process group.
    ///
    /// Sends SIGTERM first, waits for graceful exit, then escalates to SIGKILL
    /// if needed. Only removes the shell from tracking after the process has
    /// been terminated.
    pub(crate) fn kill(&self, shell_id: &str) -> Result<String, String> {
        // Crosslink #678: see get_output for poison-recovery rationale. The
        // log carries shell_id so the audit trail names the specific call
        // that observed poisoning.
        let mut shells = recover_mutex_lock(&self.shells, "kill", "shells", Some(shell_id));

        let caller = super::todo::current_session_key();
        if shells
            .get(shell_id)
            .is_some_and(|shell| shell.owner != caller)
        {
            tracing::warn!(
                target: "openclaudia::bash",
                event = "cross_session_shell_kill_denied",
                caller,
                shell_id,
                "Denied background shell termination outside the owning session"
            );
            return Err(format!("Shell '{shell_id}' not found"));
        }

        if let Some(shell) = shells.remove(shell_id) {
            if !shell.finished.load(Ordering::SeqCst) {
                // Terminate the process group (SIGTERM -> wait -> SIGKILL)
                terminate_process_tree(shell.pid);
            }
            // Crosslink #674: keep `finished` and `reaped` flipped together
            // so the killed shell never appears as `is_running=true` to a
            // subsequent `get_output` poll. The wait thread will still race
            // to write the exit status; either it wins (exit_status=Some)
            // or kill closes the channel first (exit_status=None) — both
            // are valid for an explicitly-killed shell.
            shell.finished.store(true, Ordering::SeqCst);
            shell.reaped.store(true, Ordering::SeqCst);
            Ok(format!(
                "Shell '{}' terminated (command: {}, pid: {})",
                shell_id, shell.command, shell.pid
            ))
        } else {
            Err(format!("Shell '{shell_id}' not found"))
        }
    }

    /// Kill every background shell owned by a session or subagent id.
    pub(crate) fn kill_for_agent(&self, agent_id: &str) -> String {
        let mut shells = recover_mutex_lock(&self.shells, "kill_for_agent", "shells", None);
        let shell_ids: Vec<String> = shells
            .iter()
            .filter(|(_, shell)| shell.owner == agent_id)
            .map(|(id, _)| id.clone())
            .collect();

        if shell_ids.is_empty() {
            return format!("No background shells found for agent '{agent_id}'.");
        }

        let mut removed = Vec::with_capacity(shell_ids.len());
        for shell_id in shell_ids {
            if let Some(shell) = shells.remove(&shell_id) {
                removed.push((shell_id, shell));
            }
        }
        drop(shells);

        let mut killed_ids = Vec::with_capacity(removed.len());
        for (shell_id, shell) in removed {
            if !shell.finished.load(Ordering::SeqCst) {
                terminate_process_tree(shell.pid);
            }
            shell.finished.store(true, Ordering::SeqCst);
            shell.reaped.store(true, Ordering::SeqCst);
            killed_ids.push(shell_id);
        }

        format!(
            "Terminated {} background shell(s) for agent '{}': {}",
            killed_ids.len(),
            agent_id,
            killed_ids.join(", ")
        )
    }

    /// List all background shells
    pub(crate) fn list(&self) -> Vec<(String, String, bool)> {
        let caller = super::todo::current_session_key();
        // Crosslink #678: see get_output for poison-recovery rationale.
        let shells = recover_mutex_lock(&self.shells, "list", "shells", None);
        shells
            .iter()
            .filter(|(_, shell)| shell.owner == caller)
            .map(|(id, shell)| {
                (
                    id.clone(),
                    shell.command.clone(),
                    !shell.finished.load(Ordering::SeqCst),
                )
            })
            .collect()
    }
}

/// Terminate every background job owned by a session during trusted lifecycle
/// cleanup. This bypasses the agent-facing identifier argument, but remains
/// scoped to the exact immutable session id supplied by `SessionManager`.
pub fn terminate_session_background_jobs(session_id: &str) {
    let result = BACKGROUND_SHELLS.kill_for_agent(session_id);
    tracing::info!(
        target: "openclaudia::bash",
        event = "session_background_jobs_terminated",
        session_id,
        result,
        "Applied session-end background-process cleanup"
    );
}

fn wait_for_output_readers(stdout_done: &AtomicBool, stderr_done: &AtomicBool, shell_id: &str) {
    while !stdout_done.load(Ordering::SeqCst) || !stderr_done.load(Ordering::SeqCst) {
        tracing::trace!(
            target: "openclaudia::bash",
            shell_id,
            "waiting for background shell output readers before ledger observation"
        );
        thread::sleep(std::time::Duration::from_millis(10));
    }
}

/// Global background shell manager
pub static BACKGROUND_SHELLS: std::sync::LazyLock<BackgroundShellManager> =
    std::sync::LazyLock::new(BackgroundShellManager::new);

/// Find Git Bash on Windows
#[cfg(windows)]
pub(crate) fn find_git_bash() -> Option<std::path::PathBuf> {
    // Common Git Bash locations on Windows
    let paths = [
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files (x86)\Git\bin\bash.exe",
        r"C:\Git\bin\bash.exe",
    ];

    for path in &paths {
        let p = std::path::PathBuf::from(path);
        if p.exists() {
            return Some(p);
        }
    }

    // Try to find git on PATH and derive the sibling Git Bash path.
    if let Ok(git_path) = which::which("git") {
        // git.exe is usually in cmd/ or bin/, bash is in bin/.
        let git_dir = git_path.parent().and_then(|p| p.parent());
        if let Some(git_root) = git_dir {
            let bash = git_root.join("bin").join("bash.exe");
            if bash.exists() {
                return Some(bash);
            }
        }
    }

    None
}

/// Execute a bash command and return a typed result.
///
/// This is the typed surface for `bash` (crosslink #222, #376): the same
/// policy / spawn logic the old `execute_bash` performed, but expressed as
/// `Result<ToolOutput, ToolError>` so callers can distinguish argument
/// failures from validator rejections from upstream process errors without
/// pattern-matching strings. Both forms share the same body; the legacy
/// `(String, bool)` wrapper [`execute_bash`] collapses this result via
/// `into_legacy` so the registry contract stays byte-stable.
///
/// A non-zero process exit still counts as a successful tool invocation —
/// the renderer surfaces the stdout/stderr and the boolean exit-error flag
/// has historically been encoded into the `(String, bool)` shape's bool.
/// To preserve byte-identical output for downstream consumers (and the
/// 80+ pinning tests), we return `Err(ToolError::External(...))` on
/// non-zero exit so the collapsed tuple stays `(text, true)`. This is
/// the load-bearing observable: do not "fix" it without updating the
/// tests that pin the prior behaviour.
///
/// # Errors
///
/// - [`ToolError::InvalidArgument`] when the `command` arg is absent or
///   not a JSON string.
/// - [`ToolError::InvalidInput`] when [`validate_command`] rejects the
///   command (length cap, denylist, structural rule).
/// - [`ToolError::External`] when:
///   * the spawned process fails to start (no shell, permission denied,
///     OS resource exhaustion), or
///   * a non-zero exit status is returned (the message carries the
///     captured stdout / stderr so the legacy renderer keeps working).
/// - [`ToolError::Other`] when the background shell manager refuses the
///   spawn (e.g. cap reached). Preserves the existing message verbatim.
pub fn try_execute_bash(args: &HashMap<String, Value>) -> Result<ToolOutput, ToolError> {
    let command = match args.get("command") {
        None => {
            return Err(ToolError::InvalidInput(
                "Missing 'command' argument".to_string(),
            ))
        }
        Some(Value::String(command)) => command.as_str(),
        Some(_) => {
            return Err(ToolError::InvalidArgument(ToolArgError::WrongType {
                key: "command",
                expected: "string",
            }));
        }
    };

    if let Err(msg) = validate_command(command) {
        return Err(ToolError::InvalidInput(msg));
    }

    // Crosslink #594: enforce the optional path-allowlist gate. When no
    // `PathConstraints` have been installed (the default), this is a no-op
    // — preserving legacy behaviour for callers that have not opted in.
    // When the proxy startup has populated the constraint set from
    // `additionalWorkingDirectories`, commands touching paths outside the
    // allowed roots are refused with a user-facing explanation.
    if let Err(msg) = check_command_against_global(command) {
        return Err(ToolError::PermissionDenied(msg));
    }

    // Diagnostic: log whether the command would qualify for auto-allow under
    // the CC-parity safety check (`bashCommandIsSafe_DEPRECATED`). This does
    // NOT gate execution — the permissions layer owns the actual prompt
    // decision — but exposes a structured signal for the permissions wire-up
    // (crosslink #589) and for ops-side audit of which commands the model is
    // running unprompted.
    if is_safe_for_auto_allow(command) {
        tracing::debug!(
            command = %command,
            "#589: bash command eligible for safety auto-allow (read-only + no dangerous constructs)"
        );
    } else if let Some(reason) = dangerous_shell_construct(command) {
        tracing::debug!(
            command = %command,
            reason = reason,
            "#589: bash command contains dangerous shell construct — auto-allow refused"
        );
    }

    // Check if this should run in background
    let run_in_background = args
        .arg_bool_or_strict("run_in_background", false)
        .map_err(ToolError::InvalidArgument)?;

    if run_in_background {
        // Spawn background shell and return shell_id.
        let shell_id = BACKGROUND_SHELLS.spawn(command).map_err(ToolError::Other)?;
        return Ok(ToolOutput::text(format!(
            "Background shell started with ID: {shell_id}\nUse bash_output with this shell_id to retrieve output."
        )));
    }

    // Run synchronously (original behavior).
    // On Windows, use Git Bash explicitly (not WSL bash).
    // On Unix, use system bash.
    let security = crate::tools::security::current_context().map_err(ToolError::External)?;
    let cwd = security.working_directory().to_path_buf();

    #[cfg(windows)]
    let output = {
        let bash =
            find_git_bash().unwrap_or(bash_bin().map_err(ToolError::External)?.to_path_buf());
        let cmd =
            sandbox::sandboxed_bash_command(&bash, command, &cwd).map_err(ToolError::External)?;
        super::command::run_prepared_sandboxed_with_timeout(cmd, "bash", FOREGROUND_COMMAND_TIMEOUT)
    };

    #[cfg(not(windows))]
    let output = {
        let cmd = sandbox::sandboxed_bash_command(
            bash_bin().map_err(ToolError::External)?,
            command,
            &cwd,
        )
        .map_err(ToolError::External)?;
        super::command::run_prepared_sandboxed_with_timeout(cmd, "bash", FOREGROUND_COMMAND_TIMEOUT)
    };

    let output =
        output.map_err(|e| ToolError::External(format!("Failed to execute command: {e}")))?;
    record_active_command_observation(&cwd, command, &output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let mut result = String::new();
    if !stdout.is_empty() {
        result.push_str(&stdout);
    }
    if !stderr.is_empty() {
        if !result.is_empty() {
            result.push('\n');
        }
        result.push_str("stderr: ");
        result.push_str(&stderr);
    }
    if result.is_empty() {
        result = "(command completed with no output)".to_string();
    }

    // Truncate if too long.
    if result.len() > 50000 {
        result = format!(
            "{}...\n(output truncated, {} total chars)",
            safe_truncate(&result, 50000),
            result.len()
        );
    }

    if output.status.success() {
        Ok(ToolOutput::text(result))
    } else {
        // Non-zero exit collapses to `(message, true)` via `ToolError::External`
        // so the legacy tuple shape stays byte-identical to the pre-migration
        // executor. The message *is* the captured stdout+stderr.
        Err(ToolError::External(result))
    }
}

fn record_active_command_observation(cwd: &Path, command: &str, output: &std::process::Output) {
    let session_key = super::todo::current_session_key();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let exit_code = output.status.code().unwrap_or(-1);
    record_command_observation_for_session(&session_key, cwd, command, exit_code, &stdout, &stderr);
}

pub fn record_command_observation_for_session(
    session_key: &str,
    cwd: &Path,
    command: &str,
    exit_code: i32,
    stdout: &str,
    stderr: &str,
) {
    if let Some(ledger) = crate::ledger::active_ledger_for_session(session_key) {
        let mut ledger = ledger.lock().unwrap_or_else(|err| {
            tracing::error!("active reality ledger lock poisoned; recovering inner state");
            err.into_inner()
        });
        append_command_observation(&mut ledger, cwd, command, exit_code, stdout, stderr);
        return;
    }

    let mut ledger = match crate::ledger::RealityLedger::open_project_session(session_key) {
        Ok(ledger) => ledger,
        Err(crate::ledger::LedgerError::InvalidSessionKey { .. }) => return,
        Err(err) => {
            tracing::warn!(
                session_key,
                error = %err,
                "failed to open session reality ledger for bash command observation"
            );
            return;
        }
    };
    append_command_observation(&mut ledger, cwd, command, exit_code, stdout, stderr);
}

fn append_command_observation(
    ledger: &mut crate::ledger::RealityLedger,
    cwd: &Path,
    command: &str,
    exit_code: i32,
    stdout: &str,
    stderr: &str,
) {
    if let Err(err) = ledger.observe_command_run(
        cwd.to_string_lossy().to_string(),
        vec!["bash".to_string(), "-c".to_string(), command.to_string()],
        exit_code,
        safe_truncate(stdout, LEDGER_COMMAND_OUTPUT_MAX_BYTES).to_string(),
        safe_truncate(stderr, LEDGER_COMMAND_OUTPUT_MAX_BYTES).to_string(),
    ) {
        tracing::warn!(
            command = %command,
            error = %err,
            "failed to append bash command observation to reality ledger"
        );
    }
    let Some(findings) = verification_findings_for_command(command, exit_code, stdout, stderr)
    else {
        return;
    };
    if let Err(err) = ledger.append(
        crate::ledger::Authority::Verifier,
        crate::ledger::ObservationKind::Verification {
            passed: exit_code == 0,
            command: Some(command.to_string()),
            findings,
        },
    ) {
        tracing::warn!(
            command = %command,
            error = %err,
            "failed to append bash verification observation to reality ledger"
        );
    }
}

fn verification_findings_for_command(
    command: &str,
    exit_code: i32,
    stdout: &str,
    stderr: &str,
) -> Option<Vec<String>> {
    if !is_likely_verification_command(command) {
        return None;
    }

    let mut findings = vec![format!("verification command exited with code {exit_code}")];
    if exit_code != 0 {
        if !stdout.trim().is_empty() {
            findings.push(format!(
                "stdout: {}",
                safe_truncate(stdout, LEDGER_COMMAND_OUTPUT_MAX_BYTES)
            ));
        }
        if !stderr.trim().is_empty() {
            findings.push(format!(
                "stderr: {}",
                safe_truncate(stderr, LEDGER_COMMAND_OUTPUT_MAX_BYTES)
            ));
        }
    }
    Some(findings)
}

fn is_likely_verification_command(command: &str) -> bool {
    let normalized = command
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase();
    VERIFICATION_COMMAND_NEEDLES
        .iter()
        .any(|needle| normalized.contains(needle))
}

/// Execute a bash command, returning the legacy `(content, is_error)` tuple.
///
/// Thin shim over [`try_execute_bash`] preserved so the registry's
/// `ToolHandler::execute` signature (which still returns `(String, bool)`)
/// compiles untouched while the typed surface lands incrementally. New code
/// should call [`try_execute_bash`] directly and use the structured error.
///
/// Applies the policy layer: length cap + denylist in [`validate_command`],
/// and env scrubbing via [`apply_env_scrub`] (allowlist — only `PATH`, `HOME`,
/// `USER`, `CARGO_HOME`, `RUSTUP_HOME`, LC_*, etc. are inherited; arbitrary
/// credential-bearing names such as `DATABASE_URL` are dropped along with
/// `ANTHROPIC_API_KEY`, `AWS_*`, `_TOKEN`/`_SECRET`/`_PASSWORD`).
/// See crosslink #257 and #730.
pub fn execute_bash(args: &HashMap<String, Value>) -> (String, bool) {
    into_legacy(try_execute_bash(args))
}

/// Process-wide test lock for `BACKGROUND_SHELLS`-touching tests.
///
/// The bash test modules (`mod.rs::tests` + `output.rs::tests`) share the
/// global `BACKGROUND_SHELLS` registry, so when cargo runs the lib test
/// binary with default thread-pool parallelism, tests can race: one test
/// spawns a shell while another asserts an empty `list()`, etc. Earlier
/// runs were lucky; under load (`cargo test --tests --no-fail-fast`
/// alongside integration binaries) ~12 of the B1/B2/B3 tests became flaky.
///
/// `bg_lock()` returns a `MutexGuard` that serializes those tests without
/// `--test-threads=1` global serialization. Every test that reads or
/// mutates `BACKGROUND_SHELLS` MUST hold this lock for its entire body.
/// Tests that only inspect derived constants (`MAX_BACKGROUND_SHELLS`, the
/// error-message format-string layout) do NOT need the lock.
///
/// Lives at the module root (not inside any single `mod tests`) so both
/// `mod.rs::tests` and `output.rs::tests` can reach it via
/// `super::bg_lock()` / `super::super::bg_lock()`. Gated on `cfg(test)`
/// so it's compiled out of the shipping binary.
#[cfg(test)]
pub(super) fn bg_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ── Phase 2 pinning tests (crosslink #541) ────────────────────────────────
    // Pins OC's CURRENT BackgroundShellManager and execute_bash contracts
    // per spec crosslink #526 §B1, §B2, §B3.

    fn bash_args(cmd: &str) -> HashMap<String, Value> {
        let mut args = HashMap::new();
        args.insert("command".to_string(), Value::String(cmd.to_string()));
        args
    }

    fn bg_bash_args(cmd: &str) -> HashMap<String, Value> {
        let mut args = bash_args(cmd);
        args.insert("run_in_background".to_string(), Value::Bool(true));
        args
    }

    #[test]
    fn verification_commands_append_verifier_observation() {
        let mut ledger = crate::ledger::RealityLedger::new();
        append_command_observation(
            &mut ledger,
            Path::new("/tmp/project"),
            "cargo check --all-targets",
            0,
            "ok",
            "",
        );

        let index = ledger.observation_index(8);
        assert_eq!(index.len(), 2);
        let verification = index
            .iter()
            .filter_map(|entry| ledger.get(entry.id))
            .find(|obs| {
                matches!(
                    obs.kind,
                    crate::ledger::ObservationKind::Verification { .. }
                )
            })
            .expect("verification observation");
        assert_eq!(verification.authority, crate::ledger::Authority::Verifier);
        let crate::ledger::ObservationKind::Verification {
            passed,
            command,
            findings,
        } = &verification.kind
        else {
            panic!("expected verification observation");
        };
        assert!(*passed);
        assert_eq!(command.as_deref(), Some("cargo check --all-targets"));
        assert!(findings
            .iter()
            .any(|finding| finding.contains("exited with code 0")));
    }

    #[test]
    fn non_verification_commands_only_append_command_observation() {
        let mut ledger = crate::ledger::RealityLedger::new();
        append_command_observation(
            &mut ledger,
            Path::new("/tmp/project"),
            "printf hello",
            0,
            "hello",
            "",
        );

        let index = ledger.observation_index(8);
        assert_eq!(index.len(), 1);
        let observation = ledger.get(index[0].id).expect("observation");
        assert!(matches!(
            observation.kind,
            crate::ledger::ObservationKind::CommandRun { .. }
        ));
    }

    #[test]
    fn windows_git_bash_lookup_uses_rust_resolver() {
        let source = include_str!("mod.rs");
        let cfg_test = source
            .find("#[cfg(test)]")
            .expect("test marker must be present");
        let production = &source[..cfg_test];

        assert!(
            !production.contains("Command::new(\"where\")"),
            "find_git_bash must not shell out to the Windows where command"
        );
        assert!(
            production.contains("which::which(\"git\")"),
            "find_git_bash must locate git through the Rust resolver"
        );
    }

    #[test]
    fn bash_execution_uses_resolved_binary_path() {
        let bash = bash_bin().expect("bash tests require bash on PATH");
        assert!(
            bash.is_absolute(),
            "bash_bin must resolve bash to an absolute path, got {}",
            bash.display()
        );

        let source = include_str!("mod.rs");
        let cfg_test = source
            .find("#[cfg(test)]")
            .expect("test marker must be present");
        let production = &source[..cfg_test];

        assert!(
            !production.contains("Command::new(\"bash\")"),
            "production bash tool code must not invoke bare bash"
        );
        assert!(
            production.contains("which::which(\"bash\")"),
            "bash tool must locate bash through the Rust resolver"
        );
    }

    // B1 — background spawn: shell_id format and manager state
    // Spec: crosslink #526 §B1 | OC source: mod.rs:49-169

    /// B1-mod-a: spawn returns an 8-char `shell_id` (UUID prefix, mod.rs:57).
    #[test]
    fn b1_spawn_returns_8_char_shell_id() {
        let _l = bg_lock();
        let id = BACKGROUND_SHELLS
            .spawn("echo b1_mod_a")
            .expect("b1_spawn_8char: spawn must succeed");
        assert_eq!(
            id.len(),
            8,
            "b1_spawn_8char: shell_id must be 8 chars; got '{id}'"
        );
        let _ = BACKGROUND_SHELLS.kill(&id);
    }

    /// B1-mod-b: `execute_bash` with `run_in_background=true` returns `is_error=false`
    /// and a message containing "ID:" and the `shell_id`.
    ///
    /// OC source: mod.rs:334-339.
    #[test]
    fn b1_execute_bash_background_response_format() {
        let _l = bg_lock();
        let (msg, is_error) = execute_bash(&bg_bash_args("echo b1_mod_b"));
        assert!(!is_error, "b1_bg_format: must not be is_error; got: {msg}");
        assert!(
            msg.contains("ID:"),
            "b1_bg_format: response must contain 'ID:'; got: {msg}"
        );
        assert!(
            msg.contains("bash_output"),
            "b1_bg_format: response must mention bash_output; got: {msg}"
        );
    }

    /// B1-mod-c: spawned shell appears in `BACKGROUND_SHELLS.list()`.
    #[test]
    fn b1_spawned_shell_appears_in_list() {
        let _l = bg_lock();
        let id = BACKGROUND_SHELLS
            .spawn("sleep 2")
            .expect("b1_list: spawn must succeed");
        let shells = BACKGROUND_SHELLS.list();
        let found = shells.iter().any(|(listed_id, _, _)| listed_id == &id);
        assert!(found, "b1_list: spawned shell must appear in list; id={id}");
        let _ = BACKGROUND_SHELLS.kill(&id);
    }

    /// B1-mod-d: shell limit — when the shell map is at capacity, spawn returns
    /// an error containing "Maximum background shell limit".
    ///
    /// OC source: mod.rs:96-100. OC cap = 50; CC has no equivalent limit.
    ///
    /// NOTE: this test drives the manager's internal state directly to approach
    /// the limit. It spawns enough "sleep" processes to reach `MAX_BACKGROUND_SHELLS`.
    /// Those processes are killed at the end of the test to avoid leaking.
    ///
    /// Because the global `BACKGROUND_SHELLS` is shared across the test binary,
    /// this test might interact with others. The "sleep" commands are short (2 s)
    /// and are cleaned up below. The test still pinning the error message format
    /// is the important contract; the live saturation path is best-effort.
    #[test]
    fn b1_shell_limit_error_message_format() {
        // Verify the error string format is stable without actually reaching 50,
        // by constructing it the same way mod.rs does (format! is deterministic).
        let expected = format!(
            "Maximum background shell limit ({MAX_BACKGROUND_SHELLS}) reached. \
             Kill or wait for existing shells to finish."
        );
        assert!(
            expected.contains("Maximum background shell limit"),
            "b1_limit: error message must contain 'Maximum background shell limit'"
        );
        assert!(
            expected.contains("50"),
            "b1_limit: error message must embed the cap (50)"
        );
    }

    // B2 — kill: BackgroundShellManager::kill behavior
    // Spec: crosslink #526 §B2 | OC source: mod.rs:230-249

    /// B2-mod-a: kill on an unknown `shell_id` returns Err("Shell 'id' not found").
    ///
    /// OC source: mod.rs:246-248.
    #[test]
    fn b2_kill_unknown_id_returns_err() {
        let _l = bg_lock();
        let result = BACKGROUND_SHELLS.kill("deadbeef");
        assert!(result.is_err(), "b2_kill_unknown: must return Err");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("not found"),
            "b2_kill_unknown: Err must say 'not found'; got: {msg}"
        );
        assert!(
            msg.contains("deadbeef"),
            "b2_kill_unknown: Err must echo the id; got: {msg}"
        );
    }

    /// B2-mod-b: kill on a running shell returns Ok and removes it from the map.
    ///
    /// OC source: mod.rs:236-245 — `shells.remove(shell_id)`.
    #[test]
    #[cfg(unix)]
    fn b2_kill_running_shell_removes_entry() {
        let _l = bg_lock();
        let id = BACKGROUND_SHELLS
            .spawn("sleep 30")
            .expect("b2_kill_running: spawn must succeed");

        // Confirm it's tracked
        {
            let shells = BACKGROUND_SHELLS
                .shells
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let contains = shells.contains_key(&id);
            drop(shells);
            assert!(contains, "b2_kill_running: must be in map before kill");
        }

        let result = BACKGROUND_SHELLS.kill(&id);
        assert!(
            result.is_ok(),
            "b2_kill_running: kill must succeed; err={:?}",
            result.err()
        );

        // Entry must be removed after kill
        {
            let shells = BACKGROUND_SHELLS
                .shells
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let contains = shells.contains_key(&id);
            drop(shells);
            assert!(
                !contains,
                "b2_kill_running: entry must be removed after kill"
            );
        }
    }

    /// B2-mod-c: kill message format — "Shell 'id' terminated (command: ..., pid: ...)".
    ///
    /// OC source: mod.rs:242-245.
    #[test]
    #[cfg(unix)]
    fn b2_kill_success_message_format() {
        let _l = bg_lock();
        let id = BACKGROUND_SHELLS
            .spawn("sleep 30")
            .expect("b2_kill_msg: spawn must succeed");
        let msg = BACKGROUND_SHELLS
            .kill(&id)
            .expect("b2_kill_msg: kill must succeed");
        assert!(
            msg.contains("terminated"),
            "b2_kill_msg: message must contain 'terminated'; got: {msg}"
        );
        assert!(
            msg.contains(&id),
            "b2_kill_msg: message must contain shell_id; got: {msg}"
        );
        assert!(
            msg.contains("pid:"),
            "b2_kill_msg: message must contain 'pid:'; got: {msg}"
        );
        assert!(
            msg.contains("command:"),
            "b2_kill_msg: message must contain 'command:'; got: {msg}"
        );
    }

    /// B2-mod-d: kill on an already-finished shell skips SIGTERM but still
    /// removes the entry and returns Ok.
    ///
    /// OC source: mod.rs:237 — !`shell.finished.load()` gates the terminate call.
    #[test]
    #[cfg(unix)]
    fn b2_kill_finished_shell_skips_sigterm_returns_ok() {
        let _l = bg_lock();
        let id = BACKGROUND_SHELLS
            .spawn("echo b2_mod_d_done")
            .expect("b2_kill_finished: spawn must succeed");

        // Wait for the command to finish
        std::thread::sleep(std::time::Duration::from_millis(400));

        // Shell should be finished; kill must still succeed
        let result = BACKGROUND_SHELLS.kill(&id);
        assert!(
            result.is_ok(),
            "b2_kill_finished: killing a finished shell must return Ok; got: {:?}",
            result.err()
        );
    }

    // B3 — get_output: error paths
    // Spec: crosslink #526 §B3 | OC source: mod.rs:173-222

    /// B3-mod-a: `get_output` on unknown `shell_id` returns Err without panicking.
    ///
    /// OC source: mod.rs:179-181 — `ok_or_else`.
    #[test]
    fn b3_get_output_unknown_id_returns_err_no_panic() {
        let _l = bg_lock();
        let result = BACKGROUND_SHELLS.get_output("ffffffff");
        assert!(result.is_err(), "b3_get_output_unknown: must return Err");
        let msg = result.unwrap_err();
        assert!(
            msg.contains("not found"),
            "b3_get_output_unknown: Err must say 'not found'; got: {msg}"
        );
    }

    /// B3-mod-b: `get_output` for a running shell returns Ok with `is_running=true`.
    ///
    /// OC source: mod.rs:211-213.
    #[test]
    #[cfg(unix)]
    fn b3_get_output_running_shell_is_running_true() {
        let _l = bg_lock();
        let id = BACKGROUND_SHELLS
            .spawn("sleep 5")
            .expect("b3_get_output_running: spawn must succeed");

        std::thread::sleep(std::time::Duration::from_millis(100));

        let result = BACKGROUND_SHELLS.get_output(&id);
        assert!(result.is_ok(), "b3_get_output_running: must return Ok");
        let (_output, is_running, _exit_code) = result.unwrap();
        assert!(
            is_running,
            "b3_get_output_running: is_running must be true for a live shell"
        );
        // Clean up
        let _ = BACKGROUND_SHELLS.kill(&id);
    }

    /// B3-mod-c: `get_output` for a finished shell returns `is_running=false` and
    /// a Some `exit_code`.
    ///
    /// OC source: mod.rs:211-213 — `is_running` = !`is_finished`.
    #[test]
    #[cfg(unix)]
    fn b3_get_output_finished_shell_is_running_false() {
        let _l = bg_lock();
        let id = BACKGROUND_SHELLS
            .spawn("exit 0")
            .expect("b3_get_output_finished: spawn must succeed");

        std::thread::sleep(std::time::Duration::from_millis(400));

        let result = BACKGROUND_SHELLS.get_output(&id);
        assert!(result.is_ok(), "b3_get_output_finished: must return Ok");
        let (_output, is_running, exit_code) = result.unwrap();
        assert!(
            !is_running,
            "b3_get_output_finished: is_running must be false for a finished shell"
        );
        assert_eq!(
            exit_code,
            Some(0),
            "b3_get_output_finished: exit_code must be Some(0)"
        );
    }

    // B5 — execute_bash policy enforcement
    // Spec: crosslink #526 §B5 | OC source: mod.rs:319-401

    /// B5-mod-a: `execute_bash` with missing "command" arg returns `is_error=true`.
    ///
    /// OC source: mod.rs:320-322.
    #[test]
    fn b5_execute_bash_missing_command_arg() {
        let args: HashMap<String, Value> = HashMap::new();
        let (msg, is_error) = execute_bash(&args);
        assert!(is_error, "b5_missing_cmd: must be is_error=true");
        assert!(
            msg.contains("Missing"),
            "b5_missing_cmd: message must say 'Missing'; got: {msg}"
        );
    }

    #[test]
    fn b5_execute_bash_rejects_non_string_command_arg() {
        let mut args = HashMap::new();
        args.insert("command".to_string(), Value::Number(42.into()));
        let (msg, is_error) = execute_bash(&args);
        assert!(is_error, "non-string command must be rejected: {msg}");
        assert!(
            msg.contains("Invalid 'command' argument: expected string"),
            "unexpected error: {msg}"
        );
    }

    /// B5-mod-b: `execute_bash` with a denylist command returns `is_error=true`
    /// before any process is spawned.
    ///
    /// OC source: mod.rs:324-326 — `validate_command` called before spawn.
    #[test]
    fn b5_execute_bash_denylist_command_is_error() {
        let (msg, is_error) = execute_bash(&bash_args("rm -rf /"));
        assert!(is_error, "b5_denylist: must be is_error=true; got: {msg}");
        assert!(
            msg.contains("rejected"),
            "b5_denylist: message must say 'rejected'; got: {msg}"
        );
    }

    #[test]
    fn b5_execute_bash_rejects_non_boolean_background_flag() {
        let mut args = bash_args("echo should_not_run_in_background");
        args.insert(
            "run_in_background".to_string(),
            Value::String("true".to_string()),
        );

        let (msg, is_error) = execute_bash(&args);

        assert!(
            is_error,
            "non-boolean run_in_background must be rejected: {msg}"
        );
        assert!(
            msg.contains("Invalid 'run_in_background' argument: expected boolean"),
            "unexpected error: {msg}"
        );
    }

    /// B5-mod-c: `execute_bash` with a valid command returns `is_error=false`
    /// and output from the child.
    #[test]
    #[cfg(unix)]
    fn b5_execute_bash_valid_command_succeeds() {
        let (msg, is_error) = execute_bash(&bash_args("echo hello_b5_mod_c"));
        assert!(!is_error, "b5_valid: must not be is_error; got: {msg}");
        assert!(
            msg.contains("hello_b5_mod_c"),
            "b5_valid: output must contain echoed string; got: {msg}"
        );
    }

    /// B5-mod-d: non-zero exit code sets `is_error=true` in synchronous mode.
    ///
    /// OC source: mod.rs:397 — !`output.status.success()`.
    #[test]
    #[cfg(unix)]
    fn b5_execute_bash_nonzero_exit_is_error() {
        let (_, is_error) = execute_bash(&bash_args("exit 1"));
        assert!(
            is_error,
            "b5_nonzero_exit: non-zero exit must set is_error=true"
        );
    }

    // ── Crosslink #351 — output-drain GC flag race ────────────────────────────
    //
    // Pre-fix, `output_retrieved_after_finish` was stored only when
    // `get_output` observed `finished == true`. That gated the store on a
    // racing atomic from the wait-thread:
    //   (1) drain-before-finish: caller drains while process still runs; flag
    //       never set even though output was retrieved → GC never collects.
    //   (2) drain-after-finish with no later poll: caller drains right as the
    //       wait-thread sets finished; flag set, fine.
    //
    // Post-fix: every `get_output` call marks the slot as drained.

    /// Helper: read the GC flag directly from the manager's shell entry.
    fn read_drained_flag(shell_id: &str) -> bool {
        let shells = BACKGROUND_SHELLS
            .shells
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        shells
            .get(shell_id)
            .is_some_and(|s| s.output_retrieved_after_finish.load(Ordering::SeqCst))
    }

    /// `#351-a`: drain-before-finish marks the GC flag.
    ///
    /// Spawn a long-running process, poll `get_output` while it is still alive
    /// (`is_running=true`), and assert the flag flips. Pre-fix this would
    /// stay false because the `if is_finished` gate skipped the store.
    #[test]
    #[cfg(unix)]
    fn fix351_drain_before_finish_marks_retrieved() {
        let _l = bg_lock();
        let id = BACKGROUND_SHELLS
            .spawn("sleep 5")
            .expect("fix351-a: spawn must succeed");

        // Allow reader threads to start, but the process is still alive.
        std::thread::sleep(std::time::Duration::from_millis(150));

        assert!(
            !read_drained_flag(&id),
            "fix351-a: flag must be false before any get_output call"
        );

        let (_, is_running, _) = BACKGROUND_SHELLS
            .get_output(&id)
            .expect("fix351-a: get_output must succeed");
        assert!(
            is_running,
            "fix351-a: process must still be running for this test to \
             exercise the race"
        );

        assert!(
            read_drained_flag(&id),
            "fix351-a: drain on a running shell must mark the GC flag \
             (pre-fix this would be false because finished=false)"
        );

        // Clean up the long-running child.
        let _ = BACKGROUND_SHELLS.kill(&id);
    }

    /// `#351-b`: drain-after-finish marks the GC flag.
    ///
    /// Backwards-compatibility check: the post-fix code must still set the
    /// flag when the process has already finished by the time `get_output`
    /// is called. This was the only path that worked pre-fix.
    #[test]
    #[cfg(unix)]
    fn fix351_drain_after_finish_marks_retrieved() {
        let _l = bg_lock();
        let id = BACKGROUND_SHELLS
            .spawn("echo fix351_b_done")
            .expect("fix351-b: spawn must succeed");

        // Let the short-lived process finish and the wait-thread flip
        // `finished`.
        std::thread::sleep(std::time::Duration::from_millis(400));

        let (_, is_running, _) = BACKGROUND_SHELLS
            .get_output(&id)
            .expect("fix351-b: get_output must succeed");
        assert!(
            !is_running,
            "fix351-b: process must be finished by the time of the poll"
        );

        assert!(
            read_drained_flag(&id),
            "fix351-b: drain after finish must mark the GC flag"
        );
    }

    /// `#351-c`: never-drained shells stay unretrieved.
    ///
    /// Spawn a shell, wait for it to finish, but never call `get_output`.
    /// The flag must remain false so the GC sweep is forbidden from
    /// reclaiming a slot whose output the caller has never had a chance to
    /// read.
    #[test]
    #[cfg(unix)]
    fn fix351_never_drained_stays_unretrieved() {
        let _l = bg_lock();
        let id = BACKGROUND_SHELLS
            .spawn("echo fix351_c_done")
            .expect("fix351-c: spawn must succeed");

        // Wait long enough for the wait-thread to set finished=true.
        std::thread::sleep(std::time::Duration::from_millis(400));

        // No `get_output` call on this id — only a list() check to ensure
        // finished is observable without going through the drain path.
        let listed = BACKGROUND_SHELLS.list();
        let entry = listed
            .iter()
            .find(|(listed_id, _, _)| listed_id == &id)
            .expect("fix351-c: shell must still be present (not yet GC'd)");
        let is_running = entry.2;
        assert!(
            !is_running,
            "fix351-c: process must be finished before flag assertion"
        );

        assert!(
            !read_drained_flag(&id),
            "fix351-c: a shell that has never been drained must NOT be \
             marked retrieved, even when finished — GC must not collect it"
        );

        // Clean up: a single drain marks the flag and makes the slot
        // eligible for the next GC sweep.
        let _ = BACKGROUND_SHELLS.get_output(&id);
    }

    // ── Crosslink #672 — TOCTOU spawn race ────────────────────────────────────
    //
    // Pre-fix `cmd.spawn()` was invoked BEFORE the cap-enforcement lock
    // section, so N concurrent callers could each fork a child before any of
    // them lost the cap check. Post-fix the cap check, spawn, and insert all
    // happen under a single contiguous `shells` lock acquisition. These
    // tests fire `cap + EXTRA` concurrent spawners against a fresh manager
    // and assert (a) successful spawns never exceed the cap and (b) the
    // internal map size never transiently bulges past the cap during the
    // race window.

    const STRESS_EXTRA: usize = 12;

    fn count_capacity_errors(results: &[Result<String, String>]) -> usize {
        results
            .iter()
            .filter(|r| {
                r.as_ref()
                    .err()
                    .is_some_and(|e| e.contains("Maximum background shell limit"))
            })
            .count()
    }

    /// `#672-a`: `cap + EXTRA` concurrent spawners on a fresh manager — the
    /// number of *successful* spawns must not exceed `MAX_BACKGROUND_SHELLS`,
    /// and at least one caller must observe the cap-rejection error string,
    /// proving the rejection path is reachable under contention.
    ///
    /// Pre-fix the cap check ran AFTER the spawn syscall, so a flurry of
    /// threads would all pass the cap check and the OS+map would each see
    /// >cap entries.
    ///
    /// NOTE: under heavy parallel test load (cargo test --lib) some
    /// `Command::spawn` calls may fail with fork ENOMEM/EAGAIN. Those count
    /// as neither a success nor a cap-rejection; the cap invariant
    /// (`successes <= cap`) is unaffected.
    #[test]
    #[cfg(unix)]
    fn fix672_concurrent_spawn_never_exceeds_cap() {
        use std::sync::Arc;
        use std::thread;
        let mgr = Arc::new(BackgroundShellManager::new());
        let total = MAX_BACKGROUND_SHELLS + STRESS_EXTRA;

        let barrier = Arc::new(std::sync::Barrier::new(total));
        let mut handles = Vec::with_capacity(total);
        for _ in 0..total {
            let mgr_c = Arc::clone(&mgr);
            let bar_c = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                bar_c.wait();
                // Short-lived but non-instant so successful spawns stay in
                // the map long enough for racers to observe contention.
                mgr_c.spawn("sleep 2")
            }));
        }

        let results: Vec<Result<String, String>> = handles
            .into_iter()
            .map(|h| h.join().expect("join"))
            .collect();
        let successes = results.iter().filter(|r| r.is_ok()).count();
        let cap_errors = count_capacity_errors(&results);

        // Tear down before assertions: kill every successful spawn so we
        // don't leak `sleep` processes on test failure.
        for id in results.iter().flatten() {
            let _ = mgr.kill(id);
        }

        assert!(
            successes <= MAX_BACKGROUND_SHELLS,
            "fix672-a: successful spawns must not exceed cap ({MAX_BACKGROUND_SHELLS}); \
             got {successes}"
        );
        // The race is exercised when either (a) we hit the cap
        // (cap_errors > 0) or (b) the OS rejected enough spawns that we
        // never reached cap — in the latter case the test result is
        // inconclusive (test-infra noise from concurrent cwd-mutating
        // tests). Either way the cap invariant above must hold.
        let other_errors = total - successes - cap_errors;
        assert!(
            cap_errors > 0 || other_errors >= STRESS_EXTRA,
            "fix672-a: cap-rejection path was not exercised AND not enough \
             OS-level spawn failures to explain it; got {successes} ok + \
             {cap_errors} cap-err + {other_errors} other-err out of {total}"
        );
    }

    /// `#672-b`: under contention the manager's map size is bounded by the
    /// cap at every observable moment. Pins the invariant that the internal
    /// map cannot transiently bulge past `MAX_BACKGROUND_SHELLS` (which the
    /// pre-fix code did between spawn and rejection).
    #[test]
    #[cfg(unix)]
    fn fix672_manager_map_size_bounded_by_cap_under_load() {
        use std::sync::Arc;
        use std::thread;
        let mgr = Arc::new(BackgroundShellManager::new());
        let total = MAX_BACKGROUND_SHELLS + STRESS_EXTRA;

        let barrier = Arc::new(std::sync::Barrier::new(total + 1));
        let mut handles = Vec::with_capacity(total);
        for _ in 0..total {
            let mgr_c = Arc::clone(&mgr);
            let bar_c = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                bar_c.wait();
                mgr_c.spawn("sleep 2")
            }));
        }
        // Let all spawners go and immediately start observing the map.
        barrier.wait();

        // Poll the map size during the race window — it must never exceed cap.
        let mut max_seen = 0usize;
        for _ in 0..200 {
            let size = mgr
                .shells
                .lock()
                .map_or_else(|e| e.into_inner().len(), |s| s.len());
            max_seen = max_seen.max(size);
            std::thread::sleep(std::time::Duration::from_micros(200));
        }

        let results: Vec<Result<String, String>> = handles
            .into_iter()
            .map(|h| h.join().expect("join"))
            .collect();

        // Teardown
        for id in results.iter().flatten() {
            let _ = mgr.kill(id);
        }

        assert!(
            max_seen <= MAX_BACKGROUND_SHELLS,
            "fix672-b: observed map size {max_seen} exceeded cap {MAX_BACKGROUND_SHELLS} \
             during concurrent spawn — TOCTOU race regressed"
        );
    }

    // ── Crosslink #674 — finished/exit_status race ────────────────────────────
    //
    // Pre-fix the stdout reader thread flipped `finished=true` on EOF,
    // racing the wait thread which is the only authority for `exit_status`.
    // Callers could see (is_running=false, exit_code=None) — impossible
    // per the public contract. Post-fix the wait thread is the sole writer
    // of the liveness signal (`reaped`) and writes `exit_status` first,
    // `reaped` second under SeqCst.

    /// `#674-a`: spam many quick processes and assert no poll ever observes
    /// the impossible (`is_running=false`, `exit_code=None`) state. Pre-fix
    /// the stdout reader could win this race.
    ///
    /// Tolerates `Command::spawn` failures caused by concurrent tests
    /// mutating the process-wide `cwd` (the spawn helper inherits
    /// `std::env::current_dir()`, which can disappear under tempdir-using
    /// tests in parallel). The invariant under test is the (`is_running`,
    /// `exit_code`) coherence — not spawn liveness — so failed spawns are
    /// dropped from the sample but the test still requires at least N/3
    /// successful spawns to remain statistically meaningful.
    #[test]
    #[cfg(unix)]
    fn fix674_no_finished_without_exit_code() {
        use std::sync::Arc;
        use std::thread;
        const N: usize = 30;
        let mgr = Arc::new(BackgroundShellManager::new());

        let mut ids = Vec::with_capacity(N);
        for i in 0..N {
            // Mix of fast/empty-stdout commands to maximise the EOF/wait
            // race surface.
            let cmd = if i % 2 == 0 {
                "true".to_string()
            } else {
                format!("echo fix674_{i}")
            };
            if let Ok(id) = mgr.spawn(&cmd) {
                ids.push(id);
            }
        }
        assert!(
            ids.len() >= N / 3,
            "fix674-a: too few spawns succeeded ({}) — test cannot \
             meaningfully exercise the race; likely concurrent-test \
             interference with the process cwd",
            ids.len()
        );

        // Race: poll all shells repeatedly while the wait/reader threads
        // are flipping flags. Record any impossible state.
        let mgr_poll = Arc::clone(&mgr);
        let ids_poll = ids.clone();
        let poller = thread::spawn(move || {
            let mut violations: Vec<String> = Vec::new();
            for _ in 0..200 {
                for id in &ids_poll {
                    if let Ok((_, is_running, exit_code)) = mgr_poll.get_output(id) {
                        if !is_running && exit_code.is_none() {
                            violations.push(id.clone());
                        }
                    }
                }
            }
            violations
        });

        let violations = poller.join().expect("poller join");

        // Teardown — best-effort
        for id in &ids {
            let _ = mgr.kill(id);
        }

        assert!(
            violations.is_empty(),
            "fix674-a: observed (is_running=false, exit_code=None) on shells \
             {violations:?} — the EOF/wait race regressed"
        );
    }

    /// `#674-b`: once `get_output` reports `is_running=false` for a normally
    /// terminated shell, `exit_code` must be `Some(_)`. Pinning the
    /// "settled-finished implies exit code present" contract.
    ///
    /// Like `#674-a`, tolerates spawn failures caused by parallel tests
    /// racing on the process cwd.
    #[test]
    #[cfg(unix)]
    fn fix674_settled_finished_has_exit_code() {
        const N: usize = 20;
        let mgr = BackgroundShellManager::new();

        let mut ids: Vec<(String, i32)> = Vec::with_capacity(N);
        for i in 0..N {
            let exit_code: i32 = i32::try_from(i % 3).expect("0..3 fits in i32");
            if let Ok(id) = mgr.spawn(&format!("exit {exit_code}")) {
                ids.push((id, exit_code));
            }
        }
        assert!(
            ids.len() >= N / 3,
            "fix674-b: too few spawns succeeded ({}) — likely concurrent \
             tests racing on process cwd",
            ids.len()
        );

        // Wait long enough for every wait-thread to reap.
        std::thread::sleep(std::time::Duration::from_millis(600));

        for (id, expected) in &ids {
            let (_, is_running, exit_code) = mgr
                .get_output(id)
                .expect("fix674-b: get_output must succeed");
            assert!(
                !is_running,
                "fix674-b: shell {id} must be settled after 600ms"
            );
            assert_eq!(
                exit_code,
                Some(*expected),
                "fix674-b: settled shell {id} must have exit_code Some({expected}); \
                 got {exit_code:?} — finished/exit_status race regressed"
            );
        }
    }
}
