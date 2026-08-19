//! Shared subprocess-with-timeout helper.
//!
//! Several tool implementations spawn external programs that can hang
//! indefinitely on adversarial input — `git` against a slow remote,
//! `pdftotext` against a malformed PDF, `pdfinfo` against a file whose
//! `XRef` table loops. Previously each module re-implemented its own
//! polling loop (or skipped the timeout entirely). [`run_with_timeout`]
//! is the single chokepoint so a fix or tuning change applies
//! uniformly (crosslink #836).
//!
//! The polling-with-backoff loop is intentionally NOT a `tokio::spawn`
//! / `tokio::time::timeout` pair: many callers (the `read_pdf_file`
//! tool, the `git_in` helper in worktree.rs) execute synchronously
//! inside a blocking tool dispatch — pulling tokio in would require a
//! runtime handle the caller does not always have. The exponential
//! backoff matches the schedule worktree.rs already used so trivial
//! commands still see sub-millisecond exit-detection overhead.

use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write as _};
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

/// Exponential-backoff polling schedule (ms between `try_wait` calls).
/// Pins on the last entry once exhausted so long-running commands cost
/// at most one poll per 100 ms (crosslink #956, #836).
const WAIT_BACKOFF_MS: &[u64] = &[1, 2, 5, 10, 25, 50, 100];
const MAX_CAPTURE_BYTES_PER_STREAM: usize = 10 * 1024 * 1024;
const OUTPUT_TRUNCATED_MARKER: &[u8] = b"\n[output truncated at 10 MiB]\n";

static ACTIVE_SANDBOX_PROCESSES: LazyLock<Mutex<HashMap<String, HashSet<u32>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static CANCELLED_SANDBOX_SESSIONS: LazyLock<Mutex<HashSet<String>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

pub struct ActiveSandboxProcess {
    owner: String,
    pid: u32,
}

impl ActiveSandboxProcess {
    pub(crate) fn register(pid: u32) -> Self {
        let owner = crate::tools::todo::current_session_key();
        let mut active = ACTIVE_SANDBOX_PROCESSES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        active.entry(owner.clone()).or_default().insert(pid);
        tracing::debug!(
            target: "openclaudia::sandbox",
            event = "sandbox_process_started",
            session_id = owner,
            pid,
            "Registered cancellable sandbox process"
        );
        drop(active);
        let cancelled = CANCELLED_SANDBOX_SESSIONS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&owner);
        if cancelled {
            crate::tools::bash::terminate_process_tree(pid);
        }
        Self { owner, pid }
    }
}

impl Drop for ActiveSandboxProcess {
    fn drop(&mut self) {
        let mut active = ACTIVE_SANDBOX_PROCESSES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(processes) = active.get_mut(&self.owner) {
            processes.remove(&self.pid);
            if processes.is_empty() {
                active.remove(&self.owner);
            }
        }
    }
}

/// Terminate every synchronous sandbox process currently owned by a session.
pub fn cancel_session_sandbox_processes(session_id: &str) -> usize {
    CANCELLED_SANDBOX_SESSIONS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .insert(session_id.to_string());
    let pids: Vec<u32> = ACTIVE_SANDBOX_PROCESSES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(session_id)
        .map(|pids| pids.iter().copied().collect())
        .unwrap_or_default();
    for pid in &pids {
        crate::tools::bash::terminate_process_tree(*pid);
    }
    if !pids.is_empty() {
        tracing::info!(
            target: "openclaudia::sandbox",
            event = "sandbox_processes_cancelled",
            session_id,
            count = pids.len(),
            "Terminated session sandbox processes"
        );
    }
    pids.len()
}

/// Start a new cancellation generation for a session. ACP calls this exactly
/// once when accepting a fresh prompt, before any of its tool workers spawn.
pub fn clear_session_process_cancellation(session_id: &str) {
    CANCELLED_SANDBOX_SESSIONS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .remove(session_id);
}

/// ACP runs as a dedicated process. On transport EOF, terminate any remaining
/// synchronous sandbox work before shutting the server down.
pub fn cancel_all_sandbox_processes() {
    let owners: Vec<String> = ACTIVE_SANDBOX_PROCESSES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .keys()
        .cloned()
        .collect();
    for owner in owners {
        cancel_session_sandbox_processes(&owner);
    }
}

/// Run `program` with `args` under `timeout`. Captures stdout and
/// stderr (both `Stdio::piped`) and returns them in [`Output`] on a
/// clean exit. On deadline expiry, sends SIGKILL via [`Child::kill`]
/// and reaps the zombie before returning a structured timeout error
/// so callers can render the program name + argv tail to the user.
///
/// `cwd` is applied via [`Command::current_dir`] when `Some`. Pass
/// `None` to inherit the parent's working directory — the caller is
/// expected to have validated that path globally; this helper does
/// not.
///
/// # Errors
///
/// Returns [`CommandError::SpawnFailed`] if the program could not be
/// invoked at all (binary not on PATH, EACCES, fork failure), and
/// [`CommandError::TimedOut`] if the deadline elapsed before exit.
/// Wait errors (a rare kernel-side condition: signal handler races,
/// EINTR after retry exhaustion) surface as
/// [`CommandError::WaitFailed`].
#[cfg(test)]
pub fn run_with_timeout(
    program: &(impl AsRef<OsStr> + ?Sized),
    args: &[impl AsRef<OsStr>],
    cwd: Option<&Path>,
    timeout: Duration,
) -> Result<Output, CommandError> {
    run_with_timeout_with_env(program, args, cwd, timeout, &HashMap::new())
}

/// Run `program` under `timeout`, applying additional environment variables
/// to the child process.
///
/// See [`run_with_timeout`] for timeout and error semantics.
///
/// # Errors
///
/// Returns the same structured [`CommandError`] variants as
/// [`run_with_timeout`].
#[cfg(test)]
pub fn run_with_timeout_with_env(
    program: &(impl AsRef<OsStr> + ?Sized),
    args: &[impl AsRef<OsStr>],
    cwd: Option<&Path>,
    timeout: Duration,
    env: &HashMap<String, String>,
) -> Result<Output, CommandError> {
    run_test_host_with_timeout_inner(program, args, cwd, timeout, env, None)
}

/// Run `program` under `timeout`, writing `stdin_input` to the child before
/// waiting for completion.
///
/// The child's stdout/stderr are captured exactly like [`run_with_timeout`].
/// The stdin pipe is closed after the bytes are written so tools that read
/// until EOF can complete.
///
/// # Errors
///
/// Returns the same structured [`CommandError`] variants as
/// [`run_with_timeout`]. A stdin write failure is reported as
/// [`CommandError::WaitFailed`] after killing and reaping the child.
#[cfg(test)]
pub fn run_with_timeout_with_input(
    program: &(impl AsRef<OsStr> + ?Sized),
    args: &[impl AsRef<OsStr>],
    cwd: Option<&Path>,
    timeout: Duration,
    stdin_input: &[u8],
) -> Result<Output, CommandError> {
    run_test_host_with_timeout_inner(
        program,
        args,
        cwd,
        timeout,
        &HashMap::new(),
        Some(stdin_input),
    )
}

/// Sandboxed counterpart to [`run_with_timeout_with_input`].
///
/// # Errors
///
/// Returns the same structured [`CommandError`] variants as
/// [`run_sandboxed_with_timeout`].
pub fn run_sandboxed_with_timeout_with_input(
    program: &(impl AsRef<OsStr> + ?Sized),
    args: &[impl AsRef<OsStr>],
    project_root: &Path,
    timeout: Duration,
    stdin_input: &[u8],
) -> Result<Output, CommandError> {
    run_sandboxed_with_timeout_inner(
        crate::tools::SandboxProfile::DocumentParser,
        program,
        args,
        project_root,
        timeout,
        &HashMap::new(),
        Some(stdin_input),
    )
}

/// Run a process under a named sandbox profile with explicit environment
/// grants and no stdin payload.
pub fn run_sandboxed_with_timeout_with_env(
    profile: crate::tools::SandboxProfile,
    program: &(impl AsRef<OsStr> + ?Sized),
    args: &[impl AsRef<OsStr>],
    project_root: &Path,
    timeout: Duration,
    env: &HashMap<String, String>,
) -> Result<Output, CommandError> {
    run_sandboxed_with_timeout_inner(profile, program, args, project_root, timeout, env, None)
}

fn run_sandboxed_with_timeout_inner(
    profile: crate::tools::SandboxProfile,
    program: &(impl AsRef<OsStr> + ?Sized),
    args: &[impl AsRef<OsStr>],
    project_root: &Path,
    timeout: Duration,
    env: &HashMap<String, String>,
    stdin_input: Option<&[u8]>,
) -> Result<Output, CommandError> {
    let program_str = program.as_ref().to_string_lossy().into_owned();
    let sandbox_args: Vec<OsString> = args.iter().map(|arg| arg.as_ref().to_os_string()).collect();
    let mut cmd = crate::tools::sandboxed_process_command(
        profile,
        program.as_ref(),
        &sandbox_args,
        project_root,
    )
    .map_err(|source| CommandError::SpawnFailed {
        program: program_str.clone(),
        source,
    })?;
    cmd.envs(env);
    run_prepared_with_timeout(cmd, program_str, timeout, stdin_input, true)
}

#[cfg(test)]
fn run_test_host_with_timeout_inner(
    program: &(impl AsRef<OsStr> + ?Sized),
    args: &[impl AsRef<OsStr>],
    cwd: Option<&Path>,
    timeout: Duration,
    env: &HashMap<String, String>,
    stdin_input: Option<&[u8]>,
) -> Result<Output, CommandError> {
    let program_str = program.as_ref().to_string_lossy().into_owned();
    let mut command = Command::new(program);
    command.args(args.iter().map(AsRef::as_ref)).envs(env);
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    run_prepared_with_timeout(command, program_str, timeout, stdin_input, false)
}

/// Execute an already sandboxed command with bounded capture and a wall-clock
/// deadline.
pub fn run_prepared_sandboxed_with_timeout(
    command: Command,
    program_label: &str,
    timeout: Duration,
) -> Result<Output, CommandError> {
    run_prepared_with_timeout(command, program_label.to_string(), timeout, None, true)
}

fn run_prepared_with_timeout(
    mut cmd: Command,
    program_str: String,
    timeout: Duration,
    stdin_input: Option<&[u8]>,
    terminate_tree: bool,
) -> Result<Output, CommandError> {
    #[cfg(unix)]
    if terminate_tree {
        use std::os::unix::process::CommandExt as _;

        // `terminate_process_tree` signals `-pid` so the spawned wrapper must
        // lead its own process group.  Foreground callers historically omitted
        // this even though the teardown helper documented the requirement,
        // leaving cancellation dependent on racy `/proc` descendant scans.
        cmd.process_group(0);
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
    if stdin_input.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.spawn().map_err(|e| CommandError::SpawnFailed {
        program: program_str.clone(),
        source: e.to_string(),
    })?;
    let pid = child.id();
    let _active_process = terminate_tree.then(|| ActiveSandboxProcess::register(pid));
    let stdout_reader = child.stdout.take().map(spawn_bounded_reader);
    let stderr_reader = child.stderr.take().map(spawn_bounded_reader);

    if let Some(input) = stdin_input {
        let write_result = child
            .stdin
            .take()
            .ok_or_else(|| CommandError::WaitFailed {
                program: program_str.clone(),
                source: "stdin pipe unavailable".to_string(),
            })
            .and_then(|mut stdin| {
                stdin
                    .write_all(input)
                    .map_err(|e| CommandError::WaitFailed {
                        program: program_str.clone(),
                        source: format!("stdin write failed: {e}"),
                    })
            });
        if let Err(err) = write_result {
            terminate_child(&mut child, pid, terminate_tree);
            let _ = child.wait();
            let _ = join_bounded_reader(stdout_reader);
            let _ = join_bounded_reader(stderr_reader);
            return Err(err);
        }
    }

    let deadline = Instant::now() + timeout;
    let mut step = 0usize;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let stdout = join_bounded_reader(stdout_reader).map_err(|source| {
                    CommandError::WaitFailed {
                        program: program_str.clone(),
                        source,
                    }
                })?;
                let stderr = join_bounded_reader(stderr_reader).map_err(|source| {
                    CommandError::WaitFailed {
                        program: program_str.clone(),
                        source,
                    }
                })?;
                return Ok(Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    terminate_child(&mut child, pid, terminate_tree);
                    let _ = child.wait();
                    let _ = join_bounded_reader(stdout_reader);
                    let _ = join_bounded_reader(stderr_reader);
                    return Err(CommandError::TimedOut {
                        program: program_str,
                        timeout,
                    });
                }
                let idx = step.min(WAIT_BACKOFF_MS.len() - 1);
                std::thread::sleep(Duration::from_millis(WAIT_BACKOFF_MS[idx]));
                step = step.saturating_add(1);
            }
            Err(e) => {
                terminate_child(&mut child, pid, terminate_tree);
                let _ = child.wait();
                let _ = join_bounded_reader(stdout_reader);
                let _ = join_bounded_reader(stderr_reader);
                return Err(CommandError::WaitFailed {
                    program: program_str,
                    source: e.to_string(),
                });
            }
        }
    }
}

fn terminate_child(child: &mut std::process::Child, pid: u32, terminate_tree: bool) {
    if terminate_tree {
        crate::tools::bash::terminate_process_tree(pid);
    }
    let _ = child.kill();
}

fn spawn_bounded_reader<R: Read + Send + 'static>(
    mut reader: R,
) -> std::thread::JoinHandle<Result<Vec<u8>, String>> {
    std::thread::spawn(move || {
        let mut retained = Vec::new();
        let mut buffer = [0u8; 8192];
        let mut truncated = false;
        loop {
            let count = reader
                .read(&mut buffer)
                .map_err(|error| format!("captured-output read failed: {error}"))?;
            if count == 0 {
                break;
            }
            let remaining = MAX_CAPTURE_BYTES_PER_STREAM.saturating_sub(retained.len());
            let keep = count.min(remaining);
            retained.extend_from_slice(&buffer[..keep]);
            truncated |= keep < count;
        }
        if truncated {
            retained.extend_from_slice(OUTPUT_TRUNCATED_MARKER);
        }
        Ok(retained)
    })
}

fn join_bounded_reader(
    reader: Option<std::thread::JoinHandle<Result<Vec<u8>, String>>>,
) -> Result<Vec<u8>, String> {
    reader.map_or_else(
        || Ok(Vec::new()),
        |reader| {
            reader
                .join()
                .map_err(|_| "captured-output reader panicked".to_string())?
        },
    )
}

/// Errors returned by [`run_with_timeout`]. The variants are
/// structured (program name kept) so callers can render messages
/// without re-parsing the source error string. Implements
/// [`std::fmt::Display`] with a stable format so tool-output assertions
/// in tests stay readable.
#[derive(Debug)]
pub enum CommandError {
    /// `Command::spawn` failed — program not on PATH, EACCES,
    /// fork failure, etc.
    SpawnFailed { program: String, source: String },
    /// Deadline elapsed before the child exited; the child has been
    /// killed and reaped before this variant is returned.
    TimedOut { program: String, timeout: Duration },
    /// The `wait`/`wait_with_output` path itself returned an error. Rare;
    /// usually signal-handler races (`EINTR` storms) or pipe-buffer
    /// exhaustion after the child exited.
    WaitFailed { program: String, source: String },
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SpawnFailed { program, source } => {
                write!(f, "Failed to spawn {program}: {source}")
            }
            Self::TimedOut { program, timeout } => {
                write!(f, "{program} timed out after {}s", timeout.as_secs())
            }
            Self::WaitFailed { program, source } => {
                write!(f, "{program} wait failed: {source}")
            }
        }
    }
}

impl std::error::Error for CommandError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trivial `true` invocation completes well inside the timeout
    /// and reports an empty-stdout success Output. This pins the
    /// happy path so refactors don't accidentally introduce a sleep
    /// after exit.
    #[test]
    fn run_with_timeout_succeeds_for_fast_command() {
        let out = run_with_timeout("true", &Vec::<&str>::new(), None, Duration::from_secs(5))
            .expect("`true` must exit cleanly");
        assert!(out.status.success(), "exit status must be 0");
        assert!(
            out.stdout.is_empty(),
            "`true` writes no stdout, got {:?}",
            out.stdout
        );
    }

    /// A `sleep` that exceeds the timeout returns
    /// [`CommandError::TimedOut`] WITHOUT leaking the child. The exact
    /// wall-clock varies between schedulers; we assert only that the
    /// total elapsed is close to the timeout, not under it.
    #[test]
    fn run_with_timeout_kills_command_past_deadline() {
        let start = Instant::now();
        let res = run_with_timeout("sleep", &["5"], None, Duration::from_millis(100));
        let elapsed = start.elapsed();
        match res {
            Err(CommandError::TimedOut { program, .. }) => {
                assert_eq!(program, "sleep");
            }
            other => panic!("expected TimedOut, got {other:?}"),
        }
        // Hard upper bound: 2× the deadline tolerates CI jitter
        // without masking a "didn't kill the child" regression.
        assert!(
            elapsed < Duration::from_millis(500),
            "run_with_timeout must return promptly after timeout; took {elapsed:?}"
        );
    }

    /// Spawning a nonexistent program surfaces `SpawnFailed`, not a
    /// timeout — important because the caller's error rendering branch
    /// differs (install hint vs retry suggestion).
    #[test]
    fn run_with_timeout_reports_spawn_failure() {
        let res = run_with_timeout(
            "definitely-not-on-path-xyzzy-9f87",
            &Vec::<&str>::new(),
            None,
            Duration::from_secs(1),
        );
        match res {
            Err(CommandError::SpawnFailed { program, .. }) => {
                assert!(
                    program.contains("xyzzy"),
                    "program field must echo the requested binary, got: {program}"
                );
            }
            other => panic!("expected SpawnFailed, got {other:?}"),
        }
    }

    /// Tools such as `git check-ignore --stdin` need both stdin input and a
    /// deadline. The helper must close stdin after writing so the child can
    /// observe EOF and produce captured output.
    #[test]
    fn run_with_timeout_with_input_writes_stdin_and_captures_stdout() {
        let out = run_with_timeout_with_input(
            "cat",
            &Vec::<&str>::new(),
            None,
            Duration::from_secs(5),
            b"alpha\nbeta\n",
        )
        .expect("cat must echo stdin");
        assert!(out.status.success(), "cat exit status must be 0");
        assert_eq!(out.stdout, b"alpha\nbeta\n");
    }

    #[test]
    #[cfg(unix)]
    fn captured_output_is_bounded_while_pipe_is_fully_drained() {
        let out = run_with_timeout(
            "sh",
            &["-c", "yes x | head -c 12582912"],
            None,
            Duration::from_secs(10),
        )
        .expect("output producer must complete without a pipe deadlock");
        assert!(out.status.success());
        assert!(
            out.stdout.len() <= MAX_CAPTURE_BYTES_PER_STREAM + OUTPUT_TRUNCATED_MARKER.len(),
            "capture exceeded the configured bound: {} bytes",
            out.stdout.len()
        );
        assert!(
            out.stdout.ends_with(OUTPUT_TRUNCATED_MARKER),
            "truncated output must carry a bounded diagnostic"
        );
    }
}
