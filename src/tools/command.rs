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
//! The supervisor is async so stdin delivery, stdout/stderr draining, child
//! exit, cancellation, and the aggregate deadline advance concurrently.
//! Synchronous tool paths use a small runtime-aware bridge rather than
//! maintaining a second process lifecycle.

use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};

const MAX_CAPTURE_BYTES_PER_STREAM: usize = 10 * 1024 * 1024;
const MAX_STDIN_BYTES: usize = 64 * 1024 * 1024;
const OUTPUT_TRUNCATED_MARKER: &[u8] = b"\n[output truncated at 10 MiB]\n";
const PROCESS_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

/// A process command together with any host-side workspace transaction that
/// must be settled after the child reaches a terminal state.
pub struct PreparedProcessCommand {
    command: Command,
    workspace_projection: Option<crate::tools::file::workspace_projection::WorkspaceProjection>,
}

impl PreparedProcessCommand {
    #[must_use]
    pub(crate) const fn host(command: Command) -> Self {
        Self {
            command,
            workspace_projection: None,
        }
    }

    #[must_use]
    pub(crate) const fn sandboxed(
        command: Command,
        workspace_projection: Option<crate::tools::file::workspace_projection::WorkspaceProjection>,
    ) -> Self {
        Self {
            command,
            workspace_projection,
        }
    }

    pub(crate) const fn command_mut(&mut self) -> &mut Command {
        &mut self.command
    }

    #[cfg(test)]
    pub(crate) fn get_args(&self) -> std::process::CommandArgs<'_> {
        self.command.get_args()
    }

    #[cfg(test)]
    pub(crate) fn get_envs(&self) -> std::process::CommandEnvs<'_> {
        self.command.get_envs()
    }

    #[cfg(test)]
    pub(crate) fn output(&mut self) -> std::io::Result<Output> {
        if self.workspace_projection.is_some() {
            return Err(std::io::Error::other(
                "writable projected commands must use the shared supervisor",
            ));
        }
        self.command.output()
    }

    #[cfg(test)]
    pub(crate) fn status(&mut self) -> std::io::Result<ExitStatus> {
        if self.workspace_projection.is_some() {
            return Err(std::io::Error::other(
                "writable projected commands must use the shared supervisor",
            ));
        }
        self.command.status()
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        Command,
        Option<crate::tools::file::workspace_projection::WorkspaceProjection>,
    ) {
        (self.command, self.workspace_projection)
    }
}

struct ActiveRunProcesses {
    session_id: String,
    cancellation: crate::runtime::CancellationHandle,
    pids: HashSet<u32>,
}

static ACTIVE_SANDBOX_PROCESSES: LazyLock<Mutex<HashMap<String, ActiveRunProcesses>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
pub struct ActiveSandboxProcess {
    owner: String,
    pid: u32,
}

impl ActiveSandboxProcess {
    pub(crate) fn register(run: &crate::tools::security::ToolRunContext, pid: u32) -> Self {
        let owner = run.run_id().to_string();
        let mut active = ACTIVE_SANDBOX_PROCESSES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        active
            .entry(owner.clone())
            .or_insert_with(|| ActiveRunProcesses {
                session_id: run.session_id().to_string(),
                cancellation: run.runtime().cancellation(),
                pids: HashSet::new(),
            })
            .pids
            .insert(pid);
        tracing::debug!(
            target: "openclaudia::sandbox",
            event = "sandbox_process_started",
            run_id = owner,
            session_id = run.session_id(),
            pid,
            "Registered cancellable sandbox process"
        );
        drop(active);
        if run.runtime().cancellation().is_cancelled() {
            crate::tools::bash::terminate_sandbox_process_tree(pid);
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
            processes.pids.remove(&self.pid);
            if processes.pids.is_empty() {
                active.remove(&self.owner);
            }
        }
    }
}

fn cancel_sandbox_process_owner(
    owner_run: &str,
    reason: Option<crate::runtime::CancellationReason>,
) -> usize {
    let (pids, cancellation) = ACTIVE_SANDBOX_PROCESSES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(owner_run)
        .map_or_else(
            || (Vec::new(), None),
            |processes| {
                (
                    processes.pids.iter().copied().collect(),
                    Some(processes.cancellation.clone()),
                )
            },
        );
    if let (Some(cancellation), Some(reason)) = (cancellation, reason) {
        let _receipt = cancellation.cancel(reason);
    }
    for pid in &pids {
        crate::tools::bash::terminate_sandbox_process_tree(*pid);
    }
    if !pids.is_empty() {
        tracing::info!(
            target: "openclaudia::sandbox",
            event = "sandbox_processes_cancelled",
            owner_run,
            count = pids.len(),
            "Terminated run sandbox processes"
        );
    }
    pids.len()
}

/// Terminate synchronous sandbox processes owned by this exact run generation.
pub fn cancel_run_sandbox_processes(run: &crate::tools::security::ToolRunContext) -> usize {
    let _receipt = run
        .runtime()
        .cancellation()
        .cancel(crate::runtime::CancellationReason::User);
    cancel_sandbox_process_owner(&run.run_id().to_string(), None)
}

/// Trusted session teardown across all still-active run generations.
pub fn cancel_session_sandbox_processes(session_id: &str) -> usize {
    let owners: Vec<String> = ACTIVE_SANDBOX_PROCESSES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .filter(|(_, processes)| processes.session_id == session_id)
        .map(|(owner, _)| owner.clone())
        .collect();
    owners
        .iter()
        .map(|owner| {
            cancel_sandbox_process_owner(
                owner,
                Some(crate::runtime::CancellationReason::ParentTerminated),
            )
        })
        .sum()
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
        cancel_sandbox_process_owner(
            &owner,
            Some(crate::runtime::CancellationReason::FrontendDisconnected),
        );
    }
}

/// Run `program` with `args` under `timeout`. Captures stdout and
/// stderr (both `Stdio::piped`) and returns them in [`Output`] on a
/// clean exit. On deadline expiry, terminates the owned process tree and reaps
/// the root before returning a structured timeout error so callers can render
/// the program name + argv tail to the user.
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
    run: &crate::tools::security::ToolRunContext,
    program: &(impl AsRef<OsStr> + ?Sized),
    args: &[impl AsRef<OsStr>],
    project_root: &Path,
    timeout: Duration,
    stdin_input: &[u8],
) -> Result<Output, CommandError> {
    run_sandboxed_with_timeout_inner(
        run,
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
    run: &crate::tools::security::ToolRunContext,
    profile: crate::tools::SandboxProfile,
    program: &(impl AsRef<OsStr> + ?Sized),
    args: &[impl AsRef<OsStr>],
    project_root: &Path,
    timeout: Duration,
    env: &HashMap<String, String>,
) -> Result<Output, CommandError> {
    run_sandboxed_with_timeout_inner(
        run,
        profile,
        program,
        args,
        project_root,
        timeout,
        env,
        None,
    )
}

#[allow(clippy::too_many_arguments)] // Internal adapter keeps public process entry points explicit.
fn run_sandboxed_with_timeout_inner(
    run: &crate::tools::security::ToolRunContext,
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
    let explicit_environment = env
        .iter()
        .map(|(name, value)| (OsString::from(name), OsString::from(value)))
        .collect::<Vec<_>>();
    let cmd = crate::tools::sandboxed_process_command_with_env(
        run,
        profile,
        program.as_ref(),
        &sandbox_args,
        project_root,
        &explicit_environment,
    )
    .map_err(|source| CommandError::SpawnFailed {
        program: program_str.clone(),
        source,
    })?;
    run_prepared_with_timeout(
        ProcessExecution::RunOwned(run),
        cmd,
        program_str,
        timeout,
        stdin_input,
    )
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
    run_prepared_with_timeout(
        ProcessExecution::TestHost,
        PreparedProcessCommand::host(command),
        program_str,
        timeout,
        stdin_input,
    )
}

/// Execute an already sandboxed command with bounded capture and a wall-clock
/// deadline.
pub fn run_prepared_sandboxed_with_timeout(
    run: &crate::tools::security::ToolRunContext,
    command: PreparedProcessCommand,
    program_label: &str,
    timeout: Duration,
) -> Result<Output, CommandError> {
    run_prepared_run_owned_sync(run, command, program_label, ProcessLimits::new(timeout))
        .map(SupervisedProcessOutput::into_std_output)
}

/// Execute a prepared run-owned process on the shared synchronous supervisor
/// while preserving typed bounded-stream metadata for capability callers.
pub fn run_prepared_run_owned_sync(
    run: &crate::tools::security::ToolRunContext,
    command: PreparedProcessCommand,
    program_label: &str,
    limits: ProcessLimits,
) -> Result<SupervisedProcessOutput, CommandError> {
    drive_supervisor_sync(
        ProcessExecution::RunOwned(run),
        command,
        program_label.to_string(),
        limits,
        None,
    )
}

#[derive(Clone, Copy)]
enum ProcessExecution<'a> {
    RunOwned(&'a crate::tools::security::ToolRunContext),
    #[cfg(test)]
    TestHost,
}

/// Aggregate limits for one supervised child invocation.
#[derive(Clone, Copy)]
pub struct ProcessLimits {
    timeout: Duration,
    stdout_bytes: usize,
    stderr_bytes: usize,
    stdin_bytes: usize,
    stdout_truncated_marker: &'static [u8],
    stderr_truncated_marker: &'static [u8],
}

impl ProcessLimits {
    #[must_use]
    pub const fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            stdout_bytes: MAX_CAPTURE_BYTES_PER_STREAM,
            stderr_bytes: MAX_CAPTURE_BYTES_PER_STREAM,
            stdin_bytes: MAX_STDIN_BYTES,
            stdout_truncated_marker: OUTPUT_TRUNCATED_MARKER,
            stderr_truncated_marker: OUTPUT_TRUNCATED_MARKER,
        }
    }

    #[must_use]
    pub const fn with_output_limit(
        mut self,
        bytes_per_stream: usize,
        truncated_marker: &'static [u8],
    ) -> Self {
        self.stdout_bytes = bytes_per_stream;
        self.stderr_bytes = bytes_per_stream;
        self.stdout_truncated_marker = truncated_marker;
        self.stderr_truncated_marker = truncated_marker;
        self
    }
}

/// How much of the supplied stdin payload reached the child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StdinDelivery {
    NotRequested,
    Pending {
        written: usize,
        total: usize,
    },
    Complete {
        bytes: usize,
    },
    Failed {
        written: usize,
        total: usize,
        error: String,
    },
}

/// Bounded bytes retained from one child output stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedStream {
    pub bytes: Vec<u8>,
    pub truncated: bool,
}

impl CapturedStream {
    fn rendered(mut self, marker: &[u8]) -> Vec<u8> {
        if self.truncated {
            self.bytes.extend_from_slice(marker);
        }
        self.bytes
    }
}

/// The observable state of a child at a terminal supervisor outcome.
#[derive(Debug, Clone)]
pub struct ProcessSnapshot {
    pub status: Option<ExitStatus>,
    pub stdout: CapturedStream,
    pub stderr: CapturedStream,
    pub stdin: StdinDelivery,
}

/// Successful typed result from the shared process supervisor.
#[derive(Debug)]
pub struct SupervisedProcessOutput {
    pub status: ExitStatus,
    pub stdout: CapturedStream,
    pub stderr: CapturedStream,
    pub stdin: StdinDelivery,
    stdout_truncated_marker: &'static [u8],
    stderr_truncated_marker: &'static [u8],
}

impl SupervisedProcessOutput {
    pub fn into_std_output(self) -> Output {
        debug_assert!(matches!(
            self.stdin,
            StdinDelivery::NotRequested | StdinDelivery::Complete { .. }
        ));
        Output {
            status: self.status,
            stdout: self.stdout.rendered(self.stdout_truncated_marker),
            stderr: self.stderr.rendered(self.stderr_truncated_marker),
        }
    }
}

#[derive(Default)]
struct CaptureState {
    bytes: Vec<u8>,
    truncated: bool,
}

fn capture_snapshot(state: &Arc<Mutex<CaptureState>>) -> CapturedStream {
    let state = state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    CapturedStream {
        bytes: state.bytes.clone(),
        truncated: state.truncated,
    }
}

fn stdin_snapshot(state: &Arc<Mutex<StdinDelivery>>) -> StdinDelivery {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

fn process_snapshot(
    status: Option<ExitStatus>,
    stdout: &Arc<Mutex<CaptureState>>,
    stderr: &Arc<Mutex<CaptureState>>,
    stdin: &Arc<Mutex<StdinDelivery>>,
) -> ProcessSnapshot {
    ProcessSnapshot {
        status,
        stdout: capture_snapshot(stdout),
        stderr: capture_snapshot(stderr),
        stdin: stdin_snapshot(stdin),
    }
}

fn run_prepared_with_timeout(
    execution: ProcessExecution<'_>,
    cmd: PreparedProcessCommand,
    program_str: String,
    timeout: Duration,
    stdin_input: Option<&[u8]>,
) -> Result<Output, CommandError> {
    let stdin = stdin_input.map(<[u8]>::to_vec);
    drive_supervisor_sync(
        execution,
        cmd,
        program_str,
        ProcessLimits::new(timeout),
        stdin,
    )
    .map(SupervisedProcessOutput::into_std_output)
}

/// Execute a prepared run-owned process on the shared async supervisor.
pub async fn run_prepared_run_owned(
    run: &crate::tools::security::ToolRunContext,
    command: PreparedProcessCommand,
    program_label: &str,
    limits: ProcessLimits,
    stdin_input: Option<Vec<u8>>,
) -> Result<SupervisedProcessOutput, CommandError> {
    supervise_prepared_process(
        ProcessExecution::RunOwned(run),
        command,
        program_label.to_string(),
        limits,
        stdin_input,
    )
    .await
}

fn build_process_runtime(context: &'static str) -> Result<tokio::runtime::Runtime, CommandError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| CommandError::RuntimeFailed {
            source: format!("failed to build {context} process runtime: {error}"),
        })
}

fn drive_supervisor_sync(
    execution: ProcessExecution<'_>,
    command: PreparedProcessCommand,
    program: String,
    limits: ProcessLimits,
    stdin_input: Option<Vec<u8>>,
) -> Result<SupervisedProcessOutput, CommandError> {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        return match handle.runtime_flavor() {
            tokio::runtime::RuntimeFlavor::MultiThread => tokio::task::block_in_place(|| {
                handle.block_on(supervise_prepared_process(
                    execution,
                    command,
                    program,
                    limits,
                    stdin_input,
                ))
            }),
            _ => std::thread::scope(|scope| {
                scope
                    .spawn(move || {
                        build_process_runtime("helper")?.block_on(supervise_prepared_process(
                            execution,
                            command,
                            program,
                            limits,
                            stdin_input,
                        ))
                    })
                    .join()
                    .map_err(|_| CommandError::RuntimeFailed {
                        source: "process runtime helper thread panicked".to_string(),
                    })?
            }),
        };
    }
    build_process_runtime("foreground")?.block_on(supervise_prepared_process(
        execution,
        command,
        program,
        limits,
        stdin_input,
    ))
}

#[allow(clippy::too_many_lines)] // Spawn setup and terminal transitions form one lifecycle state machine.
async fn supervise_prepared_process(
    execution: ProcessExecution<'_>,
    prepared: PreparedProcessCommand,
    program: String,
    limits: ProcessLimits,
    stdin_input: Option<Vec<u8>>,
) -> Result<SupervisedProcessOutput, CommandError> {
    let (mut command, mut workspace_projection) = prepared.into_parts();
    if let Some(input) = stdin_input.as_ref() {
        if input.len() > limits.stdin_bytes {
            return Err(CommandError::InputTooLarge {
                program,
                bytes: input.len(),
                max_bytes: limits.stdin_bytes,
            });
        }
    }

    let deadline = tokio::time::Instant::now() + limits.timeout;
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    if stdin_input.is_some() {
        command.stdin(Stdio::piped());
    }
    let mut command = tokio::process::Command::from(command);
    command.kill_on_drop(true);
    let mut child = command.spawn().map_err(|error| CommandError::SpawnFailed {
        program: program.clone(),
        source: error.to_string(),
    })?;
    let pid = child.id().ok_or_else(|| CommandError::WaitFailed {
        program: program.clone(),
        source: "spawned process has no process identifier".to_string(),
        partial: Box::new(ProcessSnapshot {
            status: None,
            stdout: CapturedStream {
                bytes: Vec::new(),
                truncated: false,
            },
            stderr: CapturedStream {
                bytes: Vec::new(),
                truncated: false,
            },
            stdin: StdinDelivery::NotRequested,
        }),
    })?;
    let tracked_run = match execution {
        ProcessExecution::RunOwned(run) => Some(run),
        #[cfg(test)]
        ProcessExecution::TestHost => None,
    };
    let _active_process = tracked_run.map(|run| ActiveSandboxProcess::register(run, pid));
    let cancellation = tracked_run.map(|run| run.runtime().cancellation());

    let stdout_state = Arc::new(Mutex::new(CaptureState::default()));
    let stderr_state = Arc::new(Mutex::new(CaptureState::default()));
    let stdin_state = Arc::new(Mutex::new(stdin_input.as_ref().map_or(
        StdinDelivery::NotRequested,
        |input| StdinDelivery::Pending {
            written: 0,
            total: input.len(),
        },
    )));
    let mut io_tasks = tokio::task::JoinSet::new();

    let Some(stdout) = child.stdout.take() else {
        let status = terminate_and_reap(&mut child, pid, None, &mut io_tasks).await;
        return Err(CommandError::WaitFailed {
            program,
            source: "stdout pipe unavailable after spawn".to_string(),
            partial: Box::new(process_snapshot(
                status,
                &stdout_state,
                &stderr_state,
                &stdin_state,
            )),
        });
    };
    io_tasks.spawn(read_bounded_stream(
        stdout,
        Arc::clone(&stdout_state),
        limits.stdout_bytes,
        "stdout",
    ));
    let Some(stderr) = child.stderr.take() else {
        let status = terminate_and_reap(&mut child, pid, None, &mut io_tasks).await;
        return Err(CommandError::WaitFailed {
            program,
            source: "stderr pipe unavailable after spawn".to_string(),
            partial: Box::new(process_snapshot(
                status,
                &stdout_state,
                &stderr_state,
                &stdin_state,
            )),
        });
    };
    io_tasks.spawn(read_bounded_stream(
        stderr,
        Arc::clone(&stderr_state),
        limits.stderr_bytes,
        "stderr",
    ));
    if let Some(input) = stdin_input {
        let Some(stdin) = child.stdin.take() else {
            let status = terminate_and_reap(&mut child, pid, None, &mut io_tasks).await;
            return Err(CommandError::WaitFailed {
                program,
                source: "stdin pipe unavailable after spawn".to_string(),
                partial: Box::new(process_snapshot(
                    status,
                    &stdout_state,
                    &stderr_state,
                    &stdin_state,
                )),
            });
        };
        io_tasks.spawn(write_stdin(stdin, input, Arc::clone(&stdin_state)));
    }

    let mut status = None;
    loop {
        if let Some(exit_status) = status {
            if io_tasks.is_empty() {
                let output = SupervisedProcessOutput {
                    status: exit_status,
                    stdout: capture_snapshot(&stdout_state),
                    stderr: capture_snapshot(&stderr_state),
                    stdin: stdin_snapshot(&stdin_state),
                    stdout_truncated_marker: limits.stdout_truncated_marker,
                    stderr_truncated_marker: limits.stderr_truncated_marker,
                };
                if let Some(projection) = workspace_projection.as_mut() {
                    if let Err(error) = projection.settle(exit_status.success()) {
                        return Err(CommandError::WorkspaceReconciliationFailed {
                            program,
                            source: error.to_string(),
                            recovery_path: error.recovery_path().map(Path::to_path_buf),
                            partial: Box::new(ProcessSnapshot {
                                status: Some(output.status),
                                stdout: output.stdout,
                                stderr: output.stderr,
                                stdin: output.stdin,
                            }),
                        });
                    }
                }
                return Ok(output);
            }
        }

        tokio::select! {
            biased;
            receipt = wait_for_cancellation(cancellation.clone()) => {
                let final_status = terminate_and_reap(&mut child, pid, status, &mut io_tasks).await;
                return Err(CommandError::Cancelled {
                    program,
                    reason: receipt.reason,
                    partial: Box::new(process_snapshot(
                        final_status,
                        &stdout_state,
                        &stderr_state,
                        &stdin_state,
                    )),
                });
            }
            () = tokio::time::sleep_until(deadline) => {
                let final_status = terminate_and_reap(&mut child, pid, status, &mut io_tasks).await;
                return Err(CommandError::TimedOut {
                    program,
                    timeout: limits.timeout,
                    partial: Box::new(process_snapshot(
                        final_status,
                        &stdout_state,
                        &stderr_state,
                        &stdin_state,
                    )),
                });
            }
            wait_result = child.wait(), if status.is_none() => {
                match wait_result {
                    Ok(exit_status) => status = Some(exit_status),
                    Err(error) => {
                        let final_status = terminate_and_reap(&mut child, pid, None, &mut io_tasks).await;
                        return Err(CommandError::WaitFailed {
                            program,
                            source: error.to_string(),
                            partial: Box::new(process_snapshot(
                                final_status,
                                &stdout_state,
                                &stderr_state,
                                &stdin_state,
                            )),
                        });
                    }
                }
            }
            task_result = io_tasks.join_next(), if !io_tasks.is_empty() => {
                let task_error = match task_result {
                    Some(Ok(Ok(()))) | None => None,
                    Some(Ok(Err(error))) => Some(error),
                    Some(Err(error)) => Some(format!("process I/O task failed: {error}")),
                };
                if let Some(source) = task_error {
                    let final_status = terminate_and_reap(&mut child, pid, status, &mut io_tasks).await;
                    return Err(CommandError::WaitFailed {
                        program,
                        source,
                        partial: Box::new(process_snapshot(
                            final_status,
                            &stdout_state,
                            &stderr_state,
                            &stdin_state,
                        )),
                    });
                }
            }
        }
    }
}

async fn wait_for_cancellation(
    cancellation: Option<crate::runtime::CancellationHandle>,
) -> crate::runtime::CancellationReceipt {
    match cancellation {
        Some(cancellation) => cancellation.cancelled().await,
        None => std::future::pending().await,
    }
}

async fn read_bounded_stream<R>(
    mut stream: R,
    state: Arc<Mutex<CaptureState>>,
    limit: usize,
    label: &'static str,
) -> Result<(), String>
where
    R: AsyncRead + Unpin,
{
    let mut chunk = [0_u8; 8192];
    loop {
        let count = stream
            .read(&mut chunk)
            .await
            .map_err(|error| format!("{label} read failed: {error}"))?;
        if count == 0 {
            return Ok(());
        }
        let mut state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let remaining = limit.saturating_sub(state.bytes.len());
        let keep = count.min(remaining);
        state.bytes.extend_from_slice(&chunk[..keep]);
        state.truncated |= keep < count;
    }
}

async fn write_stdin(
    mut stdin: tokio::process::ChildStdin,
    input: Vec<u8>,
    state: Arc<Mutex<StdinDelivery>>,
) -> Result<(), String> {
    let total = input.len();
    let mut written = 0_usize;
    while written < total {
        match stdin.write(&input[written..]).await {
            Ok(0) => {
                let error = "stdin closed before the input payload was delivered".to_string();
                *state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = StdinDelivery::Failed {
                    written,
                    total,
                    error: error.clone(),
                };
                return Err(error);
            }
            Ok(count) => {
                written += count;
                *state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) =
                    StdinDelivery::Pending { written, total };
            }
            Err(error) => {
                let error = format!("stdin write failed: {error}");
                *state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = StdinDelivery::Failed {
                    written,
                    total,
                    error: error.clone(),
                };
                return Err(error);
            }
        }
    }
    if let Err(error) = stdin.shutdown().await {
        let error = format!("stdin close failed: {error}");
        *state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = StdinDelivery::Failed {
            written,
            total,
            error: error.clone(),
        };
        return Err(error);
    }
    *state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        StdinDelivery::Complete { bytes: written };
    Ok(())
}

async fn terminate_and_reap(
    child: &mut tokio::process::Child,
    pid: u32,
    known_status: Option<ExitStatus>,
    io_tasks: &mut tokio::task::JoinSet<Result<(), String>>,
) -> Option<ExitStatus> {
    let _ = tokio::task::spawn_blocking(move || {
        crate::tools::bash::terminate_sandbox_process_tree(pid);
    })
    .await;
    let _ = child.start_kill();
    let status = match known_status {
        Some(status) => Some(status),
        None => tokio::time::timeout(PROCESS_CLEANUP_TIMEOUT, child.wait())
            .await
            .ok()
            .and_then(Result::ok),
    };
    io_tasks.abort_all();
    while io_tasks.join_next().await.is_some() {}
    status
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
    /// Caller supplied more stdin than the configured process boundary allows.
    InputTooLarge {
        program: String,
        bytes: usize,
        max_bytes: usize,
    },
    /// Deadline elapsed before the child exited; the child has been
    /// killed and reaped before this variant is returned.
    TimedOut {
        program: String,
        timeout: Duration,
        partial: Box<ProcessSnapshot>,
    },
    /// The owning run was cancelled; its process tree has been killed and
    /// reaped and any retained output is attached.
    Cancelled {
        program: String,
        reason: crate::runtime::CancellationReason,
        partial: Box<ProcessSnapshot>,
    },
    /// The `wait`/`wait_with_output` path itself returned an error. Rare;
    /// usually signal-handler races (`EINTR` storms) or pipe-buffer
    /// exhaustion after the child exited.
    WaitFailed {
        program: String,
        source: String,
        partial: Box<ProcessSnapshot>,
    },
    /// The child reached a terminal state, but its isolated workspace
    /// generation could not be reconciled with ordinary certainty.
    WorkspaceReconciliationFailed {
        program: String,
        source: String,
        recovery_path: Option<PathBuf>,
        partial: Box<ProcessSnapshot>,
    },
    /// A synchronous compatibility caller could not create or drive Tokio.
    RuntimeFailed { source: String },
}

impl CommandError {
    #[must_use]
    pub const fn partial(&self) -> Option<&ProcessSnapshot> {
        match self {
            Self::TimedOut { partial, .. }
            | Self::Cancelled { partial, .. }
            | Self::WaitFailed { partial, .. }
            | Self::WorkspaceReconciliationFailed { partial, .. } => Some(partial),
            Self::SpawnFailed { .. } | Self::InputTooLarge { .. } | Self::RuntimeFailed { .. } => {
                None
            }
        }
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SpawnFailed { program, source } => {
                write!(f, "Failed to spawn {program}: {source}")
            }
            Self::InputTooLarge {
                program,
                bytes,
                max_bytes,
            } => write!(
                f,
                "{program} stdin payload is {bytes} bytes; maximum is {max_bytes} bytes"
            ),
            Self::TimedOut {
                program, timeout, ..
            } => {
                write!(f, "{program} timed out after {}s", timeout.as_secs())
            }
            Self::Cancelled {
                program, reason, ..
            } => write!(f, "{program} was cancelled: {reason:?}"),
            Self::WaitFailed {
                program, source, ..
            } => {
                write!(f, "{program} wait failed: {source}")
            }
            Self::WorkspaceReconciliationFailed {
                program,
                source,
                recovery_path,
                ..
            } => {
                write!(f, "{program} workspace reconciliation failed: {source}")?;
                if let Some(path) = recovery_path {
                    write!(f, " (recovery: {})", path.display())?;
                }
                Ok(())
            }
            Self::RuntimeFailed { source } => write!(f, "process runtime failed: {source}"),
        }
    }
}

impl std::error::Error for CommandError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

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
    fn blocked_stdin_delivery_obeys_the_aggregate_deadline() {
        let payload = vec![b'x'; 1024 * 1024];
        let started = Instant::now();
        let result = run_with_timeout_with_input(
            "sh",
            &["-c", "sleep 60"],
            None,
            Duration::from_millis(200),
            &payload,
        );
        let elapsed = started.elapsed();

        let Err(CommandError::TimedOut { partial, .. }) = result else {
            panic!("blocked stdin must time out, got {result:?}");
        };
        assert!(elapsed < Duration::from_secs(2), "timeout took {elapsed:?}");
        match partial.stdin {
            StdinDelivery::Pending { written, total }
            | StdinDelivery::Failed { written, total, .. } => {
                assert_eq!(total, payload.len());
                assert!(written < total, "child unexpectedly consumed all stdin");
            }
            other => panic!("expected partial stdin delivery, got {other:?}"),
        }
    }

    #[test]
    #[cfg(unix)]
    fn descendant_held_output_pipe_cannot_outlive_deadline() {
        let started = Instant::now();
        let result = run_with_timeout(
            "sh",
            &["-c", "sleep 60 & printf done"],
            None,
            Duration::from_millis(200),
        );
        let elapsed = started.elapsed();

        let Err(CommandError::TimedOut { partial, .. }) = result else {
            panic!("descendant-held pipe must time out, got {result:?}");
        };
        assert!(elapsed < Duration::from_secs(2), "timeout took {elapsed:?}");
        assert!(
            partial.status.is_some(),
            "root shell should exit before its descendant closes the pipe"
        );
        assert_eq!(partial.stdout.bytes, b"done");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn run_cancellation_reaps_the_owned_process() {
        let root = tempfile::TempDir::new().expect("temporary run root");
        let run = crate::tools::security::test_run_context_for(root.path());
        let run_for_process = Arc::clone(&run);
        let process = tokio::spawn(async move {
            let mut command = Command::new("sh");
            command.args(["-c", "printf '%s\\n' $$; sleep 60"]);
            run_prepared_run_owned(
                &run_for_process,
                PreparedProcessCommand::host(command),
                "cancellation-test",
                ProcessLimits::new(Duration::from_secs(30)),
                None,
            )
            .await
        });
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _receipt = run
            .runtime()
            .cancellation()
            .cancel(crate::runtime::CancellationReason::User);

        let result = process.await.expect("supervisor task must join");
        let Err(CommandError::Cancelled {
            reason, partial, ..
        }) = result
        else {
            panic!("run cancellation must stop the child, got {result:?}");
        };
        assert_eq!(reason, crate::runtime::CancellationReason::User);
        let pid = String::from_utf8_lossy(&partial.stdout.bytes)
            .trim()
            .parse::<u32>()
            .expect("child must report its pid before sleeping");
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "cancelled child {pid} must be reaped"
        );
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
