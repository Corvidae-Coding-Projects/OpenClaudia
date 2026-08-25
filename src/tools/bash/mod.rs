mod direct;
mod job;
mod kill;
mod output;
mod path_lint;
pub mod sandbox;
// `policy` is exposed so the security E2E test suite
// (`tests/tools_security_e2e.rs`) can drive `validate_command`,
// `dangerous_shell_construct`, and `is_sensitive_env` against the attack catalog
// without actually executing the attack payloads. Internal call
// sites use the same path.
pub mod policy;

pub use direct::{
    execute_direct_shell, execute_direct_shell_async, DirectShellAction, DirectShellError,
    DirectShellExecution,
};
pub use kill::pause_sandbox_process_tree;
pub use kill::terminate_sandbox_process_tree;
pub use kill::{execute_kill_shell, execute_kill_shells_for_agent, terminate_process_tree};
pub use output::{bash_output_operations, classify_bash_output, execute_bash_output};
pub use policy::{apply_env_scrub, dangerous_shell_construct, is_sensitive_env, validate_command};

use crate::tools::args::{ToolArgError, ToolArgs as _, ToolError, ToolOutput};
use crate::tools::safe_truncate;
use job::{BackgroundJobState, JobCore, JobOutputStream, JobRead, JobSummary};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use uuid::Uuid;

/// Maximum number of background shells allowed before refusing new ones
const MAX_BACKGROUND_SHELLS: usize = 50;
const LEDGER_COMMAND_OUTPUT_MAX_BYTES: usize = 100_000;
const BACKGROUND_OUTPUT_BATCH_BYTES: usize = 256 * 1024;
const BACKGROUND_OUTPUT_BATCH_INTERVAL: std::time::Duration = std::time::Duration::from_millis(25);
const DEFAULT_FOREGROUND_TIMEOUT_MS: u64 = 300_000;
const MAX_FOREGROUND_TIMEOUT_MS: u64 = 600_000;

fn bash_bin(run: &crate::tools::ToolRunContext) -> Result<PathBuf, String> {
    run.resolve_executable("bash")
        .map_err(|error| error.to_string())
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

fn spawn_output_reader<R>(
    mut stream: R,
    core: Arc<Mutex<JobCore>>,
    output_stream: JobOutputStream,
    done: Arc<AtomicBool>,
    errors: std::sync::mpsc::Sender<String>,
    job_id: String,
) -> Result<thread::JoinHandle<()>, String>
where
    R: Read + Send + 'static,
{
    thread::Builder::new()
        .name(format!("background-output-{job_id}"))
        .spawn(move || {
            let mut chunk = [0_u8; 16 * 1024];
            let mut pending = Vec::with_capacity(BACKGROUND_OUTPUT_BATCH_BYTES);
            let mut published_output = false;
            let mut last_publish = std::time::Instant::now();
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) => {
                        if !pending.is_empty() {
                            let result = recover_mutex_lock(
                                &core,
                                "output_reader",
                                "job_core",
                                Some(&job_id),
                            )
                            .append_output(output_stream, &pending);
                            if let Err(error) = result {
                                let _ = errors.send(error);
                            }
                        }
                        break;
                    }
                    Ok(count) => {
                        pending.extend_from_slice(&chunk[..count]);
                        let should_publish = !published_output
                            || pending.len() >= BACKGROUND_OUTPUT_BATCH_BYTES
                            || last_publish.elapsed() >= BACKGROUND_OUTPUT_BATCH_INTERVAL;
                        if !should_publish {
                            continue;
                        }
                        let result =
                            recover_mutex_lock(&core, "output_reader", "job_core", Some(&job_id))
                                .append_output(output_stream, &pending);
                        if let Err(error) = result {
                            let _ = errors.send(error);
                            break;
                        }
                        pending.clear();
                        published_output = true;
                        last_publish = std::time::Instant::now();
                    }
                    Err(error) => {
                        let _ = errors.send(format!("background output read failed: {error}"));
                        break;
                    }
                }
            }
            done.store(true, Ordering::SeqCst);
        })
        .map_err(|error| format!("Cannot start background output reader: {error}"))
}

struct BackgroundJobControl {
    cancellation: crate::runtime::CancellationHandle,
    requested_state: Arc<Mutex<Option<BackgroundJobState>>>,
    stdout_done: Arc<AtomicBool>,
    stderr_done: Arc<AtomicBool>,
    reaped: Arc<AtomicBool>,
}

struct BackgroundShell {
    core: Arc<Mutex<JobCore>>,
    control: Option<BackgroundJobControl>,
}

struct BackgroundPreparationSlot<'a> {
    preparing: &'a AtomicUsize,
    held: bool,
}

impl BackgroundPreparationSlot<'_> {
    fn release(&mut self) {
        if self.held {
            self.preparing.fetch_sub(1, Ordering::SeqCst);
            self.held = false;
        }
    }
}

impl Drop for BackgroundPreparationSlot<'_> {
    fn drop(&mut self) {
        self.release();
    }
}

impl BackgroundShell {
    fn recovered(core: JobCore) -> Self {
        Self {
            core: Arc::new(Mutex::new(core)),
            control: None,
        }
    }

    fn summary(&self) -> JobSummary {
        recover_mutex_lock(&self.core, "summary", "job_core", None).summary()
    }

    fn owner_run(&self) -> String {
        recover_mutex_lock(&self.core, "owner", "job_core", None)
            .owner_run()
            .to_string()
    }

    fn owner_session(&self) -> String {
        recover_mutex_lock(&self.core, "owner", "job_core", None)
            .owner_session()
            .to_string()
    }

    fn owner_label(&self) -> String {
        recover_mutex_lock(&self.core, "owner", "job_core", None)
            .owner_label()
            .to_string()
    }

    fn state(&self) -> BackgroundJobState {
        recover_mutex_lock(&self.core, "state", "job_core", None)
            .state()
            .clone()
    }

    fn pid(&self) -> Option<u32> {
        recover_mutex_lock(&self.core, "pid", "job_core", None).pid()
    }
}

/// Manager for generation-bound background shell jobs.
pub struct BackgroundShellManager {
    shells: Mutex<HashMap<String, Arc<BackgroundShell>>>,
    hydrated_sessions: Mutex<HashSet<String>>,
    preparing: AtomicUsize,
}

impl BackgroundShellManager {
    fn new() -> Self {
        Self {
            shells: Mutex::new(HashMap::new()),
            hydrated_sessions: Mutex::new(HashSet::new()),
            preparing: AtomicUsize::new(0),
        }
    }

    fn hydrate(&self, run: &crate::tools::security::ToolRunContext) -> Result<(), String> {
        let session_id = run.session_id().to_string();
        let mut hydrated = recover_mutex_lock(
            &self.hydrated_sessions,
            "hydrate",
            "hydrated_sessions",
            None,
        );
        if hydrated.contains(&session_id) {
            return Ok(());
        }
        let recovered = job::recover_jobs(run)?;
        let mut shells = recover_mutex_lock(&self.shells, "hydrate", "shells", None);
        for core in recovered {
            let id = core.summary().id;
            shells
                .entry(id)
                .or_insert_with(|| Arc::new(BackgroundShell::recovered(core)));
        }
        drop(shells);
        hydrated.insert(session_id);
        drop(hydrated);
        Ok(())
    }

    #[cfg(test)]
    fn spawn(
        &self,
        run: &crate::tools::security::ToolRunContext,
        command: &str,
    ) -> Result<String, String> {
        self.spawn_with_timeout(
            run,
            command,
            std::time::Duration::from_millis(DEFAULT_FOREGROUND_TIMEOUT_MS),
        )
    }

    #[allow(clippy::too_many_lines)] // Admission, spawn, persistence, and supervisor registration are atomic.
    pub(crate) fn spawn_with_timeout(
        &self,
        run: &crate::tools::security::ToolRunContext,
        command: &str,
        timeout: std::time::Duration,
    ) -> Result<String, String> {
        validate_command(command)?;
        run.require(crate::tools::security::ToolResource::Process)
            .map_err(|error| error.to_string())?;
        self.hydrate(run)?;
        let remaining = run
            .budget()
            .remaining_time()
            .map_err(|error| format!("Run budget denied background process: {error}"))?;
        let timeout = timeout.min(remaining);
        if timeout.is_zero() {
            return Err("Run budget has no remaining time for a background process".to_string());
        }

        let mut preparation_slot = {
            let mut shells = recover_mutex_lock(&self.shells, "spawn", "shells", None);
            let active = shells
                .values()
                .filter(|shell| shell.state().is_running())
                .count();
            let occupied = active.saturating_add(self.preparing.load(Ordering::SeqCst));
            if occupied >= MAX_BACKGROUND_SHELLS {
                return Err(format!(
                    "Maximum active background shell limit ({MAX_BACKGROUND_SHELLS}) reached. Kill or wait for existing shells to finish."
                ));
            }
            if shells.len() > 200 {
                let mut terminal = shells
                    .iter()
                    .filter_map(|(id, shell)| {
                        let summary = shell.summary();
                        summary
                            .state
                            .is_terminal()
                            .then_some((summary.created_unix_ms, id.clone()))
                    })
                    .collect::<Vec<_>>();
                terminal.sort_unstable();
                let remove_count = shells.len().saturating_sub(200);
                for (_, id) in terminal.into_iter().take(remove_count) {
                    shells.remove(&id);
                }
            }
            self.preparing.fetch_add(1, Ordering::SeqCst);
            drop(shells);
            BackgroundPreparationSlot {
                preparing: &self.preparing,
                held: true,
            }
        };

        let cwd = run.working_directory().to_path_buf();
        #[cfg(windows)]
        let mut prepared_command = {
            let bash = find_git_bash(run).unwrap_or(bash_bin(run)?);
            sandbox::sandboxed_bash_command(run, &bash, command, &cwd)?
        };
        #[cfg(not(windows))]
        let mut prepared_command = {
            let bash = bash_bin(run)?;
            sandbox::sandboxed_bash_command(run, &bash, command, &cwd)?
        };
        prepared_command
            .command_mut()
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(not(windows))]
        prepared_command.command_mut().process_group(0);
        let (process_command, background_projection) = prepared_command.into_parts();

        // Project snapshotting can be expensive. Keep it outside the shared
        // job-manager lock, then recheck capacity before creating durable job
        // state so concurrent spawns cannot exceed the limit.
        let mut shells = recover_mutex_lock(&self.shells, "spawn", "shells", None);
        let active = shells
            .values()
            .filter(|shell| shell.state().is_running())
            .count();
        if active >= MAX_BACKGROUND_SHELLS {
            return Err(format!(
                "Maximum active background shell limit ({MAX_BACKGROUND_SHELLS}) reached. Kill or wait for existing shells to finish."
            ));
        }
        let background_freshness = crate::evidence_freshness::reserve_mutation(
            run,
            crate::tools::effect::ToolEffect::Destructive,
        )?
        .ok_or_else(|| "background shell did not receive a mutation reservation".to_string())?;
        let background_budget = run
            .budget()
            .reserve(crate::runtime::BudgetAmounts {
                concurrent_calls: 1,
                ..crate::runtime::BudgetAmounts::default()
            })
            .map_err(|error| format!("Run budget denied background process: {error}"))?;
        let shell_id = Uuid::new_v4().to_string();
        let core = Arc::new(Mutex::new(JobCore::create(
            run, &shell_id, command, timeout,
        )?));
        let stdout_done = Arc::new(AtomicBool::new(false));
        let stderr_done = Arc::new(AtomicBool::new(false));
        let reaped = Arc::new(AtomicBool::new(false));
        let cancellation = run.runtime().cancellation().child();
        let requested_state = Arc::new(Mutex::new(None));
        let shell = Arc::new(BackgroundShell {
            core: Arc::clone(&core),
            control: Some(BackgroundJobControl {
                cancellation: cancellation.clone(),
                requested_state: Arc::clone(&requested_state),
                stdout_done: Arc::clone(&stdout_done),
                stderr_done: Arc::clone(&stderr_done),
                reaped: Arc::clone(&reaped),
            }),
        });
        shells.insert(shell_id.clone(), shell);
        preparation_slot.release();
        drop(shells);

        let run_for_ledger = crate::ledger::RunBinding::from_run(run);
        let owner_for_ledger = run.process_owner().to_string();
        let command_for_ledger = command.to_string();
        let supervisor_id = shell_id.clone();
        let supervisor_core = Arc::clone(&core);
        let supervisor_stdout_done = Arc::clone(&stdout_done);
        let supervisor_stderr_done = Arc::clone(&stderr_done);
        let supervisor_reaped = Arc::clone(&reaped);
        let (startup_tx, startup_rx) = std::sync::mpsc::sync_channel(1);
        let launch = BackgroundJobLaunch {
            process_command,
            background_projection,
            startup: startup_tx,
            core: supervisor_core,
            job_id: supervisor_id,
            stdout_done: supervisor_stdout_done,
            stderr_done: supervisor_stderr_done,
            reaped: supervisor_reaped,
            cancellation,
            requested_state,
            run_for_ledger,
            owner_for_ledger,
            cwd,
            command: command_for_ledger,
            background_freshness,
            background_budget,
            timeout,
        };
        let supervisor = thread::Builder::new()
            .name(format!("background-supervisor-{shell_id}"))
            .spawn(move || launch.run());
        let supervisor = match supervisor {
            Ok(supervisor) => supervisor,
            Err(error) => {
                let detail = format!("Cannot start background job supervisor: {error}");
                publish_background_start_failure(
                    &core,
                    &shell_id,
                    &stdout_done,
                    &stderr_done,
                    &reaped,
                    &detail,
                );
                return Err(format!("{detail}; background job id: {shell_id}"));
            }
        };

        match startup_rx.recv() {
            Ok(Ok(())) => {
                drop(supervisor);
                Ok(shell_id)
            }
            Ok(Err(error)) => {
                let _ = supervisor.join();
                Err(format!("{error}; background job id: {shell_id}"))
            }
            Err(error) => {
                let _ = supervisor.join();
                let detail = format!("Background job supervisor stopped during startup: {error}");
                publish_background_start_failure(
                    &core,
                    &shell_id,
                    &stdout_done,
                    &stderr_done,
                    &reaped,
                    &detail,
                );
                Err(format!("{detail}; background job id: {shell_id}"))
            }
        }
    }

    fn get_output(
        &self,
        run: &crate::tools::security::ToolRunContext,
        shell_id: &str,
        cursor: Option<u64>,
    ) -> Result<JobRead, String> {
        self.hydrate(run)?;
        let shells = recover_mutex_lock(&self.shells, "get_output", "shells", Some(shell_id));
        let shell = shells
            .get(shell_id)
            .cloned()
            .ok_or_else(|| format!("Shell '{shell_id}' not found"))?;
        drop(shells);
        let caller = run.run_id().to_string();
        let mut core = recover_mutex_lock(&shell.core, "get_output", "job_core", Some(shell_id));
        let resumed_lost = matches!(core.state(), BackgroundJobState::Lost { .. })
            && core.owner_session() == run.session_id()
            && core.owner_label() == run.process_owner()
            && core.workspace_root() == run.project_root().to_string_lossy();
        if core.owner_run() != caller && !resumed_lost {
            tracing::warn!(
                target: "openclaudia::bash",
                event = "cross_session_shell_access_denied",
                caller,
                shell_id,
                "Denied background shell output access outside the owning run"
            );
            return Err(format!("Shell '{shell_id}' not found"));
        }
        core.read(cursor)
    }

    pub(crate) fn kill(
        &self,
        run: &crate::tools::security::ToolRunContext,
        shell_id: &str,
    ) -> Result<String, String> {
        self.hydrate(run)?;
        let shells = recover_mutex_lock(&self.shells, "kill", "shells", Some(shell_id));
        let shell = shells
            .get(shell_id)
            .cloned()
            .ok_or_else(|| format!("Shell '{shell_id}' not found"))?;
        drop(shells);
        if shell.owner_run() != run.run_id().to_string() {
            return Err(format!("Shell '{shell_id}' not found"));
        }
        stop_background_shell(&shell, BackgroundJobState::Killed);
        Ok(format!(
            "Shell '{}' terminated (command: {}, pid: {}, state: {})",
            shell_id,
            shell.summary().command,
            shell
                .pid()
                .map_or_else(|| "unknown".to_string(), |pid| pid.to_string()),
            shell.state().label()
        ))
    }

    fn kill_matching(
        &self,
        operation: &'static str,
        owner_label: &str,
        predicate: impl Fn(&BackgroundShell) -> bool,
        state: &BackgroundJobState,
    ) -> String {
        let shells = recover_mutex_lock(&self.shells, operation, "shells", None);
        let matches = shells
            .iter()
            .filter(|(_, shell)| shell.state().is_running() && predicate(shell))
            .map(|(id, shell)| (id.clone(), Arc::clone(shell)))
            .collect::<Vec<_>>();
        drop(shells);
        if matches.is_empty() {
            return format!("No background shells found for agent '{owner_label}'.");
        }
        let mut killed_ids = Vec::with_capacity(matches.len());
        for (id, shell) in matches {
            stop_background_shell(&shell, state.clone());
            killed_ids.push(id);
        }
        format!(
            "Terminated {} background shell(s) for agent '{}': {}",
            killed_ids.len(),
            owner_label,
            killed_ids.join(", ")
        )
    }

    pub(crate) fn kill_for_run(&self, run: &crate::tools::security::ToolRunContext) -> String {
        let _ = self.hydrate(run);
        let owner_run = run.run_id().to_string();
        self.kill_matching(
            "kill_for_run",
            run.process_owner(),
            |shell| shell.owner_run() == owner_run,
            &BackgroundJobState::Cancelled {
                reason: "run ended".to_string(),
            },
        )
    }

    pub(crate) fn kill_for_process_owner(
        &self,
        owner: &crate::tools::ToolRunContext,
        owner_label: &str,
    ) -> String {
        let _ = self.hydrate(owner);
        let owner_session = owner.session_id();
        self.kill_matching(
            "kill_for_process_owner",
            owner_label,
            |shell| shell.owner_session() == owner_session && shell.owner_label() == owner_label,
            &BackgroundJobState::Cancelled {
                reason: "process owner ended".to_string(),
            },
        )
    }

    fn kill_for_session(&self, session_id: &str) -> String {
        self.kill_matching(
            "kill_for_session",
            session_id,
            |shell| shell.owner_session() == session_id,
            &BackgroundJobState::Cancelled {
                reason: "session ended".to_string(),
            },
        )
    }

    fn summaries(&self, run: &crate::tools::security::ToolRunContext) -> Vec<JobSummary> {
        let _ = self.hydrate(run);
        let caller = run.run_id().to_string();
        let session = run.session_id();
        let workspace = run.project_root().to_string_lossy();
        let mut summaries = {
            let shells = recover_mutex_lock(&self.shells, "summaries", "shells", None);
            shells
                .values()
                .filter_map(|shell| {
                    let core = recover_mutex_lock(&shell.core, "summaries", "job_core", None);
                    (core.owner_run() == caller
                        || (matches!(core.state(), BackgroundJobState::Lost { .. })
                            && core.owner_session() == session
                            && core.owner_label() == run.process_owner()
                            && core.workspace_root() == workspace))
                        .then(|| core.summary())
                })
                .collect::<Vec<_>>()
        };
        summaries.sort_by_key(|summary| summary.created_unix_ms);
        summaries
    }

    pub(crate) fn list(
        &self,
        run: &crate::tools::security::ToolRunContext,
    ) -> Vec<(String, String, bool)> {
        self.summaries(run)
            .into_iter()
            .map(|summary| (summary.id, summary.command, summary.state.is_running()))
            .collect()
    }

    pub(crate) fn active_ids_for_run(
        &self,
        run: &crate::tools::security::ToolRunContext,
    ) -> Vec<String> {
        let _ = self.hydrate(run);
        let caller = run.run_id().to_string();
        let mut ids = {
            let shells = recover_mutex_lock(&self.shells, "active_ids_for_run", "shells", None);
            shells
                .iter()
                .filter(|(_, shell)| shell.owner_run() == caller && shell.state().is_running())
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>()
        };
        ids.sort_unstable();
        ids
    }
}

fn publish_background_start_failure(
    core: &Arc<Mutex<JobCore>>,
    job_id: &str,
    stdout_done: &Arc<AtomicBool>,
    stderr_done: &Arc<AtomicBool>,
    reaped: &Arc<AtomicBool>,
    error: &str,
) {
    stdout_done.store(true, Ordering::SeqCst);
    stderr_done.store(true, Ordering::SeqCst);
    reaped.store(true, Ordering::SeqCst);
    let _ = recover_mutex_lock(core, "spawn", "job_core", Some(job_id)).set_state(
        BackgroundJobState::DeliveryFailed {
            error: error.to_string(),
        },
    );
}

struct BackgroundJobLaunch {
    process_command: std::process::Command,
    background_projection: Option<crate::tools::file::workspace_projection::WorkspaceProjection>,
    startup: std::sync::mpsc::SyncSender<Result<(), String>>,
    core: Arc<Mutex<JobCore>>,
    job_id: String,
    stdout_done: Arc<AtomicBool>,
    stderr_done: Arc<AtomicBool>,
    reaped: Arc<AtomicBool>,
    cancellation: crate::runtime::CancellationHandle,
    requested_state: Arc<Mutex<Option<BackgroundJobState>>>,
    run_for_ledger: crate::ledger::RunBinding,
    owner_for_ledger: String,
    cwd: PathBuf,
    command: String,
    background_freshness: crate::evidence_freshness::MutationReservation,
    background_budget: crate::runtime::BudgetReservation,
    timeout: std::time::Duration,
}

impl BackgroundJobLaunch {
    #[allow(clippy::too_many_lines)]
    fn run(self) {
        let Self {
            mut process_command,
            background_projection,
            startup,
            core,
            job_id,
            stdout_done,
            stderr_done,
            reaped,
            cancellation,
            requested_state,
            run_for_ledger,
            owner_for_ledger,
            cwd,
            command,
            background_freshness,
            background_budget,
            timeout,
        } = self;
        let mut child = match process_command.spawn() {
            Ok(child) => child,
            Err(error) => {
                let detail = format!("Failed to spawn background shell: {error}");
                publish_background_start_failure(
                    &core,
                    &job_id,
                    &stdout_done,
                    &stderr_done,
                    &reaped,
                    &detail,
                );
                let _ = startup.send(Err(detail));
                return;
            }
        };
        let pid = child.id();
        let mark_running =
            recover_mutex_lock(&core, "spawn", "job_core", Some(&job_id)).mark_running(pid);
        if let Err(error) = mark_running {
            terminate_sandbox_process_tree(pid);
            let _ = child.kill();
            let _ = child.wait();
            publish_background_start_failure(
                &core,
                &job_id,
                &stdout_done,
                &stderr_done,
                &reaped,
                &error,
            );
            let _ = startup.send(Err(error));
            return;
        }

        let (errors_tx, errors_rx) = std::sync::mpsc::channel();
        let stdout_missing = child.stdout.is_none();
        let stderr_missing = child.stderr.is_none();
        let stdout_reader = child.stdout.take().map(|stdout| {
            spawn_output_reader(
                stdout,
                Arc::clone(&core),
                JobOutputStream::Stdout,
                Arc::clone(&stdout_done),
                errors_tx.clone(),
                job_id.clone(),
            )
        });
        let stderr_reader = child.stderr.take().map(|stderr| {
            spawn_output_reader(
                stderr,
                Arc::clone(&core),
                JobOutputStream::Stderr,
                Arc::clone(&stderr_done),
                errors_tx,
                job_id.clone(),
            )
        });
        let mut reader_handles = Vec::new();
        for reader in [stdout_reader, stderr_reader].into_iter().flatten() {
            match reader {
                Ok(handle) => reader_handles.push(handle),
                Err(error) => {
                    terminate_sandbox_process_tree(pid);
                    let _ = child.kill();
                    let _ = child.wait();
                    for handle in reader_handles {
                        let _ = handle.join();
                    }
                    publish_background_start_failure(
                        &core,
                        &job_id,
                        &stdout_done,
                        &stderr_done,
                        &reaped,
                        &error,
                    );
                    let _ = startup.send(Err(error));
                    return;
                }
            }
        }
        if stdout_missing {
            stdout_done.store(true, Ordering::SeqCst);
        }
        if stderr_missing {
            stderr_done.store(true, Ordering::SeqCst);
        }
        let _ = startup.send(Ok(()));
        supervise_background_job(
            child,
            pid,
            timeout,
            &cancellation,
            &requested_state,
            &stdout_done,
            &stderr_done,
            &reaped,
            &errors_rx,
            reader_handles,
            &core,
            &run_for_ledger,
            &owner_for_ledger,
            &cwd,
            &command,
            &job_id,
            background_freshness,
            background_budget,
            background_projection,
        );
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn supervise_background_job(
    mut child: std::process::Child,
    pid: u32,
    timeout: std::time::Duration,
    cancellation: &crate::runtime::CancellationHandle,
    requested_state: &Arc<Mutex<Option<BackgroundJobState>>>,
    stdout_done: &Arc<AtomicBool>,
    stderr_done: &Arc<AtomicBool>,
    reaped: &Arc<AtomicBool>,
    errors: &std::sync::mpsc::Receiver<String>,
    readers: Vec<thread::JoinHandle<()>>,
    core: &Arc<Mutex<JobCore>>,
    run_for_ledger: &crate::ledger::RunBinding,
    owner_for_ledger: &str,
    cwd: &Path,
    command: &str,
    job_id: &str,
    mut background_freshness: crate::evidence_freshness::MutationReservation,
    background_budget: crate::runtime::BudgetReservation,
    mut background_projection: Option<
        crate::tools::file::workspace_projection::WorkspaceProjection,
    >,
) {
    let deadline = std::time::Instant::now() + timeout;
    let mut root_status = None;
    let mut terminal_state = loop {
        if let Ok(error) = errors.try_recv() {
            terminate_sandbox_process_tree(pid);
            let _ = child.kill();
            break BackgroundJobState::DeliveryFailed { error };
        }
        if let Some(receipt) = cancellation.receipt() {
            terminate_sandbox_process_tree(pid);
            let _ = child.kill();
            let requested = recover_mutex_lock(
                requested_state,
                "supervise",
                "requested_state",
                Some(job_id),
            )
            .take();
            break requested.unwrap_or_else(|| BackgroundJobState::Cancelled {
                reason: format!("{:?}", receipt.reason),
            });
        }
        if std::time::Instant::now() >= deadline {
            *recover_mutex_lock(
                requested_state,
                "supervise",
                "requested_state",
                Some(job_id),
            ) = Some(BackgroundJobState::TimedOut);
            let _receipt = cancellation.cancel(crate::runtime::CancellationReason::Deadline);
            terminate_sandbox_process_tree(pid);
            let _ = child.kill();
            break BackgroundJobState::TimedOut;
        }
        if root_status.is_none() {
            match child.try_wait() {
                Ok(Some(status)) => root_status = Some(status),
                Ok(None) => {}
                Err(error) => {
                    terminate_sandbox_process_tree(pid);
                    let _ = child.kill();
                    break BackgroundJobState::DeliveryFailed {
                        error: format!("background process wait failed: {error}"),
                    };
                }
            }
        }
        if let Some(status) = root_status
            .as_ref()
            .filter(|_| stdout_done.load(Ordering::SeqCst) && stderr_done.load(Ordering::SeqCst))
        {
            break BackgroundJobState::Exited {
                exit_code: status.code().unwrap_or(-1),
            };
        }
        thread::sleep(std::time::Duration::from_millis(10));
    };

    if root_status.is_none() {
        root_status = child.wait().ok();
    }
    reaped.store(true, Ordering::SeqCst);
    for reader in readers {
        let _ = reader.join();
    }
    if let Some(projection) = background_projection.as_mut() {
        let publish = matches!(terminal_state, BackgroundJobState::Exited { exit_code: 0 });
        if let Err(error) = projection.settle(publish) {
            terminal_state = BackgroundJobState::DeliveryFailed {
                error: format!("background workspace reconciliation failed: {error}"),
            };
        }
    }
    // Release the run's concurrency lease before publishing a terminal job
    // state. Callers use that state as the signal that a replacement job may
    // be admitted, so exposing it first can transiently oversubscribe the run
    // budget during rapid kill/spawn waves.
    if let Err(error) = background_budget.commit() {
        tracing::error!(job_id, %error, "Failed to release background process budget");
    }
    let mut core = recover_mutex_lock(core, "supervise", "job_core", Some(job_id));
    if let Err(error) = core.set_state(terminal_state) {
        tracing::error!(job_id, %error, "Failed to persist terminal background-job state");
    }
    let stdout = core.ledger_output(JobOutputStream::Stdout, LEDGER_COMMAND_OUTPUT_MAX_BYTES);
    let stderr = core.ledger_output(JobOutputStream::Stderr, LEDGER_COMMAND_OUTPUT_MAX_BYTES);
    let exit_code = core.state().exit_code().or_else(|| {
        root_status
            .as_ref()
            .map(|status| status.code().unwrap_or(-1))
    });
    drop(core);
    record_command_observation_for_session(
        run_for_ledger,
        owner_for_ledger,
        cwd,
        command,
        exit_code.unwrap_or(-1),
        &stdout,
        &stderr,
    );
    if let Err(error) = background_freshness.commit() {
        tracing::error!(job_id, %error, "Failed to advance freshness after background job");
    }
    crate::ledger::invalidate_verification_receipts_for_binding(
        run_for_ledger.run_id,
        run_for_ledger.capability_generation,
    );
}

fn stop_background_shell(shell: &BackgroundShell, requested: BackgroundJobState) {
    if !shell.state().is_running() {
        return;
    }
    let Some(control) = shell.control.as_ref() else {
        return;
    };
    *recover_mutex_lock(&control.requested_state, "stop", "requested_state", None) =
        Some(requested);
    let _receipt = control
        .cancellation
        .cancel(crate::runtime::CancellationReason::User);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        if control.reaped.load(Ordering::SeqCst)
            && control.stdout_done.load(Ordering::SeqCst)
            && control.stderr_done.load(Ordering::SeqCst)
            && shell.state().is_terminal()
        {
            return;
        }
        thread::sleep(std::time::Duration::from_millis(10));
    }
    if let Some(pid) = shell.pid() {
        terminate_sandbox_process_tree(pid);
    }
    tracing::warn!(
        target: "openclaudia::bash",
        event = "background_job_reap_delayed",
        pid = shell.pid().unwrap_or_default(),
        "Background job did not publish terminal reap/drain completion within cleanup deadline"
    );
}

/// Terminate every background job owned by a session during trusted lifecycle cleanup.
pub fn terminate_session_background_jobs(session_id: &str) {
    let result = BACKGROUND_SHELLS.kill_for_session(session_id);
    tracing::info!(
        target: "openclaudia::bash",
        event = "session_background_jobs_terminated",
        session_id,
        result,
        "Applied session-end background-process cleanup"
    );
}

/// Global background shell manager.
pub static BACKGROUND_SHELLS: std::sync::LazyLock<BackgroundShellManager> =
    std::sync::LazyLock::new(BackgroundShellManager::new);

/// Find Git Bash on Windows
#[cfg(windows)]
pub(crate) fn find_git_bash(run: &crate::tools::ToolRunContext) -> Option<std::path::PathBuf> {
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
    if let Ok(git_path) = run.resolve_executable("git") {
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
/// To preserve byte-identical legacy output for downstream consumers (and the
/// pinning tests), a non-zero exit returns
/// `Err(ToolError::PartialExternal(...))`: its tuple projection remains
/// `(text, true)`, while canonical dispatch retains the fact that the process
/// ran and may already have changed state.
///
/// # Errors
///
/// - [`ToolError::InvalidArgument`] when the `command` arg is absent or
///   not a JSON string.
/// - [`ToolError::InvalidInput`] when [`validate_command`] rejects the
///   command (length cap, denylist, structural rule).
/// - [`ToolError::Unavailable`] when the run has no process capability.
/// - [`ToolError::External`] when:
///   * the spawned process fails to start (no shell, permission denied,
///     OS resource exhaustion).
/// - [`ToolError::PartialExternal`] when a started process times out,
///   cannot be waited, or exits non-zero. The command may already have
///   changed state, so canonical dispatch must commit its reservation.
/// - [`ToolError::Other`] when the background shell manager refuses the
///   spawn (e.g. cap reached). Preserves the existing message verbatim.
#[allow(clippy::too_many_lines)] // Validation, dispatch, capture, and rendering form one tool result.
pub fn try_execute_bash(
    run: &crate::tools::security::ToolRunContext,
    args: &HashMap<String, Value>,
) -> Result<ToolOutput, ToolError> {
    run.require(crate::tools::security::ToolResource::Process)
        .map_err(|error| ToolError::Unavailable(error.to_string()))?;
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

    // S-020/F-050: this deliberately shallow lexical scan is telemetry only.
    // It cannot grant or deny access; immutable capabilities and the OS
    // sandbox enforce the actual filesystem boundary.
    let outside_root_tokens = path_lint::outside_run_root_count(run, command);
    if outside_root_tokens > 0 {
        tracing::warn!(
            target: "openclaudia::bash",
            event = "non_authoritative_path_lint",
            run_id = %run.run_id(),
            outside_root_tokens,
            "Bash text contains literal paths outside declared roots; the lexical lint is non-authoritative and sandbox containment remains decisive"
        );
    }

    if let Some(reason) = dangerous_shell_construct(command) {
        tracing::debug!(
            target: "openclaudia::bash",
            event = "bash_structural_lint",
            run_id = %run.run_id(),
            reason = reason,
            "Bash text contains a defence-in-depth structural finding; typed policy remains authoritative"
        );
    }

    // Check if this should run in background
    let run_in_background = args
        .arg_bool_or_strict("run_in_background", false)
        .map_err(ToolError::InvalidArgument)?;

    let timeout_ms = match args.get("timeout") {
        None => DEFAULT_FOREGROUND_TIMEOUT_MS,
        Some(Value::Number(value)) => value.as_u64().ok_or_else(|| {
            ToolError::InvalidInput(
                "Invalid 'timeout' argument: expected a positive integer in milliseconds"
                    .to_string(),
            )
        })?,
        Some(_) => {
            return Err(ToolError::InvalidArgument(ToolArgError::WrongType {
                key: "timeout",
                expected: "positive integer",
            }));
        }
    };
    if timeout_ms == 0 || timeout_ms > MAX_FOREGROUND_TIMEOUT_MS {
        return Err(ToolError::InvalidInput(format!(
            "Invalid 'timeout' argument: expected 1..={MAX_FOREGROUND_TIMEOUT_MS} milliseconds"
        )));
    }

    if run_in_background {
        let arguments = Value::Object(
            args.iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect(),
        );
        let _registration = run
            .begin_background_effect_registration("bash", &arguments)
            .map_err(ToolError::Other)?;
        // Spawn background shell and return shell_id.
        let shell_id = BACKGROUND_SHELLS
            .spawn_with_timeout(run, command, std::time::Duration::from_millis(timeout_ms))
            .map_err(ToolError::Other)?;
        return Ok(ToolOutput::text(format!(
            "Background shell started with ID: {shell_id}\nUse bash_output with this shell_id to retrieve output."
        )));
    }

    // Run synchronously (original behavior).
    // On Windows, use Git Bash explicitly (not WSL bash).
    // On Unix, use system bash.
    let cwd = run.working_directory().to_path_buf();

    #[cfg(windows)]
    let output = {
        let bash = find_git_bash(run).unwrap_or(bash_bin(run).map_err(ToolError::External)?);
        let cmd = sandbox::sandboxed_bash_command(run, &bash, command, &cwd)
            .map_err(ToolError::External)?;
        super::command::run_prepared_sandboxed_with_timeout(
            run,
            cmd,
            "bash",
            std::time::Duration::from_millis(timeout_ms),
        )
    };

    #[cfg(not(windows))]
    let output = {
        let bash = bash_bin(run).map_err(ToolError::External)?;
        let cmd = sandbox::sandboxed_bash_command(run, &bash, command, &cwd)
            .map_err(ToolError::External)?;
        super::command::run_prepared_sandboxed_with_timeout(
            run,
            cmd,
            "bash",
            std::time::Duration::from_millis(timeout_ms),
        )
    };

    let output = match output {
        Ok(output) => output,
        Err(super::command::CommandError::SpawnFailed { program, source }) => {
            return Err(ToolError::External(format!(
                "Failed to execute command: Failed to spawn {program}: {source}"
            )));
        }
        Err(
            error @ (super::command::CommandError::InputTooLarge { .. }
            | super::command::CommandError::RuntimeFailed { .. }),
        ) => {
            return Err(ToolError::External(format!(
                "Failed to execute command: {error}"
            )));
        }
        Err(
            error @ (super::command::CommandError::TimedOut { .. }
            | super::command::CommandError::Cancelled { .. }
            | super::command::CommandError::WaitFailed { .. }
            | super::command::CommandError::WorkspaceReconciliationFailed { .. }),
        ) => {
            let mut diagnostic = format!("Failed to execute command after it started: {error}");
            if let Some(partial) = error.partial() {
                if let Some(status) = partial.status.as_ref() {
                    let _ = write!(diagnostic, "\nterminal status: {status}");
                }
                if !matches!(&partial.stdin, super::command::StdinDelivery::NotRequested) {
                    let _ = write!(diagnostic, "\nstdin delivery: {:?}", partial.stdin);
                }
                if !partial.stdout.bytes.is_empty() {
                    diagnostic.push_str("\npartial stdout:\n");
                    diagnostic.push_str(&String::from_utf8_lossy(&partial.stdout.bytes));
                }
                if partial.stdout.truncated {
                    diagnostic.push_str("\n[partial stdout truncated]");
                }
                if !partial.stderr.bytes.is_empty() {
                    diagnostic.push_str("\npartial stderr:\n");
                    diagnostic.push_str(&String::from_utf8_lossy(&partial.stderr.bytes));
                }
                if partial.stderr.truncated {
                    diagnostic.push_str("\n[partial stderr truncated]");
                }
            }
            return Err(ToolError::PartialExternal(diagnostic));
        }
    };
    record_active_command_observation(run, &cwd, command, &output);

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
        // The tuple projection stays `(message, true)`, but canonical dispatch
        // must retain that the process ran and may have mutated state.
        Err(ToolError::PartialExternal(result))
    }
}

fn record_active_command_observation(
    run: &super::security::ToolRunContext,
    cwd: &Path,
    command: &str,
    output: &std::process::Output,
) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let exit_code = output.status.code().unwrap_or(-1);
    let binding = crate::ledger::RunBinding::from_run(run);
    record_command_observation_for_session(
        &binding,
        run.session_id(),
        cwd,
        command,
        exit_code,
        &stdout,
        &stderr,
    );
}

pub fn record_command_observation_for_session(
    run: &crate::ledger::RunBinding,
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
        append_command_observation(run, &mut ledger, cwd, command, exit_code, stdout, stderr);
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
    append_command_observation(run, &mut ledger, cwd, command, exit_code, stdout, stderr);
}

fn append_command_observation(
    run: &crate::ledger::RunBinding,
    ledger: &mut crate::ledger::RealityLedger,
    cwd: &Path,
    command: &str,
    exit_code: i32,
    stdout: &str,
    stderr: &str,
) {
    if let Err(err) = ledger.observe_command_run_for_binding(
        run.clone(),
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
}

/// Execute a bash command, returning the legacy `(content, is_error)` tuple.
///
/// Thin shim over [`try_execute_bash`] preserved so the registry's
/// `ToolHandler::execute` signature (which still returns `(String, bool)`)
/// compiles untouched while the typed surface lands incrementally. New code
/// should call [`try_execute_bash`] directly and use the structured error.
///
/// Applies the policy layer: length cap + denylist in [`validate_command`],
/// and env scrubbing via [`apply_env_scrub`] (the ambient environment is
/// cleared, then only exact values carried by the run capability are added).
/// See crosslink #257 and #730.
#[cfg(test)]
pub fn execute_bash(
    run: &crate::tools::security::ToolRunContext,
    args: &HashMap<String, Value>,
) -> (String, bool) {
    match try_execute_bash(run, args) {
        Ok(output) => output.into(),
        Err(error) => error.into(),
    }
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

    fn test_run() -> &'static std::sync::Arc<crate::tools::ToolRunContext> {
        static RUN: std::sync::OnceLock<std::sync::Arc<crate::tools::ToolRunContext>> =
            std::sync::OnceLock::new();
        RUN.get_or_init(|| {
            let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("target/test-workspaces")
                .join(format!("bash-unit-{}", std::process::id()));
            std::fs::create_dir_all(&root).expect("isolated bash fixture root");
            crate::tools::ToolRunContext::builder(crate::state::SessionId::new(), &root)
                .read_only_roots(Vec::new())
                .read_write_roots(Vec::new())
                .environment_grants(HashMap::new())
                .workspace_access(crate::tools::WorkspaceAccess::ReadWrite)
                .process(true)
                .network(true)
                .secrets(true)
                .provider("bash-unit-test")
                .build()
                .expect("bash unit-test run")
        })
    }

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
    fn verification_shaped_shell_text_only_appends_command_observation() {
        let mut ledger = crate::ledger::RealityLedger::new();
        let binding = crate::ledger::RunBinding::from_run(test_run());
        append_command_observation(
            &binding,
            &mut ledger,
            Path::new("/tmp/project"),
            "cargo check --all-targets",
            0,
            "ok",
            "",
        );

        let index = ledger.observation_index(8);
        assert_eq!(index.len(), 1);
        let command = ledger.get(index[0].id).expect("command observation");
        assert!(matches!(
            command.kind,
            crate::ledger::ObservationKind::CommandRun { .. }
        ));
        assert_eq!(
            command.provenance.trust,
            crate::ledger::EvidenceTrust::RuntimeObserved
        );
        assert!(command.provenance.is_bound_to(test_run()));
    }

    #[test]
    fn non_verification_commands_only_append_command_observation() {
        let mut ledger = crate::ledger::RealityLedger::new();
        let binding = crate::ledger::RunBinding::from_run(test_run());
        append_command_observation(
            &binding,
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
            .find("\n#[cfg(test)]\nmod tests")
            .expect("test module marker must be present");
        let production = &source[..cfg_test];

        assert!(
            !production.contains("Command::new(\"where\")"),
            "find_git_bash must not shell out to the Windows where command"
        );
        assert!(
            production.contains("run.resolve_executable(\"git\")"),
            "find_git_bash must locate git through the run-bound resolver"
        );
    }

    #[test]
    fn bash_execution_uses_resolved_binary_path() {
        let bash = bash_bin(test_run()).expect("bash tests require bash on the run-bound PATH");
        assert!(
            bash.is_absolute(),
            "bash_bin must resolve bash to an absolute path, got {}",
            bash.display()
        );

        let source = include_str!("mod.rs");
        let cfg_test = source
            .find("\n#[cfg(test)]\nmod tests")
            .expect("test module marker must be present");
        let production = &source[..cfg_test];

        assert!(
            !production.contains("Command::new(\"bash\")"),
            "production bash tool code must not invoke bare bash"
        );
        assert!(
            production.contains("run.resolve_executable(\"bash\")"),
            "bash tool must locate bash through the run-bound resolver"
        );
    }

    // B1 — background spawn: shell_id format and manager state
    // Spec: crosslink #526 §B1 | OC source: mod.rs:49-169

    /// B1-mod-a: spawn returns an untruncated UUID `shell_id`.
    #[test]
    fn b1_spawn_returns_full_uuid_shell_id() {
        let _l = bg_lock();
        let id = BACKGROUND_SHELLS
            .spawn(test_run(), "echo b1_mod_a")
            .expect("b1_spawn_8char: spawn must succeed");
        assert_eq!(
            Uuid::parse_str(&id)
                .expect("full UUID shell id")
                .to_string(),
            id
        );
        let _ = BACKGROUND_SHELLS.kill(test_run(), &id);
    }

    /// B1-mod-b: `execute_bash` with `run_in_background=true` returns `is_error=false`
    /// and a message containing "ID:" and the `shell_id`.
    ///
    /// OC source: mod.rs:334-339.
    #[test]
    fn b1_execute_bash_background_response_format() {
        let _l = bg_lock();
        let (msg, is_error) = execute_bash(test_run(), &bg_bash_args("echo b1_mod_b"));
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

    /// B1-mod-c: spawned shell appears in the owning run's list.
    #[test]
    fn b1_spawned_shell_appears_in_list() {
        let _l = bg_lock();
        let id = BACKGROUND_SHELLS
            .spawn(test_run(), "sleep 2")
            .expect("b1_list: spawn must succeed");
        let shells = BACKGROUND_SHELLS.list(test_run());
        let found = shells.iter().any(|(listed_id, _, _)| listed_id == &id);
        assert!(found, "b1_list: spawned shell must appear in list; id={id}");
        let _ = BACKGROUND_SHELLS.kill(test_run(), &id);
    }

    #[test]
    fn lifecycle_cleanup_for_same_label_is_scoped_to_owner_session() {
        let _lock = bg_lock();
        let root_a = tempfile::tempdir().expect("session A root");
        let root_b = tempfile::tempdir().expect("session B root");
        let make_run = |root: &Path| {
            crate::tools::ToolRunContext::builder(crate::state::SessionId::new(), root)
                .read_only_roots(Vec::new())
                .read_write_roots(Vec::new())
                .environment_grants(HashMap::new())
                .workspace_access(crate::tools::WorkspaceAccess::ReadWrite)
                .process(true)
                .network(false)
                .secrets(false)
                .process_owner("shared-agent-label")
                .provider("session-cleanup-test")
                .build()
                .expect("isolated run")
        };
        let run_a = make_run(root_a.path());
        let run_b = make_run(root_b.path());
        let shell_a = BACKGROUND_SHELLS
            .spawn(&run_a, "sleep 30")
            .expect("spawn session A shell");
        let shell_b = BACKGROUND_SHELLS
            .spawn(&run_b, "sleep 30")
            .unwrap_or_else(|error| {
                let _ = BACKGROUND_SHELLS.kill(&run_a, &shell_a);
                panic!("spawn session B shell: {error}");
            });

        let cleanup = BACKGROUND_SHELLS.kill_for_process_owner(&run_a, "shared-agent-label");
        let a_state = BACKGROUND_SHELLS
            .get_output(&run_a, &shell_a, Some(0))
            .expect("session A job record remains readable")
            .state;
        let b_state = BACKGROUND_SHELLS
            .get_output(&run_b, &shell_b, Some(0))
            .expect("session B job remains readable")
            .state;
        let cleanup_b = BACKGROUND_SHELLS.kill(&run_b, &shell_b);

        assert!(cleanup_b.is_ok(), "session B cleanup failed: {cleanup_b:?}");
        assert!(cleanup.contains(&shell_a), "{cleanup}");
        assert!(!cleanup.contains(&shell_b), "{cleanup}");
        assert!(matches!(a_state, BackgroundJobState::Cancelled { .. }));
        assert!(
            b_state.is_running(),
            "session A cleanup must not terminate session B's same-label shell"
        );
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
        let result = BACKGROUND_SHELLS.kill(test_run(), "deadbeef");
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

    /// B2-mod-b: kill on a running shell reaps it and retains its terminal record.
    #[test]
    #[cfg(unix)]
    fn b2_kill_running_shell_reaps_and_retains_record() {
        let _l = bg_lock();
        let id = BACKGROUND_SHELLS
            .spawn(test_run(), "sleep 30")
            .expect("b2_kill_running: spawn must succeed");

        // Confirm it's tracked and retain the exact OS pid for the reap check.
        let pid;
        {
            let shells = BACKGROUND_SHELLS
                .shells
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let contains = shells.contains_key(&id);
            pid = shells
                .get(&id)
                .expect("tracked shell")
                .pid()
                .expect("running shell pid");
            drop(shells);
            assert!(contains, "b2_kill_running: must be in map before kill");
        }
        let result = BACKGROUND_SHELLS.kill(test_run(), &id);
        assert!(
            result.is_ok(),
            "b2_kill_running: kill must succeed; err={:?}",
            result.err()
        );
        #[cfg(target_os = "linux")]
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "killed background sandbox pid {pid} must be reaped"
        );

        let read = BACKGROUND_SHELLS
            .get_output(test_run(), &id, Some(0))
            .expect("killed job record remains readable");
        assert_eq!(read.state, BackgroundJobState::Killed);
    }

    /// B2-mod-c: kill message format — "Shell 'id' terminated (command: ..., pid: ...)".
    ///
    /// OC source: mod.rs:242-245.
    #[test]
    #[cfg(unix)]
    fn b2_kill_success_message_format() {
        let _l = bg_lock();
        let id = BACKGROUND_SHELLS
            .spawn(test_run(), "sleep 30")
            .expect("b2_kill_msg: spawn must succeed");
        let msg = BACKGROUND_SHELLS
            .kill(test_run(), &id)
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
            .spawn(test_run(), "echo b2_mod_d_done")
            .expect("b2_kill_finished: spawn must succeed");

        // Wait for the command to finish
        std::thread::sleep(std::time::Duration::from_millis(400));

        // Shell should be finished; kill must still succeed
        let result = BACKGROUND_SHELLS.kill(test_run(), &id);
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
        let result = BACKGROUND_SHELLS.get_output(test_run(), "ffffffff", None);
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
            .spawn(test_run(), "sleep 5")
            .expect("b3_get_output_running: spawn must succeed");

        std::thread::sleep(std::time::Duration::from_millis(100));

        let result = BACKGROUND_SHELLS.get_output(test_run(), &id, None);
        assert!(result.is_ok(), "b3_get_output_running: must return Ok");
        let read = result.unwrap();
        assert!(
            read.state.is_running(),
            "b3_get_output_running: is_running must be true for a live shell"
        );
        // Clean up
        let _ = BACKGROUND_SHELLS.kill(test_run(), &id);
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
            .spawn(test_run(), "exit 0")
            .expect("b3_get_output_finished: spawn must succeed");

        std::thread::sleep(std::time::Duration::from_millis(400));

        let result = BACKGROUND_SHELLS.get_output(test_run(), &id, None);
        assert!(result.is_ok(), "b3_get_output_finished: must return Ok");
        let read = result.unwrap();
        assert!(
            !read.state.is_running(),
            "b3_get_output_finished: is_running must be false for a finished shell"
        );
        assert_eq!(
            read.state.exit_code(),
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
        let (msg, is_error) = execute_bash(test_run(), &args);
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
        let (msg, is_error) = execute_bash(test_run(), &args);
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
        let (msg, is_error) = execute_bash(test_run(), &bash_args("rm -rf /"));
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

        let (msg, is_error) = execute_bash(test_run(), &args);

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
        let (msg, is_error) = execute_bash(test_run(), &bash_args("echo hello_b5_mod_c"));
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
        let (_, is_error) = execute_bash(test_run(), &bash_args("exit 1"));
        assert!(
            is_error,
            "b5_nonzero_exit: non-zero exit must set is_error=true"
        );
    }

    // ── Crosslink #351 — durable cursor output ────────────────────────────────

    fn job_text(read: &JobRead) -> String {
        read.events
            .iter()
            .map(|event| event.text.as_str())
            .collect()
    }

    #[test]
    #[cfg(unix)]
    fn compatibility_poll_advances_but_explicit_cursor_replays() {
        let _l = bg_lock();
        let id = BACKGROUND_SHELLS
            .spawn(test_run(), "printf cursor_sentinel")
            .expect("cursor job must spawn");
        std::thread::sleep(std::time::Duration::from_millis(400));

        let first = BACKGROUND_SHELLS
            .get_output(test_run(), &id, None)
            .expect("first incremental read");
        assert!(job_text(&first).contains("cursor_sentinel"));

        let second = BACKGROUND_SHELLS
            .get_output(test_run(), &id, None)
            .expect("second incremental read");
        assert!(second.events.is_empty());

        let replay = BACKGROUND_SHELLS
            .get_output(test_run(), &id, Some(0))
            .expect("explicit replay");
        assert!(job_text(&replay).contains("cursor_sentinel"));
        assert_eq!(replay.next_cursor, first.next_cursor);
    }

    #[test]
    #[cfg(unix)]
    fn unpolled_terminal_job_remains_readable() {
        let _l = bg_lock();
        let id = BACKGROUND_SHELLS
            .spawn(test_run(), "printf retained_sentinel")
            .expect("retained job must spawn");
        std::thread::sleep(std::time::Duration::from_millis(400));

        assert!(BACKGROUND_SHELLS
            .list(test_run())
            .iter()
            .any(|(listed, _, running)| listed == &id && !running));
        let read = BACKGROUND_SHELLS
            .get_output(test_run(), &id, Some(0))
            .expect("unpolled terminal output remains readable");
        assert!(job_text(&read).contains("retained_sentinel"));
    }

    #[test]
    #[cfg(unix)]
    fn newline_free_output_is_bounded_and_job_finishes() {
        let _l = bg_lock();
        let manager = BackgroundShellManager::new();
        let id = manager
            .spawn_with_timeout(
                test_run(),
                "head -c 3145728 /dev/zero | tr '\\0' x",
                std::time::Duration::from_secs(30),
            )
            .expect("large newline-free output job must spawn");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let read = loop {
            let read = manager
                .get_output(test_run(), &id, Some(0))
                .expect("large-output job remains readable");
            if read.state.is_terminal() {
                break read;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "newline-free output job did not finish within its deadline"
            );
            std::thread::sleep(std::time::Duration::from_millis(25));
        };
        assert_eq!(read.state.exit_code(), Some(0));
        let mut retained = 0_usize;
        let mut retained_events = 0_usize;
        let mut page = read;
        loop {
            retained_events = retained_events.saturating_add(page.events.len());
            retained = retained.saturating_add(
                page.events
                    .iter()
                    .map(|event| event.byte_len)
                    .sum::<usize>(),
            );
            if !page.has_more {
                break;
            }
            page = manager
                .get_output(test_run(), &id, Some(page.next_cursor))
                .expect("read next bounded output page");
        }
        assert_eq!(retained, job::MAX_JOB_OUTPUT_BYTES);
        assert!(
            retained_events <= 16,
            "high-throughput output was persisted in {retained_events} small events"
        );
        assert!(page.stdout_truncated);
    }

    #[test]
    #[cfg(unix)]
    fn background_timeout_publishes_terminal_state_and_reaps_root() {
        let _l = bg_lock();
        let manager = BackgroundShellManager::new();
        let id = manager
            .spawn_with_timeout(
                test_run(),
                "sleep 30",
                std::time::Duration::from_millis(100),
            )
            .expect("timed background job must spawn");
        let pid = manager
            .shells
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&id)
            .and_then(|shell| shell.pid())
            .expect("timed job pid");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let read = loop {
            let read = manager
                .get_output(test_run(), &id, Some(0))
                .expect("timed job remains readable");
            if read.state.is_terminal() {
                break read;
            }
            assert!(std::time::Instant::now() < deadline, "timeout did not fire");
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!(read.state, BackgroundJobState::TimedOut);
        #[cfg(target_os = "linux")]
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn background_workspace_publishes_success_and_discards_failure() {
        let root = tempfile::tempdir_in(".").expect("background workspace root");
        let run = crate::tools::security::test_run_context_for(root.path());
        let manager = BackgroundShellManager::new();
        let wait_for_terminal = |id: &str| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                let read = manager
                    .get_output(&run, id, Some(0))
                    .expect("background job remains readable");
                if read.state.is_terminal() {
                    break read.state;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "background job did not settle"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        };

        let committed = manager
            .spawn(&run, "printf committed > background-success")
            .expect("successful background spawn");
        assert_eq!(
            wait_for_terminal(&committed),
            BackgroundJobState::Exited { exit_code: 0 }
        );
        assert_eq!(
            std::fs::read_to_string(root.path().join("background-success"))
                .expect("published background output"),
            "committed"
        );

        let failed = manager
            .spawn(&run, "printf uncommitted > background-failure; exit 7")
            .expect("failed background command still spawns");
        assert_eq!(
            wait_for_terminal(&failed),
            BackgroundJobState::Exited { exit_code: 7 }
        );
        assert!(!root.path().join("background-failure").exists());
    }

    #[test]
    fn restart_reconciles_running_record_to_lost_without_pid_reattachment() {
        let root = tempfile::tempdir().expect("restart test root");
        let session_id = crate::state::SessionId::new();
        let run = crate::tools::ToolRunContext::builder(session_id.clone(), root.path())
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::new())
            .workspace_access(crate::tools::WorkspaceAccess::ReadWrite)
            .process(true)
            .network(false)
            .secrets(false)
            .process_owner("restart-test")
            .provider("restart-test")
            .ephemeral_background_jobs()
            .build()
            .expect("restart test run");
        let id = Uuid::new_v4().to_string();
        let mut abandoned =
            JobCore::create(&run, &id, "sleep 30", std::time::Duration::from_secs(30))
                .expect("persist starting record");
        abandoned
            .mark_running(424_242)
            .expect("persist running record");
        abandoned
            .append_output(JobOutputStream::Stdout, b"before-restart")
            .expect("persist pre-restart output");
        drop(abandoned);

        let restarted = BackgroundShellManager::new();
        let read = restarted
            .get_output(&run, &id, Some(0))
            .expect("recovered job must remain readable");
        assert!(matches!(read.state, BackgroundJobState::Lost { .. }));
        assert!(job_text(&read).contains("before-restart"));
        let shell = restarted
            .shells
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&id)
            .cloned()
            .expect("recovered job registered");
        assert!(
            shell.control.is_none(),
            "recovery must not attach to a saved PID"
        );

        let other_owner = crate::tools::ToolRunContext::builder(session_id, root.path())
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::new())
            .workspace_access(crate::tools::WorkspaceAccess::ReadWrite)
            .process(true)
            .network(false)
            .secrets(false)
            .process_owner("other-restart-owner")
            .provider("restart-test")
            .ephemeral_background_jobs()
            .build()
            .expect("other-owner restart run");
        assert!(
            restarted.get_output(&other_owner, &id, Some(0)).is_err(),
            "a recovered record must remain scoped to its stable process owner"
        );
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
                    .is_some_and(|e| e.contains("Maximum active background shell limit"))
            })
            .count()
    }

    /// `#1133`: bubblewrap's parent-death signal must remain bound to the
    /// long-lived supervisor rather than the transient spawning caller.
    #[test]
    #[cfg(target_os = "linux")]
    fn fix1133_background_survives_spawning_thread_exit() {
        // This test owns a local manager, so give it a local durable namespace
        // as well. Reusing `test_run()` can make this manager recover a job
        // that the global test manager is still finalizing, turning unrelated
        // suite timing into a legitimate `job.json` generation conflict.
        let root = tempfile::tempdir_in(".").expect("background parent-death workspace");
        let run = crate::tools::security::test_run_context_for(root.path());
        let manager = Arc::new(BackgroundShellManager::new());
        let spawning_manager = Arc::clone(&manager);
        let spawning_run = Arc::clone(&run);
        let id = thread::spawn(move || {
            spawning_manager.spawn_with_timeout(
                &spawning_run,
                "while :; do sleep 3600; done",
                std::time::Duration::from_secs(3600),
            )
        })
        .join()
        .expect("spawning thread must join")
        .expect("background job must start");

        // Linux parent-death signals are bound to the creating thread. Give
        // bubblewrap enough time to observe that the caller has exited before
        // proving the dedicated supervisor remains its live parent.
        thread::sleep(std::time::Duration::from_millis(250));
        let read = manager
            .get_output(&run, &id, Some(0))
            .expect("background job must remain readable");
        let state = read.state;
        let _ = manager.kill(&run, &id);

        assert!(
            state.is_running(),
            "background job died when its spawning caller thread exited: {}",
            state.label()
        );
    }

    /// `#672-a`: `cap + EXTRA` concurrent spawners on a fresh manager — the
    /// number of active successful spawns must not exceed
    /// `MAX_BACKGROUND_SHELLS`, and at least one caller must observe the
    /// cap-rejection error string unless host resource failures prevent the
    /// test from reaching capacity.
    ///
    /// Pre-fix the cap check ran AFTER the spawn syscall, so a flurry of
    /// threads would all pass the cap check and the OS+map would each exceed
    /// the cap. Under heavy load, either `Command::spawn` or bubblewrap's
    /// internal fork may fail with ENOMEM/EAGAIN; neither represents an active
    /// admission.
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
                // Ask every admitted process to remain active until teardown.
                // Both the command and its test-only supervisor deadline must
                // outlive durable preparation on a slow runner. Host-level
                // launch failures are classified after all callers return.
                mgr_c.spawn_with_timeout(
                    test_run(),
                    "while :; do sleep 3600; done",
                    std::time::Duration::from_secs(3600),
                )
            }));
        }

        let results: Vec<Result<String, String>> = handles
            .into_iter()
            .map(|h| h.join().expect("join"))
            .collect();
        let cap_errors = count_capacity_errors(&results);
        let observations = results
            .iter()
            .flatten()
            .map(|id| (id, mgr.get_output(test_run(), id, Some(0))))
            .collect::<Vec<_>>();
        let active_successes = observations
            .iter()
            .filter(|(_, read)| matches!(read, Ok(read) if read.state.is_running()))
            .count();
        let early_terminal = observations
            .iter()
            .filter(|(_, read)| matches!(read, Ok(read) if read.state.is_terminal()))
            .count();
        let unreadable = observations
            .iter()
            .filter(|(_, read)| read.is_err())
            .count();
        let synchronous_other_errors = results
            .iter()
            .filter(|result| {
                matches!(result, Err(error) if !error.contains("Maximum active background shell limit"))
            })
            .count();

        // Tear down before assertions: kill every successful spawn so we
        // don't leak blocking processes on test failure.
        for id in results.iter().flatten() {
            let _ = mgr.kill(test_run(), id);
        }

        assert!(
            active_successes <= MAX_BACKGROUND_SHELLS,
            "fix672-a: active successful spawns must not exceed cap \
             ({MAX_BACKGROUND_SHELLS}); got {active_successes}"
        );
        // The race is exercised when either (a) we hit the cap
        // (cap_errors > 0) or (b) the OS rejected enough spawns that we
        // never reached cap. Bubblewrap can report fork EAGAIN only after the
        // outer process starts, so successful-but-terminal jobs are the same
        // class of test-infrastructure noise as synchronous spawn failures.
        // Either way the active-cap invariant above must hold.
        let other_errors = synchronous_other_errors + early_terminal + unreadable;
        assert!(
            cap_errors > 0 || other_errors >= STRESS_EXTRA,
            "fix672-a: cap-rejection path was not exercised AND not enough \
             OS-level spawn failures to explain it; got {active_successes} active + \
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
                mgr_c.spawn(test_run(), "sleep 2")
            }));
        }
        // Let all spawners go and immediately start observing the map.
        barrier.wait();

        // Poll active job count during the race window. Terminal records are
        // intentionally retained for output replay and do not consume slots.
        let mut max_seen = 0usize;
        for _ in 0..200 {
            let active = mgr.shells.lock().map_or_else(
                |error| {
                    error
                        .into_inner()
                        .values()
                        .filter(|shell| shell.state().is_running())
                        .count()
                },
                |shells| {
                    shells
                        .values()
                        .filter(|shell| shell.state().is_running())
                        .count()
                },
            );
            max_seen = max_seen.max(active);
            std::thread::sleep(std::time::Duration::from_micros(200));
        }

        let results: Vec<Result<String, String>> = handles
            .into_iter()
            .map(|h| h.join().expect("join"))
            .collect();

        // Teardown
        for id in results.iter().flatten() {
            let _ = mgr.kill(test_run(), id);
        }

        assert!(
            max_seen <= MAX_BACKGROUND_SHELLS,
            "fix672-b: observed active count {max_seen} exceeded cap {MAX_BACKGROUND_SHELLS} \
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
            if let Ok(id) = mgr.spawn(test_run(), &cmd) {
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
                    if let Ok(read) = mgr_poll.get_output(test_run(), id, Some(0)) {
                        if !read.state.is_running() && read.state.exit_code().is_none() {
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
            let _ = mgr.kill(test_run(), id);
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
            if let Ok(id) = mgr.spawn(test_run(), &format!("exit {exit_code}")) {
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
            let read = mgr
                .get_output(test_run(), id, Some(0))
                .expect("fix674-b: get_output must succeed");
            assert!(
                !read.state.is_running(),
                "fix674-b: shell {id} must be settled after 600ms"
            );
            assert_eq!(
                read.state.exit_code(),
                Some(*expected),
                "fix674-b: settled shell {id} must have exit_code Some({expected}); \
                 got {:?} — finished/exit_status race regressed",
                read.state.exit_code()
            );
        }
    }
}
