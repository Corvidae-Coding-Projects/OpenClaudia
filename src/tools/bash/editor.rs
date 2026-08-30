//! Supervised execution for an explicitly user-selected external editor.

use crate::runtime::BudgetAmounts;
use crate::tools::command::{CommandError, ProcessLimits};
use crate::tools::{SandboxProfile, ToolRunContext};
use std::ffi::OsString;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::time::Duration;

const MAX_USER_EDITOR_PLAN_BYTES: usize = 10 * 1_024 * 1_024;

type StagedPlan = (
    tempfile::NamedTempFile,
    PathBuf,
    crate::runtime::ContentDigest,
);

/// Terminal outcome from a supervised user-origin editor process.
#[derive(Debug)]
pub struct UserEditorExecution {
    status: ExitStatus,
}

impl UserEditorExecution {
    /// Consume the receipt and return the editor's terminal exit status.
    #[must_use]
    pub const fn into_status(self) -> ExitStatus {
        self.status
    }
}

/// Typed editor failure preserving whether a child process started.
#[derive(Debug)]
pub enum UserEditorError {
    Rejected(String),
    Partial {
        message: String,
        status: Option<ExitStatus>,
    },
}

impl std::fmt::Display for UserEditorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(message) | Self::Partial { message, .. } => formatter.write_str(message),
        }
    }
}

impl std::error::Error for UserEditorError {}

/// Run a user-selected editor against one capability-bound file.
///
/// Message composition is confined to the run's private scratch directory.
/// The canonical plan resource is copied into scratch and atomically published
/// only after a successful editor exit. The shared supervisor owns deadline,
/// cancellation, termination, and reap in both cases.
///
/// # Errors
///
/// Returns [`UserEditorError::Rejected`] before spawn when authority or input
/// validation fails, and [`UserEditorError::Partial`] after a child starts.
pub fn execute_user_editor(
    run: &ToolRunContext,
    program: &Path,
    editor_args: &[OsString],
    target: &Path,
    timeout: Duration,
) -> Result<UserEditorExecution, UserEditorError> {
    if timeout.is_zero() {
        return Err(UserEditorError::Rejected(
            "External editor timeout must be greater than zero".to_string(),
        ));
    }
    if !program.is_absolute() {
        return Err(UserEditorError::Rejected(
            "External editor executable must be resolved by the run capability".to_string(),
        ));
    }

    let scratch = run.private_temp_root().canonicalize().map_err(|error| {
        UserEditorError::Rejected(format!(
            "Cannot resolve run-owned editor scratch directory: {error}"
        ))
    })?;
    let target = target.canonicalize().map_err(|error| {
        UserEditorError::Rejected(format!(
            "Cannot resolve run-owned editor target '{}': {error}",
            target.display()
        ))
    })?;
    let (editor_target, staged_plan) = prepare_editor_target(run, &scratch, target)?;

    let mut args = Vec::with_capacity(editor_args.len().saturating_add(1));
    args.extend_from_slice(editor_args);
    args.push(editor_target.as_os_str().to_os_string());
    let prepared = super::sandbox::sandboxed_process_command(
        run,
        SandboxProfile::UserEditor,
        program.as_os_str(),
        &args,
        &scratch,
    )
    .map_err(UserEditorError::Rejected)?;
    let budget = run
        .budget()
        .reserve(BudgetAmounts {
            concurrent_calls: 1,
            ..BudgetAmounts::default()
        })
        .map_err(|error| {
            UserEditorError::Rejected(format!("Run budget denied external editor: {error}"))
        })?;

    tracing::info!(
        target: "openclaudia::user_editor",
        event = "user_editor_admitted",
        run_id = %run.run_id(),
        generation = %run.generation(),
        timeout_ms = timeout.as_millis(),
        "Admitted one supervised user-origin editor"
    );
    let outcome = crate::tools::command::run_prepared_run_owned_sync(
        run,
        prepared,
        "external editor",
        ProcessLimits::new(timeout).with_inherited_terminal_stdio(),
    );
    let started = match &outcome {
        Ok(_) => true,
        Err(error) => error.partial().is_some(),
    };
    let mut result = match outcome {
        Ok(output) => Ok(UserEditorExecution {
            status: output.status,
        }),
        Err(error) => command_error(&error),
    };
    result = publish_staged_plan(run, staged_plan, result);
    if let Err(error) = budget.commit() {
        result = match result {
            Ok(execution) => Err(UserEditorError::Partial {
                message: format!("External editor completed but budget accounting failed: {error}"),
                status: Some(execution.status),
            }),
            Err(UserEditorError::Partial { message, status }) => Err(UserEditorError::Partial {
                message: format!("{message}; budget accounting failed: {error}"),
                status,
            }),
            Err(UserEditorError::Rejected(message)) => Err(UserEditorError::Rejected(format!(
                "{message}; budget accounting failed: {error}"
            ))),
        };
    }
    tracing::info!(
        target: "openclaudia::user_editor",
        event = "user_editor_finished",
        run_id = %run.run_id(),
        started,
        success = result.is_ok(),
        "Settled one supervised user-origin editor"
    );
    result
}

fn prepare_editor_target(
    run: &ToolRunContext,
    scratch: &Path,
    target: PathBuf,
) -> Result<(PathBuf, Option<StagedPlan>), UserEditorError> {
    if target.starts_with(scratch) && run.permits_write(&target) {
        Ok((target, None))
    } else if target == run.agent_plan_file() && run.permits_write(&target) {
        let (_, original) = crate::tools::file::read_bounded_capability_text_attachment(
            run,
            &target.to_string_lossy(),
            MAX_USER_EDITOR_PLAN_BYTES,
        )
        .map_err(UserEditorError::Rejected)?;
        if original.len() > MAX_USER_EDITOR_PLAN_BYTES {
            return Err(UserEditorError::Rejected(format!(
                "Plan file '{}' exceeds the {}-byte editor limit",
                target.display(),
                MAX_USER_EDITOR_PLAN_BYTES
            )));
        }
        let expected = crate::runtime::ContentDigest::sha256(original.as_bytes());
        let mut staging = tempfile::Builder::new()
            .prefix("plan-editor-")
            .suffix(".md")
            .tempfile_in(scratch)
            .map_err(|error| {
                UserEditorError::Rejected(format!("Cannot stage plan for editing: {error}"))
            })?;
        staging.write_all(original.as_bytes()).map_err(|error| {
            UserEditorError::Rejected(format!("Cannot stage plan for editing: {error}"))
        })?;
        staging.as_file().sync_all().map_err(|error| {
            UserEditorError::Rejected(format!("Cannot synchronize staged plan: {error}"))
        })?;
        let staging_path = staging.path().to_path_buf();
        Ok((staging_path, Some((staging, target, expected))))
    } else {
        Err(UserEditorError::Rejected(format!(
            "External editor target '{}' is not a writable run-owned editor resource",
            target.display()
        )))
    }
}

fn publish_staged_plan(
    run: &ToolRunContext,
    staged_plan: Option<StagedPlan>,
    result: Result<UserEditorExecution, UserEditorError>,
) -> Result<UserEditorExecution, UserEditorError> {
    let Some((staging, plan_target, expected)) = staged_plan else {
        return result;
    };
    match result {
        Ok(execution) if execution.status.success() => {
            let status = execution.status;
            match crate::tools::file::read_bounded_capability_text_attachment(
                run,
                &staging.path().to_string_lossy(),
                MAX_USER_EDITOR_PLAN_BYTES,
            ) {
                Ok((_, edited)) => crate::tools::file::replace_capability_text_generation(
                    run,
                    &plan_target,
                    expected,
                    &edited,
                    MAX_USER_EDITOR_PLAN_BYTES,
                )
                .map_or_else(
                    |message| {
                        Err(UserEditorError::Partial {
                            message,
                            status: Some(status),
                        })
                    },
                    |()| Ok(UserEditorExecution { status }),
                ),
                Err(message) => Err(UserEditorError::Partial {
                    message: format!(
                        "External editor completed but staged plan was invalid: {message}"
                    ),
                    status: Some(status),
                }),
            }
        }
        other => other,
    }
}

fn command_error(error: &CommandError) -> Result<UserEditorExecution, UserEditorError> {
    error.partial().map_or_else(
        || Err(UserEditorError::Rejected(error.to_string())),
        |partial| {
            Err(UserEditorError::Partial {
                message: format!("External editor failed after starting: {error}"),
                status: partial.status,
            })
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn editor_run(root: &Path, process: bool) -> std::sync::Arc<ToolRunContext> {
        ToolRunContext::builder(crate::state::SessionId::new(), root)
            .workspace_access(crate::tools::WorkspaceAccess::ReadWrite)
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(std::collections::HashMap::new())
            .process(process)
            .network(false)
            .secrets(false)
            .provider("editor-test")
            .build()
            .expect("editor run")
    }

    #[test]
    fn editor_refuses_workspace_file_without_plan_authority() {
        let root = tempfile::tempdir().expect("workspace");
        let target = root.path().join("message.txt");
        std::fs::write(&target, "unchanged").expect("target");
        let run = editor_run(root.path(), false);

        let error = execute_user_editor(
            &run,
            Path::new("/bin/true"),
            &[],
            &target,
            Duration::from_secs(1),
        )
        .expect_err("ordinary workspace files are not editor scratch authority");
        assert!(matches!(error, UserEditorError::Rejected(_)));
        assert_eq!(
            std::fs::read_to_string(target).expect("unchanged"),
            "unchanged"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn plan_editor_publishes_only_successful_staged_content() {
        let root = tempfile::tempdir().expect("workspace");
        let run = editor_run(root.path(), true);
        std::fs::create_dir_all(
            run.agent_plan_file()
                .parent()
                .expect("plan parent directory"),
        )
        .expect("create plan directory");
        std::fs::write(run.agent_plan_file(), "# original\n").expect("write original plan");

        let execution = execute_user_editor(
            &run,
            Path::new("/bin/sh"),
            &[
                OsString::from("-c"),
                OsString::from("printf '# edited\\n' > \"$1\""),
                OsString::from("plan-editor-test"),
            ],
            run.agent_plan_file(),
            Duration::from_secs(5),
        )
        .expect("plan editor succeeds through scratch staging");

        assert!(execution.into_status().success());
        assert_eq!(
            std::fs::read_to_string(run.agent_plan_file()).expect("published plan"),
            "# edited\n"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn failed_plan_editor_leaves_published_plan_unchanged() {
        let root = tempfile::tempdir().expect("workspace");
        let run = editor_run(root.path(), true);
        std::fs::create_dir_all(
            run.agent_plan_file()
                .parent()
                .expect("plan parent directory"),
        )
        .expect("create plan directory");
        std::fs::write(run.agent_plan_file(), "# original\n").expect("write original plan");

        let execution = execute_user_editor(
            &run,
            Path::new("/bin/sh"),
            &[
                OsString::from("-c"),
                OsString::from("printf '# incomplete\\n' > \"$1\"; exit 7"),
                OsString::from("plan-editor-test"),
            ],
            run.agent_plan_file(),
            Duration::from_secs(5),
        )
        .expect("nonzero editor status remains observable");

        assert_eq!(execution.into_status().code(), Some(7));
        assert_eq!(
            std::fs::read_to_string(run.agent_plan_file()).expect("unchanged plan"),
            "# original\n"
        );
    }
}
