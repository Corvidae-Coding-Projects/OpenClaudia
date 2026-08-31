//! Static analysis execution for VDD reviews.
//!
//! Provides bounded process execution with timeout for configured analyzers.

use std::ffi::OsString;
use std::time::Duration;

use serde::Serialize;

use crate::vdd::transport::VddReviewBudget;

const VDD_ANALYZER_TRUNCATED_MARKER: &[u8] = b"\n[VDD analyzer output truncated]\n";

// ==========================================================================
// StaticAnalysisResult
// ==========================================================================

/// Result of running a static analysis command
#[derive(Debug, Clone, Serialize)]
pub struct StaticAnalysisResult {
    pub command: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub passed: bool,
}

// ==========================================================================
// Shell Command Execution
// ==========================================================================

/// Run a shell command with timeout, returning structured result.
///
/// # Security
/// The command string is parsed with POSIX shlex into argv tokens and
/// executed via `Command::new(argv[0]).args(&argv[1..])` — **no shell is
/// invoked**. Previously this function routed through `sh -c` / `cmd /C`
/// with the raw string, allowing shell-metacharacter injection from any
/// config-sourced command (crosslink #277). Pipelines, redirections, and
/// `&&`/`||` are therefore no longer supported in this entry point; callers
/// that need them must compose subprocess invocations at the Rust level.
#[allow(clippy::too_many_lines)] // Parsing, sandbox admission, bounded execution, and result mapping are atomic.
pub(crate) async fn run_shell_command(
    run: &std::sync::Arc<crate::tools::ToolRunContext>,
    budget: &VddReviewBudget,
    command: &str,
    timeout: Duration,
) -> StaticAnalysisResult {
    let tokens: Vec<String> = match shlex::split(command) {
        Some(t) if !t.is_empty() => t,
        Some(_) => {
            return StaticAnalysisResult {
                command: command.to_string(),
                exit_code: -1,
                stdout: String::new(),
                stderr: "Empty command".to_string(),
                passed: false,
            };
        }
        None => {
            return StaticAnalysisResult {
                command: command.to_string(),
                exit_code: -1,
                stdout: String::new(),
                stderr: "Could not parse command (unbalanced quotes or unsupported escape)"
                    .to_string(),
                passed: false,
            };
        }
    };

    let Some((program, argv_rest)) = tokens.split_first() else {
        return StaticAnalysisResult {
            command: command.to_string(),
            exit_code: -1,
            stdout: String::new(),
            stderr: "Empty command".to_string(),
            passed: false,
        };
    };
    let cwd = run.working_directory();
    let args: Vec<OsString> = argv_rest.iter().map(OsString::from).collect();
    let resolved_program = match run.resolve_executable(program) {
        Ok(path) => path,
        Err(error) => {
            return StaticAnalysisResult {
                command: command.to_string(),
                exit_code: -1,
                stdout: String::new(),
                stderr: format!("Static-analysis executable unavailable: {error}"),
                passed: false,
            };
        }
    };
    let sandboxed = match crate::tools::sandboxed_process_command(
        run,
        crate::tools::SandboxProfile::StaticAnalyzer,
        resolved_program.as_os_str(),
        &args,
        cwd,
    ) {
        Ok(command) => command,
        Err(error) => {
            return StaticAnalysisResult {
                command: command.to_string(),
                exit_code: -1,
                stdout: String::new(),
                stderr: format!("Static-analysis sandbox unavailable: {error}"),
                passed: false,
            };
        }
    };
    if let Err(error) = budget.begin_process() {
        return StaticAnalysisResult {
            command: command.to_string(),
            exit_code: -1,
            stdout: String::new(),
            stderr: format!("Static-analysis budget denied process: {error}"),
            passed: false,
        };
    }
    let timeout = match budget.remaining_time() {
        Ok(remaining) => timeout.min(remaining),
        Err(error) => {
            budget.abandon_process();
            return StaticAnalysisResult {
                command: command.to_string(),
                exit_code: -1,
                stdout: String::new(),
                stderr: error,
                passed: false,
            };
        }
    };
    let result = crate::tools::command::run_prepared_run_owned(
        run,
        sandboxed,
        program,
        crate::tools::command::ProcessLimits::new(timeout).with_output_limit(
            VddReviewBudget::analyzer_output_limit(),
            VDD_ANALYZER_TRUNCATED_MARKER,
        ),
        None,
    )
    .await;

    let retained_bytes = match &result {
        Ok(output) => output
            .stdout
            .bytes
            .len()
            .saturating_add(output.stderr.bytes.len()),
        Err(error) => error.partial().map_or(0, |partial| {
            partial
                .stdout
                .bytes
                .len()
                .saturating_add(partial.stderr.bytes.len())
        }),
    };
    if let Err(error) = budget.finish_process(retained_bytes) {
        return StaticAnalysisResult {
            command: command.to_string(),
            exit_code: -1,
            stdout: String::new(),
            stderr: format!("Static-analysis budget reconciliation failed: {error}"),
            passed: false,
        };
    }

    match result {
        Ok(output) => {
            if output.stdout.truncated || output.stderr.truncated {
                return StaticAnalysisResult {
                    command: command.to_string(),
                    exit_code: output.status.code().unwrap_or(-1),
                    stdout: String::from_utf8_lossy(&output.stdout.bytes).to_string(),
                    stderr: "Static-analysis output exceeded the bounded review limit".to_string(),
                    passed: false,
                };
            }
            let output = output.into_std_output();
            let exit_code = output.status.code().unwrap_or(-1);
            StaticAnalysisResult {
                command: command.to_string(),
                exit_code,
                stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                passed: exit_code == 0,
            }
        }
        Err(e) => StaticAnalysisResult {
            command: command.to_string(),
            exit_code: -1,
            stdout: String::new(),
            stderr: format!("Command failed to execute: {e}"),
            passed: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_run() -> &'static std::sync::Arc<crate::tools::ToolRunContext> {
        crate::tools::security::test_run_context()
    }

    #[tokio::test]
    async fn run_shell_command_rejects_empty_command() {
        let budget = VddReviewBudget::admit(test_run(), &test_config(), false).expect("budget");
        let result = run_shell_command(test_run(), &budget, "   ", Duration::from_secs(1)).await;

        assert_eq!(result.exit_code, -1);
        assert_eq!(result.stderr, "Empty command");
        assert!(!result.passed);
    }

    #[tokio::test]
    async fn run_shell_command_rejects_unbalanced_quotes() {
        let budget = VddReviewBudget::admit(test_run(), &test_config(), false).expect("budget");
        let result = run_shell_command(
            test_run(),
            &budget,
            "echo 'unterminated",
            Duration::from_secs(1),
        )
        .await;

        assert_eq!(result.exit_code, -1);
        assert!(result.stderr.contains("Could not parse command"));
        assert!(!result.passed);
    }

    #[tokio::test]
    async fn run_shell_command_reports_nonzero_analyzer_exit_as_failed() {
        let budget = VddReviewBudget::admit(test_run(), &test_config(), false).expect("budget");
        let result = run_shell_command(test_run(), &budget, "false", Duration::from_secs(1)).await;

        assert_eq!(result.exit_code, 1);
        assert!(!result.passed);
    }

    #[tokio::test]
    #[cfg(target_os = "linux")]
    async fn analyzer_profile_blocks_host_files_and_network_syscalls() {
        let outside = tempfile::NamedTempFile::new().expect("host sentinel");
        std::fs::write(outside.path(), "analyzer-secret").expect("sentinel");
        let script = format!(
            r#"
import errno, pathlib, socket
path = pathlib.Path({path:?})
file_blocked = not path.exists()
try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    network_blocked = False
except OSError as error:
    network_blocked = error.errno in (errno.EPERM, errno.EACCES)
print("analyzer_confined=" + str(file_blocked and network_blocked).lower())
"#,
            path = outside.path().to_string_lossy()
        );
        let command = format!(
            "python3 -c {}",
            shlex::try_quote(&script).expect("quote analyzer probe")
        );
        let budget = VddReviewBudget::admit(test_run(), &test_config(), false).expect("budget");
        let result = run_shell_command(test_run(), &budget, &command, Duration::from_secs(5)).await;
        assert!(result.passed, "analyzer probe failed: {}", result.stderr);
        assert!(result.stdout.contains("analyzer_confined=true"));
        assert!(!result.stdout.contains("analyzer-secret"));
    }

    fn test_config() -> crate::config::VddConfig {
        crate::config::VddConfig {
            enabled: true,
            ..crate::config::VddConfig::default()
        }
    }
}
