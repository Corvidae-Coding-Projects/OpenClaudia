/// Prompt user for permission to perform a sensitive operation
pub fn prompt_permission(
    operation: &str,
    details: &str,
    approvals: &mut openclaudia::permissions::LocalApprovalCache,
) -> bool {
    use std::io::{self, Write};

    if let Some(decision) = approvals.decision(operation, details) {
        return decision == openclaudia::permissions::LocalApprovalDecision::Allowed;
    }

    println!("\n=== Permission Required ===");
    println!("Operation: {operation}");
    println!("Details: {details}");
    println!();
    println!("  [y] Allow once");
    println!("  [n] Deny");
    println!("  [a] Always allow this");
    println!("  [d] Always deny this");
    print!("\nChoice [y/n/a/d]: ");
    io::stdout().flush().ok();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }

    match input.trim().to_lowercase().as_str() {
        "y" | "yes" => true,
        "a" | "always" => {
            approvals.remember_allowed(
                operation,
                details,
                openclaudia::permissions::ApprovalProvenance::InteractiveUser,
            );
            println!("(Will allow this exact operation for a bounded session receipt)\n");
            true
        }
        "d" => {
            approvals.remember_denied(
                operation,
                details,
                openclaudia::permissions::ApprovalProvenance::InteractiveUser,
            );
            println!("(Will deny this exact operation for the session)\n");
            false
        }
        _ => {
            println!("(Denied)\n");
            false
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellCommandExecution {
    pub cwd: std::path::PathBuf,
    pub command: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

/// Execute a shell command and print output (with permission check)
pub fn execute_shell_command_with_permission(
    cmd: &str,
    permissions: &mut openclaudia::permissions::LocalApprovalCache,
) -> Option<ShellCommandExecution> {
    let dangerous_patterns = [
        // Destructive file operations
        "rm -rf",
        "rm -fr",
        "rmdir /s",
        "del /f",
        "del /q",
        // Disk/filesystem operations
        "format",
        "mkfs",
        "dd if=",
        "dd of=",
        // Device writes
        "> /dev/",
        ">> /dev/",
        // Privileged destructive ops
        "sudo rm",
        "sudo dd",
        "sudo mkfs",
        // Permission changes (recursive)
        "chmod -R 777",
        "chmod -R 000",
        "chown -R",
        // Git destructive ops
        "git push --force",
        "git push -f",
        "git reset --hard",
        "git clean -fd",
        // Process/system
        "kill -9",
        "killall",
        "pkill",
        // Python/shell destructive
        "shutil.rmtree",
        "os.remove",
    ];
    let is_dangerous = dangerous_patterns.iter().any(|p| cmd.contains(p));

    if is_dangerous && !prompt_permission("Dangerous Shell Command", cmd, permissions) {
        println!("Command blocked.\n");
        return None;
    }

    execute_shell_command_internal(cmd)
}

fn resolved_process_command(binary: &str) -> Result<std::process::Command, String> {
    which::which(binary)
        .map(std::process::Command::new)
        .map_err(|e| format!("{binary} binary not found on PATH: {e}"))
}

/// Execute a shell command and print output
pub fn execute_shell_command_internal(cmd: &str) -> Option<ShellCommandExecution> {
    println!();
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(err) => {
            eprintln!("Failed to determine current directory: {err}");
            return None;
        }
    };

    #[cfg(windows)]
    let output = resolved_process_command("cmd").and_then(|mut command| {
        command
            .args(["/C", cmd])
            .output()
            .map_err(|e| e.to_string())
    });

    #[cfg(not(windows))]
    let output = resolved_process_command("sh").and_then(|mut command| {
        command
            .args(["-c", cmd])
            .output()
            .map_err(|e| e.to_string())
    });

    match &output {
        Ok(output) => {
            if !output.stdout.is_empty() {
                print!("{}", String::from_utf8_lossy(&output.stdout));
            }
            if !output.stderr.is_empty() {
                eprint!("{}", String::from_utf8_lossy(&output.stderr));
            }
            if !output.status.success() {
                if let Some(code) = output.status.code() {
                    println!("(exit code: {code})");
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to execute command: {e}");
        }
    }
    println!();

    output.ok().map(|output| ShellCommandExecution {
        cwd,
        command: cmd.to_string(),
        exit_code: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repl_permission_shells_use_resolved_binaries() {
        let source = include_str!("permissions.rs");
        let cfg_test = source
            .find("#[cfg(test)]")
            .expect("test marker must be present");
        let production = &source[..cfg_test];

        assert!(
            !production.contains("Command::new(\"cmd\")")
                && !production.contains("std::process::Command::new(\"cmd\")"),
            "permission shell runner must not invoke bare cmd"
        );
        assert!(
            !production.contains("Command::new(\"sh\")")
                && !production.contains("std::process::Command::new(\"sh\")"),
            "permission shell runner must not invoke bare sh"
        );
        assert!(
            production.contains("which::which(binary)"),
            "permission shell runner must resolve shell binaries through the Rust resolver"
        );
    }

    #[test]
    fn shell_command_internal_returns_execution_metadata() {
        let execution = execute_shell_command_internal("printf openclaudia-ledger")
            .expect("shell command should run");

        assert_eq!(execution.command, "printf openclaudia-ledger");
        assert_eq!(execution.exit_code, 0);
        assert_eq!(execution.stdout, "openclaudia-ledger");
        assert!(execution.stderr.is_empty());
        assert!(execution.cwd.is_absolute());
    }
}
