use super::BACKGROUND_SHELLS;
use crate::tools::args::ToolArgError;
use serde_json::Value;
use std::collections::HashMap;
#[cfg(not(unix))]
use std::process::Command;

/// Kill a background shell
pub fn execute_kill_shell(args: &HashMap<String, Value>) -> (String, bool) {
    let shell_id = match args.get("shell_id") {
        None => return ("Missing 'shell_id' argument".to_string(), true),
        Some(Value::String(shell_id)) => shell_id.as_str(),
        Some(_) => {
            return ToolArgError::WrongType {
                key: "shell_id",
                expected: "string",
            }
            .into_tool_error();
        }
    };

    match BACKGROUND_SHELLS.kill(shell_id) {
        Ok(msg) => (msg, false),
        Err(e) => (e, true),
    }
}

/// Kill every background shell owned by an agent/session id.
pub fn execute_kill_shells_for_agent(args: &HashMap<String, Value>) -> (String, bool) {
    let agent_id = match args.get("agent_id") {
        None => return ("Missing 'agent_id' argument".to_string(), true),
        Some(Value::String(agent_id)) => agent_id.as_str(),
        Some(_) => {
            return ToolArgError::WrongType {
                key: "agent_id",
                expected: "string",
            }
            .into_tool_error();
        }
    };
    if agent_id.is_empty() {
        return ("Missing 'agent_id' argument".to_string(), true);
    }
    let caller = crate::tools::todo::current_session_key();
    if agent_id != caller {
        tracing::warn!(
            target: "openclaudia::bash",
            event = "cross_session_shell_cleanup_denied",
            caller,
            requested_owner = agent_id,
            "Denied model-requested cleanup of another session's processes"
        );
        return (
            "Cannot terminate background shells owned by another session".to_string(),
            true,
        );
    }

    (BACKGROUND_SHELLS.kill_for_agent(agent_id), false)
}

/// Terminate a process and its entire process group.
///
/// On Unix, sends SIGTERM to the process group (negative PID) via `libc::kill`,
/// waits up to 2 seconds for the process to exit, then escalates to SIGKILL if
/// needed. Uses direct syscalls — no PATH lookup, no fork/exec.
/// The process must have been spawned with `process_group(0)` for group
/// killing to work correctly.
///
/// On Windows, uses `taskkill /T` which terminates the process tree.
pub fn terminate_process_tree(pid: u32) {
    #[cfg(target_os = "linux")]
    {
        terminate_linux_process_tree(pid);
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    {
        use std::time::{Duration, Instant};

        // libc::pid_t is i32 on supported Unix targets. Child PIDs returned
        // by the OS fit that range, but this public helper can be called with
        // any u32.
        let Ok(signed_pid) = i32::try_from(pid) else {
            tracing::debug!(
                pid,
                "terminate_process_tree: PID exceeds supported Unix pid_t range"
            );
            return;
        };
        // Negative pid targets the entire process group (POSIX kill(2)).
        let process_group_id = -signed_pid;

        // Step 1: Send SIGTERM to the entire process group.
        // SAFETY: process_group_id is a valid negative process-group ID derived
        // from a u32 PID; SIGTERM is a well-defined signal constant. kill(2) is
        // async-signal-safe and does not dereference pointers.
        let sigterm_result = unsafe { libc::kill(process_group_id, libc::SIGTERM) };
        if sigterm_result != 0 {
            tracing::debug!(
                pid,
                errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
                "terminate_process_tree: SIGTERM to process group failed"
            );
        }

        // Step 2: Wait up to 2 seconds for the process to exit.
        // kill(pid, 0) returns 0 if the process exists, -1 (ESRCH) if not.
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut exited = false;
        while Instant::now() < deadline {
            // SAFETY: signed_pid is a valid pid_t; signal 0 never delivers,
            // it only checks process existence. No pointers involved.
            let exists = unsafe { libc::kill(signed_pid, 0) };
            if exists != 0 {
                // ESRCH: process no longer exists
                exited = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        // Step 3: If still alive, send SIGKILL to the process group.
        if !exited {
            // SAFETY: same invariants as the SIGTERM call above; SIGKILL is
            // a well-defined signal constant that cannot be caught or ignored.
            let sigkill_result = unsafe { libc::kill(process_group_id, libc::SIGKILL) };
            if sigkill_result != 0 {
                tracing::debug!(
                    pid,
                    errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0),
                    "terminate_process_tree: SIGKILL to process group failed"
                );
            }

            // Brief wait for SIGKILL to take effect
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    #[cfg(not(unix))]
    {
        // /T kills the process tree, /F forces termination
        if let Ok(taskkill) = which::which("taskkill") {
            let _ = Command::new(taskkill)
                .args(["/PID", &pid.to_string(), "/T", "/F"])
                .output();
        }
    }
}

#[cfg(target_os = "linux")]
fn terminate_linux_process_tree(pid: u32) {
    use std::collections::{HashSet, VecDeque};
    use std::time::{Duration, Instant};

    let Ok(root) = i32::try_from(pid) else {
        return;
    };
    let descendants = || {
        let mut found = Vec::new();
        let mut seen = HashSet::from([root]);
        let mut queue = VecDeque::from([root]);
        while let Some(parent) = queue.pop_front() {
            let task_dir = format!("/proc/{parent}/task");
            let Ok(tasks) = std::fs::read_dir(task_dir) else {
                continue;
            };
            for task in tasks.flatten() {
                let children_path = task.path().join("children");
                let Ok(children) = std::fs::read_to_string(children_path) else {
                    continue;
                };
                for child in children
                    .split_whitespace()
                    .filter_map(|value| value.parse::<i32>().ok())
                {
                    if child > 0 && seen.insert(child) {
                        found.push(child);
                        queue.push_back(child);
                    }
                }
            }
        }
        found
    };
    let signal_tree = |signal| {
        let mut targets = descendants();
        targets.reverse();
        for target in targets {
            unsafe {
                libc::kill(target, signal);
            }
        }
        // Also cover conventional process-group children, then the wrapper.
        unsafe {
            libc::kill(-root, signal);
            libc::kill(root, signal);
        }
    };

    signal_tree(libc::SIGTERM);
    // A long grace period makes cancellation itself a denial-of-service
    // vector, and a terminated-but-not-yet-reaped wrapper remains visible to
    // `kill(pid, 0)` as a zombie. Give cooperative children a short grace,
    // then deterministically escalate; the owning caller performs the reap.
    let deadline = Instant::now() + Duration::from_millis(250);
    while Instant::now() < deadline {
        let root_exists = unsafe { libc::kill(root, 0) } == 0;
        if !root_exists && descendants().is_empty() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // Re-scan immediately before SIGKILL so children forked by a signal
    // handler or daemonization attempt are included.
    signal_tree(libc::SIGKILL);
    std::thread::sleep(Duration::from_millis(100));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn windows_taskkill_uses_resolved_binary() {
        let source = include_str!("kill.rs");
        let cfg_test = source
            .find("#[cfg(test)]")
            .expect("test marker must be present");
        let production = &source[..cfg_test];

        assert!(
            !production.contains("Command::new(\"taskkill\")"),
            "production kill helper must not invoke bare taskkill"
        );
        assert!(
            production.contains("which::which(\"taskkill\")"),
            "production kill helper must locate taskkill through the Rust resolver"
        );
    }

    #[cfg(unix)]
    #[test]
    fn terminate_process_tree_ignores_pid_outside_pid_t_range() {
        let out_of_range_pid = (i32::MAX as u32) + 1;
        terminate_process_tree(out_of_range_pid);
    }

    // ── Phase 2 pinning tests (crosslink #541) ────────────────────────────────
    // Pins OC's CURRENT kill_shell contracts per spec crosslink #526 §B2.

    /// B2-kill-a: missing `shell_id` arg → `is_error=true`, message contains "Missing".
    ///
    /// OC source: kill.rs:8-10 — arg check fires before any `BACKGROUND_SHELLS` call.
    #[test]
    fn b2_kill_missing_shell_id_arg() {
        let args: HashMap<String, serde_json::Value> = HashMap::new();
        let (msg, is_error) = execute_kill_shell(&args);
        assert!(is_error, "b2_kill_missing_arg: must be is_error=true");
        assert!(
            msg.contains("Missing"),
            "b2_kill_missing_arg: message must contain 'Missing'; got: {msg}"
        );
    }

    #[test]
    fn b2_kill_rejects_non_string_shell_id_arg() {
        let mut args = HashMap::new();
        args.insert("shell_id".to_string(), serde_json::json!(42));
        let (msg, is_error) = execute_kill_shell(&args);
        assert!(is_error, "non-string shell_id must be rejected: {msg}");
        assert!(
            msg.contains("Invalid 'shell_id' argument: expected string"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn kill_shells_for_agent_rejects_non_string_agent_id_arg() {
        let mut args = HashMap::new();
        args.insert("agent_id".to_string(), serde_json::json!(42));
        let (msg, is_error) = execute_kill_shells_for_agent(&args);
        assert!(is_error, "non-string agent_id must be rejected: {msg}");
        assert!(
            msg.contains("Invalid 'agent_id' argument: expected string"),
            "unexpected error: {msg}"
        );
    }

    /// B2-kill-b: unknown `shell_id` → `is_error=true`, message contains "not found".
    ///
    /// OC source: kill.rs:13-15 via `BackgroundShellManager::kill` (mod.rs:246-248).
    #[test]
    fn b2_kill_unknown_shell_id() {
        let mut args = HashMap::new();
        args.insert(
            "shell_id".to_string(),
            serde_json::Value::String("deadbeef".to_string()),
        );
        let (msg, is_error) = execute_kill_shell(&args);
        assert!(is_error, "b2_kill_unknown_id: must be is_error=true");
        assert!(
            msg.contains("not found"),
            "b2_kill_unknown_id: message must contain 'not found'; got: {msg}"
        );
    }

    /// B2-kill-c: kill of a running shell returns `is_error=false` and a
    /// confirmation message containing "terminated" and the `shell_id`.
    ///
    /// OC source: kill.rs:12-14 (Ok branch), mod.rs:242-245.
    /// Uses `BACKGROUND_SHELLS.spawn` to create a real process.
    #[test]
    #[cfg(unix)]
    fn b2_kill_running_shell_returns_terminated_message() {
        // Spawn a long-running background shell via the manager
        let shell_id = super::super::BACKGROUND_SHELLS
            .spawn("sleep 30")
            .expect("b2_kill_running: spawn must succeed");

        let mut args = HashMap::new();
        args.insert(
            "shell_id".to_string(),
            serde_json::Value::String(shell_id.clone()),
        );
        let (msg, is_error) = execute_kill_shell(&args);

        assert!(
            !is_error,
            "b2_kill_running: must be is_error=false; got: {msg}"
        );
        assert!(
            msg.contains("terminated"),
            "b2_kill_running: message must contain 'terminated'; got: {msg}"
        );
        assert!(
            msg.contains(&shell_id),
            "b2_kill_running: message must contain the shell_id; got: {msg}"
        );
    }

    /// B2-kill-d: killing the same `shell_id` twice — second call must return
    /// `is_error=true` ("not found"), because the entry is removed on first kill.
    ///
    /// OC source: mod.rs:236 — `shells.remove(shell_id)` evicts the entry.
    #[test]
    #[cfg(unix)]
    fn b2_kill_same_shell_twice_second_is_not_found() {
        let shell_id = super::super::BACKGROUND_SHELLS
            .spawn("sleep 30")
            .expect("b2_kill_twice: spawn must succeed");

        let make_args = |id: &str| {
            let mut args = HashMap::new();
            args.insert(
                "shell_id".to_string(),
                serde_json::Value::String(id.to_string()),
            );
            args
        };

        let (_, first_err) = execute_kill_shell(&make_args(&shell_id));
        assert!(!first_err, "b2_kill_twice: first kill must succeed");

        let (msg2, second_err) = execute_kill_shell(&make_args(&shell_id));
        assert!(
            second_err,
            "b2_kill_twice: second kill must be is_error=true (entry removed)"
        );
        assert!(
            msg2.contains("not found"),
            "b2_kill_twice: second kill must say 'not found'; got: {msg2}"
        );
    }
}
