use super::BACKGROUND_SHELLS;
use crate::tools::args::ToolArgError;
use serde_json::Value;
use std::collections::HashMap;
#[cfg(not(unix))]
use std::process::Command;

/// Kill a background shell
pub fn execute_kill_shell(
    run: &crate::tools::security::ToolRunContext,
    args: &HashMap<String, Value>,
) -> (String, bool) {
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

    match BACKGROUND_SHELLS.kill(run, shell_id) {
        Ok(msg) => (msg, false),
        Err(e) => (e, true),
    }
}

/// Kill every background shell owned by an agent/session id.
pub fn execute_kill_shells_for_agent(
    run: &crate::tools::security::ToolRunContext,
    args: &HashMap<String, Value>,
) -> (String, bool) {
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
    let caller = run.process_owner();
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

    (BACKGROUND_SHELLS.kill_for_run(run), false)
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
    if pid == 0 {
        tracing::debug!("terminate_process_tree: refusing process-group sentinel PID 0");
        return;
    }

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

/// Force-stop a synchronous sandbox tree without allowing signal handlers to
/// fork a replacement process during cancellation.
///
/// Bubblewrap creates a new session inside its PID namespace. That terminal
/// isolation means the inner command is not necessarily in the outer
/// wrapper's process group. Linux cancellation therefore freezes the wrapper,
/// discovers and freezes every current descendant, and only then sends
/// `SIGKILL`. The ordinary [`terminate_process_tree`] path remains available
/// for cooperative long-lived services; this stronger path is used when a
/// supervised deadline, run cancellation, or explicit background-shell kill
/// revokes the owned sandbox's authority to continue.
pub fn terminate_sandbox_process_tree(pid: u32) {
    if pid == 0 {
        tracing::debug!("terminate_sandbox_process_tree: refusing process-group sentinel PID 0");
        return;
    }

    #[cfg(target_os = "linux")]
    {
        force_terminate_linux_process_tree(pid);
    }

    #[cfg(not(target_os = "linux"))]
    {
        terminate_process_tree(pid);
    }
}

#[cfg(target_os = "linux")]
fn force_terminate_linux_process_tree(pid: u32) {
    use std::collections::{HashSet, VecDeque};
    use std::time::Duration;

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
                let Ok(children) = std::fs::read_to_string(task.path().join("children")) else {
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

    // Stop the group leader before taking a descendant snapshot. Otherwise a
    // wrapper can fork the namespace child after the snapshot but before the
    // terminating signal reaches it.
    // SAFETY: `root` is a positive PID representable by `pid_t`; negative
    // values select its process group. `kill(2)` does not dereference memory.
    unsafe {
        libc::kill(-root, libc::SIGSTOP);
        libc::kill(root, libc::SIGSTOP);
    }

    let mut frozen = HashSet::from([root]);
    let mut stable_rounds = 0_u8;
    for _ in 0..32 {
        let mut added = false;
        for descendant in descendants() {
            if frozen.insert(descendant) {
                // SAFETY: descendants are positive PIDs read from procfs;
                // `kill(2)` does not dereference memory.
                unsafe {
                    libc::kill(descendant, libc::SIGSTOP);
                }
                added = true;
            }
        }
        if added {
            stable_rounds = 0;
        } else {
            stable_rounds = stable_rounds.saturating_add(1);
            if stable_rounds >= 2 {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(1));
    }

    // Every observed process is stopped, so no TERM trap can fork a new
    // session between the final snapshot and termination.
    for descendant in frozen
        .iter()
        .copied()
        .filter(|candidate| *candidate != root)
    {
        // SAFETY: each target is a positive PID previously read from procfs
        // and frozen by this function; `kill(2)` does not dereference memory.
        unsafe {
            libc::kill(descendant, libc::SIGKILL);
        }
    }
    // SAFETY: same validated root/process-group identity as the SIGSTOP calls
    // above; `kill(2)` does not dereference memory.
    unsafe {
        libc::kill(-root, libc::SIGKILL);
        libc::kill(root, libc::SIGKILL);
    }
    std::thread::sleep(Duration::from_millis(100));
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

    fn test_run() -> &'static std::sync::Arc<crate::tools::ToolRunContext> {
        crate::tools::security::test_run_context()
    }
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

    #[test]
    fn process_tree_termination_refuses_process_group_sentinel_pid_zero() {
        terminate_process_tree(0);
        terminate_sandbox_process_tree(0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn forced_sandbox_termination_prevents_a_descendant_from_forking_on_term() {
        use std::os::unix::process::CommandExt as _;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant};

        which::which("setsid").expect("Linux cancellation fixture requires the setsid utility");
        let fixture = tempfile::tempdir().expect("cancellation fixture");
        let marker_path = fixture.path().join("escaped-marker");
        let pid_file_path = fixture.path().join("escaped-pid");
        let marker = shlex::try_quote(marker_path.to_str().expect("UTF-8 marker")).expect("quote");
        let pid_file =
            shlex::try_quote(pid_file_path.to_str().expect("UTF-8 pid file")).expect("quote");
        let descendant_script = fixture.path().join("term-fork.sh");
        std::fs::write(
            &descendant_script,
            format!(
                "#!/bin/sh\n\
                 trap 'setsid sh -c \"sleep 1; echo survived > {marker}\" & exit 0' TERM\n\
                 echo $$ > {pid_file}\n\
                 while :; do sleep 1; done\n"
            ),
        )
        .expect("write signal-handler fixture");
        let descendant_script =
            shlex::try_quote(descendant_script.to_str().expect("UTF-8 descendant script"))
                .expect("quote");
        let script = format!("sh {descendant_script} & sleep 30");
        let mut command = Command::new("sh");
        command
            .args(["-c", &script])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0);
        let mut child = command.spawn().expect("spawn process tree");

        let ready_deadline = Instant::now() + Duration::from_secs(2);
        while !pid_file_path.exists() && Instant::now() < ready_deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            pid_file_path.exists(),
            "signal-handler descendant did not start"
        );

        terminate_sandbox_process_tree(child.id());
        let _ = child.wait();
        std::thread::sleep(Duration::from_millis(1_200));

        if let Ok(pid) = std::fs::read_to_string(&pid_file_path) {
            if let Ok(pid) = pid.trim().parse::<i32>() {
                if pid > 0 {
                    // SAFETY: this is a best-effort cleanup of the positive PID
                    // written by the test fixture; `kill(2)` dereferences no memory.
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                    }
                }
            }
        }
        assert!(
            !marker_path.exists(),
            "a signal handler forked a replacement process during sandbox termination"
        );
    }

    // ── Phase 2 pinning tests (crosslink #541) ────────────────────────────────
    // Pins OC's CURRENT kill_shell contracts per spec crosslink #526 §B2.

    /// B2-kill-a: missing `shell_id` arg → `is_error=true`, message contains "Missing".
    ///
    /// OC source: kill.rs:8-10 — arg check fires before any `BACKGROUND_SHELLS` call.
    #[test]
    fn b2_kill_missing_shell_id_arg() {
        let args: HashMap<String, serde_json::Value> = HashMap::new();
        let (msg, is_error) = execute_kill_shell(test_run(), &args);
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
        let (msg, is_error) = execute_kill_shell(test_run(), &args);
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
        let (msg, is_error) = execute_kill_shells_for_agent(test_run(), &args);
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
        let (msg, is_error) = execute_kill_shell(test_run(), &args);
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
            .spawn(test_run(), "sleep 30")
            .expect("b2_kill_running: spawn must succeed");

        let mut args = HashMap::new();
        args.insert(
            "shell_id".to_string(),
            serde_json::Value::String(shell_id.clone()),
        );
        let (msg, is_error) = execute_kill_shell(test_run(), &args);

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
            .spawn(test_run(), "sleep 30")
            .expect("b2_kill_twice: spawn must succeed");

        let make_args = |id: &str| {
            let mut args = HashMap::new();
            args.insert(
                "shell_id".to_string(),
                serde_json::Value::String(id.to_string()),
            );
            args
        };

        let (_, first_err) = execute_kill_shell(test_run(), &make_args(&shell_id));
        assert!(!first_err, "b2_kill_twice: first kill must succeed");

        let (msg2, second_err) = execute_kill_shell(test_run(), &make_args(&shell_id));
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
