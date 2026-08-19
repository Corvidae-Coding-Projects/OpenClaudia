//! Deterministic local escape probes for the Linux agent sandbox.
//!
//! Every sentinel and listener is owned by this test process. No probe reads
//! unrelated host data or contacts an external network.

#![cfg(target_os = "linux")]
#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]

use openclaudia::permissions::{ApprovalProvenance, PermissionManager};
use openclaudia::services::tool_executor::{ToolExecutor, ToolExecutorRequest};
use openclaudia::tools::{FunctionCall, ToolCall};
use serde_json::json;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd};
use std::os::unix::net::UnixListener;
use std::sync::{LazyLock, Mutex, MutexGuard};

// Every probe shares the process-wide default security context, whose writable
// root is this repository. A few probes deliberately place hostile filesystem
// entries in that root. Keep setup, sandbox validation, and teardown atomic so
// a sibling probe cannot observe another probe's temporary attack fixture.
static SANDBOX_PROBE_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

fn sandbox_probe_lock() -> MutexGuard<'static, ()> {
    SANDBOX_PROBE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn bash(command: &str) -> openclaudia::tools::ToolResult {
    let _probe = sandbox_probe_lock();
    bash_unlocked(command)
}

fn bash_unlocked(command: &str) -> openclaudia::tools::ToolResult {
    let tool_call = ToolCall {
        id: "sandbox-escape-probe".to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: "bash".to_string(),
            arguments: json!({"command": command}).to_string(),
        },
    };
    // These probes intentionally need compound shell syntax to inspect several
    // sandbox properties in one process. Exercise that syntax through the
    // production exact-approval path so this suite tests capability
    // confinement instead of relying on the retired manager-less bypass.
    let state = tempfile::TempDir::new().expect("create permission state directory");
    let manager = PermissionManager::new(state.path().join("permissions.json"), true, Vec::new());
    let permit = manager
        .approve_tool_call_once(&tool_call, None, ApprovalProvenance::InteractiveUser)
        .expect("host approval must mint an exact one-use permit");
    ToolExecutor::execute(ToolExecutorRequest {
        tool_call: &tool_call,
        memory_db: None,
        app_config: None,
        task_mgr: None,
        permission_mgr: &manager,
        authorization: Some(permit),
        session_id: None,
        policy_enforcer: None,
    })
}

fn project_fixture(prefix: &str) -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(".")
        .expect("project-local fixture")
}

#[test]
fn host_file_network_and_kernel_trees_are_absent() {
    let outside = tempfile::tempdir().expect("host sentinel dir");
    let sentinel = outside.path().join("sentinel");
    std::fs::write(&sentinel, "host-secret").expect("host sentinel");
    let quoted = shlex::try_quote(sentinel.to_str().expect("UTF-8 sentinel")).expect("quote");
    let python = r#"
import errno, socket
blocked = []
for family, kind in [(socket.AF_INET, socket.SOCK_STREAM), (socket.AF_INET6, socket.SOCK_DGRAM), (socket.AF_UNIX, socket.SOCK_STREAM)]:
    try:
        socket.socket(family, kind)
        blocked.append(False)
    except OSError as error:
        blocked.append(error.errno in (errno.EPERM, errno.EACCES))
print("network_blocked=" + str(all(blocked)).lower())
"#;
    let python = shlex::try_quote(python).expect("quote Python");
    let result = bash(&format!(
        "if test -e {quoted}; then echo host_file_visible; else echo host_file_blocked; fi; \
         if test -e /sys/kernel; then echo sys_visible; else echo sys_blocked; fi; \
         python3 -c {python}"
    ));
    assert!(!result.is_error(), "probe failed: {}", result.content());
    assert!(result.content().contains("host_file_blocked"));
    assert!(result.content().contains("sys_blocked"));
    assert!(result.content().contains("network_blocked=true"));
    assert!(!result.content().contains("host-secret"));
}

#[test]
fn project_socket_and_fifo_block_sandbox_startup() {
    let _probe = sandbox_probe_lock();
    let fixture = project_fixture(".tmp-openclaudia-special-");
    let socket = fixture.path().join("service.sock");
    let listener = UnixListener::bind(&socket).expect("local Unix listener");
    let socket_result = bash_unlocked("true");
    assert!(
        socket_result.is_error() && socket_result.content().contains("socket, FIFO, or device"),
        "project socket was not rejected: {}",
        socket_result.content()
    );
    drop(listener);
    std::fs::remove_file(&socket).expect("remove socket");

    let fifo = fixture.path().join("pipe");
    let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).expect("FIFO path");
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
    let fifo_result = bash_unlocked("true");
    assert!(
        fifo_result.is_error() && fifo_result.content().contains("socket, FIFO, or device"),
        "project FIFO was not rejected: {}",
        fifo_result.content()
    );
}

#[test]
fn external_hardlink_alias_is_rejected_but_internal_alias_is_supported() {
    let _probe = sandbox_probe_lock();
    let outside = tempfile::Builder::new()
        .prefix(".tmp-openclaudia-outside-hardlink-")
        .tempdir_in("..")
        .expect("same-filesystem outside dir");
    let sentinel = outside.path().join("sentinel");
    std::fs::write(&sentinel, "unchanged").expect("sentinel");
    let fixture = project_fixture(".tmp-openclaudia-hardlink-");
    let alias = fixture.path().join("outside-alias");
    std::fs::hard_link(&sentinel, &alias).expect("same-filesystem hardlink fixture");
    let rejected = bash_unlocked("true");
    assert!(
        rejected.is_error(),
        "external hardlink alias must block startup"
    );
    assert_eq!(
        std::fs::read_to_string(&sentinel).expect("sentinel"),
        "unchanged"
    );
    std::fs::remove_file(&alias).expect("remove external alias");

    let first = fixture.path().join("internal-a");
    let second = fixture.path().join("internal-b");
    std::fs::write(&first, "before").expect("internal file");
    std::fs::hard_link(&first, &second).expect("internal hardlink");
    let command = format!(
        "printf changed > {}",
        shlex::try_quote(first.to_str().expect("UTF-8 path")).expect("quote")
    );
    let allowed = bash_unlocked(&command);
    assert!(
        !allowed.is_error(),
        "internal hardlinks should be usable: {}",
        allowed.content()
    );
    assert_eq!(
        std::fs::read_to_string(second).expect("internal alias"),
        "changed"
    );
}

#[test]
fn inherited_host_file_descriptor_is_closed() {
    let _probe = sandbox_probe_lock();
    let outside = tempfile::NamedTempFile::new().expect("outside sentinel");
    std::fs::write(outside.path(), "fd-secret").expect("sentinel contents");
    let path = std::ffi::CString::new(outside.path().as_os_str().as_encoded_bytes()).expect("path");
    let raw = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) };
    assert!(raw >= 0, "open inherited descriptor");
    let inherited = unsafe { OwnedFd::from_raw_fd(raw) };
    let result = bash_unlocked(&format!(
        "cat /proc/self/fd/{} 2>/dev/null || echo fd_blocked",
        inherited.as_raw_fd()
    ));
    assert!(
        !result.content().contains("fd-secret"),
        "host FD leaked: {}",
        result.content()
    );
    assert!(result.content().contains("fd_blocked"));
}

#[test]
fn seccomp_denies_socket_unshare_and_ptrace_syscalls() {
    let python = r#"
import ctypes, errno, socket
libc = ctypes.CDLL(None, use_errno=True)
checks = []
try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    checks.append(False)
except OSError as error:
    checks.append(error.errno == errno.EPERM)
checks.append(libc.unshare(0x10000000) == -1 and ctypes.get_errno() == errno.EPERM)
ctypes.set_errno(0)
checks.append(libc.ptrace(0, 0, 0, 0) == -1 and ctypes.get_errno() == errno.EPERM)
print("seccomp_blocked=" + str(all(checks)).lower())
"#;
    let result = bash(&format!(
        "python3 -c {}",
        shlex::try_quote(python).expect("quote Python")
    ));
    assert!(
        !result.is_error(),
        "seccomp probe failed: {}",
        result.content()
    );
    assert!(result.content().contains("seccomp_blocked=true"));
}

#[test]
fn effective_rlimits_include_process_memory_cpu_file_and_fd_caps() {
    let result = bash(
        "printf 'cpu=%s nofile=%s fsize=%s as=%s nproc=%s\\n' \
         \"$(ulimit -t)\" \"$(ulimit -n)\" \"$(ulimit -f)\" \"$(ulimit -v)\" \"$(ulimit -u)\"",
    );
    assert!(
        !result.is_error(),
        "rlimit probe failed: {}",
        result.content()
    );
    assert!(result.content().contains("cpu=300"));
    assert!(result.content().contains("nofile=1024"));
    assert!(
        !result.content().contains("fsize=unlimited"),
        "file-size limit was not applied: {}",
        result.content()
    );
    assert!(result.content().contains("as=4194304"));
}

#[test]
fn process_count_limit_stops_a_fork_flood() {
    let python = r#"
import os, time
children = []
for _ in range(300):
    try:
        pid = os.fork()
    except OSError:
        break
    if pid == 0:
        time.sleep(0.25)
        os._exit(0)
    children.append(pid)
for pid in children:
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
print("children=" + str(len(children)))
"#;
    let result = bash(&format!(
        "python3 -c {}",
        shlex::try_quote(python).expect("quote Python")
    ));
    assert!(
        !result.is_error(),
        "fork-limit probe failed: {}",
        result.content()
    );
    let count = result
        .content()
        .split("children=")
        .nth(1)
        .and_then(|tail| tail.lines().next())
        .and_then(|value| value.trim().parse::<usize>().ok())
        .expect("child count");
    assert!(
        count < 300,
        "process limit allowed the entire flood: {count}"
    );
}

#[test]
fn git_inspection_works_without_repository_execution_configuration() {
    let result = bash(
        "git -c core.hooksPath=/dev/null -c core.pager=cat \
         -c credential.helper= -c diff.external= status --porcelain >/dev/null && \
         git -c core.hooksPath=/dev/null -c core.pager=cat \
         -c credential.helper= -c diff.external= diff --stat >/dev/null && \
         if git config --get credential.helper >/dev/null 2>&1; then \
           echo credential_config_visible; else echo git_config_hidden; fi",
    );
    assert!(
        !result.is_error(),
        "safe Git inspection failed: {}",
        result.content()
    );
    assert!(result.content().contains("git_config_hidden"));
    assert!(!result.content().contains("credential_config_visible"));
}

#[test]
fn toolchain_mounts_are_read_only_and_exclude_user_credentials() {
    let result = bash(
        "cargo --version >/dev/null && \
         test ! -e \"$HOME/.cargo/credentials\" && \
         test ! -e \"$HOME/.cargo/credentials.toml\" && \
         if touch \"$HOME/.cargo/bin/openclaudia-write-probe\" 2>/dev/null; then \
           echo cache_writable; else echo toolchain_confined; fi",
    );
    assert!(
        !result.is_error(),
        "read-only Cargo toolchain probe failed: {}",
        result.content()
    );
    assert!(result.content().contains("toolchain_confined"));
    assert!(!result.content().contains("cache_writable"));
}

#[test]
fn ambient_ipc_proxy_and_secret_shaped_environment_is_absent() {
    struct EnvironmentCanaries;
    impl Drop for EnvironmentCanaries {
        fn drop(&mut self) {
            // SAFETY: this probe holds SANDBOX_PROBE_LOCK for the full
            // environment mutation lifetime, and every sibling sandbox probe
            // acquires the same lock before launching a child process. These
            // names are test-unique.
            unsafe {
                std::env::remove_var("SSH_OPENCLAUDIA_CANARY");
                std::env::remove_var("DBUS_OPENCLAUDIA_CANARY");
                std::env::remove_var("HTTPS_PROXY_OPENCLAUDIA_CANARY");
                std::env::remove_var("OPENCLAUDIA_TEST_API_KEY");
            }
        }
    }
    let _probe = sandbox_probe_lock();
    // SAFETY: see the lock and cleanup guard above.
    unsafe {
        std::env::set_var("SSH_OPENCLAUDIA_CANARY", "secret");
        std::env::set_var("DBUS_OPENCLAUDIA_CANARY", "secret");
        std::env::set_var("HTTPS_PROXY_OPENCLAUDIA_CANARY", "secret");
        std::env::set_var("OPENCLAUDIA_TEST_API_KEY", "secret");
    }
    let _canaries = EnvironmentCanaries;
    let result = bash_unlocked(
        "env | grep -E '^(SSH_OPENCLAUDIA_CANARY|DBUS_OPENCLAUDIA_CANARY|\
         HTTPS_PROXY_OPENCLAUDIA_CANARY|OPENCLAUDIA_TEST_API_KEY)=' \
         && echo env_leaked || echo env_confined",
    );
    assert!(
        !result.is_error(),
        "environment probe failed: {}",
        result.content()
    );
    assert!(result.content().contains("env_confined"));
    assert!(!result.content().contains("secret"));
}

#[test]
fn address_space_and_open_file_limits_are_effective() {
    let python = r#"
memory_blocked = False
try:
    bytearray(5 * 1024 * 1024 * 1024)
except (MemoryError, OverflowError):
    memory_blocked = True
files = []
try:
    while True:
        files.append(open("/dev/null", "rb"))
except OSError:
    pass
print("memory_blocked=" + str(memory_blocked).lower())
print("open_files=" + str(len(files)))
"#;
    let result = bash(&format!(
        "python3 -c {}",
        shlex::try_quote(python).expect("quote Python")
    ));
    assert!(
        !result.is_error(),
        "resource probe failed: {}",
        result.content()
    );
    assert!(result.content().contains("memory_blocked=true"));
    let count = result
        .content()
        .split("open_files=")
        .nth(1)
        .and_then(|tail| tail.lines().next())
        .and_then(|value| value.trim().parse::<usize>().ok())
        .expect("open-file count");
    assert!(count <= 1024, "open-file cap was not enforced: {count}");
}
