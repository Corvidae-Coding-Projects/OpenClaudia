//! Adversarial coverage for per-session filesystem capabilities and
//! descriptor-relative path resolution.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::{execute_tool, FunctionCall, SessionIdGuard, ToolCall};
use serde_json::json;
use std::sync::{Mutex, MutexGuard, OnceLock};

fn session_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[allow(clippy::needless_pass_by_value)]
fn call(name: &str, arguments: serde_json::Value) -> openclaudia::tools::ToolResult {
    execute_tool(&ToolCall {
        id: format!("filesystem-capability-{name}"),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: name.to_string(),
            arguments: arguments.to_string(),
        },
    })
}

#[cfg(unix)]
#[test]
fn private_session_temp_is_narrow_isolated_and_symlink_safe() {
    let _serial = session_lock();
    let session_a = SessionIdGuard::set("filesystem-private-temp-a");
    let context_a = openclaudia::tools::security::current_context().expect("context A");
    let a_file = context_a.private_temp_root().join("owned.txt");
    std::fs::write(&a_file, "session-a-secret").expect("write A fixture");

    let own_read = call("read_file", json!({ "path": a_file }));
    assert!(
        !own_read.is_error(),
        "session must read its own temp: {own_read:?}"
    );
    assert!(own_read.content().contains("session-a-secret"));

    let sibling = tempfile::tempdir().expect("sibling OS temp");
    let sibling_file = sibling.path().join("sibling.txt");
    std::fs::write(&sibling_file, "sibling-secret").expect("write sibling");
    let sibling_read = call("read_file", json!({ "path": sibling_file }));
    assert!(
        sibling_read.is_error(),
        "shared OS temp must not be granted"
    );
    assert!(!sibling_read.content().contains("sibling-secret"));

    let link = context_a.private_temp_root().join("escape-link");
    std::os::unix::fs::symlink(&sibling_file, &link).expect("plant symlink");
    let link_read = call("read_file", json!({ "path": link }));
    assert!(link_read.is_error(), "temp symlink escape must be denied");
    assert!(!link_read.content().contains("sibling-secret"));

    drop(session_a);
    let _session_b = SessionIdGuard::set("filesystem-private-temp-b");
    let context_b = openclaudia::tools::security::current_context().expect("context B");
    assert_ne!(
        context_a.private_temp_root(),
        context_b.private_temp_root(),
        "sessions must not share temporary roots"
    );
    let cross_read = call("read_file", json!({ "path": a_file }));
    assert!(
        cross_read.is_error(),
        "session B must not read session A temp"
    );
    assert!(!cross_read.content().contains("session-a-secret"));
}

#[cfg(target_os = "linux")]
fn rename_exchange(first: &std::path::Path, second: &std::path::Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;

    let first = CString::new(first.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let second = CString::new(second.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    // SAFETY: both path buffers are stable and NUL-terminated for the syscall.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            first.as_ptr(),
            libc::AT_FDCWD,
            second.as_ptr(),
            libc::RENAME_EXCHANGE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
#[test]
fn intermediate_directory_symlink_swap_cannot_escape_reads_or_writes() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    struct Swapper {
        stop: Arc<AtomicBool>,
        handle: Option<std::thread::JoinHandle<()>>,
    }
    impl Drop for Swapper {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    let _serial = session_lock();
    let _session = SessionIdGuard::set("filesystem-openat2-intermediate-race");
    let project_fixture = tempfile::tempdir_in(".").expect("project fixture");
    let outside = tempfile::tempdir().expect("outside fixture");

    let live = project_fixture.path().join("live");
    let alternate = project_fixture.path().join("alternate");
    std::fs::create_dir(&live).expect("safe directory");
    std::fs::write(live.join("secret.txt"), "INSIDE").expect("safe content");
    std::fs::write(outside.path().join("secret.txt"), "OUTSIDE-SENTINEL").expect("outside content");
    std::os::unix::fs::symlink(outside.path(), &alternate).expect("outside symlink");
    // Prove the kernel/filesystem supports the atomic primitive before the
    // adversarial loop, restoring the initial arrangement afterward.
    rename_exchange(&live, &alternate).expect("first exchange");
    rename_exchange(&live, &alternate).expect("restore exchange");

    let stop = Arc::new(AtomicBool::new(false));
    let swap_stop = Arc::clone(&stop);
    let swap_live = live.clone();
    let swap_alternate = alternate;
    let handle = std::thread::spawn(move || {
        while !swap_stop.load(Ordering::Relaxed) {
            if rename_exchange(&swap_live, &swap_alternate).is_err() {
                break;
            }
        }
    });
    let swapper = Swapper {
        stop,
        handle: Some(handle),
    };

    for index in 0..500 {
        let read = call("read_file", json!({ "path": live.join("secret.txt") }));
        assert!(
            !read.content().contains("OUTSIDE-SENTINEL"),
            "confined read returned outside content: {read:?}"
        );

        let write_name = format!("race-write-{index}.txt");
        let write = call(
            "write_file",
            json!({
                "path": live.join(&write_name),
                "content": "confined"
            }),
        );
        let _ = write;
        assert!(
            !outside.path().join(&write_name).exists(),
            "write escaped through swapped intermediate directory"
        );
    }

    drop(swapper);
    assert_eq!(
        std::fs::read_to_string(outside.path().join("secret.txt")).expect("outside sentinel"),
        "OUTSIDE-SENTINEL"
    );
}
