use super::{resolve_open_path, resolve_path, secure_fs, READ_TRACKER};
use crate::tools::args::ToolArgs as _;
use crate::tools::{ToolFailure, ToolFailureCode, ToolHandlerResult, ToolRetryability};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{Seek as _, SeekFrom, Write as _};
use std::path::Path;

/// Write content to a file
pub fn execute_write_file(
    run: &std::sync::Arc<crate::tools::security::ToolRunContext>,
    args: &HashMap<String, Value>,
) -> ToolHandlerResult {
    let user_path = match args.arg_str_strict("path") {
        Ok(path) => path,
        Err(e) => {
            let (message, _) = e.into_tool_error();
            return write_error(message);
        }
    };

    let p = match resolve_path(run, user_path) {
        Ok(p) => p,
        Err(e) => return write_error(e),
    };

    // Path passed to `open(2)`: canonical parent + original leaf name. A
    // fully canonicalized path has already resolved the leaf symlink, so
    // `O_NOFOLLOW` against it is useless. This leaf-preserving variant
    // makes `O_NOFOLLOW` reject a swapped leaf with `ELOOP`. See #417.
    let open_path = match resolve_open_path(run, user_path) {
        Ok(p) => p,
        Err(e) => return write_error(e),
    };

    let path = p.to_string_lossy().to_string();
    let path = path.as_str();

    let content = match args.arg_str_strict("content") {
        Ok(content) => content,
        Err(e) => {
            let (message, _) = e.into_tool_error();
            return write_error(message);
        }
    };

    let prepared = match prepare_write(run, path, &open_path, content) {
        Ok(prepared) => prepared,
        Err(error) => return write_error(error),
    };
    persist_write(run, path, content, prepared)
}

struct PreparedWrite {
    file: std::fs::File,
    old_content: String,
    lines_added: u32,
    lines_removed: u32,
    line_reservation: crate::guardrails::ChangedLineReservation,
}

fn prepare_write(
    run: &crate::tools::ToolRunContext,
    path: &str,
    open_path: &Path,
    content: &str,
) -> Result<PreparedWrite, String> {
    // Observe without creating anything. Admission therefore happens before
    // a missing target or parent directory can become an effect.
    let (old_content, observed_exists) = match secure_fs::open_regular_read(run, open_path) {
        Ok(mut file) => (secure_fs::read_to_string(&mut file, Path::new(path))?, true),
        Err(error) if secure_fs::is_not_found_message(&error) => (String::new(), false),
        Err(error) => {
            return Err(format!(
                "Failed to securely inspect file '{path}' before writing: {error}"
            ));
        }
    };

    // Existing content must have been observed by this exact run before it
    // can be replaced. New files have no prior state to ground.
    if observed_exists && !READ_TRACKER.has_been_read(run, Path::new(path)) {
        return Err(format!(
            "You must read '{path}' before overwriting it. Use read_file first to see the actual contents, then write_file to replace them."
        ));
    }
    if observed_exists {
        super::require_fresh_file_observation_if_ledger_active(
            run,
            Path::new(path),
            "overwriting it",
        )?;
    }

    let (lines_added, lines_removed) = super::changed_line_counts(&old_content, content);
    let line_reservation = crate::guardrails::reserve_changed_lines(
        run,
        u64::from(lines_added) + u64::from(lines_removed),
    )?;
    let (mut file, target_exists) = open_observed_target(run, path, open_path, observed_exists)?;
    if target_exists != observed_exists {
        return Err(format!(
            "File '{path}' changed existence while the write was being prepared; read it again and retry"
        ));
    }
    if target_exists {
        let current_content = secure_fs::read_to_string(&mut file, Path::new(path))?;
        if current_content != old_content {
            return Err(format!(
                "File '{path}' changed while the write was being prepared; read it again and retry"
            ));
        }
    }
    Ok(PreparedWrite {
        file,
        old_content,
        lines_added,
        lines_removed,
        line_reservation,
    })
}

fn open_observed_target(
    run: &crate::tools::ToolRunContext,
    path: &str,
    open_path: &Path,
    observed_exists: bool,
) -> Result<(std::fs::File, bool), String> {
    if observed_exists {
        // Never fall back to create here. If the observed inode disappeared,
        // recreating an empty path would be a partial effect on an error path.
        return secure_fs::open_regular_edit(run, open_path)
            .map(|file| (file, true))
            .map_err(|error| {
                format!("Failed to securely reopen file '{path}' for writing: {error}")
            });
    }
    secure_fs::open_regular_update_or_create(run, open_path)
        .map_err(|error| format!("Failed to securely create file '{path}' for writing: {error}"))
}

fn persist_write(
    run: &crate::tools::ToolRunContext,
    path: &str,
    content: &str,
    mut prepared: PreparedWrite,
) -> ToolHandlerResult {
    let write_result = prepared
        .file
        .seek(SeekFrom::Start(0))
        .and_then(|_| prepared.file.set_len(0))
        .and_then(|()| prepared.file.write_all(content.as_bytes()));
    match write_result {
        Ok(()) => {
            prepared.line_reservation.commit();
            crate::guardrails::record_file_modification(
                run,
                path,
                prepared.lines_added,
                prepared.lines_removed,
            );
            super::record_active_diff_observation(run, path, &prepared.old_content, content);
            let mut result = format!("Successfully wrote {} bytes to '{}'", content.len(), path);
            if let Some(warning) = crate::guardrails::check_diff_thresholds(run) {
                let _ = write!(result, "\n\nWarning: {}", warning.message);
            }
            ToolHandlerResult::success_text(result)
        }
        Err(error) => {
            let failure_message = format!("Failed to write file '{path}': {error}");
            if let Ok(actual_content) =
                secure_fs::read_to_string(&mut prepared.file, Path::new(path))
            {
                let (actual_added, actual_removed) =
                    super::changed_line_counts(&prepared.old_content, &actual_content);
                prepared
                    .line_reservation
                    .reconcile_and_commit(u64::from(actual_added) + u64::from(actual_removed));
                crate::guardrails::record_file_modification(
                    run,
                    path,
                    actual_added,
                    actual_removed,
                );
                super::record_active_diff_observation(
                    run,
                    path,
                    &prepared.old_content,
                    &actual_content,
                );
            } else {
                prepared.line_reservation.commit();
            }
            ToolHandlerResult::partial_text(
                failure_message.clone(),
                vec![ToolFailure::new(
                    ToolFailureCode::External,
                    failure_message,
                    ToolRetryability::Unknown,
                )],
            )
        }
    }
}

fn write_error(message: String) -> ToolHandlerResult {
    ToolHandlerResult::error(ToolFailure::new(
        ToolFailureCode::Legacy,
        message,
        ToolRetryability::Unknown,
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use tempfile::TempDir;

    fn test_run() -> &'static std::sync::Arc<crate::tools::ToolRunContext> {
        crate::tools::security::test_run_context()
    }

    /// Serialize tests that touch the process-global `READ_TRACKER`.
    /// Delegates to the crate-wide `shared_tracker_lock` so write tests
    /// don't race with `clear_all()` calls in the tracker-internal test
    /// module (`src/tools/file/mod.rs::tests`).
    fn tracker_lock() -> std::sync::MutexGuard<'static, ()> {
        super::super::shared_tracker_lock()
    }

    fn make_args(path: &str, content: &str) -> HashMap<String, serde_json::Value> {
        let mut m = HashMap::new();
        m.insert("path".to_string(), serde_json::json!(path));
        m.insert("content".to_string(), serde_json::json!(content));
        m
    }

    #[test]
    fn observed_existing_target_is_not_recreated_if_it_disappears() {
        let dir = TempDir::new_in(".").expect("tempdir");
        let missing = dir.path().join("disappeared.txt");
        let user_path = missing.to_string_lossy();
        let open_path =
            super::super::resolve_open_path(test_run(), &user_path).expect("leaf-preserving path");

        let error = super::open_observed_target(test_run(), &user_path, &open_path, true)
            .expect_err("an observed-existing target must not fall back to create");

        assert!(error.contains("reopen"), "unexpected error: {error}");
        assert!(!missing.exists(), "failed reopen must have no file effect");
    }

    #[test]
    fn write_creates_parent_directories_recursively() {
        let dir = TempDir::new_in(".").expect("tempdir");
        let deep = dir.path().join("a").join("b").join("c").join("file.txt");
        let args = make_args(&deep.to_string_lossy(), "hello");
        let (msg, is_err) = super::execute_write_file(test_run(), &args).into_legacy();
        assert!(!is_err, "deep path write must succeed: {msg}");
        assert!(
            std::fs::read_to_string(&deep).expect("read back") == "hello",
            "content correct"
        );
    }

    #[test]
    fn write_success_message_contains_byte_count_and_path() {
        let dir = TempDir::new_in(".").expect("tempdir");
        let path = dir.path().join("out.txt");
        let content = "abc";
        let args = make_args(&path.to_string_lossy(), content);
        let (msg, is_err) = super::execute_write_file(test_run(), &args).into_legacy();
        assert!(!is_err, "write should succeed: {msg}");
        assert!(msg.contains("Successfully wrote"), "message: {msg}");
        assert!(msg.contains("3 bytes"), "byte count: {msg}");
    }

    #[test]
    fn write_parent_already_exists_is_idempotent() {
        let _lock = tracker_lock();
        let dir = TempDir::new_in(".").expect("tempdir");
        let path = dir.path().join("file.txt");
        let args = make_args(&path.to_string_lossy(), "first");
        let (_, is_err) = super::execute_write_file(test_run(), &args).into_legacy();
        assert!(!is_err, "first write must succeed");
        // crosslink #968: second-write to an existing file now requires
        // the file to have been read first (parity with edit_file).
        super::READ_TRACKER.mark_read(test_run(), &path);
        let args2 = make_args(&path.to_string_lossy(), "second");
        let (msg2, is_err2) = super::execute_write_file(test_run(), &args2).into_legacy();
        assert!(!is_err2, "second write must succeed: {msg2}");
        let content = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(content, "second");
    }

    #[test]
    fn write_overwrites_existing_file() {
        let _lock = tracker_lock();
        let dir = TempDir::new_in(".").expect("tempdir");
        let path = dir.path().join("existing.txt");
        std::fs::write(&path, "old content").expect("setup");
        // crosslink #968: overwrite requires a prior read.
        super::READ_TRACKER.mark_read(test_run(), &path);
        let args = make_args(&path.to_string_lossy(), "new content");
        let (msg, is_err) = super::execute_write_file(test_run(), &args).into_legacy();
        assert!(!is_err, "overwrite must succeed: {msg}");
        let content = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(content, "new content");
    }

    #[test]
    fn successful_overwrite_invalidates_prior_read_marker() {
        let _lock = tracker_lock();
        let dir = TempDir::new_in(".").expect("tempdir");
        let path = dir.path().join("stale_after_write.txt");
        std::fs::write(&path, "old").expect("setup");
        super::READ_TRACKER.mark_read(test_run(), &path);

        let args = make_args(&path.to_string_lossy(), "new");
        let (msg, is_err) = super::execute_write_file(test_run(), &args).into_legacy();
        assert!(!is_err, "overwrite must succeed: {msg}");

        let args2 = make_args(&path.to_string_lossy(), "newer");
        let (msg2, is_err2) = super::execute_write_file(test_run(), &args2).into_legacy();
        assert!(
            is_err2,
            "second overwrite without a fresh read must fail: {msg2}"
        );
        assert!(
            msg2.contains("must read") || msg2.contains("Use read_file"),
            "{msg2}"
        );
    }

    /// crosslink #968: overwriting an existing file without first calling
    /// `read_file` must fail, matching the read-before-edit invariant.
    #[test]
    fn fix968_overwrite_without_read_is_rejected() {
        let _lock = tracker_lock();
        super::READ_TRACKER.clear_all();
        let dir = TempDir::new_in(".").expect("tempdir");
        let path = dir.path().join("must_read_first.txt");
        std::fs::write(&path, "old").expect("setup");
        // Deliberately do NOT mark_read. Overwrite must fail.
        let args = make_args(&path.to_string_lossy(), "new");
        let (msg, is_err) = super::execute_write_file(test_run(), &args).into_legacy();
        assert!(is_err, "must reject overwrite without prior read: {msg}");
        assert!(
            msg.contains("must read"),
            "error should mention read requirement: {msg}"
        );
        // File contents untouched.
        let after = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(after, "old", "file must not be modified on rejection");
    }

    #[test]
    fn active_ledger_overwrite_requires_fresh_file_read_observation() {
        let _lock = tracker_lock();
        super::READ_TRACKER.clear_all();
        let run = test_run();
        let ledger =
            std::sync::Arc::new(std::sync::Mutex::new(crate::ledger::RealityLedger::new()));
        let _ledger_guard =
            crate::ledger::install_active_ledger_for_session(run.session_id(), ledger);
        let dir = TempDir::new_in(".").expect("tempdir");
        let path = dir.path().join("ledger_requires_read.txt");
        std::fs::write(&path, "old").expect("setup");
        super::READ_TRACKER.mark_read(run, &path);

        let args = make_args(&path.to_string_lossy(), "new");
        let (msg, is_err) = super::execute_write_file(run, &args).into_legacy();

        assert!(is_err, "ledger-less overwrite must be denied: {msg}");
        assert!(
            msg.contains("active reality ledger has no fresh file read observation"),
            "{msg}"
        );
        assert_eq!(std::fs::read_to_string(&path).expect("read back"), "old");
    }

    /// crosslink #968: creating a brand-new file (no prior contents to
    /// hallucinate) MUST still work without a prior read — the
    /// read-before-write rule exists to prevent overwriting unknown
    /// content, not to gate fresh creation.
    #[test]
    fn fix968_create_new_file_does_not_require_read() {
        let dir = TempDir::new_in(".").expect("tempdir");
        let path = dir.path().join("brand_new_file.txt");
        assert!(!path.exists(), "precondition: target must not exist");
        let args = make_args(&path.to_string_lossy(), "fresh");
        let (msg, is_err) = super::execute_write_file(test_run(), &args).into_legacy();
        assert!(!is_err, "create-new must succeed without prior read: {msg}");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "fresh");
    }

    #[test]
    fn write_empty_content_succeeds() {
        let dir = TempDir::new_in(".").expect("tempdir");
        let path = dir.path().join("empty.txt");
        let args = make_args(&path.to_string_lossy(), "");
        let (msg, is_err) = super::execute_write_file(test_run(), &args).into_legacy();
        assert!(!is_err, "empty content write must succeed: {msg}");
        let content = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(content, "");
    }

    #[test]
    fn write_missing_content_arg_returns_error() {
        let dir = TempDir::new_in(".").expect("tempdir");
        let path = dir.path().join("x.txt");
        let mut args = HashMap::new();
        args.insert(
            "path".to_string(),
            serde_json::json!(path.to_string_lossy().as_ref()),
        );
        let (msg, is_err) = super::execute_write_file(test_run(), &args).into_legacy();
        assert!(is_err, "missing content must error: {msg}");
        assert!(msg.contains("Missing 'content'"), "message: {msg}");
    }

    #[test]
    fn write_missing_path_arg_returns_error() {
        let mut args = HashMap::new();
        args.insert("content".to_string(), serde_json::json!("data"));
        let (msg, is_err) = super::execute_write_file(test_run(), &args).into_legacy();
        assert!(is_err, "missing path must error: {msg}");
        assert!(msg.contains("Missing 'path'"), "message: {msg}");
    }

    // ===== crosslink #417: TOCTOU symlink-swap rejected by O_NOFOLLOW =====

    #[cfg(unix)]
    #[test]
    fn fix417_write_rejects_symlink_at_target() {
        let dir = TempDir::new_in(".").expect("tempdir");
        let target = dir.path().join("attacker_secrets.txt");
        std::fs::write(&target, "DO NOT OVERWRITE").expect("setup target");
        let leaf = dir.path().join("leaf.txt");
        std::os::unix::fs::symlink(&target, &leaf).expect("create symlink");
        let args = make_args(&leaf.to_string_lossy(), "attacker would inject this");
        let (msg, is_err) = super::execute_write_file(test_run(), &args).into_legacy();
        assert!(
            is_err,
            "write through a symlink leaf must fail (O_NOFOLLOW): {msg}"
        );
        let target_contents = std::fs::read_to_string(&target).expect("read target");
        assert_eq!(
            target_contents, "DO NOT OVERWRITE",
            "symlink target must not be overwritten"
        );
    }

    #[test]
    fn fix417_write_legitimate_regular_file_still_works() {
        let _lock = tracker_lock();
        let dir = TempDir::new_in(".").expect("tempdir");
        let path = dir.path().join("real.txt");
        std::fs::write(&path, "old").expect("setup");
        // crosslink #968: overwrite requires a prior read.
        super::READ_TRACKER.mark_read(test_run(), &path);
        let args = make_args(&path.to_string_lossy(), "new");
        let (msg, is_err) = super::execute_write_file(test_run(), &args).into_legacy();
        assert!(!is_err, "regular-file overwrite must succeed: {msg}");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "new");
    }

    #[test]
    fn fix417_write_create_new_file_works() {
        let dir = TempDir::new_in(".").expect("tempdir");
        let path = dir.path().join("brand_new.txt");
        assert!(!path.exists(), "precondition: file must not exist");
        let args = make_args(&path.to_string_lossy(), "fresh");
        let (msg, is_err) = super::execute_write_file(test_run(), &args).into_legacy();
        assert!(!is_err, "create-new must succeed: {msg}");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "fresh");
    }
}
