use super::{resolve_open_path, resolve_path, secure_fs, MAX_MUTATION_BYTES, READ_TRACKER};
use crate::tools::args::ToolArgs as _;
use crate::tools::{ToolFailure, ToolFailureCode, ToolHandlerResult, ToolRetryability};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Write as _;
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

    if content.len() > MAX_MUTATION_BYTES {
        return write_invalid(format!(
            "Write result for '{path}' would be {} bytes, exceeding the {MAX_MUTATION_BYTES}-byte file limit",
            content.len()
        ));
    }

    let prepared = match prepare_write(run, path, &open_path, content, args) {
        Ok(prepared) => prepared,
        Err(failure) => return ToolHandlerResult::error(failure),
    };
    persist_write(run, path, content, prepared)
}

struct PreparedWrite {
    expected: Option<crate::runtime::ContentDigest>,
    open_path: std::path::PathBuf,
    prepared_diff: super::PreparedFileDiff,
    line_reservation: crate::guardrails::ChangedLineReservation,
    diff_permit: crate::guardrails::DiffChangePermit,
}

fn prepare_write(
    run: &crate::tools::ToolRunContext,
    path: &str,
    open_path: &Path,
    content: &str,
    args: &HashMap<String, Value>,
) -> Result<PreparedWrite, ToolFailure> {
    // Observe without creating anything. Admission therefore happens before
    // a missing target or parent directory can become an effect.
    let observed_exists = match secure_fs::open_regular_read(run, open_path) {
        Ok(_) => true,
        Err(error) if secure_fs::is_not_found_message(&error) => false,
        Err(error) => {
            return Err(ToolFailure::new(
                ToolFailureCode::External,
                format!("Failed to securely inspect file '{path}' before writing: {error}"),
                ToolRetryability::Unknown,
            ));
        }
    };

    let (old_content, expected) = if observed_exists {
        let snapshot =
            super::require_expected_snapshot(run, Path::new(path), args.get("expected_snapshot"))?;
        super::require_fresh_file_observation_if_ledger_active(
            run,
            Path::new(path),
            "overwriting it",
        )
        .map_err(|message| {
            ToolFailure::new(ToolFailureCode::Conflict, message, ToolRetryability::Safe)
        })?;
        let bytes = super::read_expected_snapshot_bytes(run, Path::new(path), snapshot)?;
        let old_content = String::from_utf8(bytes).map_err(|error| {
            ToolFailure::new(
                ToolFailureCode::InvalidInput,
                format!(
                    "File '{path}' is not UTF-8 text and cannot be overwritten with write_file: {error}"
                ),
                ToolRetryability::Never,
            )
        })?;
        (old_content, Some(snapshot.generation()))
    } else {
        if let Some(supplied) = args.get("expected_snapshot") {
            return Err(ToolFailure::new(
                ToolFailureCode::Conflict,
                format!(
                    "File '{path}' is missing but the write named expected_snapshot {supplied}; read or inspect the path again before retrying"
                ),
                ToolRetryability::Safe,
            ));
        }
        (String::new(), None)
    };

    let prepared_diff =
        super::prepare_file_diff(run, path, &old_content, content).map_err(|message| {
            ToolFailure::new(
                ToolFailureCode::InvalidInput,
                message,
                ToolRetryability::Never,
            )
        })?;
    let line_reservation = crate::guardrails::reserve_changed_lines(
        run,
        u64::from(prepared_diff.lines_added) + u64::from(prepared_diff.lines_removed),
    )
    .map_err(|message| {
        ToolFailure::new(
            ToolFailureCode::PolicyDenied,
            message,
            ToolRetryability::Never,
        )
    })?;
    let diff_permit =
        crate::guardrails::admit_file_change(run, Path::new(path), content.as_bytes()).map_err(
            |message| {
                ToolFailure::new(
                    ToolFailureCode::PolicyDenied,
                    message,
                    ToolRetryability::Never,
                )
            },
        )?;
    Ok(PreparedWrite {
        expected,
        open_path: open_path.to_path_buf(),
        prepared_diff,
        line_reservation,
        diff_permit,
    })
}

fn persist_write(
    run: &crate::tools::ToolRunContext,
    path: &str,
    content: &str,
    mut prepared: PreparedWrite,
) -> ToolHandlerResult {
    match secure_fs::write_atomic_generation(
        run,
        &prepared.open_path,
        prepared.expected,
        content.as_bytes(),
        MAX_MUTATION_BYTES,
    ) {
        Ok(after_snapshot) => {
            prepared.line_reservation.commit();
            prepared.diff_permit.commit();
            crate::guardrails::record_file_modification(
                run,
                path,
                prepared.prepared_diff.lines_added,
                prepared.prepared_diff.lines_removed,
            );
            super::record_prepared_diff_observation(
                run,
                path,
                content.as_bytes(),
                &prepared.prepared_diff,
            );
            let mut result = format!(
                "Successfully wrote {} bytes to '{}'. New snapshot generation: {after_snapshot}",
                content.len(),
                path
            );
            if let Some(warning) = crate::guardrails::check_diff_thresholds(run) {
                let _ = write!(result, "\n\nWarning: {}", warning.message);
            }
            ToolHandlerResult::success_text(result)
        }
        Err(secure_fs::AtomicWriteError::Conflict { expected, observed }) => {
            READ_TRACKER.mark_stale(run, Path::new(path));
            ToolHandlerResult::error(ToolFailure::new(
                ToolFailureCode::Conflict,
                format!(
                    "File '{path}' changed before the write could be committed (expected {}, observed {}). No newer content was overwritten; read the file again and retry.",
                    expected.map_or_else(|| "missing".to_string(), |value| value.to_string()),
                    observed.map_or_else(|| "missing".to_string(), |value| value.to_string())
                ),
                ToolRetryability::Safe,
            ))
        }
        Err(secure_fs::AtomicWriteError::Failed(message)) => {
            ToolHandlerResult::error(ToolFailure::new(
                ToolFailureCode::External,
                format!("Failed to atomically write '{path}': {message}"),
                ToolRetryability::Unknown,
            ))
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

fn write_invalid(message: String) -> ToolHandlerResult {
    ToolHandlerResult::error(ToolFailure::new(
        ToolFailureCode::InvalidInput,
        message,
        ToolRetryability::Never,
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
        if let Some(snapshot) =
            super::READ_TRACKER.snapshot_for(test_run(), std::path::Path::new(path))
        {
            m.insert(
                "expected_snapshot".to_string(),
                serde_json::json!(snapshot.generation().to_string()),
            );
        }
        m
    }

    #[test]
    fn atomic_create_does_not_overwrite_an_existing_target() {
        let dir = TempDir::new_in(".").expect("tempdir");
        let target = dir.path().join("already-there.txt");
        std::fs::write(&target, "newer").expect("setup target");
        let target = target.canonicalize().expect("canonical target");
        let result = super::secure_fs::write_atomic_generation(
            test_run(),
            &target,
            None,
            b"stale create",
            super::MAX_MUTATION_BYTES,
        );
        assert!(
            matches!(
                result,
                Err(super::secure_fs::AtomicWriteError::Conflict { .. })
            ),
            "create-only publication must report a typed conflict: {result:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&target).expect("read back"),
            "newer"
        );
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
    fn one_byte_change_after_read_is_a_typed_conflict_and_is_not_overwritten() {
        let _lock = tracker_lock();
        let dir = TempDir::new_in(".").expect("tempdir");
        let path = dir.path().join("concurrent.txt");
        std::fs::write(&path, "alpha\n").expect("setup");
        super::READ_TRACKER.mark_read(test_run(), &path);
        let args = make_args(&path.to_string_lossy(), "replacement\n");
        std::fs::write(&path, "alphb\n").expect("concurrent one-byte change");

        let result = super::execute_write_file(test_run(), &args);

        assert!(matches!(
            &result.outcome,
            crate::tools::ToolOutcome::Error { failure }
                if failure.code == crate::tools::ToolFailureCode::Conflict
                    && failure.retryability == crate::tools::ToolRetryability::Safe
        ));
        assert_eq!(
            std::fs::read_to_string(&path).expect("read back"),
            "alphb\n"
        );
    }

    #[test]
    fn overwrite_requires_the_generation_to_be_named_explicitly() {
        let _lock = tracker_lock();
        let dir = TempDir::new_in(".").expect("tempdir");
        let path = dir.path().join("explicit-generation.txt");
        std::fs::write(&path, "old").expect("setup");
        super::READ_TRACKER.mark_read(test_run(), &path);
        let mut args = make_args(&path.to_string_lossy(), "new");
        args.remove("expected_snapshot");

        let result = super::execute_write_file(test_run(), &args);

        assert!(matches!(
            &result.outcome,
            crate::tools::ToolOutcome::Error { failure }
                if failure.code == crate::tools::ToolFailureCode::InvalidArguments
        ));
        assert_eq!(std::fs::read_to_string(&path).expect("read back"), "old");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_overwrite_preserves_existing_unix_mode() {
        use std::os::unix::fs::PermissionsExt as _;

        let _lock = tracker_lock();
        let dir = TempDir::new_in(".").expect("tempdir");
        let path = dir.path().join("executable.sh");
        std::fs::write(&path, "old\n").expect("setup");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("set executable mode");
        super::READ_TRACKER.mark_read(test_run(), &path);
        let args = make_args(&path.to_string_lossy(), "new\n");

        let (message, is_error) = super::execute_write_file(test_run(), &args).into_legacy();

        assert!(!is_error, "atomic overwrite must succeed: {message}");
        assert_eq!(
            std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o755
        );
    }

    #[test]
    fn successful_overwrite_publishes_the_next_snapshot_generation() {
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
            !is_err2,
            "the generation emitted by the first write must bind the second: {msg2}"
        );
        assert_eq!(std::fs::read_to_string(&path).expect("read back"), "newer");
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
            msg.contains("Read the file") || msg.contains("read_file"),
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
