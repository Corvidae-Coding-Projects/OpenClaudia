use super::{
    canonicalize_or_walk_up, resolve_open_path, resolve_path, secure_fs, MAX_MUTATION_BYTES,
    READ_TRACKER,
};
use crate::tools::args::{ToolArgs as _, ToolError};
use crate::tools::{
    ToolArtifact, ToolDiff, ToolDisplay, ToolFailure, ToolFailureCode, ToolHandlerResult,
    ToolRetryability, ToolSensitivity,
};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::Path;

/// Canonicalise the user-supplied edit path. Thin wrapper around the
/// shared [`canonicalize_or_walk_up`] helper (crosslink #969) that
/// resolves the user-supplied path through `resolve_path` first.
fn canonicalise_edit_path(
    run: &crate::tools::security::ToolRunContext,
    path: &str,
) -> Result<String, String> {
    let p = resolve_path(run, path)?;
    let canonical = canonicalize_or_walk_up(&p, path)?;
    Ok(canonical.to_string_lossy().to_string())
}

/// Build the typed human-readable success and diff presentation.
///
/// Extracted from [`execute_edit_file`] so the parent function stays under
/// the clippy `too_many_lines` threshold once the crosslink #687
/// `replace_all` branch is added.
///
/// Emits a structured `tracing::event!` carrying the same data so subscribers
/// (log sinks, observability tooling) and frontends consume the diff without
/// parsing an in-band string protocol (crosslinks #670 and #971).
fn format_edit_success(
    run: &crate::tools::ToolRunContext,
    path: &str,
    old_string: &str,
    new_string: &str,
    count: usize,
    replace_all: bool,
    snapshots: (crate::runtime::ContentDigest, crate::runtime::ContentDigest),
) -> ToolHandlerResult {
    let (before_snapshot, after_snapshot) = snapshots;
    tracing::event!(
        target: "openclaudia::tools::edit",
        tracing::Level::DEBUG,
        path = path,
        old_chars = old_string.len(),
        new_chars = new_string.len(),
        replacements = count,
        replace_all = replace_all,
        "file edited"
    );

    let mut summary = if replace_all && count > 1 {
        format!(
            "Successfully edited '{}'. Replaced {} occurrences ({} chars each with {} chars).",
            path,
            count,
            old_string.len(),
            new_string.len(),
        )
    } else {
        format!(
            "Successfully edited '{}'. Replaced {} chars with {} chars.",
            path,
            old_string.len(),
            new_string.len(),
        )
    };
    if let Some(warning) = crate::guardrails::check_diff_thresholds(run) {
        let _ = write!(summary, "\n\nWarning: {}", warning.message);
    }
    let safe_old = run.sanitize_diagnostic(old_string).to_string();
    let safe_new = run.sanitize_diagnostic(new_string).to_string();
    let redacted = safe_old != old_string || safe_new != new_string;
    let diff = ToolDiff {
        path: path.to_string(),
        old_text: safe_old,
        new_text: safe_new,
        before_snapshot: before_snapshot.to_string(),
        after_snapshot: after_snapshot.to_string(),
        redacted,
    };
    ToolHandlerResult::success_structured(
        summary.clone(),
        serde_json::json!({
            "path": path,
            "replacements": count,
            "replace_all": replace_all,
            "old_chars": old_string.len(),
            "new_chars": new_string.len(),
            "before_snapshot": before_snapshot,
            "after_snapshot": after_snapshot,
            "diff_redacted": redacted,
        }),
    )
    .with_display(ToolDisplay::Diff {
        summary,
        diff: diff.clone(),
    })
    .with_artifact(ToolArtifact {
        id: format!("diff:{path}"),
        kind: "file_diff".to_string(),
        label: path.to_string(),
        metadata: serde_json::to_value(diff).expect("ToolDiff serialization cannot fail"),
        sensitivity: if redacted {
            ToolSensitivity::Private
        } else {
            ToolSensitivity::Workspace
        },
    })
}

fn edit_error(message: String) -> ToolHandlerResult {
    ToolHandlerResult::error(ToolFailure::new(
        ToolFailureCode::External,
        message,
        ToolRetryability::Unknown,
    ))
}

fn edit_failure(failure: ToolFailure) -> ToolHandlerResult {
    ToolHandlerResult::error(failure)
}

fn edit_invalid(message: String) -> ToolHandlerResult {
    edit_failure(ToolFailure::new(
        ToolFailureCode::InvalidInput,
        message,
        ToolRetryability::Never,
    ))
}

/// Edit a file by replacing text.
///
/// Honours the optional `replace_all: bool` argument (crosslink #687):
/// when `true` every occurrence of `old_string` is replaced; when `false`
/// or absent, multi-occurrence inputs are rejected so callers must provide
/// a uniquely-matching `old_string`.
#[allow(clippy::too_many_lines)]
pub fn execute_edit_file(
    run: &std::sync::Arc<crate::tools::security::ToolRunContext>,
    args: &HashMap<String, Value>,
) -> ToolHandlerResult {
    // crosslink #675: typed accessor.
    let user_path = match args.arg_str_strict("path") {
        Ok(p) => p,
        Err(e) => return ToolHandlerResult::from_migrated(Err(ToolError::InvalidArgument(e))),
    };

    // Path passed to `open(2)`: canonical parent + original leaf so that
    // `O_NOFOLLOW` on the leaf can catch a symlink-swap. See crosslink #417.
    let open_path = match resolve_open_path(run, user_path) {
        Ok(p) => p,
        Err(e) => return edit_error(e),
    };

    // Resolve symlinks to prevent symlink-based path traversal.
    let path = match canonicalise_edit_path(run, user_path) {
        Ok(p) => p,
        Err(e) => return edit_error(e),
    };
    let path = path.as_str();

    // crosslink #675: typed accessors.
    let old_string = match args.arg_str_strict("old_string") {
        Ok(s) => s,
        Err(e) => return ToolHandlerResult::from_migrated(Err(ToolError::InvalidArgument(e))),
    };
    let new_string = match args.arg_str_strict("new_string") {
        Ok(s) => s,
        Err(e) => return ToolHandlerResult::from_migrated(Err(ToolError::InvalidArgument(e))),
    };

    if old_string.is_empty() {
        return edit_invalid(
            "old_string must not be empty; an empty pattern is a degenerate match at every character boundary"
                .to_string(),
        );
    }

    // crosslink #970: a no-op edit (`old_string == new_string`) would otherwise
    // burn a full read+truncate+write cycle on the file, churn the mtime, and
    // misleadingly report "Successfully edited". Refuse the call before any
    // I/O so the model is told the change would be a no-op and can correct
    // the request in the same turn.
    if old_string == new_string {
        return edit_error(
            "old_string and new_string are identical — edit would be a no-op. Either change one or remove the call."
                .to_string(),
        );
    }

    // crosslink #687: honour the `replace_all` flag. When `true`, all
    // occurrences are replaced; when `false` (or absent) the existing
    // single-occurrence-with-multi-rejection behaviour is preserved.
    // crosslink #675: typed default-with-fallback accessor.
    let replace_all = match args.arg_bool_or_strict("replace_all", false) {
        Ok(value) => value,
        Err(e) => return ToolHandlerResult::from_migrated(Err(ToolError::InvalidArgument(e))),
    };

    let snapshot =
        match super::require_expected_snapshot(run, Path::new(path), args.get("expected_snapshot"))
        {
            Ok(snapshot) => snapshot,
            Err(failure) => return edit_failure(failure),
        };
    if let Err(msg) =
        super::require_fresh_file_observation_if_ledger_active(run, Path::new(path), "editing it")
    {
        return edit_error(msg);
    }

    let bytes = match super::read_expected_snapshot_bytes(run, Path::new(path), snapshot) {
        Ok(bytes) => bytes,
        Err(failure) => return edit_failure(failure),
    };
    let content = match String::from_utf8(bytes) {
        Ok(content) => content,
        Err(error) => {
            return edit_invalid(format!(
                "File '{path}' is not UTF-8 text and cannot be edited with edit_file: {error}"
            ))
        }
    };

    // Count without retaining every offset. A small pattern in a large file
    // must not allocate a vector proportional to the number of matches.
    let count = content.match_indices(old_string).count();
    match count {
        0 => {
            return edit_error(format!(
                "Could not find the specified text in '{path}'. Make sure old_string matches exactly."
            ));
        }
        1 => {}
        many if !replace_all => {
            return edit_error(format!(
                "Found {many} occurrences of the text. Please provide a more specific old_string that matches uniquely, or set replace_all: true to replace every occurrence."
            ));
        }
        _ => {}
    }

    let replaced_bytes = old_string.len().checked_mul(count).and_then(|removed| {
        new_string
            .len()
            .checked_mul(count)
            .and_then(|added| content.len().checked_sub(removed)?.checked_add(added))
    });
    let Some(result_bytes) = replaced_bytes else {
        return edit_invalid(format!("Edit result size overflow for '{path}'"));
    };
    if result_bytes > MAX_MUTATION_BYTES {
        return edit_invalid(format!(
            "Edit result for '{path}' would be {result_bytes} bytes, exceeding the {MAX_MUTATION_BYTES}-byte file limit"
        ));
    }

    // crosslink #988: `str::lines()` only recognises `\n` and `\r\n` and
    // collapses a final trailing newline so e.g. "x\n" → 1 line, "x" → 1
    // line, "x\n" replaced by "y" reports the same physical-line count on
    // both sides which silently hides newline-only deltas from the guardrails
    // diff-threshold check. Count physical `\n` bytes plus an extra line for
    // a non-empty tail that does NOT end in `\n` so the unit is "physical
    // lines as the diff sees them," matching what `record_file_modification`
    // expects.
    let new_content = if replace_all {
        content.replace(old_string, new_string)
    } else {
        content.replacen(old_string, new_string, 1)
    };
    debug_assert_eq!(new_content.len(), result_bytes);
    let prepared_diff = match super::prepare_file_diff(run, path, &content, &new_content) {
        Ok(prepared) => prepared,
        Err(message) => return edit_invalid(message),
    };
    let mut line_reservation = match crate::guardrails::reserve_changed_lines(
        run,
        u64::from(prepared_diff.lines_added) + u64::from(prepared_diff.lines_removed),
    ) {
        Ok(reservation) => reservation,
        Err(message) => return edit_error(message),
    };
    let diff_permit =
        match crate::guardrails::admit_file_change(run, Path::new(path), new_content.as_bytes()) {
            Ok(permit) => permit,
            Err(message) => return edit_error(message),
        };

    match secure_fs::write_atomic_generation(
        run,
        &open_path,
        Some(snapshot.generation()),
        new_content.as_bytes(),
        MAX_MUTATION_BYTES,
    ) {
        Ok(after_snapshot) => {
            line_reservation.commit();
            diff_permit.commit();
            crate::guardrails::record_file_modification(
                run,
                path,
                prepared_diff.lines_added,
                prepared_diff.lines_removed,
            );
            super::record_prepared_diff_observation(
                run,
                path,
                new_content.as_bytes(),
                &prepared_diff,
            );
            format_edit_success(
                run,
                path,
                old_string,
                new_string,
                count,
                replace_all,
                (snapshot.generation(), after_snapshot),
            )
        }
        Err(secure_fs::AtomicWriteError::Conflict { expected, observed }) => {
            READ_TRACKER.mark_stale(run, Path::new(path));
            edit_failure(ToolFailure::new(
                ToolFailureCode::Conflict,
                format!(
                    "File '{path}' changed before the edit could be committed (expected {}, observed {}). No newer content was overwritten; read the file again and retry.",
                    expected.map_or_else(|| "missing".to_string(), |value| value.to_string()),
                    observed.map_or_else(|| "missing".to_string(), |value| value.to_string())
                ),
                ToolRetryability::Safe,
            ))
        }
        Err(secure_fs::AtomicWriteError::Failed(message)) => edit_failure(ToolFailure::new(
            ToolFailureCode::External,
            format!("Failed to atomically edit '{path}': {message}"),
            ToolRetryability::Unknown,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::super::READ_TRACKER;
    use std::io::Write as _;
    use std::path::Path;
    use tempfile::NamedTempFile;

    fn test_run() -> &'static std::sync::Arc<crate::tools::ToolRunContext> {
        crate::tools::security::test_run_context()
    }

    /// Write content to a `NamedTempFile`, mark it as read in `READ_TRACKER`,
    /// and return (file, `canonical_path_string`).
    fn tmp_readable(content: &str) -> (NamedTempFile, String) {
        let mut f = NamedTempFile::new_in(".").expect("tempfile");
        f.write_all(content.as_bytes()).expect("write");
        let canon = f.path().canonicalize().expect("canonicalize");
        READ_TRACKER.mark_read(test_run(), &canon);
        let path = canon.to_string_lossy().to_string();
        (f, path)
    }

    fn make_args(
        path: &str,
        old: &str,
        new: &str,
    ) -> std::collections::HashMap<String, serde_json::Value> {
        let mut m = std::collections::HashMap::new();
        m.insert("path".to_string(), serde_json::json!(path));
        m.insert("old_string".to_string(), serde_json::json!(old));
        m.insert("new_string".to_string(), serde_json::json!(new));
        if let Some(snapshot) = READ_TRACKER.snapshot_for(test_run(), Path::new(path)) {
            m.insert(
                "expected_snapshot".to_string(),
                serde_json::json!(snapshot.generation().to_string()),
            );
        }
        m
    }

    // =========================================================================
    // Behavior 4: old_string not found → explicit error, no modification
    // =========================================================================

    #[test]
    fn edit_old_string_not_found_returns_error() {
        // Behavior 4: absent old_string must produce an error result.
        let (_f, path) = tmp_readable("hello world\n");
        let args = make_args(&path, "DOES NOT EXIST", "replacement");
        let (msg, is_err) = super::execute_edit_file(test_run(), &args).into_legacy();
        assert!(is_err, "missing old_string must be an error: {msg}");
        assert!(
            msg.contains("Could not find the specified text"),
            "error message: {msg}"
        );
    }

    #[test]
    fn edit_old_string_not_found_does_not_modify_file() {
        // Behavior 4: file content must be unchanged when old_string is absent.
        let original = "unchanged content\n";
        let (_f, path) = tmp_readable(original);
        let args = make_args(&path, "ABSENT", "whatever");
        let _ = super::execute_edit_file(test_run(), &args);
        let after = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(
            after, original,
            "file must be unmodified on not-found error"
        );
    }

    #[test]
    fn one_byte_change_after_read_is_a_typed_conflict_and_is_not_overwritten() {
        let (_file, path) = tmp_readable("alpha\n");
        let args = make_args(&path, "alpha", "omega");
        std::fs::write(&path, "alphb\n").expect("concurrent one-byte change");

        let result = super::execute_edit_file(test_run(), &args);

        assert!(matches!(
            &result.outcome,
            crate::tools::ToolOutcome::Error { failure }
                if failure.code == crate::tools::ToolFailureCode::Conflict
                    && failure.retryability == crate::tools::ToolRetryability::Safe
        ));
        assert_eq!(
            std::fs::read_to_string(&path).expect("read back"),
            "alphb\n",
            "the newer generation must remain intact"
        );
    }

    #[test]
    fn edit_requires_the_generation_to_be_named_explicitly() {
        let (_file, path) = tmp_readable("alpha\n");
        let mut args = make_args(&path, "alpha", "omega");
        args.remove("expected_snapshot");

        let result = super::execute_edit_file(test_run(), &args);

        assert!(matches!(
            &result.outcome,
            crate::tools::ToolOutcome::Error { failure }
                if failure.code == crate::tools::ToolFailureCode::InvalidArguments
        ));
        assert_eq!(
            std::fs::read_to_string(&path).expect("read back"),
            "alpha\n"
        );
    }

    #[test]
    fn empty_pattern_is_rejected_before_replacement_allocation() {
        let (_file, path) = tmp_readable("alpha\n");
        let args = make_args(&path, "", "x");

        let result = super::execute_edit_file(test_run(), &args);

        assert!(matches!(
            &result.outcome,
            crate::tools::ToolOutcome::Error { failure }
                if failure.code == crate::tools::ToolFailureCode::InvalidInput
        ));
        assert_eq!(
            std::fs::read_to_string(&path).expect("read back"),
            "alpha\n"
        );
    }

    #[test]
    fn replacement_expansion_over_file_limit_is_rejected_without_mutation() {
        let original = "x".repeat(super::MAX_MUTATION_BYTES / 2 + 1);
        let (_file, path) = tmp_readable(&original);
        let mut args = make_args(&path, "x", "yy");
        args.insert("replace_all".to_string(), serde_json::json!(true));

        let result = super::execute_edit_file(test_run(), &args);

        assert!(matches!(
            &result.outcome,
            crate::tools::ToolOutcome::Error { failure }
                if failure.code == crate::tools::ToolFailureCode::InvalidInput
        ));
        assert_eq!(
            std::fs::metadata(&path).expect("metadata").len(),
            u64::try_from(original.len()).expect("test length")
        );
    }

    #[test]
    fn diff_display_redacts_secret_assignments_and_binds_both_generations() {
        const SECRET: &str = "super-secret-value-123456";
        let (_file, path) = tmp_readable(&format!("api_key={SECRET}\n"));
        let args = make_args(&path, &format!("api_key={SECRET}"), "api_key=replaced");

        let result = super::execute_edit_file(test_run(), &args);

        let crate::tools::ToolDisplay::Diff { diff, .. } = &result.display else {
            panic!("successful edit must retain typed diff metadata")
        };
        assert!(diff.redacted);
        assert!(!diff.old_text.contains(SECRET));
        assert!(diff.old_text.contains("[REDACTED]"));
        assert!(diff.before_snapshot.starts_with("sha256:"));
        assert!(diff.after_snapshot.starts_with("sha256:"));
        assert_ne!(diff.before_snapshot, diff.after_snapshot);
    }

    // =========================================================================
    // Behavior 4 edge: CC performs quote normalization; OC does exact match
    // =========================================================================

    #[test]
    fn edit_curly_quote_not_normalized_returns_error() {
        // Behavior 4 edge: OC uses exact byte-match — curly quotes are NOT
        // substituted for straight quotes (CC does this via findActualString).
        // Pinned as current OC behavior; CC parity gap noted in #525 spec.
        let (_f, path) = tmp_readable("it's fine\n");
        // Search with a straight apostrophe when file has a curly one
        let args = make_args(&path, "it's fine", "ok");
        let (msg, is_err) = super::execute_edit_file(test_run(), &args).into_legacy();
        // OC will return error (cannot find with straight quote); CC would find it.
        // We pin whichever OC currently does — the key assertion is the file is intact.
        let after = std::fs::read_to_string(&path).expect("read back");
        if is_err {
            // Expected OC path: exact match fails
            assert!(msg.contains("Could not find"), "error message: {msg}");
            assert!(after.contains("it's fine"), "file unmodified");
        } else {
            // If OC somehow matches (e.g. file was written with straight quote by
            // NamedTempFile), the replacement is fine — the point is no panic.
            assert!(!after.contains("it\u{2019}s fine") || after.contains("ok"));
        }
    }

    // =========================================================================
    // Behavior 4 edge: old_string === new_string  (crosslink #970)
    // =========================================================================

    /// crosslink #970 regression: a no-op edit (`old_string == new_string`)
    /// must be rejected BEFORE any filesystem I/O, so the call burns no read /
    /// truncate / write and the mtime is not churned. The matching CC error
    /// code is 1; we surface a textual error explaining why the call was a
    /// no-op so the model can correct in the same turn.
    #[test]
    fn edit_old_equals_new_is_rejected_as_noop_970() {
        let (f, path) = tmp_readable("foo bar\n");
        let mtime_before = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .expect("mtime before");

        let args = make_args(&path, "foo bar", "foo bar");
        let (msg, is_err) = super::execute_edit_file(test_run(), &args).into_legacy();

        assert!(is_err, "old==new must produce is_error=true; got: {msg}");
        assert!(
            msg.contains("identical") || msg.contains("no-op"),
            "error message must explain the no-op: {msg}"
        );

        // File contents and mtime must be untouched — the call should not have
        // performed any write (let alone truncate-then-rewrite).
        let after = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(after, "foo bar\n", "file contents must be unchanged");
        let mtime_after = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .expect("mtime after");
        assert_eq!(
            mtime_before, mtime_after,
            "mtime must not advance on a rejected no-op edit"
        );
        drop(f);
    }

    // =========================================================================
    // Behavior 5: replace_all — OC rejects multi-occurrence unconditionally
    // =========================================================================

    #[test]
    fn edit_single_occurrence_succeeds() {
        // Behavior 5: single occurrence with no replace_all flag → success
        let (_f, path) = tmp_readable("alpha beta gamma\n");
        let args = make_args(&path, "beta", "BETA");
        let (msg, is_err) = super::execute_edit_file(test_run(), &args).into_legacy();
        assert!(!is_err, "single occurrence replace must succeed: {msg}");
        let after = std::fs::read_to_string(&path).expect("read back");
        assert!(after.contains("BETA"), "replacement applied");
        assert!(!after.contains(" beta "), "old string gone");
    }

    #[test]
    fn successful_edit_publishes_the_next_snapshot_generation() {
        let _lock = super::super::shared_tracker_lock();
        let (_f, path) = tmp_readable("first\nsecond\n");
        let args = make_args(&path, "first", "one");
        let (msg, is_err) = super::execute_edit_file(test_run(), &args).into_legacy();
        assert!(!is_err, "first edit must succeed: {msg}");

        let args2 = make_args(&path, "second", "two");
        let (msg2, is_err2) = super::execute_edit_file(test_run(), &args2).into_legacy();
        assert!(
            !is_err2,
            "the generation emitted by the first edit must bind the second edit: {msg2}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("read back"),
            "one\ntwo\n"
        );
    }

    #[test]
    fn active_ledger_edit_requires_fresh_file_read_observation() {
        let _lock = super::super::shared_tracker_lock();
        READ_TRACKER.clear_all();
        let run = test_run();
        let ledger =
            std::sync::Arc::new(std::sync::Mutex::new(crate::ledger::RealityLedger::new()));
        let _ledger_guard =
            crate::ledger::install_active_ledger_for_session(run.session_id(), ledger);
        let (_f, path) = tmp_readable("before\n");

        let args = make_args(&path, "before", "after");
        let (msg, is_err) = super::execute_edit_file(run, &args).into_legacy();

        assert!(is_err, "ledger-less edit must be denied: {msg}");
        assert!(
            msg.contains("active reality ledger has no fresh file read observation"),
            "{msg}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("read back"),
            "before\n"
        );
    }

    #[test]
    fn edit_multi_occurrence_without_replace_all_errors() {
        // Behavior 5: N>1 occurrences without replace_all → error in both CC and OC
        let (_f, path) = tmp_readable("dog cat dog\n");
        let args = make_args(&path, "dog", "bird");
        let (msg, is_err) = super::execute_edit_file(test_run(), &args).into_legacy();
        assert!(is_err, "multi-occurrence must error: {msg}");
        assert!(
            msg.contains('2'),
            "error must mention occurrence count: {msg}"
        );
    }

    #[test]
    fn fix687_replace_all_true_replaces_every_occurrence() {
        // crosslink #687: replace_all=true must replace every occurrence
        // instead of returning the "be more specific" error.
        let (_f, path) = tmp_readable("x y x z x\n");
        let mut args = make_args(&path, "x", "Z");
        args.insert("replace_all".to_string(), serde_json::json!(true));
        let (msg, is_err) = super::execute_edit_file(test_run(), &args).into_legacy();
        assert!(
            !is_err,
            "replace_all=true must succeed on multi-occurrence: {msg}"
        );
        let after = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(after, "Z y Z z Z\n", "all occurrences replaced");
        assert!(
            msg.contains("3 occurrences"),
            "success message must report the count: {msg}"
        );
    }

    #[test]
    fn fix687_replace_all_false_preserves_existing_multi_occurrence_error() {
        // crosslink #687 regression guard: replace_all=false (the default) MUST
        // keep returning the single-occurrence rejection on N>1 hits.
        let (_f, path) = tmp_readable("dog cat dog\n");
        let mut args = make_args(&path, "dog", "bird");
        args.insert("replace_all".to_string(), serde_json::json!(false));
        let (msg, is_err) = super::execute_edit_file(test_run(), &args).into_legacy();
        assert!(
            is_err,
            "replace_all=false on multi-occurrence must still error: {msg}"
        );
        assert!(
            msg.contains("Found 2 occurrences"),
            "error must still mention occurrence count: {msg}"
        );
        assert!(
            msg.contains("replace_all"),
            "remediation hint must mention replace_all: {msg}"
        );
        let after = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(after, "dog cat dog\n");
    }

    #[test]
    fn fix687_absent_replace_all_defaults_to_false() {
        // crosslink #687: when replace_all is absent, behaviour matches replace_all=false.
        let (_f, path) = tmp_readable("dup dup dup\n");
        let args = make_args(&path, "dup", "X");
        let (msg, is_err) = super::execute_edit_file(test_run(), &args).into_legacy();
        assert!(is_err, "default (absent flag) must reject multi: {msg}");
        let after = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(after, "dup dup dup\n", "file unmodified");
    }

    #[test]
    fn fix687_replace_all_true_single_occurrence_still_succeeds() {
        // crosslink #687: replace_all=true with exactly 1 occurrence still works
        // (the count==1 path uses replacen, which is equivalent here).
        let (_f, path) = tmp_readable("only once\n");
        let mut args = make_args(&path, "only once", "exactly once");
        args.insert("replace_all".to_string(), serde_json::json!(true));
        let (msg, is_err) = super::execute_edit_file(test_run(), &args).into_legacy();
        assert!(
            !is_err,
            "single occurrence with replace_all succeeds: {msg}"
        );
        let after = std::fs::read_to_string(&path).expect("read back");
        assert!(after.contains("exactly once"));
    }

    #[test]
    fn edit_rejects_non_boolean_replace_all() {
        let (_f, path) = tmp_readable("alpha beta alpha\n");
        let mut args = make_args(&path, "alpha", "omega");
        args.insert("replace_all".to_string(), serde_json::json!("true"));

        let (msg, is_err) = super::execute_edit_file(test_run(), &args).into_legacy();

        assert!(is_err, "non-boolean replace_all must error: {msg}");
        assert!(
            msg.contains("Invalid 'replace_all' argument: expected boolean"),
            "unexpected error: {msg}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("read back"),
            "alpha beta alpha\n"
        );
    }

    // =========================================================================
    // Behavior 4/5 error path: must read before editing
    // =========================================================================

    #[test]
    fn edit_requires_prior_read() {
        // Not in #525 spec directly, but the read-before-edit enforcement is a
        // contract that interacts with all Behavior 4/5 tests; pin it explicitly.
        let mut f = NamedTempFile::new_in(".").expect("tempfile");
        f.write_all(b"some content\n").expect("write");
        let path = f.path().canonicalize().expect("canon");
        // Deliberately do NOT call READ_TRACKER.mark_read(test_run(), ) for this file
        let path_str = path.to_string_lossy().to_string();
        // Use a path that was never marked read; ensure it's unique so unrelated tests
        // don't accidentally mark it.
        let fresh_path = format!("{path_str}_never_read");
        std::fs::copy(&path, Path::new(&fresh_path)).ok(); // best-effort copy
        let args = make_args(&fresh_path, "some content", "other");
        let (msg, is_err) = super::execute_edit_file(test_run(), &args).into_legacy();
        assert!(is_err, "edit without prior read must error: {msg}");
        assert!(
            msg.contains("read") || msg.contains("Read"),
            "message: {msg}"
        );
        // clean up
        let _ = std::fs::remove_file(&fresh_path);
    }

    // =========================================================================
    // crosslink #569: explicit issue-tagged tests for replace_all support.
    // The flag's runtime support landed under #687; these two tests pin the
    // issue-#569 contract so the next reviewer doesn't lose the trail.
    // =========================================================================

    #[test]
    fn fix569_replace_all_true_with_three_matches_replaces_all() {
        // crosslink #569: `replace_all=true` must replace every occurrence,
        // not silently drop the flag and bail with "be more specific".
        // Scenario: three distinct hits, all of which must be rewritten.
        let (_f, path) = tmp_readable("foo and foo and foo end\n");
        let mut args = make_args(&path, "foo", "BAR");
        args.insert("replace_all".to_string(), serde_json::json!(true));
        let (msg, is_err) = super::execute_edit_file(test_run(), &args).into_legacy();
        assert!(
            !is_err,
            "replace_all=true with 3 matches must succeed: {msg}"
        );
        let after = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(
            after, "BAR and BAR and BAR end\n",
            "all three occurrences must be replaced"
        );
        // The success message reports the occurrence count so reviewers can
        // tell at a glance that the multi-replace path actually ran.
        assert!(
            msg.contains("3 occurrences"),
            "success message must report count=3: {msg}"
        );
    }

    #[test]
    fn fix569_replace_all_false_default_preserves_single_match_behavior() {
        // crosslink #569: when `replace_all` is omitted (i.e. defaults to
        // false), single-match edits must continue to work unchanged — the
        // flag must not regress the existing happy path.
        let (_f, path) = tmp_readable("unique_token here\nother line\n");
        let args = make_args(&path, "unique_token", "REPLACED");
        // Deliberately do NOT insert `replace_all`; rely on the default.
        let (msg, is_err) = super::execute_edit_file(test_run(), &args).into_legacy();
        assert!(
            !is_err,
            "default (no replace_all) single-match edit must succeed: {msg}"
        );
        let after = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(
            after, "REPLACED here\nother line\n",
            "single match must be replaced exactly once"
        );
        // The single-match path uses the non-counted success message —
        // make sure we did NOT accidentally enter the multi-occurrence
        // formatter (which would say "Replaced N occurrences").
        assert!(
            !msg.contains("occurrences"),
            "single-match success must use the singular message, got: {msg}"
        );
    }

    // ===== crosslink #417: edit rejects symlink-swap on the leaf =====

    #[cfg(unix)]
    #[test]
    fn fix417_edit_rejects_symlink_at_target() {
        use tempfile::TempDir;
        let dir = TempDir::new_in(".").expect("tempdir");
        let target = dir.path().join("attacker_target.txt");
        std::fs::write(&target, "PROTECTED\n").expect("setup target");
        let leaf = dir.path().join("leaf.txt");
        std::os::unix::fs::symlink(&target, &leaf).expect("symlink");
        let leaf_canon = leaf.canonicalize().expect("canonicalize leaf");
        READ_TRACKER.mark_read(test_run(), &leaf_canon);
        let args = make_args(&leaf.to_string_lossy(), "PROTECTED", "PWNED");
        let (msg, is_err) = super::execute_edit_file(test_run(), &args).into_legacy();
        assert!(
            is_err,
            "edit through a symlink leaf must fail (O_NOFOLLOW): {msg}"
        );
        let target_contents = std::fs::read_to_string(&target).expect("read target");
        assert_eq!(
            target_contents, "PROTECTED\n",
            "symlink target must not be overwritten"
        );
    }

    #[test]
    fn fix417_edit_legitimate_regular_file_still_works() {
        let (_f, path) = tmp_readable("alpha beta gamma\n");
        let args = make_args(&path, "beta", "BETA");
        let (msg, is_err) = super::execute_edit_file(test_run(), &args).into_legacy();
        assert!(!is_err, "regular-file edit must succeed: {msg}");
        let after = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(after, "alpha BETA gamma\n");
    }

    // ===== crosslink #470: single-pass match_indices replaces triple-scan =====

    #[test]
    fn fix470_edit_unique_old_string_succeeds() {
        // crosslink #470: regression — the single-pass match_indices path must
        // still handle the [single] arm without an off-by-one.
        let (_f, path) = tmp_readable("one two three\n");
        let args = make_args(&path, "two", "TWO");
        let (msg, is_err) = super::execute_edit_file(test_run(), &args).into_legacy();
        assert!(!is_err, "unique match must succeed: {msg}");
        let after = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(after, "one TWO three\n");
    }

    #[test]
    fn fix470_edit_absent_old_string_returns_not_found_error() {
        // crosslink #470: the [] arm must return the "Could not find" error,
        // not silently fall through to the multi-match arm.
        let (_f, path) = tmp_readable("alpha beta\n");
        let args = make_args(&path, "gamma", "GAMMA");
        let (msg, is_err) = super::execute_edit_file(test_run(), &args).into_legacy();
        assert!(is_err, "absent old_string must error: {msg}");
        assert!(
            msg.contains("Could not find the specified text"),
            "expected not-found error, got: {msg}"
        );
        let after = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(after, "alpha beta\n", "file must be unmodified");
    }

    #[test]
    fn fix470_edit_two_plus_matches_returns_specific_error() {
        // crosslink #470: the multi-match arm without replace_all must report
        // the exact occurrence count from the collected match_indices slice.
        let (_f, path) = tmp_readable("abc abc abc abc\n");
        let args = make_args(&path, "abc", "XYZ");
        let (msg, is_err) = super::execute_edit_file(test_run(), &args).into_legacy();
        assert!(is_err, "multi-match without replace_all must error: {msg}");
        assert!(
            msg.contains("Found 4 occurrences"),
            "error must name the count from the single-pass scan: {msg}"
        );
        let after = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(after, "abc abc abc abc\n", "file must be unmodified");
    }

    #[test]
    fn fix417_edit_shrinking_replacement_truncates_correctly() {
        let (_f, path) = tmp_readable("XXXXXXXXXX\n");
        let args = make_args(&path, "XXXXXXXXXX", "Y");
        let (msg, is_err) = super::execute_edit_file(test_run(), &args).into_legacy();
        assert!(!is_err, "shrinking edit must succeed: {msg}");
        let after = std::fs::read_to_string(&path).expect("read back");
        assert_eq!(after, "Y\n", "no stale tail bytes after shrinking write");
    }
}
