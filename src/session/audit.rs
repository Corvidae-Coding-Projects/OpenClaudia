//! JSONL audit logging for sessions.
//!
//! # Error policy (crosslink #377)
//!
//! Earlier revisions treated audit failures as "best effort": [`AuditLogger`]
//! held an `Option<File>`, swallowed writes with `.ok()`, and printed to
//! `stderr` on `new()` failure. For a security-critical primitive that is the
//! wrong default — a disk-full condition or a permission error must not be
//! silently absorbed.
//!
//! This module now:
//!
//! 1. Returns [`AuditError`] from [`AuditLogger::new`] so the caller decides
//!    whether running un-audited is acceptable.
//! 2. Returns `Result<(), AuditError>` from [`AuditLogger::log`] and
//!    [`AuditLogger::log_security`] — callers MUST handle, propagate, or
//!    explicitly discard with a `tracing::warn!`/`tracing::error!`.
//! 3. Uses `tracing` (not `eprintln!`) for every failure path so log output is
//!    consistent with the rest of the codebase.
//! 4. Escalates failures of security-relevant events (tool dispatch, permission
//!    denials, etc.) to `tracing::error!` via [`AuditLogger::log_security`].
//!    Operational dashboards can alert on this distinct level.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use thiserror::Error;

/// Errors returned by [`AuditLogger`]. Distinguishes setup failures from
/// per-event write failures so callers can react differently (e.g. abort
/// session start vs. surface a warning mid-session).
#[derive(Debug, Error)]
pub enum AuditError {
    /// Failed to create the audit log directory.
    #[error("failed to create audit log directory {path}: {source}")]
    Mkdir {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Failed to open the audit log file for appending.
    #[error("failed to open audit log {path}: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The caller supplied a session id that cannot safely be used as a
    /// single audit-log filename component.
    #[error("invalid audit session id {session_id:?}: {reason}")]
    InvalidSessionId {
        session_id: String,
        reason: &'static str,
    },

    /// Failed to write/flush an audit entry. This is the variant that
    /// supersedes the previous silent `.ok()` swallow, so its name preserves
    /// the `Failed` suffix mandated by the issue brief (crosslink #377).
    #[error("failed to write audit entry: {source}")]
    WriteFailed {
        #[source]
        source: std::io::Error,
    },

    /// Failed to serialise the event payload to JSON. Should be unreachable
    /// for inputs the rest of the code produces, but exposed so callers do not
    /// have to introduce a separate error wrapping just for serialisation.
    #[error("failed to serialise audit entry: {source}")]
    Serialize {
        #[source]
        source: serde_json::Error,
    },
}

/// JSONL audit logger that records events for a session.
///
/// Unlike the pre-#377 implementation this type always holds an open file
/// handle. A disabled logger is no longer expressible — the constructor
/// either returns a usable logger or an error.
pub struct AuditLogger {
    file: std::fs::File,
    /// Retained for diagnostics on write failure (e.g. logrotate moved the file).
    path: PathBuf,
}

impl AuditLogger {
    /// Create an audit logger for `session_id` rooted at the standard
    /// `.openclaudia/logs` directory.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::Mkdir`] if the log directory cannot be
    /// created, or [`AuditError::Open`] if the JSONL file cannot be
    /// opened for appending.
    pub fn new(session_id: &str) -> Result<Self, AuditError> {
        match Self::new_in(Path::new(".openclaudia/logs"), session_id) {
            Ok(logger) => Ok(logger),
            Err(invalid @ AuditError::InvalidSessionId { .. }) => Err(invalid),
            Err(project_error) => {
                // The project directory can be read-only (for example when
                // an external supervisor mounts the workspace read-only for
                // a sandboxed agent). Audit logging must not kill the
                // session in that case: fall back to the per-user data
                // directory, and only fail when neither location works.
                let Some(fallback) = dirs::data_local_dir()
                    .map(|data_dir| data_dir.join("openclaudia").join("logs"))
                else {
                    return Err(project_error);
                };
                Self::new_in(&fallback, session_id).map_err(|_| project_error)
            }
        }
    }

    /// Variant of [`Self::new`] that targets a caller-supplied directory.
    /// Used by tests so they do not have to mutate the process CWD.
    ///
    /// # Errors
    ///
    /// Same as [`Self::new`].
    pub fn new_in(dir: &Path, session_id: &str) -> Result<Self, AuditError> {
        super::validate_session_file_id(session_id).map_err(|reason| {
            AuditError::InvalidSessionId {
                session_id: session_id.to_string(),
                reason,
            }
        })?;
        std::fs::create_dir_all(dir).map_err(|source| AuditError::Mkdir {
            path: dir.to_path_buf(),
            source,
        })?;
        let path = dir.join(format!("{session_id}.jsonl"));
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|source| AuditError::Open {
                path: path.clone(),
                source,
            })?;
        Ok(Self { file, path })
    }

    /// Path the logger is currently writing to. Exposed for diagnostics
    /// (callers may want to mention it when re-emitting an error).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Log a routine (non-security-critical) event.
    ///
    /// On failure this method does **not** itself log — the caller is
    /// responsible for deciding whether to escalate. Most call sites should
    /// pair this with `tracing::warn!` on the returned error.
    ///
    /// # Errors
    ///
    /// Returns [`AuditError::Serialize`] if `data` cannot be encoded as
    /// JSON, or [`AuditError::WriteFailed`] if the underlying file write
    /// fails.
    pub fn log(&mut self, event_type: &str, data: &serde_json::Value) -> Result<(), AuditError> {
        self.write_entry(event_type, data)
    }

    /// Log a security-relevant event (tool dispatch, permission denial,
    /// privilege change, etc.). Failure is escalated to `tracing::error!` so
    /// that operator dashboards alert on it — the caller still receives the
    /// `Result` and may take additional action.
    ///
    /// # Errors
    ///
    /// Same as [`Self::log`]. The error variant is returned **and** logged at
    /// `error` level before the return.
    pub fn log_security(
        &mut self,
        event_type: &str,
        data: &serde_json::Value,
    ) -> Result<(), AuditError> {
        match self.write_entry(event_type, data) {
            Ok(()) => Ok(()),
            Err(err) => {
                tracing::error!(
                    target: "audit",
                    event = event_type,
                    path = %self.path.display(),
                    error = %err,
                    "security audit event failed to persist"
                );
                Err(err)
            }
        }
    }

    fn write_entry(
        &mut self,
        event_type: &str,
        data: &serde_json::Value,
    ) -> Result<(), AuditError> {
        let entry = serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "event": event_type,
            "data": data,
        });
        let line =
            serde_json::to_string(&entry).map_err(|source| AuditError::Serialize { source })?;
        writeln!(self.file, "{line}").map_err(|source| AuditError::WriteFailed { source })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;
    use tracing::subscriber;
    use tracing_subscriber::fmt::MakeWriter;

    /// Shared buffer that satisfies `MakeWriter` so tests can capture the
    /// `tracing` output emitted by [`AuditLogger::log_security`].
    #[derive(Clone, Default)]
    struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

    impl CapturedWriter {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl std::io::Write for CapturedWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for CapturedWriter {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn happy_path_writes_jsonl_entry() {
        let dir = TempDir::new().unwrap();
        let mut logger = AuditLogger::new_in(dir.path(), "happy-session").unwrap();
        logger
            .log("test_event", &serde_json::json!({ "key": "value" }))
            .expect("log should succeed");
        let content = std::fs::read_to_string(dir.path().join("happy-session.jsonl")).unwrap();
        assert!(content.contains("test_event"));
        assert!(content.contains("\"key\":\"value\""));
    }

    #[test]
    fn new_rejects_path_traversal_session_id_without_creating_outside_log() {
        let dir = TempDir::new().unwrap();
        let escape_name = format!("audit-escape-{}", uuid::Uuid::new_v4().simple());
        let hostile_id = format!("../{escape_name}");
        let outside_path = dir
            .path()
            .parent()
            .expect("tempdir must have parent")
            .join(format!("{escape_name}.jsonl"));
        assert!(
            !outside_path.exists(),
            "unique outside fixture path should not pre-exist"
        );

        let Err(err) = AuditLogger::new_in(dir.path(), &hostile_id) else {
            panic!("path traversal session id must be rejected");
        };

        assert!(
            matches!(err, AuditError::InvalidSessionId { .. }),
            "expected InvalidSessionId, got {err:?}"
        );
        assert!(
            !outside_path.exists(),
            "invalid session id must not create a log outside the target directory"
        );
    }

    /// Mkdir failure surfaces a typed error — formerly this was an
    /// `eprintln!` + silent disabling. (`AuditLogger` deliberately does not
    /// implement `Debug` — it holds an open file handle — so we destructure
    /// rather than calling `unwrap_err`.)
    #[test]
    fn new_fails_when_target_path_is_not_a_directory() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("not_a_dir");
        std::fs::write(&file_path, b"").unwrap();
        // Passing a regular file as the log directory causes mkdir to fail.
        let Err(err) = AuditLogger::new_in(&file_path, "x") else {
            panic!("expected Err, got Ok");
        };
        assert!(
            matches!(err, AuditError::Mkdir { .. }),
            "expected AuditError::Mkdir, got {err:?}"
        );
    }

    /// Core #377 regression: a failed write must surface as
    /// `AuditError::WriteFailed`, not be silently dropped.
    #[test]
    fn write_failure_surfaces_as_write_failed() {
        let dir = TempDir::new().unwrap();
        let mut logger = AuditLogger::new_in(dir.path(), "write-fail").unwrap();
        // Replace the file handle with one opened read-only — the next
        // `writeln!` will fail with EBADF.
        let ro_file = std::fs::OpenOptions::new()
            .read(true)
            .open(dir.path().join("write-fail.jsonl"))
            .unwrap();
        logger.file = ro_file;
        let err = logger
            .log("evt", &serde_json::json!({}))
            .expect_err("write to read-only fd must error");
        assert!(
            matches!(err, AuditError::WriteFailed { .. }),
            "expected AuditError::WriteFailed, got {err:?}"
        );
    }

    /// Security-event failures must additionally be escalated to
    /// `tracing::error!`, so operator dashboards alert. We assert both the
    /// returned `Err` AND the captured tracing output.
    #[test]
    fn security_event_failure_escalates_to_error_log() {
        let captured = CapturedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_max_level(tracing::Level::ERROR)
            .with_ansi(false)
            .finish();

        subscriber::with_default(subscriber, || {
            let dir = TempDir::new().unwrap();
            let mut logger = AuditLogger::new_in(dir.path(), "sec-fail").unwrap();
            let ro_file = std::fs::OpenOptions::new()
                .read(true)
                .open(dir.path().join("sec-fail.jsonl"))
                .unwrap();
            logger.file = ro_file;

            let err = logger
                .log_security("tool_call", &serde_json::json!({"name": "bash"}))
                .expect_err("security write must fail");
            assert!(
                matches!(err, AuditError::WriteFailed { .. }),
                "expected AuditError::WriteFailed, got {err:?}"
            );
        });

        let captured = captured.contents();
        assert!(
            captured.contains("ERROR"),
            "expected ERROR-level tracing output, got: {captured}"
        );
        assert!(
            captured.contains("security audit event failed to persist"),
            "missing escalation message in: {captured}"
        );
        assert!(
            captured.contains("tool_call"),
            "captured output should mention the failing event: {captured}"
        );
    }

    /// Successful security events MUST NOT emit any tracing output —
    /// confirms the escalation is gated on the error path only.
    #[test]
    fn security_event_success_is_silent() {
        let captured = CapturedWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_max_level(tracing::Level::ERROR)
            .with_ansi(false)
            .finish();

        subscriber::with_default(subscriber, || {
            let dir = TempDir::new().unwrap();
            let mut logger = AuditLogger::new_in(dir.path(), "sec-ok").unwrap();
            logger
                .log_security("tool_call", &serde_json::json!({"name": "read"}))
                .expect("security write should succeed");
        });

        assert!(
            captured.contents().is_empty(),
            "no tracing output expected on success, got: {}",
            captured.contents()
        );
    }

    #[test]
    fn new_in_fails_cleanly_when_directory_is_read_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        let read_only = dir.path().join("frozen");
        std::fs::create_dir(&read_only).unwrap();
        std::fs::set_permissions(&read_only, std::fs::Permissions::from_mode(0o500)).unwrap();
        let target = read_only.join("logs");

        let error = AuditLogger::new_in(&target, "ro-session")
            .err()
            .expect("read-only parent must fail");
        assert!(matches!(error, AuditError::Mkdir { .. }), "{error:?}");
        std::fs::set_permissions(&read_only, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
}
