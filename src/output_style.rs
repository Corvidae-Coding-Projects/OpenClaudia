//! Output style customization for response formatting.
//!
//! Loads an explicitly user-owned style from `~/.openclaudia/output-style.md`.
//! Repository files are deliberately not consulted because project content
//! must not gain automatic system-prompt authority.

use std::io;
use std::path::{Path, PathBuf};

use crate::context::{ContextFreshness, ContextItem, ContextSensitivity, UserInstructionSource};
use crate::file_error::{self, FileError};

const USER_STYLE_DISPLAY_PATH: &str = "~/.openclaudia/output-style.md";

fn user_style_path() -> Option<PathBuf> {
    dirs::home_dir().map(|home| home.join(".openclaudia/output-style.md"))
}

/// Load the active user-owned output style, if any.
///
/// Read errors other than `NotFound` (e.g. permission denied, encoding) are
/// logged at WARN with the file path and error message, then treated as
/// "no style configured" so the caller can continue without a style. A
/// missing file (`NotFound`) is the normal "no style" path and stays silent.
#[must_use]
pub fn load_output_style_context() -> Option<ContextItem> {
    let path = user_style_path()?;
    let content = read_style(&path)?;
    Some(
        ContextItem::user_instruction(
            "user.output_style",
            UserInstructionSource::OutputStyle,
            path.display().to_string(),
            format!("## User Output Style\n{content}"),
            ContextFreshness::Session,
            120,
        )
        .with_sensitivity(ContextSensitivity::Confidential),
    )
}

fn read_style(path: &Path) -> Option<String> {
    match std::fs::read_to_string(path) {
        Ok(content) => {
            let trimmed = content.trim();
            if trimmed.is_empty() {
                None
            } else {
                // This file is explicitly user-owned instruction input. Its
                // authority is carried by ContextItem rather than inferred
                // from delimiter escaping.
                Some(trimmed.to_string())
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "Failed to read output-style file; treating as no style configured"
            );
            None
        }
    }
}

/// Get a list of built-in style presets
#[must_use]
pub fn builtin_styles() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "concise",
            "Be extremely concise. Lead with the answer. No filler, no preamble. One sentence when possible.",
        ),
        (
            "detailed",
            "Provide thorough, detailed explanations. Include examples and edge cases. Use headers for organization.",
        ),
        (
            "minimal",
            "Respond with the absolute minimum text needed. No greetings, no sign-offs, no explanations unless asked.",
        ),
        (
            "educational",
            "Explain concepts step by step. Use analogies. Highlight key terms. Suitable for learning.",
        ),
        (
            "code-only",
            "When asked to write code, respond with ONLY the code. No explanations before or after unless specifically asked.",
        ),
    ]
}

fn save_style_at(path: &Path, content: &str) -> Result<(), FileError> {
    let Some(directory) = path.parent() else {
        return Err(FileError::Invalid {
            path: path.to_path_buf(),
            reason: "output-style path has no parent directory".to_string(),
        });
    };
    file_error::create_dir_all(directory)?;
    file_error::write_file(path, content)
}

fn clear_style_at(path: &Path) -> Result<(), FileError> {
    if path.exists() {
        std::fs::remove_file(path).map_err(FileError::with_path(path))
    } else {
        Ok(())
    }
}

fn configured_user_style_path() -> Result<PathBuf, FileError> {
    user_style_path().ok_or_else(|| FileError::Invalid {
        path: PathBuf::from(USER_STYLE_DISPLAY_PATH),
        reason: "cannot resolve the user home directory".to_string(),
    })
}

/// Save a style to the user-owned output-style file.
///
/// # Errors
///
/// Returns [`FileError::Io`] if the directory cannot be created or the file
/// cannot be written. The returned error carries the offending path and the
/// underlying `io::ErrorKind` for programmatic discrimination — see #492.
pub fn save_output_style(content: &str) -> Result<(), FileError> {
    let path = configured_user_style_path()?;
    save_style_at(&path, content)
}

/// Remove the user-owned output-style file.
///
/// # Errors
///
/// Returns [`FileError::Io`] if the file exists but cannot be removed.
pub fn clear_output_style() -> Result<(), FileError> {
    let path = configured_user_style_path()?;
    clear_style_at(&path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_builtin_styles() {
        let styles = builtin_styles();
        assert!(styles.len() >= 4);
        assert!(styles.iter().any(|(name, _)| *name == "concise"));
    }

    #[test]
    fn test_load_style_nonexistent() {
        // Should return None when no style file exists (may or may not depending on env)
        let _ = load_output_style_context();
    }

    /// In-memory writer used to capture tracing output emitted during a test.
    /// Cloning shares the buffer (Arc<Mutex<…>>), so the writer handed to the
    /// subscriber writes to the same buffer the test inspects after the fact.
    #[derive(Clone, Default)]
    struct BufWriter(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for BufWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BufWriter {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// `NotFound` is the normal "no style configured" path and MUST stay silent —
    /// no WARN/ERROR log lines should be emitted when the file simply isn't there.
    #[test]
    fn read_style_notfound_returns_none_silently() {
        let buf = BufWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_max_level(tracing::Level::WARN)
            .without_time()
            .finish();

        let result = tracing::subscriber::with_default(subscriber, || {
            let missing = std::path::PathBuf::from(
                "/nonexistent-openclaudia-test-path/definitely/not/here.md",
            );
            read_style(&missing)
        });

        assert!(result.is_none(), "NotFound must yield None");
        let captured = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(
            captured.is_empty(),
            "NotFound must not emit any log output, got: {captured}"
        );
    }

    /// A non-NotFound read error (here: permission denied on a 0o000 file)
    /// must log at WARN with the file path + error message, and still return
    /// None so the caller can continue without an output style.
    #[cfg(unix)]
    #[test]
    fn read_style_permission_denied_logs_warn_and_returns_none() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("output-style.md");
        std::fs::write(&path, "some style content").expect("write fixture");
        // Strip all permission bits so read_to_string fails with PermissionDenied.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).expect("chmod 000");

        // If the test runs as root, permission bits are bypassed and the
        // PermissionDenied branch is unreachable — skip rather than assert
        // a false invariant.
        if nix_is_root() {
            return;
        }

        let buf = BufWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_max_level(tracing::Level::WARN)
            .without_time()
            .finish();

        let result = tracing::subscriber::with_default(subscriber, || read_style(&path));

        // Restore perms so tempdir cleanup succeeds.
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));

        assert!(
            result.is_none(),
            "PermissionDenied must yield None so the caller continues without a style"
        );
        let captured = String::from_utf8(buf.0.lock().unwrap().clone()).unwrap();
        assert!(
            captured.contains("WARN"),
            "expected a WARN log line, got: {captured}"
        );
        assert!(
            captured.contains("output-style.md"),
            "WARN log should mention the file path, got: {captured}"
        );
    }

    #[cfg(unix)]
    fn nix_is_root() -> bool {
        // SAFETY: getuid is a thread-safe libc call with no preconditions.
        unsafe { libc::getuid() == 0 }
    }

    /// Spec — `clear_output_style` propagates a typed [`FileError::Io`] (not
    /// a stringly-typed error) so callers can branch on
    /// [`std::io::ErrorKind`]. Regression guard for crosslink #492.
    ///
    /// Removing a directory through the file API forces a deterministic I/O
    /// error whose typed path must survive to the caller.
    #[test]
    fn clear_output_style_returns_typed_io_error_with_path() {
        use std::io::ErrorKind;

        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("output-style.md");
        std::fs::create_dir_all(&target).unwrap(); // make the leaf a dir!

        let result = clear_style_at(&target);

        let err = result.expect_err("removing a directory via remove_file must fail");
        // The typed variant — not a String — must come through.
        let kind = err
            .io_kind()
            .expect("must be the Io variant, not Json/Yaml");
        assert!(
            matches!(
                kind,
                ErrorKind::IsADirectory
                    | ErrorKind::PermissionDenied
                    | ErrorKind::Other
                    | ErrorKind::InvalidInput
            ),
            "expected an io::Error from remove_file-on-dir, got: {err}"
        );
        // And the path is carried through end-to-end.
        assert!(
            err.path().ends_with("output-style.md"),
            "FileError must carry the offending path, got: {}",
            err.path().display()
        );
    }

    #[test]
    fn explicit_user_store_round_trips_without_project_discovery() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("home/.openclaudia/output-style.md");

        save_style_at(&path, "  Be concise.  ").expect("save");
        assert_eq!(read_style(&path).as_deref(), Some("Be concise."));
        clear_style_at(&path).expect("clear");
        assert!(read_style(&path).is_none());
    }
}
