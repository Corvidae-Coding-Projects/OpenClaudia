//! Typed errors for file I/O and on-disk serialization.
//!
//! Replaces the `map_err(|e| e.to_string())` and `map_err(|e| format!(...))`
//! pattern that previously littered file-touching code paths. Stringly-typed
//! errors lose the source chain ([`std::io::ErrorKind`], `serde` line/column
//! information) and prevent programmatic discrimination between e.g.
//! `NotFound`, `PermissionDenied`, and `AlreadyExists`. See crosslink #492.
//!
//! Callers gain three benefits over the old pattern:
//!
//! 1. The underlying `io::Error` / `serde_json::Error` / `serde_yaml::Error`
//!    is preserved via `#[source]`, so `Display` chains expose the cause and
//!    consumers can downcast or match.
//! 2. Every variant carries the offending [`PathBuf`], so the rendered error
//!    always says *which* file failed (the old pattern routinely dropped this).
//! 3. [`FileError::io_kind`] surfaces the [`std::io::ErrorKind`] without forcing
//!    the consumer to know about the inner type — enough to distinguish the
//!    common cases (missing, permission denied) in a render or retry path.
//!
//! Helpers [`read_file`], [`write_file`], [`read_json`], [`read_yaml`],
//! [`write_json_pretty`], and [`create_dir_all`] are provided for the
//! ergonomically common case where callers want the typed error for free
//! without writing the `.map_err(...)` themselves. The legacy-named
//! [`write_json_pretty_atomic`] adapter is restricted to session documents and
//! delegates to [`crate::persistence`]; new stores should use that capability
//! directly so class, expected generation, and commit receipt remain visible.

use std::path::{Path, PathBuf};

use thiserror::Error;

/// Errors raised by file I/O and on-disk parse/serialize operations.
///
/// All variants carry the [`PathBuf`] that was being operated on, so the
/// rendered message always names the offending file. The original
/// [`std::io::Error`] / `serde` error is preserved via `#[source]`.
#[derive(Debug, Error)]
pub enum FileError {
    /// Raw I/O failure (`open`/`read`/`write`/`rename`/`create_dir`).
    #[error("I/O error on {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// JSON serialization or deserialization failure.
    #[error("JSON error on {}: {source}", path.display())]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    /// YAML serialization or deserialization failure.
    #[error("YAML error on {}: {source}", path.display())]
    Yaml {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },

    /// File content decoded as UTF-8 was not valid UTF-8.
    #[error("UTF-8 decoding error on {}: {source}", path.display())]
    Utf8 {
        path: PathBuf,
        #[source]
        source: std::string::FromUtf8Error,
    },

    /// File or directory failed a precondition check (symlink, missing
    /// parent, wrong owner, etc.) before any I/O was attempted.
    #[error("invalid file state on {}: {reason}", path.display())]
    Invalid { path: PathBuf, reason: String },

    /// Descriptor-safe persistence rejected or failed an operation before
    /// publication.
    #[error("persistence error on {}: {source}", path.display())]
    Persistence {
        path: PathBuf,
        #[source]
        source: Box<crate::persistence::PersistenceError>,
    },

    /// Replacement bytes are visible, but directory durability remains
    /// uncertain. The receipt gives callers the exact generation needed for
    /// reconciliation rather than collapsing this into an ordinary I/O error.
    #[error(
        "persistence publication on {} has uncertain directory durability at generation {}",
        path.display(),
        receipt.generation()
    )]
    DurabilityUncertain {
        path: PathBuf,
        receipt: Box<crate::persistence::CommitReceipt>,
    },
}

impl FileError {
    /// Surface the inner [`std::io::ErrorKind`] when the error is an
    /// [`FileError::Io`]. Returns `None` for the parse/decoding variants
    /// — callers that branch on `NotFound`/`PermissionDenied` don't need
    /// to know the inner type.
    #[must_use]
    pub fn io_kind(&self) -> Option<std::io::ErrorKind> {
        if let Self::Io { source, .. } = self {
            Some(source.kind())
        } else {
            None
        }
    }

    /// Return the [`Path`] that was being operated on when the error
    /// occurred. Always present — every variant carries one.
    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            Self::Io { path, .. }
            | Self::Json { path, .. }
            | Self::Yaml { path, .. }
            | Self::Utf8 { path, .. }
            | Self::Invalid { path, .. }
            | Self::Persistence { path, .. }
            | Self::DurabilityUncertain { path, .. } => path.as_path(),
        }
    }
}

/// Trait-style helpers so callers can write
/// `std::fs::read(...).map_err(FileError::with_path(&path))?` instead of
/// hand-rolling a closure. Kept as inherent associated functions to avoid
/// a public extension trait surface.
impl FileError {
    /// Build an `Io` variant closure for the given path.
    pub fn with_path(path: impl Into<PathBuf>) -> impl FnOnce(std::io::Error) -> Self {
        let path = path.into();
        move |source| Self::Io { path, source }
    }

    /// Build a `Json` variant closure for the given path.
    pub fn json_with_path(path: impl Into<PathBuf>) -> impl FnOnce(serde_json::Error) -> Self {
        let path = path.into();
        move |source| Self::Json { path, source }
    }

    /// Build a `Yaml` variant closure for the given path.
    pub fn yaml_with_path(path: impl Into<PathBuf>) -> impl FnOnce(serde_yaml::Error) -> Self {
        let path = path.into();
        move |source| Self::Yaml { path, source }
    }
}

/// Read a file's contents as a UTF-8 string, returning a typed [`FileError`]
/// that names the path on failure.
///
/// # Errors
/// Returns [`FileError::Io`] if the file cannot be read.
pub fn read_file(path: impl AsRef<Path>) -> Result<String, FileError> {
    let path = path.as_ref();
    std::fs::read_to_string(path).map_err(FileError::with_path(path))
}

/// Write `contents` to `path`, returning a typed [`FileError`].
///
/// # Errors
/// Returns [`FileError::Io`] if the file cannot be written.
pub fn write_file(path: impl AsRef<Path>, contents: impl AsRef<[u8]>) -> Result<(), FileError> {
    let path = path.as_ref();
    std::fs::write(path, contents).map_err(FileError::with_path(path))
}

/// Atomically publish `tmp` at `path`, replacing an existing file.
///
/// This low-level crate-internal compatibility primitive reports only the
/// rename result. It does not validate path authority, synchronize either
/// descriptor, or make a durability claim. New persistent stores must use
/// [`crate::persistence`] instead.
#[cfg(unix)]
pub(crate) fn replace_file_atomic(tmp: &Path, path: &Path) -> std::io::Result<()> {
    std::fs::rename(tmp, path)
}

#[cfg(windows)]
pub(crate) fn replace_file_atomic(tmp: &Path, path: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;

    let from = tmp
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let to = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let flags = windows_sys::Win32::Storage::FileSystem::MOVEFILE_REPLACE_EXISTING
        | windows_sys::Win32::Storage::FileSystem::MOVEFILE_WRITE_THROUGH;
    // SAFETY: both buffers are NUL-terminated and remain alive for the call.
    let succeeded = unsafe {
        windows_sys::Win32::Storage::FileSystem::MoveFileExW(from.as_ptr(), to.as_ptr(), flags)
    };
    if succeeded == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn replace_file_atomic(tmp: &Path, path: &Path) -> std::io::Result<()> {
    std::fs::rename(tmp, path)
}

/// Create `path` and all parent directories as needed.
///
/// # Errors
/// Returns [`FileError::Io`] on any underlying filesystem failure.
pub fn create_dir_all(path: impl AsRef<Path>) -> Result<(), FileError> {
    let path = path.as_ref();
    std::fs::create_dir_all(path).map_err(FileError::with_path(path))
}

/// Read and parse a JSON file into `T`.
///
/// # Errors
/// Returns [`FileError::Io`] if the file cannot be read, or
/// [`FileError::Json`] if the contents fail to deserialize.
pub fn read_json<T: serde::de::DeserializeOwned>(path: impl AsRef<Path>) -> Result<T, FileError> {
    let path = path.as_ref();
    let s = read_file(path)?;
    serde_json::from_str(&s).map_err(FileError::json_with_path(path))
}

/// Read and parse a YAML file into `T`.
///
/// # Errors
/// Returns [`FileError::Io`] if the file cannot be read, or
/// [`FileError::Yaml`] if the contents fail to deserialize.
pub fn read_yaml<T: serde::de::DeserializeOwned>(path: impl AsRef<Path>) -> Result<T, FileError> {
    let path = path.as_ref();
    let s = read_file(path)?;
    serde_yaml::from_str(&s).map_err(FileError::yaml_with_path(path))
}

/// Serialize `value` as pretty JSON and write it to `path`.
///
/// # Errors
/// Returns [`FileError::Json`] if serialization fails or
/// [`FileError::Io`] if the file cannot be written.
pub fn write_json_pretty<T: serde::Serialize>(
    path: impl AsRef<Path>,
    value: &T,
) -> Result<(), FileError> {
    let path = path.as_ref();
    let json = serde_json::to_string_pretty(value).map_err(FileError::json_with_path(path))?;
    write_file(path, json)
}

/// Serialize one session document as pretty JSON and commit it through the
/// descriptor-safe persistence capability.
///
/// This compatibility adapter exists for the pre-S-037 session frontends. It
/// opens the already-existing parent as the explicit storage root, observes an
/// exact generation, then commits with [`crate::persistence::FileClass::Session`].
/// It never turns a post-rename directory-sync failure into an ordinary I/O
/// error: [`FileError::DurabilityUncertain`] retains the typed receipt.
///
/// # Errors
/// Returns [`FileError::Json`] on serialization failure,
/// [`FileError::Persistence`] on validation/conflict/pre-publication failure,
/// or [`FileError::DurabilityUncertain`] when publication is visible but its
/// directory sync could not be proven.
pub fn write_json_pretty_atomic<T: serde::Serialize>(
    path: impl AsRef<Path>,
    value: &T,
) -> Result<(), FileError> {
    use crate::persistence::{CommitState, FileClass, PersistentStorage};

    let path = path.as_ref();
    let json = serde_json::to_vec_pretty(value).map_err(FileError::json_with_path(path))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| FileError::Invalid {
            path: path.to_path_buf(),
            reason: "descriptor-safe persistence requires an explicit parent directory".to_string(),
        })?;
    let target = path.file_name().ok_or_else(|| FileError::Invalid {
        path: path.to_path_buf(),
        reason: "descriptor-safe persistence requires a file-name target".to_string(),
    })?;
    let storage = PersistentStorage::open(parent).map_err(|source| FileError::Persistence {
        path: path.to_path_buf(),
        source: Box::new(source),
    })?;
    let expected = storage
        .read(target, FileClass::Session)
        .map_err(|source| FileError::Persistence {
            path: path.to_path_buf(),
            source: Box::new(source),
        })?
        .generation();
    let receipt = storage
        .commit(target, FileClass::Session, expected, json)
        .map_err(|source| FileError::Persistence {
            path: path.to_path_buf(),
            source: Box::new(source),
        })?;
    if receipt.state() == CommitState::PublishedDurabilityUncertain {
        Err(FileError::DurabilityUncertain {
            path: path.to_path_buf(),
            receipt: Box::new(receipt),
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, ErrorKind};
    use std::path::PathBuf;

    /// Spec — `FileError::Io` preserves the inner `io::ErrorKind` so callers
    /// can branch on `NotFound` / `PermissionDenied` etc. without restringing.
    #[test]
    fn io_variant_preserves_error_kind_not_found() {
        let io_err = io::Error::new(ErrorKind::NotFound, "missing");
        let err = FileError::Io {
            path: PathBuf::from("/nope/here"),
            source: io_err,
        };
        assert_eq!(err.io_kind(), Some(ErrorKind::NotFound));
    }

    /// Spec — `io_kind()` returns `None` for non-Io variants so callers
    /// distinguish parse failure from underlying-filesystem failure.
    #[test]
    fn io_kind_returns_none_for_non_io_variants() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let err = FileError::Json {
            path: PathBuf::from("/tmp/x.json"),
            source: json_err,
        };
        assert!(err.io_kind().is_none());
    }

    /// Spec — `Display` impl always names the offending file path.
    /// The old stringly-typed pattern routinely dropped this information,
    /// which is the regression #492 calls out.
    #[test]
    fn display_includes_path() {
        let io_err = io::Error::new(ErrorKind::PermissionDenied, "nope");
        let err = FileError::Io {
            path: PathBuf::from("/etc/protected.yaml"),
            source: io_err,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("/etc/protected.yaml"),
            "Display must include path, got: {msg}"
        );
    }

    /// Spec — `with_path` closure produces an `Io` variant tagged with
    /// the right path and preserves the source error kind. This is the
    /// hot helper code paths use in place of `.map_err(|e| e.to_string())`.
    #[test]
    fn with_path_helper_builds_correct_io_variant() {
        let io_err = io::Error::new(ErrorKind::AlreadyExists, "dup");
        let map = FileError::with_path("/var/lib/openclaudia/state.json");
        let err = map(io_err);
        match err {
            FileError::Io { path, source } => {
                assert_eq!(path, PathBuf::from("/var/lib/openclaudia/state.json"));
                assert_eq!(source.kind(), ErrorKind::AlreadyExists);
            }
            other => panic!("expected Io variant, got {other:?}"),
        }
    }

    /// Spec — `read_file` on a missing path returns a typed `Io` variant
    /// whose `io_kind()` reports `NotFound`. Exercises a real call site
    /// to prove the typed variant survives end-to-end through the helper,
    /// not just in synthesized test errors.
    #[test]
    fn read_file_propagates_typed_not_found() {
        let p = PathBuf::from("/this/path/definitely/does/not/exist/openclaudia/x.json");
        let err = read_file(&p).expect_err("missing path must error");
        assert_eq!(
            err.io_kind(),
            Some(ErrorKind::NotFound),
            "expected NotFound from typed FileError, got: {err}"
        );
        assert_eq!(err.path(), p.as_path());
    }

    /// Spec — `read_json` on a syntactically invalid file returns the
    /// `Json` variant (not `Io`) and the path is preserved.
    #[test]
    fn read_json_returns_typed_json_variant_on_parse_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("bad.json");
        std::fs::write(&p, "{ this is not json").unwrap();
        let err = read_json::<serde_json::Value>(&p).expect_err("must fail");
        assert!(
            matches!(err, FileError::Json { .. }),
            "expected Json variant, got: {err:?}"
        );
        assert_eq!(err.path(), p.as_path());
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn session_json_adapter_uses_private_descriptor_safe_commit() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("session root");
        let path = directory.path().join("session.json");
        write_json_pretty_atomic(&path, &serde_json::json!({"generation": 1}))
            .expect("descriptor-safe JSON commit");

        let value: serde_json::Value = read_json(&path).expect("read session JSON");
        assert_eq!(value["generation"], 1);
        #[cfg(unix)]
        assert_eq!(
            std::fs::metadata(&path)
                .expect("session metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
        #[cfg(windows)]
        crate::windows_fs::validate_owned_acl(
            &std::fs::File::open(&path).expect("session file handle"),
            true,
        )
        .expect("owner-private session ACL");
    }

    #[cfg(any(unix, windows))]
    #[test]
    fn session_json_adapter_rejects_linked_parent_without_outside_write() {
        let holder = tempfile::tempdir().expect("holder");
        let outside = tempfile::tempdir().expect("outside");
        let linked_parent = holder.path().join("linked");
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path(), &linked_parent).expect("parent symlink");
        #[cfg(windows)]
        std::os::windows::fs::symlink_dir(outside.path(), &linked_parent)
            .expect("parent directory reparse point");
        let path = linked_parent.join("session.json");

        let error = write_json_pretty_atomic(&path, &serde_json::json!({"redirect": true}))
            .expect_err("symlinked parent must be rejected");
        assert!(matches!(error, FileError::Persistence { .. }));
        assert!(!outside.path().join("session.json").exists());
    }
}
