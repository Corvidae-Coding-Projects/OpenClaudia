//! Filesystem-path validation for user/managed/env-supplied config values.
//!
//! Closes crosslink #342. `VddTracking.path` and `SessionConfig.persist_path`
//! previously accepted any [`PathBuf`] from YAML / env / managed-settings and
//! handed it straight to [`std::fs::create_dir_all`] / [`std::fs::write`].
//! An enterprise managed-settings file specifying
//! `vdd.tracking.path: /etc/cron.d` would silently make the harness write
//! cron jobs into a system directory when run with elevated privileges.
//!
//! [`validate_persist_path`] is a configuration diagnostic precheck. It:
//!   1. Lexically resolves `..` / `.` components without touching the
//!      filesystem (no [`Path::canonicalize`] — that follows symlinks and
//!      requires the path to exist).
//!   2. Rejects any path under a known-dangerous system tree
//!      (`/etc`, `/var`, `/usr`, `/bin`, `/sbin`, `/boot`, `/dev`, `/proc`,
//!      `/sys`, `/root`, `/tmp`, `/private/etc`, `C:\Windows`, `C:\Program Files`).
//!   3. Requires the resolved path to live under one of:
//!        - the project root, OR
//!        - [`dirs::data_dir`], OR
//!        - [`dirs::cache_dir`], OR
//!        - `<home>/.openclaudia/`.
//!   4. Refuses every existing symlink component, including parent links.
//!   5. Honours `OPENCLAUDIA_ALLOW_OUT_OF_ROOT=1` as an explicit opt-out for
//!      operators who genuinely need an external location. The escape hatch
//!      still rejects the hard-coded system-tree denylist (we never write to
//!      `/etc` no matter what the operator asks for) but lets `/opt/foo/state`
//!      or `/srv/openclaudia/state` through. A `warn!` is emitted so the
//!      managed-settings audit log captures the escape.
//!
//! The returned [`PathBuf`] is never an authorization capability: all checks
//! can race a later path-based open. Persistent readers and writers must use
//! [`crate::persistence::PersistentStorage`] (or another descriptor-bound
//! capability) for the authoritative operation.

use std::env;
use std::path::{Component, Path, PathBuf};

use thiserror::Error;
use tracing::warn;

/// Environment variable that opts out of the project-root requirement.
///
/// Setting it to `1` lets paths outside the project/home/data trees through
/// (still blocked from the hard system-tree denylist). Emits a `warn!` on use.
pub const ALLOW_OUT_OF_ROOT_ENV: &str = "OPENCLAUDIA_ALLOW_OUT_OF_ROOT";

/// Errors produced by [`validate_persist_path`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PathValidationError {
    #[error("persist path is empty")]
    Empty,
    #[error("persist path contains NUL byte")]
    NulByte,
    #[error(
        "persist path '{path}' resolves to system directory '{system_root}' — refusing for safety"
    )]
    SystemDirectory { path: String, system_root: String },
    #[error(
        "persist path '{path}' is outside the project root, data dir, and home/.openclaudia — set OPENCLAUDIA_ALLOW_OUT_OF_ROOT=1 to override"
    )]
    OutsideProjectRoot { path: String },
    #[error("persist path traverses symlink '{path}' — refusing diagnostic path")]
    SymlinkRejected { path: String },
}

/// System trees that we refuse to write into, even when the operator sets
/// [`ALLOW_OUT_OF_ROOT_ENV`]. These are the locations where a successful
/// write turns into privilege escalation.
const SYSTEM_DENYLIST: &[&str] = &[
    "/etc",
    "/var",
    "/usr",
    "/bin",
    "/sbin",
    "/boot",
    "/dev",
    "/proc",
    "/sys",
    "/root",
    "/private/etc",
    "/private/var",
    "/System",
    "/Library",
    "C:\\Windows",
    "C:\\Program Files",
    "C:\\Program Files (x86)",
];

/// `/tmp` is special: the task spec wants it rejected by default but allowed
/// when `cache_dir()` happens to land there (some sandboxes set
/// `TMPDIR=/tmp/...`). We treat `/tmp` as out-of-root rather than as
/// denylisted-system so the [`ALLOW_OUT_OF_ROOT_ENV`] escape hatch can
/// admit `/tmp/state.json` for tests / one-shot sandboxes.
const TMP_PREFIXES: &[&str] = &["/tmp", "/private/tmp"];

/// Resolve `..` and `.` components without following symlinks.
///
/// This is a pure lexical normalisation — equivalent to Go's `filepath.Clean`
/// or Python's `os.path.normpath`. It deliberately does NOT call
/// [`Path::canonicalize`] because canonicalize requires the path to exist
/// AND follows symlinks, both of which are exactly the attack surface we
/// are defending against.
fn lexical_clean(path: &Path) -> PathBuf {
    let mut out: Vec<Component<'_>> = Vec::with_capacity(8);
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                // Only pop a normal component; do not climb past root or
                // a leading prefix (e.g. `C:\`).
                match out.last() {
                    Some(Component::Normal(_)) => {
                        out.pop();
                    }
                    Some(Component::ParentDir) | None => {
                        out.push(comp);
                    }
                    Some(Component::RootDir | Component::Prefix(_) | Component::CurDir) => {
                        // Refuse to climb above root — drop the `..` silently.
                    }
                }
            }
            other => out.push(other),
        }
    }
    if out.is_empty() {
        PathBuf::from(".")
    } else {
        out.iter().collect()
    }
}

/// Join `base` with `candidate`, then [`lexical_clean`] the result. Used so a
/// project-relative `vdd/state.json` resolves against the project root rather
/// than the current working directory of the test runner.
fn join_and_clean(base: &Path, candidate: &Path) -> PathBuf {
    if candidate.is_absolute() {
        lexical_clean(candidate)
    } else {
        lexical_clean(&base.join(candidate))
    }
}

/// Return `true` when `candidate` lies under `root` after both have been
/// lexically cleaned. Uses [`Path::starts_with`] (component-wise prefix) so
/// `/etcfoo` is NOT considered under `/etc`.
fn is_under(candidate: &Path, root: &Path) -> bool {
    let candidate_clean = lexical_clean(candidate);
    let root_clean = lexical_clean(root);
    candidate_clean.starts_with(&root_clean)
}

/// Reject any path that lives under a hard-coded system tree, even with
/// [`ALLOW_OUT_OF_ROOT_ENV`] set. This list is enforced *before* the
/// project-root check so the escape hatch cannot unlock these locations.
fn check_system_denylist(cleaned: &Path) -> Result<(), PathValidationError> {
    for sys in SYSTEM_DENYLIST {
        let sys_path = Path::new(sys);
        if is_under(cleaned, sys_path) {
            return Err(PathValidationError::SystemDirectory {
                path: cleaned.display().to_string(),
                system_root: (*sys).to_string(),
            });
        }
    }
    Ok(())
}

/// Diagnose every existing symlink component. This closes the obvious parent
/// link bypass in configuration feedback, but is intentionally not represented
/// as a race-safe authority boundary; the later I/O still needs a descriptor-
/// bound capability.
fn check_existing_components_not_symlinks(cleaned: &Path) -> Result<(), PathValidationError> {
    let mut prefix = PathBuf::new();
    for component in cleaned.components() {
        prefix.push(component.as_os_str());
        match std::fs::symlink_metadata(&prefix) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(PathValidationError::SymlinkRejected {
                    path: prefix.display().to_string(),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(_) => {
                // This function is a lexical/configuration diagnostic. Leave
                // permission and transient I/O failures to the authoritative
                // descriptor operation, which returns a typed source error.
                break;
            }
        }
    }
    Ok(())
}

/// Validate `p` for use as a directory or file path that the harness will
/// later create or write into. Returns the lexically resolved [`PathBuf`].
///
/// `project_root` should be the absolute path to the project root (the dir
/// containing `.openclaudia/`). Relative inputs are resolved against it.
///
/// # Errors
///
/// Returns [`PathValidationError`] if the path is empty, contains a NUL byte,
/// lands in a system directory, lives outside all allowed roots (without the
/// escape hatch set), or traverses an existing symlink. A successful result is
/// a normalized diagnostic value, not permission to perform path-based I/O.
pub fn validate_persist_path(
    p: &Path,
    project_root: &Path,
) -> Result<PathBuf, PathValidationError> {
    // (1) Reject obviously bogus input. `Path::as_os_str` lets us detect
    //     empty AND NUL-containing inputs without doing a UTF-8 round-trip.
    let raw = p.as_os_str();
    if raw.is_empty() {
        return Err(PathValidationError::Empty);
    }
    if raw.to_string_lossy().contains('\0') {
        return Err(PathValidationError::NulByte);
    }

    // (2) Lexically resolve `..` components against the project root. We
    //     never call `Path::canonicalize` here — see [`lexical_clean`].
    let cleaned = join_and_clean(project_root, p);

    // (3) The system denylist is non-negotiable. It runs BEFORE the
    //     escape-hatch check so `OPENCLAUDIA_ALLOW_OUT_OF_ROOT=1` cannot
    //     unlock `/etc/cron.d`.
    check_system_denylist(&cleaned)?;

    // (4) Diagnose existing parent and leaf links. The persistence capability
    //     repeats this invariant authoritatively during descriptor lookup.
    check_existing_components_not_symlinks(&cleaned)?;

    // (5) Allowed roots: project root, dirs::data_dir, dirs::cache_dir,
    //     home/.openclaudia/.
    let project_clean = lexical_clean(project_root);
    if cleaned.starts_with(&project_clean) {
        return Ok(cleaned);
    }
    if let Some(data) = dirs::data_dir() {
        if cleaned.starts_with(lexical_clean(&data)) {
            return Ok(cleaned);
        }
    }
    if let Some(cache) = dirs::cache_dir() {
        if cleaned.starts_with(lexical_clean(&cache)) {
            return Ok(cleaned);
        }
    }
    if let Some(home) = dirs::home_dir() {
        let oc_home = lexical_clean(&home.join(".openclaudia"));
        if cleaned.starts_with(&oc_home) {
            return Ok(cleaned);
        }
    }

    // (6) `/tmp` and friends: only allowed via the escape hatch.
    let in_tmp = TMP_PREFIXES
        .iter()
        .any(|t| cleaned.starts_with(Path::new(t)));

    // (7) Escape hatch. Emits a structured warn for the managed-settings
    //     audit log so an operator setting this in production leaves a
    //     trail.
    if env::var(ALLOW_OUT_OF_ROOT_ENV).as_deref() == Ok("1") {
        warn!(
            path = %cleaned.display(),
            env = ALLOW_OUT_OF_ROOT_ENV,
            in_tmp,
            "persist path lies outside project root, data dir, and home/.openclaudia — \
             admitted via escape hatch"
        );
        return Ok(cleaned);
    }

    Err(PathValidationError::OutsideProjectRoot {
        path: cleaned.display().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::fs;
    use std::sync::Mutex;
    use tempfile::TempDir;

    // The escape-hatch env var is process-global; serialise the few tests
    // that mutate it.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard {
        previous: Option<String>,
    }

    impl EnvGuard {
        fn set(value: &str) -> Self {
            let previous = env::var(ALLOW_OUT_OF_ROOT_ENV).ok();
            // SAFETY: env mutation serialised by ENV_LOCK.
            unsafe { env::set_var(ALLOW_OUT_OF_ROOT_ENV, value) };
            Self { previous }
        }
        fn unset() -> Self {
            let previous = env::var(ALLOW_OUT_OF_ROOT_ENV).ok();
            // SAFETY: env mutation serialised by ENV_LOCK.
            unsafe { env::remove_var(ALLOW_OUT_OF_ROOT_ENV) };
            Self { previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            // SAFETY: env mutation serialised by ENV_LOCK.
            unsafe {
                match &self.previous {
                    Some(v) => env::set_var(ALLOW_OUT_OF_ROOT_ENV, v),
                    None => env::remove_var(ALLOW_OUT_OF_ROOT_ENV),
                }
            }
        }
    }

    fn project() -> TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    // ── #342 test 1: /etc/cron.d rejected ───────────────────────────────────
    #[test]
    fn issue_342_etc_cron_d_is_rejected() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _g = EnvGuard::unset();
        let root = project();
        let err = validate_persist_path(Path::new("/etc/cron.d"), root.path())
            .expect_err("/etc/cron.d must be rejected");
        match err {
            PathValidationError::SystemDirectory { system_root, .. } => {
                assert_eq!(system_root, "/etc");
            }
            other => panic!("expected SystemDirectory, got {other:?}"),
        }
    }

    // ── #342 test 1b: even with the escape hatch on, /etc is still blocked ─
    #[test]
    fn issue_342_etc_cron_d_blocked_even_with_escape_hatch() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _g = EnvGuard::set("1");
        let root = project();
        let err = validate_persist_path(Path::new("/etc/cron.d"), root.path())
            .expect_err("/etc/cron.d must STILL be rejected with escape hatch");
        assert!(matches!(err, PathValidationError::SystemDirectory { .. }));
    }

    // ── #342 test 2: ../../../etc/passwd resolves to /etc/passwd, rejected ─
    #[test]
    fn issue_342_dotdot_traversal_resolves_and_is_rejected() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _g = EnvGuard::unset();
        // Use an absolute project_root we know is shallow enough that
        // `../../../etc/passwd` actually escapes it.
        let root = Path::new("/home/u/proj");
        let err = validate_persist_path(Path::new("../../../etc/passwd"), root)
            .expect_err("dot-dot traversal into /etc must be rejected");
        match err {
            PathValidationError::SystemDirectory { path, system_root } => {
                assert_eq!(system_root, "/etc");
                assert!(
                    path.ends_with("/etc/passwd"),
                    "traversal must resolve to /etc/passwd: got {path}"
                );
            }
            other => panic!("expected SystemDirectory, got {other:?}"),
        }
    }

    // ── #342 test 3: project-relative paths accepted ─────────────────────────
    #[test]
    fn issue_342_project_relative_path_accepted() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _g = EnvGuard::unset();
        let root = project();
        let ok = validate_persist_path(Path::new("vdd/state.json"), root.path())
            .expect("project-relative path must be accepted");
        assert!(ok.starts_with(root.path()));
        assert!(ok.ends_with("vdd/state.json"));
    }

    // ── #342 test 4: ~/.openclaudia/state.json accepted ─────────────────────
    #[test]
    fn issue_342_home_dot_openclaudia_accepted() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _g = EnvGuard::unset();
        let home = dirs::home_dir().expect("test env has a HOME");
        let candidate = home.join(".openclaudia").join("state.json");
        let root = project();
        let ok = validate_persist_path(&candidate, root.path())
            .expect("~/.openclaudia/state.json must be accepted");
        assert_eq!(ok, candidate);
    }

    // ── #342 test 5: symlink at expected path is rejected ────────────────────
    #[test]
    #[cfg(unix)]
    fn issue_342_symlink_at_target_is_rejected() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _g = EnvGuard::unset();
        let root = project();
        // Create a benign target inside the project, then a symlink that
        // *also* lives inside the project but points elsewhere. Validation
        // should refuse it because the target IS a symlink.
        let target = root.path().join("real.json");
        fs::write(&target, b"{}").expect("write real");
        let link = root.path().join("state.json");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        let err =
            validate_persist_path(&link, root.path()).expect_err("symlink target must be rejected");
        assert!(matches!(err, PathValidationError::SymlinkRejected { .. }));
    }

    #[test]
    #[cfg(unix)]
    fn parent_symlink_is_diagnosed_but_not_treated_as_authority() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _g = EnvGuard::unset();
        let root = project();
        let outside = project();
        let linked_parent = root.path().join("linked-parent");
        std::os::unix::fs::symlink(outside.path(), &linked_parent).expect("parent symlink");

        let err = validate_persist_path(&linked_parent.join("state.json"), root.path())
            .expect_err("an existing parent symlink must be diagnosed");
        assert_eq!(
            err,
            PathValidationError::SymlinkRejected {
                path: linked_parent.display().to_string(),
            }
        );
    }

    // ── #342 test 6: escape hatch admits /tmp/state.json ────────────────────
    #[test]
    fn issue_342_escape_hatch_allows_tmp_state_json() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _g = EnvGuard::set("1");
        let root = project();
        // Use a path that's clearly inside /tmp but isn't a real preexisting
        // symlink (skip the symlink check by using a non-existent file).
        let candidate = PathBuf::from("/tmp/openclaudia-342-escape-hatch.json");
        let ok = validate_persist_path(&candidate, root.path())
            .expect("escape hatch must admit /tmp/state.json");
        assert_eq!(ok, candidate);
    }

    // ── #342 test 6b: WITHOUT the escape hatch, /tmp is rejected ────────────
    #[test]
    fn issue_342_tmp_rejected_without_escape_hatch() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _g = EnvGuard::unset();
        let root = project();
        let err =
            validate_persist_path(Path::new("/tmp/openclaudia-342-no-hatch.json"), root.path())
                .expect_err("/tmp must be rejected without escape hatch");
        assert!(matches!(
            err,
            PathValidationError::OutsideProjectRoot { .. }
        ));
    }

    // ── #342 test 7: empty path is a clear error ────────────────────────────
    #[test]
    fn issue_342_empty_path_rejected() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _g = EnvGuard::unset();
        let root = project();
        let err = validate_persist_path(Path::new(""), root.path())
            .expect_err("empty path must be rejected");
        assert_eq!(err, PathValidationError::Empty);
    }

    // ── #342 test 7b: NUL byte in path is a clear error ─────────────────────
    #[test]
    fn issue_342_nul_byte_rejected() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _g = EnvGuard::unset();
        let root = project();
        // OsStr from bytes is the only way to embed a NUL on Unix without
        // tripping PathBuf::from. On Windows we just synthesise a string
        // containing \0.
        #[cfg(unix)]
        let bad = {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;
            PathBuf::from(OsStr::from_bytes(b"abc\0def"))
        };
        #[cfg(not(unix))]
        let bad = PathBuf::from("abc\0def");

        let err =
            validate_persist_path(&bad, root.path()).expect_err("NUL byte path must be rejected");
        assert_eq!(err, PathValidationError::NulByte);
    }

    // ── #342 supporting: var/usr/bin/sbin/boot/dev/proc/sys/root all blocked
    #[test]
    fn issue_342_full_system_denylist_blocked() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _g = EnvGuard::unset();
        let root = project();
        for sys in &[
            "/var/log/openclaudia.log",
            "/usr/local/state",
            "/bin/payload",
            "/sbin/payload",
            "/boot/payload",
            "/dev/null/payload",
            "/proc/self/mem",
            "/sys/kernel/payload",
            "/root/state.json",
        ] {
            let result = validate_persist_path(Path::new(sys), root.path());
            match result {
                Err(PathValidationError::SystemDirectory { .. }) => {}
                Err(other) => panic!("{sys} expected SystemDirectory error, got {other:?}"),
                Ok(p) => panic!("{sys} should be rejected but was accepted as {p:?}"),
            }
        }
    }

    // ── #342 supporting: /etcfoo is NOT inside /etc (prefix-vs-component) ───
    #[test]
    fn issue_342_etc_lookalike_path_is_not_under_etc() {
        // Confirms the component-wise `Path::starts_with` we rely on does
        // NOT treat `/etcfoo` as a child of `/etc`. This would be a serious
        // false-positive if we had used string prefix matching instead.
        assert!(!is_under(Path::new("/etcfoo/bar"), Path::new("/etc")));
        assert!(is_under(Path::new("/etc/foo"), Path::new("/etc")));
    }

    // ── #342 supporting: lexical_clean strips `..` and never panics ─────────
    #[test]
    fn lexical_clean_handles_traversal_and_root() {
        assert_eq!(lexical_clean(Path::new("a/b/../c")), PathBuf::from("a/c"));
        assert_eq!(
            lexical_clean(Path::new("/a/b/../../c")),
            PathBuf::from("/c")
        );
        // climb past root is silently clamped
        assert_eq!(
            lexical_clean(Path::new("/../../etc")),
            PathBuf::from("/etc")
        );
        // empty cleans to "."
        assert_eq!(lexical_clean(Path::new("")), PathBuf::from("."));
        assert_eq!(lexical_clean(Path::new(".")), PathBuf::from("."));
    }

    // ── #342 supporting: dirs::data_dir() is an allowed root ────────────────
    #[test]
    fn issue_342_data_dir_accepted() {
        let _lock = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _g = EnvGuard::unset();
        let Some(data) = dirs::data_dir() else {
            // Headless CI without XDG: skip rather than fail spuriously.
            return;
        };
        let candidate = data.join("openclaudia").join("state.json");
        let root = project();
        let ok = validate_persist_path(&candidate, root.path())
            .expect("dirs::data_dir() must be accepted");
        assert_eq!(ok, candidate);
    }
}
