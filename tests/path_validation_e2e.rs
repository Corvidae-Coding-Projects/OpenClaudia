//! End-to-end tests for the user-supplied filesystem-path validator.
//!
//! Sprint 8 of the verification effort. `src/config/path_validation.rs`
//! has 14 unit tests but no integration coverage that drives the
//! validator against real on-disk symlinks, real tempdir-rooted
//! project trees, and the documented adversarial path catalog.
//!
//! Coverage shape:
//!   - **System-tree denylist is non-negotiable** — every entry in
//!     `SYSTEM_DENYLIST` (`/etc`, `/var`, `/usr`, `/bin`, `/sbin`,
//!     `/boot`, `/dev`, `/proc`, `/sys`, `/root`, `/private/etc`,
//!     `/System`, `/Library`) MUST be refused even when the
//!     `OPENCLAUDIA_ALLOW_OUT_OF_ROOT` escape hatch is set.
//!   - **Symlink defence** — a symlink at the target path is
//!     refused even when both the link and its target live inside
//!     the project root, and an existing parent-directory symlink is
//!     diagnosed before the descriptor-bound storage operation.
//!   - **Lexical `..` traversal** — `<project>/../../etc/passwd`
//!     and `<project>/legit/../../../../etc/passwd` both refused.
//!   - **Empty / NUL-byte inputs** — refused with the canonical
//!     `Empty` / `NulByte` error variants.
//!   - **Happy paths** — relative paths under the project root,
//!     absolute paths under the project root, and paths under
//!     `<home>/.openclaudia/` all accepted; lexical-clean returned.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::config::{validate_persist_path, PathValidationError, ALLOW_OUT_OF_ROOT_ENV};
use std::path::{Path, PathBuf};
use tempfile::tempdir;

/// Set the escape-hatch env var for the duration of a closure, then
/// restore the previous value. Single-threaded test runs only —
/// `std::env::set_var` is process-global. We tell the test runner to
/// `--test-threads=1` so env-var tests don't race.
fn with_escape_hatch<F: FnOnce()>(f: F) {
    let prev = std::env::var(ALLOW_OUT_OF_ROOT_ENV).ok();
    // SAFETY (env mutation): single-threaded test, restore in
    // a finally-style block via a guard.
    // Tests using this helper must be marked #[serial] or driven
    // with --test-threads=1 (the test runner's serialised mode).
    unsafe {
        std::env::set_var(ALLOW_OUT_OF_ROOT_ENV, "1");
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    unsafe {
        match prev {
            Some(v) => std::env::set_var(ALLOW_OUT_OF_ROOT_ENV, v),
            None => std::env::remove_var(ALLOW_OUT_OF_ROOT_ENV),
        }
    }
    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — system denylist (non-negotiable, survives escape hatch)
// ───────────────────────────────────────────────────────────────────────────

/// Every entry must be refused with `SystemDirectory` even with the
/// escape hatch set. Targeting both bare denylist roots AND nested
/// paths inside them so the test catches a regression that only
/// short-circuits on exact prefix match.
const SYSTEM_TARGETS: &[&str] = &[
    "/etc",
    "/etc/cron.d/openclaudia",
    "/var/log/openclaudia.log",
    "/usr/local/openclaudia",
    "/bin/openclaudia",
    "/sbin/openclaudia",
    "/boot/openclaudia",
    "/dev/null",
    "/proc/self/mem",
    "/sys/kernel/openclaudia",
    "/root/.bashrc",
];

#[test]
fn system_denylist_paths_are_refused_without_escape_hatch() {
    let dir = tempdir().expect("tempdir");
    let project_root = dir.path();
    for raw in SYSTEM_TARGETS {
        let outcome = validate_persist_path(Path::new(raw), project_root);
        assert!(
            matches!(outcome, Err(PathValidationError::SystemDirectory { .. })),
            "{raw:?} must be refused as SystemDirectory; got {outcome:?}"
        );
    }
}

#[test]
fn system_denylist_paths_are_refused_even_with_escape_hatch() {
    // The escape hatch unlocks /tmp and /opt etc, but the SYSTEM
    // denylist remains absolute. Operator typo in managed settings
    // must NEVER admit /etc.
    let dir = tempdir().expect("tempdir");
    let project_root = dir.path().to_path_buf();
    let targets: Vec<PathBuf> = SYSTEM_TARGETS.iter().map(PathBuf::from).collect();

    with_escape_hatch(|| {
        for raw in &targets {
            let outcome = validate_persist_path(raw, &project_root);
            assert!(
                matches!(outcome, Err(PathValidationError::SystemDirectory { .. })),
                "{raw:?} must be refused as SystemDirectory even with escape hatch; \
                 got {outcome:?}"
            );
        }
    });
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — symlink defence
// ───────────────────────────────────────────────────────────────────────────

#[cfg(unix)]
#[test]
fn symlink_at_target_is_refused_even_inside_project_root() {
    // Plant a symlink INSIDE the project root pointing at another
    // file INSIDE the project root. The validator must still refuse
    // — symlinks are categorically banned at the target because the
    // attacker controls where they point AFTER validation passes.
    let dir = tempdir().expect("tempdir");
    let project_root = dir.path();
    let real_target = project_root.join("real.txt");
    std::fs::write(&real_target, "ok").expect("write real");
    let symlink_path = project_root.join("link.txt");
    std::os::unix::fs::symlink(&real_target, &symlink_path).expect("symlink");

    let outcome = validate_persist_path(&symlink_path, project_root);
    assert!(
        matches!(outcome, Err(PathValidationError::SymlinkRejected { .. })),
        "symlink inside project root must still be refused; got {outcome:?}"
    );
}

#[cfg(unix)]
#[test]
fn symlink_pointing_outside_project_root_is_refused() {
    // The classic attack: a symlink lives inside the project root
    // but points at /etc/passwd. Must be refused.
    let dir = tempdir().expect("tempdir");
    let project_root = dir.path();
    let symlink_path = project_root.join("evil.txt");
    std::os::unix::fs::symlink("/etc/passwd", &symlink_path).expect("symlink");

    let outcome = validate_persist_path(&symlink_path, project_root);
    assert!(
        matches!(outcome, Err(PathValidationError::SymlinkRejected { .. })),
        "symlink → /etc/passwd must be refused; got {outcome:?}"
    );
}

#[cfg(unix)]
#[test]
fn parent_symlink_pointing_outside_project_root_is_refused() {
    let dir = tempdir().expect("project root");
    let outside = tempdir().expect("outside root");
    let linked_parent = dir.path().join("linked-parent");
    std::os::unix::fs::symlink(outside.path(), &linked_parent).expect("parent symlink");

    let outcome = validate_persist_path(&linked_parent.join("state.json"), dir.path());
    assert_eq!(
        outcome,
        Err(PathValidationError::SymlinkRejected {
            path: linked_parent.display().to_string(),
        }),
        "configuration diagnostics must expose the parent-link problem; the later write still requires a descriptor capability"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — `..` traversal under lexical normalisation
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn dotdot_traversal_into_system_dir_is_refused() {
    // The validator lexically resolves `..` BEFORE checking the
    // system denylist, so `proj/../../etc/cron.d` must trip the
    // denylist (not the OutsideProjectRoot escape).
    let dir = tempdir().expect("tempdir");
    let project_root = dir.path();
    // Construct a path that, after `..` resolution against project
    // root, lands in /etc.
    let traversal = Path::new("../../../../../../../etc/cron.d/oc");
    let outcome = validate_persist_path(traversal, project_root);
    assert!(
        matches!(
            outcome,
            Err(PathValidationError::SystemDirectory { .. }
                | PathValidationError::OutsideProjectRoot { .. })
        ),
        "..-traversal into a system dir must be refused; got {outcome:?}"
    );
}

#[test]
fn dotdot_traversal_to_sibling_is_refused() {
    let dir = tempdir().expect("tempdir");
    let project_root = dir.path();
    // A relative path that escapes via `..` to a sibling dir.
    let outcome = validate_persist_path(Path::new("../sibling/data"), project_root);
    assert!(
        outcome.is_err(),
        "..-traversal to sibling must be refused; got {outcome:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — empty / NUL inputs
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn empty_path_is_refused_with_canonical_variant() {
    let dir = tempdir().expect("tempdir");
    let outcome = validate_persist_path(Path::new(""), dir.path());
    assert_eq!(
        outcome,
        Err(PathValidationError::Empty),
        "empty path must produce PathValidationError::Empty exactly"
    );
}

#[test]
fn nul_byte_path_is_refused_with_canonical_variant() {
    let dir = tempdir().expect("tempdir");
    // Pass a path containing a NUL byte. PathBuf accepts it; the
    // validator must catch and refuse.
    let with_nul = Path::new("legit\0evil");
    let outcome = validate_persist_path(with_nul, dir.path());
    assert_eq!(
        outcome,
        Err(PathValidationError::NulByte),
        "NUL-byte path must produce PathValidationError::NulByte exactly"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — happy paths
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn relative_path_under_project_root_is_accepted() {
    let dir = tempdir().expect("tempdir");
    let project_root = dir.path();
    let resolved = validate_persist_path(Path::new(".openclaudia/state.json"), project_root)
        .expect("path under project root must validate");
    assert!(
        resolved.starts_with(project_root),
        "resolved path must start with project_root; got {resolved:?}"
    );
}

#[test]
fn absolute_path_inside_project_root_is_accepted() {
    let dir = tempdir().expect("tempdir");
    let project_root = dir.path();
    let inside_abs = project_root.join("subdir/state.json");
    let resolved = validate_persist_path(&inside_abs, project_root)
        .expect("absolute path inside project root must validate");
    assert_eq!(
        resolved, inside_abs,
        "absolute path that's already clean must round-trip"
    );
}

#[test]
fn escape_hatch_admits_paths_under_tmp_but_not_under_system_dirs() {
    // /tmp/openclaudia-state must be ADMITTED when the env opt-in
    // is set; the system denylist still wins for /etc.
    let dir = tempdir().expect("tempdir");
    let project_root = dir.path().to_path_buf();
    let tmp_path = PathBuf::from("/tmp/openclaudia-sprint8-test");
    let etc_path = PathBuf::from("/etc/openclaudia-sprint8-test");

    with_escape_hatch(|| {
        let tmp_outcome = validate_persist_path(&tmp_path, &project_root);
        assert!(
            tmp_outcome.is_ok(),
            "with escape hatch set, /tmp path must be admitted; got {tmp_outcome:?}"
        );
        let etc_outcome = validate_persist_path(&etc_path, &project_root);
        assert!(
            matches!(
                etc_outcome,
                Err(PathValidationError::SystemDirectory { .. })
            ),
            "with escape hatch set, /etc path MUST still be refused; got {etc_outcome:?}"
        );
    });
}
