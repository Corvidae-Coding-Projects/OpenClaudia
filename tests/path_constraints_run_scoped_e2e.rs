//! End-to-end coverage for run-scoped bash path constraints.
//!
//! A prior suite pinned a process-global install/clear slot whose empty state
//! allowed every path. S-019 removes that ambient bypass: constraints are
//! derived from the exact immutable run capability.

#![allow(clippy::expect_used)]

use openclaudia::tools::PathConstraints;
use std::sync::{Arc, Barrier};
use tempfile::TempDir;

mod support;

#[test]
fn run_constraints_allow_only_their_workspace_and_private_temp() {
    let workspace_a = TempDir::new().expect("workspace A");
    let workspace_b = TempDir::new().expect("workspace B");
    let run_a = support::test_run_context(workspace_a.path());
    let constraints = PathConstraints::from_run(&run_a);

    let own_file = workspace_a.path().join("src/main.rs");
    let foreign_file = workspace_b.path().join("secret.txt");
    let private_file = run_a.private_temp_root().join("shell-home.txt");

    assert!(constraints.allows(&own_file));
    assert!(constraints.allows(&private_file));
    assert!(!constraints.allows(&foreign_file));
    assert!(constraints
        .check_command(&format!("cat {}", own_file.display()))
        .is_ok());
    assert!(constraints
        .check_command(&format!("cat {}", foreign_file.display()))
        .is_err());
}

#[test]
fn concurrent_runs_cannot_replace_or_clear_each_others_constraints() {
    let workspace_a = TempDir::new().expect("workspace A");
    let workspace_b = TempDir::new().expect("workspace B");
    let constraints_a = Arc::new(PathConstraints::from_run(&support::test_run_context(
        workspace_a.path(),
    )));
    let constraints_b = Arc::new(PathConstraints::from_run(&support::test_run_context(
        workspace_b.path(),
    )));
    let barrier = Arc::new(Barrier::new(2));

    let checks = [
        (
            Arc::clone(&constraints_a),
            workspace_a.path().join("owned-a"),
            workspace_b.path().join("foreign-b"),
            Arc::clone(&barrier),
        ),
        (
            Arc::clone(&constraints_b),
            workspace_b.path().join("owned-b"),
            workspace_a.path().join("foreign-a"),
            Arc::clone(&barrier),
        ),
    ];

    let threads: Vec<_> = checks
        .into_iter()
        .map(|(constraints, owned, foreign, barrier)| {
            std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..128 {
                    assert!(constraints.allows(&owned));
                    assert!(!constraints.allows(&foreign));
                }
            })
        })
        .collect();

    for thread in threads {
        thread.join().expect("constraint checks must not panic");
    }
}

#[test]
fn explicit_empty_constraints_remain_a_low_level_opt_out_only() {
    let constraints = PathConstraints::new(Vec::<std::path::PathBuf>::new());
    assert!(constraints.is_empty());
    assert!(constraints.allows(std::path::Path::new("/etc/passwd")));

    let workspace = TempDir::new().expect("workspace");
    let run_constraints = PathConstraints::from_run(&support::test_run_context(workspace.path()));
    assert!(!run_constraints.is_empty());
}
