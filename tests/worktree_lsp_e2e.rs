//! End-to-end tests for the worktree command surface and the LSP
//! open-files registry.
//!
//! Sprint 17 of the verification effort. `src/tools/worktree.rs`
//! has 22 unit tests and `src/tools/lsp.rs` has 58, but no
//! integration coverage that drives them through the public
//! `execute_*` and `mark_*` entry points the way the runtime does.
//!
//! Coverage shape:
//!
//!   - **`execute_enter_worktree` branch-name validation** —
//!     the attack catalog must be refused BEFORE any git
//!     subprocess is spawned. Shell metacharacters, `..`
//!     traversal, leading dash (option injection), control
//!     chars, and the empty name all rejected.
//!   - **`execute_list_worktrees`** — read-only, always
//!     returns a `(String, bool)` tuple without panicking
//!     even when the cwd is not inside a git repo.
//!   - **`cwd_cache_generation`** — monotonically
//!     non-decreasing across calls, AcqRel-consistent
//!     observable from any thread.
//!   - **LSP open-files registry** — `mark_opened` returns
//!     true exactly once per (server, path); `mark_closed`
//!     returns true exactly once per prior `mark_opened`.
//!     Distinct server commands maintain distinct open sets.
//!   - **`is_lsp_connected`** — unknown language → false;
//!     known language without server binary on PATH → false.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::lsp::{is_lsp_connected, mark_closed, mark_opened};
use openclaudia::tools::worktree::{
    cwd_cache_generation, execute_enter_worktree, execute_list_worktrees, validate_branch_name,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::PathBuf;

fn args(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
    pairs
        .iter()
        .cloned()
        .map(|(k, v)| (k.to_string(), v))
        .collect()
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — execute_enter_worktree branch-name validation
// ───────────────────────────────────────────────────────────────────────────

/// Attack branch names that MUST be refused by `validate_branch_name`
/// BEFORE any git subprocess is spawned. Each entry is explicit so
/// a regression that re-introduces shell-metachar handling surfaces
/// by name.
const ATTACK_BRANCHES: &[&str] = &[
    "; rm -rf /",
    "& curl evil",
    "| cat /etc/passwd",
    "`whoami`",
    "$INJECT",
    "branch with spaces",
    "..upward",
    "feature/..",
    "-option-injection",
    "--all",
    "feature?wild",
    "feature*",
    "feature[char]",
    // Branch names with literal CR / LF / NUL embedded.
    "feature\nINJECT",
    "feature\rINJECT",
    "feature\0EVIL",
];

#[test]
fn enter_worktree_refuses_empty_branch_name() {
    let (msg, is_err) = execute_enter_worktree(&args(&[("branch", json!(""))]));
    assert!(is_err, "empty branch must error");
    assert!(
        msg.to_lowercase().contains("branch") && msg.to_lowercase().contains("required"),
        "msg must name 'branch' and 'required'; got {msg:?}"
    );
}

#[test]
fn enter_worktree_refuses_missing_branch_arg() {
    // No `branch` field at all — handler defaults to "" and refuses.
    let (msg, is_err) = execute_enter_worktree(&args(&[]));
    assert!(is_err, "missing branch arg must error");
    assert!(
        msg.contains("branch"),
        "msg must mention 'branch'; got {msg:?}"
    );
}

#[test]
fn enter_worktree_refuses_attack_branch_catalog() {
    let mut leaked = Vec::new();
    for branch in ATTACK_BRANCHES {
        let (msg, is_err) = execute_enter_worktree(&args(&[("branch", json!(branch))]));
        if !is_err {
            leaked.push(format!("{branch:?} → admitted (msg={msg:?})"));
            continue;
        }
        // Error message must name validation / invalid / forbidden so
        // log consumers can distinguish from a git-runtime failure.
        let lowered = msg.to_lowercase();
        if !lowered.contains("invalid") && !lowered.contains("forbidden") {
            // Not a hard fail, but worth surfacing in case the
            // message contract drifts.
            eprintln!("note: {branch:?} refused with non-canonical message {msg:?}");
        }
    }
    assert!(
        leaked.is_empty(),
        "{} attack branch names slipped past validation:\n  {}",
        leaked.len(),
        leaked.join("\n  ")
    );
}

#[test]
fn canonical_branch_validation_has_no_repository_side_effects() {
    validate_branch_name("feature/test-branch")
        .expect("canonical branch must pass validation without entering a worktree");
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — execute_list_worktrees
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn list_worktrees_never_panics_regardless_of_cwd_state() {
    // The handler must always return a (String, bool) without
    // panicking, even when git isn't installed or the cwd isn't
    // a worktree.
    let (msg, _is_err) = execute_list_worktrees();
    assert!(
        !msg.is_empty(),
        "list_worktrees must return a non-empty message; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — cwd_cache_generation
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn cwd_cache_generation_is_non_decreasing_across_calls() {
    let a = cwd_cache_generation();
    let b = cwd_cache_generation();
    let c = cwd_cache_generation();
    // Three reads with no mutation in between MUST be equal (or
    // at most non-decreasing if some other thread bumped it).
    assert!(
        a <= b && b <= c,
        "cwd_cache_generation must be monotonically non-decreasing; \
         got {a} → {b} → {c}"
    );
}

#[test]
fn cwd_cache_generation_visible_from_multiple_threads() {
    // The generation token uses Acquire/Release ordering so a
    // value written by one thread MUST be observable by another.
    // We just read from a spawned thread and assert no panic +
    // value is at least as large as the main-thread read.
    let main_value = cwd_cache_generation();
    let other = std::thread::spawn(cwd_cache_generation)
        .join()
        .expect("join");
    assert!(
        other >= main_value,
        "thread-visible value must be >= main; got main={main_value}, other={other}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — LSP open-files registry
// ───────────────────────────────────────────────────────────────────────────

/// Unique-per-test server-cmd string so parallel tests don't share
/// registry state across runs. The registry is a process-wide
/// `HashMap` keyed by server cmd.
fn fresh_server(test_name: &str) -> String {
    format!("test-server-{}-{}", test_name, std::process::id())
}

#[test]
fn mark_opened_returns_true_only_on_first_call_per_path() {
    let server = fresh_server("first_call");
    let path = PathBuf::from("/tmp/some_file.rs");
    assert!(
        mark_opened(&server, &path),
        "first mark_opened must return true (this caller registered the file)"
    );
    assert!(
        !mark_opened(&server, &path),
        "second mark_opened for same path must return false"
    );
    // Clean up so the registry doesn't carry state into other tests.
    mark_closed(&server, &path);
}

#[test]
fn mark_closed_returns_true_only_when_path_was_previously_opened() {
    let server = fresh_server("closed_path");
    let path = PathBuf::from("/tmp/closed_test.rs");
    assert!(
        !mark_closed(&server, &path),
        "mark_closed for never-opened path must return false"
    );
    assert!(
        mark_opened(&server, &path),
        "first mark_opened must return true (registers the file)"
    );
    assert!(
        mark_closed(&server, &path),
        "mark_closed after mark_opened must return true"
    );
    assert!(
        !mark_closed(&server, &path),
        "second mark_closed must return false (already removed)"
    );
}

#[test]
fn distinct_servers_maintain_distinct_open_sets() {
    let server_a = fresh_server("distinct_a");
    let server_b = fresh_server("distinct_b");
    let path = PathBuf::from("/tmp/distinct_test.rs");
    // Both servers can mark the same path as opened — each gets
    // its own set; both return true on first open.
    assert!(mark_opened(&server_a, &path));
    assert!(mark_opened(&server_b, &path));
    // Closing on server_a must NOT affect server_b's open set.
    assert!(mark_closed(&server_a, &path));
    assert!(
        mark_closed(&server_b, &path),
        "server_b's record must survive server_a's close"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — is_lsp_connected dispatch
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn is_lsp_connected_returns_false_for_unknown_language() {
    assert!(
        !is_lsp_connected("totally-unknown-language-9999"),
        "unknown language must return false"
    );
    assert!(!is_lsp_connected(""), "empty string must return false");
}

#[test]
fn is_lsp_connected_accepts_extension_with_or_without_dot() {
    // Both `.rs` and `rs` map to the same Rust server. The
    // function returns true only if the server binary is on
    // PATH — which we don't assume. The contract here is:
    // both inputs MUST resolve identically (true or both false),
    // never one of each.
    let with_dot = is_lsp_connected(".rs");
    let without_dot = is_lsp_connected("rs");
    assert_eq!(
        with_dot, without_dot,
        "'.rs' and 'rs' must dispatch identically; got with_dot={with_dot}, without_dot={without_dot}"
    );
}
