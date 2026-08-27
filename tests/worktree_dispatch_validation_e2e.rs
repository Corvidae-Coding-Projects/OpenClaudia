//! End-to-end tests for the `enter_worktree`, `exit_worktree`,
//! and `list_worktrees` tools dispatched through the registry —
//! pre-git argument validation (branch-name sanitization #408).
//!
//! Sprint 147 of the verification effort. Sprint 9 covered
//! direct `execute_enter_worktree` calls; this file pins
//! the registry-dispatched path so the wire-facing
//! contract matches.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::registry::registry;
use openclaudia::tools::security::ToolResource;
use openclaudia::tools::worktree::validate_branch_name;
use serde_json::{json, Value};
use std::collections::HashMap;
use tempfile::TempDir;

mod support;

fn dispatch(name: &str, args: &HashMap<String, Value>) -> (String, bool) {
    support::dispatch_tool(name, args)
}

fn args_with(entries: &[(&str, Value)]) -> HashMap<String, Value> {
    let mut m = HashMap::new();
    for (k, v) in entries {
        m.insert((*k).to_string(), v.clone());
    }
    m
}

fn assert_host_classification_denial(message: &str, field: &str) {
    assert!(message.contains("Host safety"), "got {message:?}");
    assert!(message.contains(field), "got {message:?}");
    assert!(
        message.contains("Missing")
            || message.contains("malformed arguments")
            || message.contains("could not be classified"),
        "got {message:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — enter_worktree: missing / empty branch
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn enter_worktree_with_no_branch_arg_returns_documented_error() {
    let (msg, is_err) = dispatch("enter_worktree", &HashMap::new());
    assert!(is_err);
    assert_host_classification_denial(&msg, "branch");
}

#[test]
fn enter_worktree_with_empty_branch_returns_required_error() {
    let args = args_with(&[("branch", json!(""))]);
    let (msg, is_err) = dispatch("enter_worktree", &args);
    assert!(is_err);
    assert_host_classification_denial(&msg, "branch");
}

#[test]
fn enter_worktree_branch_as_number_returns_validation_error() {
    let args = args_with(&[("branch", json!(42))]);
    let (msg, is_err) = dispatch("enter_worktree", &args);
    assert!(is_err);
    assert_host_classification_denial(&msg, "branch");
}

#[test]
fn enter_worktree_branch_as_null_returns_validation_error() {
    let args = args_with(&[("branch", Value::Null)]);
    let (msg, is_err) = dispatch("enter_worktree", &args);
    assert!(is_err);
    assert_host_classification_denial(&msg, "branch");
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Branch name validation (#408) — option-injection guard
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn enter_worktree_branch_starting_with_dash_rejected() {
    // PINS #408: starts-with-'-' is rejected to prevent
    // option-injection (e.g. "-D" deletes branches).
    let args = args_with(&[("branch", json!("-D"))]);
    let (msg, is_err) = dispatch("enter_worktree", &args);
    assert!(is_err);
    assert!(
        msg.contains("option-injection") || msg.contains("must not start with '-'"),
        "MUST surface option-injection guard; got {msg:?}"
    );
}

#[test]
fn enter_worktree_branch_ending_with_period_rejected() {
    let args = args_with(&[("branch", json!("foo."))]);
    let (msg, is_err) = dispatch("enter_worktree", &args);
    assert!(is_err);
    assert!(
        msg.contains("must not end with '.'"),
        "MUST surface trailing-period rule; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Shell-metacharacter rejection
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn enter_worktree_branch_with_semicolon_rejected() {
    let args = args_with(&[("branch", json!("foo;rm"))]);
    let (msg, is_err) = dispatch("enter_worktree", &args);
    assert!(is_err);
    assert!(
        msg.contains("forbidden character") || msg.contains("invalid branch"),
        "MUST reject ';'; got {msg:?}"
    );
}

#[test]
fn enter_worktree_branch_with_pipe_rejected() {
    let args = args_with(&[("branch", json!("foo|rm"))]);
    let (_msg, is_err) = dispatch("enter_worktree", &args);
    assert!(is_err);
}

#[test]
fn enter_worktree_branch_with_backtick_rejected() {
    let args = args_with(&[("branch", json!("`whoami`"))]);
    let (_msg, is_err) = dispatch("enter_worktree", &args);
    assert!(is_err);
}

#[test]
fn enter_worktree_branch_with_dollar_rejected() {
    let args = args_with(&[("branch", json!("$VAR"))]);
    let (_msg, is_err) = dispatch("enter_worktree", &args);
    assert!(is_err);
}

#[test]
fn enter_worktree_branch_with_redirect_chars_rejected() {
    for branch in &["foo>x", "foo<y"] {
        let args = args_with(&[("branch", json!(branch))]);
        let (_msg, is_err) = dispatch("enter_worktree", &args);
        assert!(is_err, "redirect chars MUST be rejected in {branch}");
    }
}

#[test]
fn enter_worktree_branch_with_parens_rejected() {
    let args = args_with(&[("branch", json!("foo(bar)"))]);
    let (_msg, is_err) = dispatch("enter_worktree", &args);
    assert!(is_err);
}

#[test]
fn enter_worktree_branch_with_quotes_rejected() {
    for branch in &["foo'bar", "foo\"bar"] {
        let args = args_with(&[("branch", json!(branch))]);
        let (_msg, is_err) = dispatch("enter_worktree", &args);
        assert!(is_err, "quote chars MUST be rejected in {branch}");
    }
}

#[test]
fn enter_worktree_branch_with_space_rejected() {
    let args = args_with(&[("branch", json!("foo bar"))]);
    let (_msg, is_err) = dispatch("enter_worktree", &args);
    assert!(is_err);
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Git ref-syntax character rejection
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn enter_worktree_branch_with_colon_rejected() {
    let args = args_with(&[("branch", json!("foo:bar"))]);
    let (_msg, is_err) = dispatch("enter_worktree", &args);
    assert!(is_err);
}

#[test]
fn enter_worktree_branch_with_backslash_rejected() {
    let args = args_with(&[("branch", json!("foo\\bar"))]);
    let (_msg, is_err) = dispatch("enter_worktree", &args);
    assert!(is_err);
}

#[test]
fn enter_worktree_branch_with_tilde_rejected() {
    let args = args_with(&[("branch", json!("foo~bar"))]);
    let (_msg, is_err) = dispatch("enter_worktree", &args);
    assert!(is_err);
}

#[test]
fn enter_worktree_branch_with_question_mark_rejected() {
    let args = args_with(&[("branch", json!("foo?bar"))]);
    let (_msg, is_err) = dispatch("enter_worktree", &args);
    assert!(is_err);
}

#[test]
fn enter_worktree_branch_with_asterisk_rejected() {
    let args = args_with(&[("branch", json!("foo*bar"))]);
    let (_msg, is_err) = dispatch("enter_worktree", &args);
    assert!(is_err);
}

#[test]
fn enter_worktree_branch_with_open_bracket_rejected() {
    let args = args_with(&[("branch", json!("foo[bar"))]);
    let (_msg, is_err) = dispatch("enter_worktree", &args);
    assert!(is_err);
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Control characters
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn enter_worktree_branch_with_control_character_rejected() {
    let args = args_with(&[("branch", json!("foo\x01bar"))]);
    let (msg, is_err) = dispatch("enter_worktree", &args);
    assert!(is_err);
    assert!(
        msg.contains("control character"),
        "MUST surface control-char message; got {msg:?}"
    );
    // Documented format: U+XXXX hex.
    assert!(
        msg.contains("U+"),
        "MUST format codepoint as U+; got {msg:?}"
    );
}

#[test]
fn enter_worktree_branch_with_newline_rejected() {
    let args = args_with(&[("branch", json!("foo\nbar"))]);
    let (_msg, is_err) = dispatch("enter_worktree", &args);
    assert!(is_err);
}

#[test]
fn enter_worktree_branch_with_null_byte_rejected() {
    let args = args_with(&[("branch", json!("foo\0bar"))]);
    let (msg, is_err) = dispatch("enter_worktree", &args);
    assert!(is_err);
    assert!(msg.contains("control character") || msg.contains("U+"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Canonical branches reach git layer
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn canonical_branch_passes_validation_without_creating_a_worktree() {
    // PINS DOC: "feature/foo" is documented as valid.
    validate_branch_name(support::shared_run_context(), "feature/foo")
        .expect("canonical branch must pass validation");
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — list_worktrees: zero-arg
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn list_worktrees_with_no_args_never_panics() {
    // PINS NO-PANIC: list works at top-level regardless of
    // cwd state — may error if not in git repo but never panic.
    let (_msg, _is_err) = dispatch("list_worktrees", &HashMap::new());
}

#[test]
fn list_worktrees_ignores_arbitrary_args() {
    let args = args_with(&[("extra", json!("ignored")), ("count", json!(42))]);
    let (_msg, _is_err) = dispatch("list_worktrees", &args);
}

// ───────────────────────────────────────────────────────────────────────────
// Section H — exit_worktree dispatch
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn exit_worktree_with_no_args_never_panics() {
    let (_msg, _is_err) = dispatch("exit_worktree", &HashMap::new());
}

#[test]
fn exit_worktree_path_as_number_returns_validation_error() {
    let args = args_with(&[("path", json!(42))]);
    let (msg, is_err) = dispatch("exit_worktree", &args);
    assert!(is_err);
    assert_host_classification_denial(&msg, "path");
}

#[test]
fn exit_worktree_path_as_null_returns_validation_error() {
    let args = args_with(&[("path", Value::Null)]);
    let (msg, is_err) = dispatch("exit_worktree", &args);
    assert!(is_err);
    assert_host_classification_denial(&msg, "path");
}

#[test]
fn exit_worktree_with_unadvertised_arguments_never_panics() {
    let args = args_with(&[("worktree", json!("ignored")), ("path", json!("/x"))]);
    let (_msg, _is_err) = dispatch("exit_worktree", &args);
}

#[test]
fn exit_worktree_apply_changes_wrong_type_returns_validation_error() {
    let dir = TempDir::new().expect("tempdir");
    let args = args_with(&[
        ("path", json!(dir.path().to_string_lossy().to_string())),
        ("apply_changes", json!("true")),
    ]);
    let (msg, is_err) = dispatch("exit_worktree", &args);
    assert!(is_err);
    assert_host_classification_denial(&msg, "apply_changes");
}

#[test]
fn exit_worktree_discard_changes_wrong_type_returns_validation_error() {
    let dir = TempDir::new().expect("tempdir");
    let args = args_with(&[
        ("path", json!(dir.path().to_string_lossy().to_string())),
        ("discard_changes", json!(["yes"])),
    ]);
    let (msg, is_err) = dispatch("exit_worktree", &args);
    assert!(is_err);
    assert_host_classification_denial(&msg, "discard_changes");
}

#[test]
fn exit_worktree_schema_exposes_explicit_transaction_phases() {
    let def = registry()
        .get("exit_worktree")
        .expect("exit_worktree registered")
        .definition();
    let params = def
        .pointer("/function/parameters")
        .expect("exit_worktree parameters");
    assert_eq!(params.get("additionalProperties"), Some(&json!(false)));
    assert_eq!(
        params.pointer("/properties/operation/enum"),
        Some(&json!([
            "preview", "stage", "commit", "merge", "discard", "remove"
        ]))
    );
    for field in ["expected_generation", "target_path", "paths", "message"] {
        assert!(
            params.pointer(&format!("/properties/{field}")).is_some(),
            "exit_worktree schema must expose transaction field {field}"
        );
    }
    let apply_desc = params
        .pointer("/properties/apply_changes/description")
        .and_then(Value::as_str)
        .expect("apply_changes description");
    assert!(
        apply_desc.contains("Deprecated") && apply_desc.contains("rejected"),
        "legacy apply description must direct callers to the transaction flow; got {apply_desc:?}"
    );
}

#[test]
fn exit_worktree_preview_needs_no_write_but_every_mutation_does() {
    let handler = registry().get("exit_worktree").expect("registered");
    let preview = args_with(&[("path", json!("/tmp/wt")), ("operation", json!("preview"))]);
    assert_eq!(
        handler.required_resources(&preview),
        &[ToolResource::WorkspaceRead, ToolResource::Process]
    );
    for operation in ["stage", "commit", "merge", "discard", "remove"] {
        let args = args_with(&[("path", json!("/tmp/wt")), ("operation", json!(operation))]);
        assert_eq!(
            handler.required_resources(&args),
            &[
                ToolResource::WorkspaceRead,
                ToolResource::WorkspaceWrite,
                ToolResource::Process,
            ],
            "{operation} must require write authority"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section I — Cross-tool consistency
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn three_worktree_tools_all_registered_in_registry() {
    assert!(registry().get("enter_worktree").is_some());
    assert!(registry().get("exit_worktree").is_some());
    assert!(registry().get("list_worktrees").is_some());
}

#[test]
fn readme_worktree_claims_match_dispatch_contract() {
    let readme = include_str!("../README.md");

    assert!(
        readme.contains(
            "Create, list, and safely remove isolated git worktrees without mutating the process CWD"
        ),
        "README feature list must state the non-CWD-mutating worktree contract"
    );
    assert!(
        readme.contains(
            "`exit_worktree` | Preview and transactionally stage, commit, merge, discard, or remove an isolated worktree"
        ),
        "README tool table must describe the explicit worktree transaction"
    );
    assert!(
        !readme.contains("switch between isolated git worktrees"),
        "README must not imply enter_worktree mutates the process CWD"
    );
    assert!(
        !readme.contains("Exit a worktree (keep or remove)"),
        "README must not imply exit_worktree has a keep mode"
    );
}
