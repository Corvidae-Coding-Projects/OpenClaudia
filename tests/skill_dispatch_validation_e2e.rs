//! End-to-end tests for the `skill` tool dispatched
//! through the registry — name validation arms +
//! typed-result and trust contract on a real skill loaded from a tempdir.
//!
//! Sprint 154 of the verification effort. Sprint 128
//! covered direct `execute_skill` calls; this file pins
//! the registry-dispatched path so the wire-facing
//! contract matches.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::registry::registry;
use serde_json::{json, Value};
use std::collections::HashMap;
use tempfile::TempDir;

mod support;

fn dispatch_skill(args: &HashMap<String, Value>) -> (String, bool) {
    support::dispatch_tool("skill", args)
}

fn dispatch_skill_in(
    root: &std::path::Path,
    args: &HashMap<String, Value>,
) -> openclaudia::tools::ToolResult {
    let policy = openclaudia::skills::SkillCapabilityPolicy::project(
        vec!["Bash(git status *)".to_string()],
        true,
        true,
        true,
    )
    .expect("bounded registry skill policy");
    let run = support::trusted_project_skill_run_context(root, policy);
    support::dispatch_tool_result_for_run(&run, "skill", args)
}

fn args_with(entries: &[(&str, Value)]) -> HashMap<String, Value> {
    let mut m = HashMap::new();
    for (k, v) in entries {
        m.insert((*k).to_string(), v.clone());
    }
    m
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Missing/wrong-type name arg
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn missing_name_arg_returns_documented_error() {
    let (msg, is_err) = dispatch_skill(&HashMap::new());
    assert!(is_err);
    assert!(
        msg.contains("Host safety") && msg.contains("Missing 'name' argument"),
        "MUST surface documented missing-name; got {msg:?}"
    );
}

#[test]
fn name_arg_as_number_returns_validation_error() {
    let args = args_with(&[("name", json!(42))]);
    let (msg, is_err) = dispatch_skill(&args);
    assert!(is_err);
    assert!(
        msg.contains("Host safety")
            && msg.contains("malformed arguments")
            && msg.contains("'name'"),
        "wrong-type name MUST be rejected clearly; got {msg:?}"
    );
}

#[test]
fn name_arg_as_array_returns_validation_error() {
    let args = args_with(&[("name", json!(["x"]))]);
    let (msg, is_err) = dispatch_skill(&args);
    assert!(is_err);
    assert!(msg.contains("Host safety"));
    assert!(msg.contains("malformed arguments"));
    assert!(msg.contains("'name'"));
}

#[test]
fn name_arg_as_null_returns_validation_error() {
    let args = args_with(&[("name", Value::Null)]);
    let (msg, is_err) = dispatch_skill(&args);
    assert!(is_err);
    assert!(msg.contains("Host safety"));
    assert!(msg.contains("Missing 'name' argument"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Empty / whitespace name
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn empty_name_returns_empty_error() {
    let args = args_with(&[("name", json!(""))]);
    let (msg, is_err) = dispatch_skill(&args);
    assert!(is_err);
    assert!(
        msg.contains("empty"),
        "MUST surface documented empty-name message; got {msg:?}"
    );
}

#[test]
fn whitespace_only_name_treated_as_empty_after_trim() {
    let args = args_with(&[("name", json!("   \t  "))]);
    let (msg, is_err) = dispatch_skill(&args);
    assert!(is_err);
    assert!(
        msg.contains("empty"),
        "MUST treat whitespace-only as empty; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Unknown skill
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn unknown_skill_returns_documented_error_with_offending_name() {
    let args = args_with(&[("name", json!("definitely-no-such-skill-marker-154"))]);
    let (msg, is_err) = dispatch_skill(&args);
    assert!(is_err);
    assert!(
        msg.contains("unknown or unavailable skill"),
        "MUST surface unavailable skill; got {msg:?}"
    );
    assert!(
        msg.contains("definitely-no-such-skill-marker-154"),
        "MUST echo offending name; got {msg:?}"
    );
}

#[test]
fn unknown_skill_message_does_not_dump_catalog() {
    // PINS DOC: error must NOT include the full skill catalog.
    let args = args_with(&[("name", json!("xyz_no_skill"))]);
    let (msg, _is_err) = dispatch_skill(&args);
    assert!(
        msg.len() < 500,
        "error MUST stay compact (<500 bytes); got {} bytes",
        msg.len()
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Name trimming before lookup
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn name_with_leading_whitespace_trimmed_before_lookup() {
    let args = args_with(&[("name", json!("   nonexistent-after-trim"))]);
    let (msg, _is_err) = dispatch_skill(&args);
    assert!(
        msg.contains("nonexistent-after-trim"),
        "trimmed name MUST appear in error; got {msg:?}"
    );
    assert!(
        !msg.contains("   nonexistent"),
        "leading whitespace MUST be trimmed; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Happy path with installed skill
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn trusted_project_skill_dispatch_returns_typed_provenance() {
    let tmp = TempDir::new().expect("tempdir");
    {
        // Write a skill at .openclaudia/skills/<name>/SKILL.md.
        let skills_dir = tmp.path().join(".openclaudia/skills/round_trip_154");
        std::fs::create_dir_all(&skills_dir).expect("mkdir skills");
        std::fs::write(
            skills_dir.join("SKILL.md"),
            "---\nname: round_trip_154\ndescription: test\n---\nBody marker: HELLO_FROM_154\n",
        )
        .expect("write SKILL.md");

        let args = args_with(&[("name", json!("round_trip_154"))]);
        let result = dispatch_skill_in(tmp.path(), &args);
        assert!(!result.is_error(), "installed skill MUST load: {result:?}");
        let text = result.content();
        assert!(
            text.contains("HELLO_FROM_154"),
            "body MUST be present; got {text:?}"
        );
        assert!(!text.contains("<skill"));
        let structured = result.structured().expect("typed skill selection");
        assert_eq!(structured["schema"], "openclaudia.skill_selection.v1");
        assert_eq!(structured["name"], "round_trip_154");
        assert_eq!(structured["trigger"], "model_selection");
        assert_eq!(structured["provenance"]["source"], "project");
    }
}

#[test]
fn registry_model_selection_does_not_activate_declared_authority() {
    let tmp = TempDir::new().expect("tempdir");
    {
        let skills_dir = tmp.path().join(".openclaudia/skills/trailing_newline_154");
        std::fs::create_dir_all(&skills_dir).expect("mkdir");
        std::fs::write(
            skills_dir.join("SKILL.md"),
            "---\nname: trailing_newline_154\ndescription: test\nallowed_tools:\n  - Bash(git status *)\nmodel: gpt-5.6\neffort: high\n---\nLast line no NL",
        )
        .expect("write");

        let args = args_with(&[("name", json!("trailing_newline_154"))]);
        let result = dispatch_skill_in(tmp.path(), &args);
        assert!(!result.is_error());
        let structured = result.structured().expect("typed selection");
        assert_eq!(
            structured["requested_allowed_tools"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );
        assert_eq!(structured["effective_allowed_tools"], json!([]));
        assert!(structured["effective_model"].is_null());
        assert!(structured["effective_effort"].is_null());
        assert_eq!(structured["hooks_active"], false);
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Registration + forward-compat
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn skill_tool_registered_in_registry() {
    assert!(registry().get("skill").is_some());
}

#[test]
fn skill_dispatch_never_panics_on_arbitrary_extra_args() {
    let args = args_with(&[
        ("name", json!("nonexistent")),
        ("extra", json!({"k": "v"})),
        ("nested", json!([1, 2, 3])),
    ]);
    let (_text, _is_err) = dispatch_skill(&args);
}

#[test]
fn skill_dispatch_return_tuple_text_always_non_empty_for_every_error_path() {
    let cases: Vec<(&str, HashMap<String, Value>)> = vec![
        ("missing", HashMap::new()),
        ("wrong-type", args_with(&[("name", json!(42))])),
        ("empty", args_with(&[("name", json!(""))])),
        ("unknown", args_with(&[("name", json!("xyz"))])),
    ];
    for (label, args) in cases {
        let (text, is_err) = dispatch_skill(&args);
        assert!(is_err, "{label} path MUST error");
        assert!(!text.is_empty(), "{label} path MUST return non-empty text");
    }
}
