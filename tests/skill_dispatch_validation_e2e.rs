//! End-to-end tests for the `skill` tool dispatched
//! through the registry — name validation arms +
//! envelope-shape contract on a real skill loaded from
//! tempdir.
//!
//! Sprint 154 of the verification effort. Sprint 128
//! covered direct `execute_skill` calls; this file pins
//! the registry-dispatched path so the wire-facing
//! contract matches.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::registry::{registry, ToolContext};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, OnceLock};
use tempfile::TempDir;

fn cwd_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn run_in_tempdir<R>(f: impl FnOnce() -> R) -> R {
    let prev = std::env::current_dir().expect("cwd");
    let tmp = TempDir::new().expect("tempdir");
    std::env::set_current_dir(tmp.path()).expect("set cwd");
    let outcome = f();
    std::env::set_current_dir(&prev).expect("restore cwd");
    outcome
}

fn dispatch_skill(args: &HashMap<String, Value>) -> (String, bool) {
    let mut ctx = ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    };
    registry()
        .dispatch("skill", args, &mut ctx)
        .expect("skill must be registered")
        .into_legacy()
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
        msg.contains("missing required argument") && msg.contains("name"),
        "MUST surface documented missing-name; got {msg:?}"
    );
}

#[test]
fn name_arg_as_number_returns_validation_error() {
    let args = args_with(&[("name", json!(42))]);
    let (msg, is_err) = dispatch_skill(&args);
    assert!(is_err);
    assert!(
        msg.contains("Invalid 'name' argument: expected string"),
        "wrong-type name MUST be rejected clearly; got {msg:?}"
    );
}

#[test]
fn name_arg_as_array_returns_validation_error() {
    let args = args_with(&[("name", json!(["x"]))]);
    let (msg, is_err) = dispatch_skill(&args);
    assert!(is_err);
    assert!(msg.contains("Invalid 'name' argument: expected string"));
}

#[test]
fn name_arg_as_null_returns_validation_error() {
    let args = args_with(&[("name", Value::Null)]);
    let (msg, is_err) = dispatch_skill(&args);
    assert!(is_err);
    assert!(msg.contains("Invalid 'name' argument: expected string"));
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
        msg.contains("unknown skill"),
        "MUST surface 'unknown skill'; got {msg:?}"
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
fn skill_installed_in_project_dir_loads_and_returns_envelope() {
    let _l = cwd_lock();
    run_in_tempdir(|| {
        // Write a skill at .openclaudia/skills/<name>/SKILL.md.
        let skills_dir = std::path::Path::new(".openclaudia/skills/round_trip_154");
        std::fs::create_dir_all(skills_dir).expect("mkdir skills");
        std::fs::write(
            skills_dir.join("SKILL.md"),
            "---\nname: round_trip_154\ndescription: test\n---\nBody marker: HELLO_FROM_154\n",
        )
        .expect("write SKILL.md");

        let args = args_with(&[("name", json!("round_trip_154"))]);
        let (text, is_err) = dispatch_skill(&args);
        assert!(!is_err, "installed skill MUST load; got error {text:?}");

        // PINS ENVELOPE: opens with <skill name="...">, ends with </skill>.
        assert!(
            text.starts_with("<skill name=\""),
            "envelope MUST open with <skill name=; got {text:?}"
        );
        assert!(
            text.contains("name=\"round_trip_154\""),
            "envelope MUST embed skill name attribute; got {text:?}"
        );
        assert!(
            text.ends_with("</skill>"),
            "envelope MUST close with </skill>; got {text:?}"
        );
        // Body content MUST appear between the tags.
        assert!(
            text.contains("HELLO_FROM_154"),
            "body MUST be present; got {text:?}"
        );
    });
}

#[test]
fn skill_envelope_normalises_trailing_newline_before_close_tag() {
    let _l = cwd_lock();
    run_in_tempdir(|| {
        let skills_dir = std::path::Path::new(".openclaudia/skills/trailing_newline_154");
        std::fs::create_dir_all(skills_dir).expect("mkdir");
        // Body ends WITHOUT trailing newline.
        std::fs::write(
            skills_dir.join("SKILL.md"),
            "---\nname: trailing_newline_154\ndescription: test\n---\nLast line no NL",
        )
        .expect("write");

        let args = args_with(&[("name", json!("trailing_newline_154"))]);
        let (text, is_err) = dispatch_skill(&args);
        assert!(!is_err);
        // PINS: render_envelope adds a newline so close-tag is on its own line.
        assert!(
            text.contains("Last line no NL\n</skill>"),
            "MUST insert trailing newline before </skill>; got {text:?}"
        );
    });
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
