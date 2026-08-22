//! End-to-end tests for `tools::skill::execute_skill` —
//! the runtime entry point that the model invokes via the
//! `/skill <name>` slash command to materialise an installed
//! skill into the conversation.
//!
//! Sprint 128 of the verification effort. Sprint 108 covered
//! `parse_skill_file` frontmatter; this file pins the
//! caller-facing `execute_skill` contract — error messages
//! on missing/empty/unknown name, return envelope shape,
//! and the `(text, is_error)` tuple discipline.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::skill::execute_skill as execute_skill_for_run;
use serde_json::{json, Value};
use std::collections::HashMap;

mod support;

fn execute_skill(args: &HashMap<String, Value>) -> (String, bool) {
    execute_skill_for_run(support::shared_run_context().as_ref(), args)
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Missing / wrong-type `name` argument
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn missing_name_argument_returns_error_tuple() {
    let args: HashMap<String, Value> = HashMap::new();
    let (text, is_err) = execute_skill(&args);
    assert!(is_err, "missing name MUST be error");
    assert!(text.contains("missing required argument"));
    assert!(text.contains("name"));
}

#[test]
fn name_with_wrong_type_returns_validation_error() {
    let mut args: HashMap<String, Value> = HashMap::new();
    args.insert("name".to_string(), json!(42));
    let (text, is_err) = execute_skill(&args);
    assert!(is_err, "non-string name MUST be error");
    assert!(
        text.contains("Invalid 'name' argument: expected string"),
        "wrong-type name MUST be rejected clearly; got {text:?}"
    );
}

#[test]
fn name_as_array_returns_validation_error() {
    let mut args: HashMap<String, Value> = HashMap::new();
    args.insert("name".to_string(), json!(["multi", "value"]));
    let (text, is_err) = execute_skill(&args);
    assert!(is_err);
    assert!(text.contains("Invalid 'name' argument: expected string"));
}

#[test]
fn name_as_object_returns_validation_error() {
    let mut args: HashMap<String, Value> = HashMap::new();
    args.insert("name".to_string(), json!({"nested": "value"}));
    let (text, is_err) = execute_skill(&args);
    assert!(is_err);
    assert!(text.contains("Invalid 'name' argument: expected string"));
}

#[test]
fn name_as_null_returns_validation_error() {
    let mut args: HashMap<String, Value> = HashMap::new();
    args.insert("name".to_string(), Value::Null);
    let (text, is_err) = execute_skill(&args);
    assert!(is_err);
    assert!(text.contains("Invalid 'name' argument: expected string"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Empty `name` argument
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn empty_name_string_returns_error_with_documented_message() {
    let mut args: HashMap<String, Value> = HashMap::new();
    args.insert("name".to_string(), json!(""));
    let (text, is_err) = execute_skill(&args);
    assert!(is_err);
    assert!(
        text.contains("empty"),
        "MUST surface `name is empty`; got {text:?}"
    );
}

#[test]
fn whitespace_only_name_is_treated_as_empty_after_trim() {
    let mut args: HashMap<String, Value> = HashMap::new();
    args.insert("name".to_string(), json!("   "));
    let (text, is_err) = execute_skill(&args);
    assert!(is_err);
    assert!(text.contains("empty"));
}

#[test]
fn tab_and_newline_only_name_is_treated_as_empty() {
    let mut args: HashMap<String, Value> = HashMap::new();
    args.insert("name".to_string(), json!("\t\n\r "));
    let (_text, is_err) = execute_skill(&args);
    assert!(is_err);
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Unknown skill name
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn unknown_skill_returns_error_with_documented_message() {
    let mut args: HashMap<String, Value> = HashMap::new();
    args.insert(
        "name".to_string(),
        json!("__definitely_no_such_skill_xyz_sprint128__"),
    );
    let (text, is_err) = execute_skill(&args);
    assert!(is_err);
    assert!(
        text.contains("unknown skill"),
        "MUST surface `unknown skill`; got {text:?}"
    );
}

#[test]
fn unknown_skill_error_message_includes_offending_name() {
    let mut args: HashMap<String, Value> = HashMap::new();
    args.insert("name".to_string(), json!("missing-skill-marker-xyz"));
    let (text, _is_err) = execute_skill(&args);
    assert!(
        text.contains("missing-skill-marker-xyz"),
        "error MUST echo offending name; got {text:?}"
    );
}

#[test]
fn unknown_skill_error_message_does_not_dump_catalog() {
    // PINS DOC: error MUST NOT include the full skill catalog
    // (would surprise the model with multi-KiB output).
    let mut args: HashMap<String, Value> = HashMap::new();
    args.insert("name".to_string(), json!("xyz"));
    let (text, _is_err) = execute_skill(&args);
    // Heuristic: a multi-KiB catalogue is well over 500 bytes.
    assert!(
        text.len() < 500,
        "error message MUST stay compact (<500 bytes); got {} bytes: {text:?}",
        text.len()
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Name-string trimming
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn name_with_leading_whitespace_trimmed_before_lookup() {
    // PINS DOC: name.trim() runs before get_skill lookup —
    // both leading + trailing whitespace stripped.
    let mut args: HashMap<String, Value> = HashMap::new();
    args.insert("name".to_string(), json!("   nonexistent-skill"));
    let (text, _is_err) = execute_skill(&args);
    // Error mentions the trimmed name (no leading spaces).
    assert!(
        text.contains("nonexistent-skill"),
        "trimmed name MUST appear in error; got {text:?}"
    );
    assert!(
        !text.contains("   nonexistent"),
        "leading spaces MUST be trimmed; got {text:?}"
    );
}

#[test]
fn name_with_trailing_whitespace_trimmed() {
    let mut args: HashMap<String, Value> = HashMap::new();
    args.insert("name".to_string(), json!("nonexistent-skill   "));
    let (text, _is_err) = execute_skill(&args);
    assert!(text.contains("nonexistent-skill"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Return tuple discipline
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn return_tuple_text_is_non_empty_for_every_error_path() {
    // Every error path returns non-empty text (operators
    // need to know why).
    let cases: Vec<HashMap<String, Value>> = vec![
        HashMap::new(),
        {
            let mut m = HashMap::new();
            m.insert("name".to_string(), json!(""));
            m
        },
        {
            let mut m = HashMap::new();
            m.insert("name".to_string(), json!(42));
            m
        },
        {
            let mut m = HashMap::new();
            m.insert("name".to_string(), json!("nonexistent-skill-name"));
            m
        },
    ];
    for args in cases {
        let (text, is_err) = execute_skill(&args);
        assert!(is_err);
        assert!(!text.is_empty(), "error path MUST return non-empty text");
    }
}

#[test]
fn execute_skill_does_not_panic_on_arbitrary_extra_args() {
    // Extra args (beyond `name`) MUST be ignored, not panic.
    let mut args: HashMap<String, Value> = HashMap::new();
    args.insert("name".to_string(), json!("unknown"));
    args.insert("extra".to_string(), json!("ignored"));
    args.insert("verbose".to_string(), json!(true));
    args.insert("count".to_string(), json!(42));
    let (_text, is_err) = execute_skill(&args);
    // Still errors (unknown skill) but doesn't panic on extras.
    assert!(is_err);
}

#[test]
fn execute_skill_is_must_use_returns_2_element_tuple() {
    // Compile-time: the return is (String, bool) — verify
    // we can destructure.
    let args = HashMap::new();
    let (_text, _is_err): (String, bool) = execute_skill(&args);
}
