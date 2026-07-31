//! End-to-end tests for `tools::ask_user::execute_ask_user_question`
//! validation arms — pre-network checks for question + option
//! shape that gate every `/ask` invocation.
//!
//! Sprint 137 of the verification effort. Sprint 82 covered
//! tool control signals; this file pins the validation
//! arms invoked through the registry dispatch path:
//! missing/wrong-type `questions` arg, 0/5+ questions, duplicate
//! question text, duplicate option labels, missing
//! or wrong-type required fields, oversize headers.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::registry::{registry, ToolContext};
use serde_json::{json, Value};
use std::collections::HashMap;

fn dispatch_ask_user(args: &HashMap<String, Value>) -> (String, bool) {
    let mut ctx = ToolContext {
        security: openclaudia::tools::security::current_context(),
        memory_db: None,
        app_config: None,
        task_mgr: None,
    };
    registry()
        .dispatch("ask_user_question", args, &mut ctx)
        .expect("ask_user_question must be registered")
}

fn args_with_questions(questions: Value) -> HashMap<String, Value> {
    let mut m = HashMap::new();
    m.insert("questions".to_string(), questions);
    m
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Missing / wrong-type `questions` arg
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn missing_questions_arg_returns_error() {
    let (msg, is_err) = dispatch_ask_user(&HashMap::new());
    assert!(is_err);
    assert!(
        msg.contains("questions") || msg.contains("Missing"),
        "MUST mention missing arg; got {msg:?}"
    );
}

#[test]
fn questions_arg_as_string_returns_validation_error() {
    let args = args_with_questions(json!("not an array"));
    let (msg, is_err) = dispatch_ask_user(&args);
    assert!(is_err);
    assert_eq!(msg, "Invalid 'questions' argument: expected array");
}

#[test]
fn questions_arg_as_object_returns_validation_error() {
    let args = args_with_questions(json!({"key": "value"}));
    let (msg, is_err) = dispatch_ask_user(&args);
    assert!(is_err);
    assert_eq!(msg, "Invalid 'questions' argument: expected array");
}

#[test]
fn questions_arg_as_null_returns_validation_error() {
    let args = args_with_questions(Value::Null);
    let (msg, is_err) = dispatch_ask_user(&args);
    assert!(is_err);
    assert_eq!(msg, "Invalid 'questions' argument: expected array");
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Count bounds: 1-4 questions allowed
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn empty_questions_array_returns_error() {
    let args = args_with_questions(json!([]));
    let (msg, is_err) = dispatch_ask_user(&args);
    assert!(is_err);
    assert!(
        msg.contains("1-4") || msg.contains("Must provide"),
        "MUST surface count error; got {msg:?}"
    );
}

#[test]
fn questions_array_with_5_entries_returns_error() {
    // PINS DOC: max 4 questions.
    let q = |i: usize| {
        json!({
            "question": format!("Q{i}?"),
            "header": format!("Q{i}"),
            "options": [
                {"label": "A", "description": "a"},
                {"label": "B", "description": "b"},
            ]
        })
    };
    let args = args_with_questions(json!([q(1), q(2), q(3), q(4), q(5)]));
    let (msg, is_err) = dispatch_ask_user(&args);
    assert!(is_err);
    assert!(
        msg.contains("1-4") || msg.contains("Must provide"),
        "MUST reject >4; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Required question fields
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn question_missing_question_field_returns_error() {
    let args = args_with_questions(json!([{
        "header": "Q1",
        "options": [
            {"label": "A", "description": "a"},
            {"label": "B", "description": "b"},
        ]
    }]));
    let (msg, is_err) = dispatch_ask_user(&args);
    assert!(is_err);
    assert!(
        msg.contains("'question'") || msg.contains("question"),
        "MUST mention missing 'question'; got {msg:?}"
    );
}

#[test]
fn question_wrong_type_question_field_returns_error() {
    let args = args_with_questions(json!([{
        "question": 42,
        "header": "Q1",
        "options": [
            {"label": "A", "description": "a"},
            {"label": "B", "description": "b"},
        ]
    }]));
    let (msg, is_err) = dispatch_ask_user(&args);
    assert!(is_err);
    assert_eq!(msg, "Question 0 'question' must be a string");
}

#[test]
fn question_missing_header_field_returns_error() {
    let args = args_with_questions(json!([{
        "question": "Pick?",
        "options": [
            {"label": "A", "description": "a"},
            {"label": "B", "description": "b"},
        ]
    }]));
    let (msg, is_err) = dispatch_ask_user(&args);
    assert!(is_err);
    assert!(
        msg.contains("'header'") || msg.contains("header"),
        "MUST mention missing 'header'; got {msg:?}"
    );
}

#[test]
fn question_wrong_type_header_field_returns_error() {
    let args = args_with_questions(json!([{
        "question": "Pick?",
        "header": ["Q1"],
        "options": [
            {"label": "A", "description": "a"},
            {"label": "B", "description": "b"},
        ]
    }]));
    let (msg, is_err) = dispatch_ask_user(&args);
    assert!(is_err);
    assert_eq!(msg, "Question 0 'header' must be a string");
}

#[test]
fn question_wrong_type_options_field_returns_error() {
    let args = args_with_questions(json!([{
        "question": "Pick?",
        "header": "Q1",
        "options": "A or B"
    }]));
    let (msg, is_err) = dispatch_ask_user(&args);
    assert!(is_err);
    assert_eq!(msg, "Question 0 'options' must be an array");
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Header chip width (12 char limit)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn header_exceeds_12_chars_returns_error() {
    let args = args_with_questions(json!([{
        "question": "Pick?",
        "header": "thisheaderiswaytoolong",
        "options": [
            {"label": "A", "description": "a"},
            {"label": "B", "description": "b"},
        ]
    }]));
    let (msg, is_err) = dispatch_ask_user(&args);
    assert!(is_err);
    assert!(
        msg.contains("12") || msg.contains("limit"),
        "MUST mention 12-char limit; got {msg:?}"
    );
}

#[test]
fn header_at_exactly_12_chars_is_accepted() {
    // 12 chars is the documented LIMIT (i.e. > 12 fails).
    let args = args_with_questions(json!([{
        "question": "Pick?",
        "header": "exactly12chr",
        "options": [
            {"label": "A", "description": "a"},
            {"label": "B", "description": "b"},
        ]
    }]));
    let (_msg, is_err) = dispatch_ask_user(&args);
    assert!(
        !is_err,
        "12-char header MUST be accepted (limit is strict >)"
    );
}

#[test]
fn unicode_header_counts_characters_not_bytes() {
    // "日本語スキル" is 6 chars but 18 bytes UTF-8.
    // 6 chars ≤ 12 → MUST be accepted (counted by chars).
    let args = args_with_questions(json!([{
        "question": "Pick?",
        "header": "日本語スキル",
        "options": [
            {"label": "A", "description": "a"},
            {"label": "B", "description": "b"},
        ]
    }]));
    let (_msg, is_err) = dispatch_ask_user(&args);
    assert!(!is_err, "6-char unicode header MUST be accepted");
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Option duplicates + missing fields
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn duplicate_option_labels_within_question_returns_error() {
    let args = args_with_questions(json!([{
        "question": "Pick?",
        "header": "Pick",
        "options": [
            {"label": "Same", "description": "first"},
            {"label": "Same", "description": "second"},
        ]
    }]));
    let (msg, is_err) = dispatch_ask_user(&args);
    assert!(is_err);
    assert!(
        msg.contains("unique") || msg.contains("Same"),
        "MUST mention uniqueness; got {msg:?}"
    );
}

#[test]
fn option_missing_label_returns_error() {
    let args = args_with_questions(json!([{
        "question": "Pick?",
        "header": "Pick",
        "options": [
            {"description": "no label"},
            {"label": "B", "description": "b"},
        ]
    }]));
    let (msg, is_err) = dispatch_ask_user(&args);
    assert!(is_err);
    assert!(
        msg.contains("'label'") || msg.contains("label"),
        "MUST mention missing label; got {msg:?}"
    );
}

#[test]
fn option_wrong_type_label_returns_error() {
    let args = args_with_questions(json!([{
        "question": "Pick?",
        "header": "Pick",
        "options": [
            {"label": 42, "description": "a"},
            {"label": "B", "description": "b"},
        ]
    }]));
    let (msg, is_err) = dispatch_ask_user(&args);
    assert!(is_err);
    assert_eq!(msg, "Question 0 option 0 'label' must be a string");
}

#[test]
fn option_missing_description_returns_error() {
    let args = args_with_questions(json!([{
        "question": "Pick?",
        "header": "Pick",
        "options": [
            {"label": "A"},
            {"label": "B", "description": "b"},
        ]
    }]));
    let (msg, is_err) = dispatch_ask_user(&args);
    assert!(is_err);
    assert!(
        msg.contains("'description'") || msg.contains("description"),
        "MUST mention missing description; got {msg:?}"
    );
}

#[test]
fn option_wrong_type_description_returns_error() {
    let args = args_with_questions(json!([{
        "question": "Pick?",
        "header": "Pick",
        "options": [
            {"label": "A", "description": null},
            {"label": "B", "description": "b"},
        ]
    }]));
    let (msg, is_err) = dispatch_ask_user(&args);
    assert!(is_err);
    assert_eq!(msg, "Question 0 option 0 'description' must be a string");
}

#[test]
fn option_preview_with_non_string_type_returns_error() {
    let args = args_with_questions(json!([{
        "question": "Pick?",
        "header": "Pick",
        "options": [
            {"label": "A", "description": "a", "preview": 42},
            {"label": "B", "description": "b"},
        ]
    }]));
    let (msg, is_err) = dispatch_ask_user(&args);
    assert!(is_err);
    assert!(
        msg.contains("preview") && msg.contains("string"),
        "MUST mention preview must be string; got {msg:?}"
    );
}

#[test]
fn option_preview_as_string_is_accepted() {
    let args = args_with_questions(json!([{
        "question": "Pick?",
        "header": "Pick",
        "options": [
            {"label": "A", "description": "a", "preview": "preview-text"},
            {"label": "B", "description": "b"},
        ]
    }]));
    let (_msg, is_err) = dispatch_ask_user(&args);
    assert!(!is_err, "string preview MUST be accepted");
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Cross-question uniqueness
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn duplicate_question_text_across_questions_returns_error() {
    let q = json!({
        "question": "Same text?",
        "header": "Q",
        "options": [
            {"label": "A", "description": "a"},
            {"label": "B", "description": "b"},
        ]
    });
    let args = args_with_questions(json!([q.clone(), q]));
    let (msg, is_err) = dispatch_ask_user(&args);
    assert!(is_err);
    assert!(
        msg.contains("unique") || msg.contains("Same"),
        "MUST mention uniqueness; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — Happy path
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn well_formed_single_question_passes_validation() {
    let args = args_with_questions(json!([{
        "question": "What library?",
        "header": "Library",
        "options": [
            {"label": "tokio", "description": "async runtime"},
            {"label": "async-std", "description": "alternative runtime"},
        ]
    }]));
    let (msg, is_err) = dispatch_ask_user(&args);
    assert!(!is_err, "well-formed input MUST pass; got {msg:?}");
}

#[test]
fn well_formed_4_question_array_passes_validation() {
    let q = |i: usize| {
        json!({
            "question": format!("Q{i}?"),
            "header": format!("Q{i}"),
            "options": [
                {"label": format!("A{i}"), "description": "a"},
                {"label": format!("B{i}"), "description": "b"},
            ]
        })
    };
    let args = args_with_questions(json!([q(1), q(2), q(3), q(4)]));
    let (_msg, is_err) = dispatch_ask_user(&args);
    assert!(!is_err);
}

#[test]
fn well_formed_with_multi_select_passes_validation() {
    let args = args_with_questions(json!([{
        "question": "Pick features",
        "header": "Features",
        "multiSelect": true,
        "options": [
            {"label": "F1", "description": "feature 1"},
            {"label": "F2", "description": "feature 2"},
            {"label": "F3", "description": "feature 3"},
        ]
    }]));
    let (_msg, is_err) = dispatch_ask_user(&args);
    assert!(!is_err);
}
