//! End-to-end tests for `tools::tool_search::execute_tool_search`
//! query forms — direct `select:` selection and keyword
//! search — invoked through the registry dispatch path.
//!
//! Sprint 140 of the verification effort. Sprint 132
//! smoke-tested dispatch; this file pins the documented
//! query contracts (#614):
//!   - `select:Read,Edit,Grep` → direct schema lookup.
//!   - keyword search returns ranked matches.
//!   - `+term` forces presence in name.
//!   - `max_results` defaults to 5, rejects invalid values, and caps at 50.
//!   - missing query / wrong type returns error.
//!   - no-match returns documented message (NOT an error).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use serde_json::{json, Value};
use std::collections::HashMap;

mod support;

fn dispatch_tool_search(args: &HashMap<String, Value>) -> (String, bool) {
    support::dispatch_tool("tool_search", args)
}

fn args_with(entries: &[(&str, Value)]) -> HashMap<String, Value> {
    let mut m = HashMap::new();
    for (k, v) in entries {
        m.insert((*k).to_string(), v.clone());
    }
    m
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Missing / wrong-type query arg
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn missing_query_arg_returns_error() {
    let (msg, is_err) = dispatch_tool_search(&HashMap::new());
    assert!(is_err);
    assert!(
        msg.contains("Host safety") && msg.contains("Missing 'query' argument"),
        "MUST mention missing query; got {msg:?}"
    );
}

#[test]
fn query_arg_as_number_treated_as_missing() {
    let args = args_with(&[("query", json!(42))]);
    let (msg, is_err) = dispatch_tool_search(&args);
    assert!(is_err);
    assert!(msg.contains("query"));
}

#[test]
fn query_arg_as_array_is_rejected_by_classification() {
    let args = args_with(&[("query", json!(["a", "b"]))]);
    let (msg, is_err) = dispatch_tool_search(&args);
    assert!(is_err);
    assert!(
        msg.contains("Host safety")
            && msg.contains("malformed arguments")
            && msg.contains("'query'"),
        "array query MUST fail before handler execution; got {msg:?}"
    );
}

#[test]
fn query_arg_as_null_treated_as_missing() {
    let args = args_with(&[("query", Value::Null)]);
    let (msg, is_err) = dispatch_tool_search(&args);
    assert!(is_err);
    assert!(msg.contains("query"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — select: prefix direct selection
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn select_single_tool_returns_function_envelope() {
    let args = args_with(&[("query", json!("select:bash"))]);
    let (text, is_err) = dispatch_tool_search(&args);
    assert!(!is_err);
    assert!(text.starts_with("<functions>"));
    assert!(text.ends_with("</functions>"));
    assert!(text.contains("\"name\":\"bash\""));
}

#[test]
fn select_multi_tool_csv_returns_each_function() {
    let args = args_with(&[("query", json!("select:bash,read_file"))]);
    let (text, is_err) = dispatch_tool_search(&args);
    assert!(!is_err);
    assert!(text.contains("\"name\":\"bash\""));
    assert!(text.contains("\"name\":\"read_file\""));
}

#[test]
fn select_tool_names_are_case_insensitive() {
    let args = args_with(&[("query", json!("select:Bash,Read_File"))]);
    let (text, is_err) = dispatch_tool_search(&args);
    assert!(!is_err);
    assert!(text.contains("\"name\":\"bash\""));
    assert!(text.contains("\"name\":\"read_file\""));
}

#[test]
fn select_preserves_order_in_envelope() {
    // PINS DOC: order from query is preserved in output.
    let args = args_with(&[("query", json!("select:bash,read_file"))]);
    let (text, _) = dispatch_tool_search(&args);
    let bash_pos = text.find("\"name\":\"bash\"").expect("bash present");
    let read_pos = text.find("\"name\":\"read_file\"").expect("read present");
    assert!(
        bash_pos < read_pos,
        "bash MUST appear before read_file (query order)"
    );
}

#[test]
fn select_unknown_name_silently_skipped() {
    // PINS DOC: unknown names ignored; valid names still returned.
    let args = args_with(&[("query", json!("select:nonexistent_tool_xyz,bash"))]);
    let (text, is_err) = dispatch_tool_search(&args);
    assert!(!is_err);
    assert!(text.contains("\"name\":\"bash\""));
    assert!(!text.contains("nonexistent_tool_xyz"));
}

#[test]
fn select_only_unknown_names_returns_no_matches_message() {
    let args = args_with(&[("query", json!("select:nonexistent_a,nonexistent_b"))]);
    let (text, is_err) = dispatch_tool_search(&args);
    // No-match returns `(text, false)` — NOT an error.
    assert!(!is_err);
    assert!(
        text.contains("no matches"),
        "MUST surface no-match message; got {text:?}"
    );
}

#[test]
fn select_with_whitespace_around_names_trims_before_lookup() {
    // PINS DOC: select tokens are trimmed.
    let args = args_with(&[("query", json!("select:  bash  ,  read_file  "))]);
    let (text, _) = dispatch_tool_search(&args);
    assert!(text.contains("\"name\":\"bash\""));
    assert!(text.contains("\"name\":\"read_file\""));
}

#[test]
fn select_with_empty_tokens_ignored() {
    // Empty entries (extra commas) are filtered.
    let args = args_with(&[("query", json!("select:bash,,read_file"))]);
    let (text, _) = dispatch_tool_search(&args);
    assert!(text.contains("\"name\":\"bash\""));
    assert!(text.contains("\"name\":\"read_file\""));
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Keyword search
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn keyword_search_returns_function_envelope() {
    // "bash" should match the bash tool (or others containing it).
    let args = args_with(&[("query", json!("bash"))]);
    let (text, is_err) = dispatch_tool_search(&args);
    assert!(!is_err);
    assert!(text.contains("<functions>") || text.contains("no matches"));
}

#[test]
fn keyword_search_completely_unrelated_query_returns_no_matches() {
    let args = args_with(&[("query", json!("xyzzy_completely_unrelated_word_marker"))]);
    let (text, is_err) = dispatch_tool_search(&args);
    assert!(!is_err, "no-match MUST NOT be error");
    assert!(text.contains("no matches"));
}

#[test]
fn keyword_search_with_plus_term_forces_presence_in_name() {
    // PINS DOC: +bash forces "bash" in name; rank by remaining terms.
    let args = args_with(&[("query", json!("+bash unrelated"))]);
    let (text, is_err) = dispatch_tool_search(&args);
    assert!(!is_err);
    // If matches found, every match name MUST contain "bash".
    if text.contains("<functions>") {
        // Check tools in envelope all contain "bash" in name.
        for part in text.split("<function>").skip(1) {
            if let Some(name_start) = part.find("\"name\":\"") {
                let rest = &part[name_start + 8..];
                if let Some(end) = rest.find('"') {
                    let name = &rest[..end];
                    assert!(
                        name.contains("bash"),
                        "+bash gate violated; tool name {name:?} lacks 'bash'"
                    );
                }
            }
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — max_results parameter
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn max_results_explicit_1_caps_envelope_to_1_function_block() {
    let args = args_with(&[("query", json!("file")), ("max_results", json!(1))]);
    let (text, is_err) = dispatch_tool_search(&args);
    assert!(!is_err);
    if text.contains("<functions>") {
        let function_count = text.matches("<function>").count();
        assert!(
            function_count <= 1,
            "max_results=1 MUST cap at 1 function block; got {function_count}"
        );
    }
}

#[test]
fn max_results_above_ceiling_clamps_to_50() {
    // PINS DOC: MAX_RESULTS_CEILING = 50; values above cap.
    let args = args_with(&[("query", json!("a")), ("max_results", json!(9999))]);
    let (text, is_err) = dispatch_tool_search(&args);
    assert!(!is_err);
    // No panic + result may surface "no matches" or up to 50 functions.
    if text.contains("<functions>") {
        let function_count = text.matches("<function>").count();
        assert!(
            function_count <= 50,
            "max_results MUST clamp at 50; got {function_count}"
        );
    }
}

#[test]
fn max_results_zero_returns_validation_error() {
    let args = args_with(&[("query", json!("file")), ("max_results", json!(0))]);
    let (text, is_err) = dispatch_tool_search(&args);
    assert!(is_err);
    assert!(
        text.contains("tool_search max_results must be an integer between 1 and 50"),
        "zero max_results MUST be rejected; got {text:?}"
    );
}

#[test]
fn max_results_default_is_5_when_omitted() {
    // No max_results → DEFAULT_MAX_RESULTS = 5.
    let args = args_with(&[("query", json!("file"))]);
    let (text, _is_err) = dispatch_tool_search(&args);
    if text.contains("<functions>") {
        let function_count = text.matches("<function>").count();
        assert!(
            function_count <= 5,
            "default max_results MUST be 5; got {function_count}"
        );
    }
}

#[test]
fn max_results_negative_returns_validation_error() {
    let args = args_with(&[("query", json!("file")), ("max_results", json!(-1))]);
    let (text, is_err) = dispatch_tool_search(&args);
    assert!(is_err);
    assert!(
        text.contains("tool_search max_results must be an integer between 1 and 50"),
        "negative max_results MUST be rejected; got {text:?}"
    );
}

#[test]
fn max_results_string_returns_validation_error() {
    let args = args_with(&[("query", json!("file")), ("max_results", json!("10"))]);
    let (text, is_err) = dispatch_tool_search(&args);
    assert!(is_err);
    assert!(
        text.contains("tool_search max_results must be an integer between 1 and 50"),
        "string max_results MUST be rejected; got {text:?}"
    );
}

#[test]
fn max_results_above_u64_max_no_panic() {
    let args = args_with(&[("query", json!("file")), ("max_results", json!(u64::MAX))]);
    let (_text, _is_err) = dispatch_tool_search(&args);
    // try_from(u64::MAX as usize) may fail on 32-bit but
    // map_or returns default 5 — no panic.
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Envelope shape
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn envelope_wraps_each_match_in_single_function_tag() {
    let args = args_with(&[("query", json!("select:bash,read_file"))]);
    let (text, _is_err) = dispatch_tool_search(&args);
    // Two matches → exactly two <function>...</function> tags.
    assert_eq!(text.matches("<function>").count(), 2);
    assert_eq!(text.matches("</function>").count(), 2);
    // Outer wrapper is exactly one functions block.
    assert_eq!(text.matches("<functions>").count(), 1);
    assert_eq!(text.matches("</functions>").count(), 1);
}

#[test]
fn envelope_definition_json_is_inline_one_line_per_tag() {
    let args = args_with(&[("query", json!("select:bash"))]);
    let (text, _is_err) = dispatch_tool_search(&args);
    // Each <function>...</function> block is on a single line
    // (no internal newlines).
    let line_with_function = text
        .lines()
        .find(|l| l.contains("<function>"))
        .expect("line present");
    assert!(line_with_function.contains("</function>"));
}
