//! End-to-end tests for `tools::get_all_tool_definitions` —
//! the subagents=true/false delta, count invariants,
//! and the wire-shape preservation across both forks.
//!
//! Sprint 182 of the verification effort. Sprint 53 had
//! basic structure tests; this file pins the count delta
//! that the subagents flag introduces and the per-tool
//! invariants applied uniformly to both base + subagent
//! tools.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::{get_all_tool_definitions, get_tool_definitions};
use serde_json::Value;

fn tool_names(defs: &Value) -> Vec<String> {
    defs.as_array()
        .expect("array")
        .iter()
        .filter_map(|t| t["function"]["name"].as_str().map(String::from))
        .collect()
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — get_tool_definitions returns the base catalog
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn get_tool_definitions_returns_array_of_function_objects() {
    let defs = get_tool_definitions();
    let arr = defs.as_array().expect("array");
    assert!(!arr.is_empty(), "base catalog MUST have tools");
    for tool in arr {
        assert_eq!(tool["type"], "function");
        assert!(tool["function"].is_object());
    }
}

#[test]
fn get_tool_definitions_matches_documented_base_tool_count() {
    // PINS CATALOG SIZE: 48 base tools with browser-backed web tools.
    // `web_search` and `web_browser` are only registered when the `browser`
    // feature is compiled in.
    let expected = if cfg!(feature = "browser") { 48 } else { 46 };
    let defs = get_tool_definitions();
    let arr = defs.as_array().expect("array");
    assert_eq!(
        arr.len(),
        expected,
        "PINS: 48 base tools w/ browser feature (adding tools requires bumping this)"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — subagents flag delta
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn get_all_with_subagents_false_matches_base_count() {
    // PINS: subagents=false → identical to get_tool_definitions.
    let base = get_tool_definitions();
    let no_sub = get_all_tool_definitions(false);
    let base_arr = base.as_array().unwrap();
    let no_sub_arr = no_sub.as_array().unwrap();
    assert_eq!(base_arr.len(), no_sub_arr.len());
}

#[test]
fn get_all_with_subagents_true_adds_3_tools() {
    // PINS DOC: get_subagent_tool_definitions adds exactly 3 tools.
    let base = get_tool_definitions();
    let with_sub = get_all_tool_definitions(true);
    let base_count = base.as_array().unwrap().len();
    let with_sub_count = with_sub.as_array().unwrap().len();
    assert_eq!(
        with_sub_count,
        base_count + 3,
        "PINS DELTA: subagents=true adds exactly 3 tools"
    );
}

#[test]
fn get_all_with_subagents_true_count_matches_documented_total() {
    // PINS: 48 base + 3 subagent = 51 total. `web_search` and `web_browser`
    // are only registered when the `browser` feature is compiled in, so
    // feature-less builds pin two fewer.
    let expected = if cfg!(feature = "browser") { 51 } else { 49 };
    let defs = get_all_tool_definitions(true);
    let arr = defs.as_array().expect("array");
    assert_eq!(arr.len(), expected);
}

#[test]
fn subagent_tools_appear_at_end_after_base_tools() {
    // PINS ORDER: subagent tools are EXTENDED onto base, so
    // they appear at the tail of the catalog.
    let base_names = tool_names(&get_tool_definitions());
    let all_names = tool_names(&get_all_tool_definitions(true));
    let base_len = base_names.len();
    // First N names match base catalog verbatim.
    assert_eq!(&all_names[..base_len], &base_names[..]);
}

#[test]
fn subagents_true_adds_task_tool() {
    // PINS DOC: task tool is one of the 3 subagent tools.
    let names = tool_names(&get_all_tool_definitions(true));
    let has_task = names.iter().any(|n| n.contains("task") || n == "Task");
    assert!(has_task, "PINS: task tool present in subagent set");
}

#[test]
fn subagents_true_adds_task_stop_tool() {
    let names = tool_names(&get_all_tool_definitions(true));
    assert!(
        names.iter().any(|n| n == "task_stop"),
        "PINS: task_stop tool present in subagent set"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Per-tool wire-shape invariants across both forks
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn every_tool_in_no_subagent_fork_has_required_shape() {
    let defs = get_all_tool_definitions(false);
    for tool in defs.as_array().unwrap() {
        assert_eq!(tool["type"], "function");
        assert!(tool["function"]["name"].is_string());
        assert!(tool["function"]["description"].is_string());
        assert!(tool["function"]["parameters"].is_object());
    }
}

#[test]
fn every_tool_in_with_subagent_fork_has_required_shape() {
    let defs = get_all_tool_definitions(true);
    for tool in defs.as_array().unwrap() {
        assert_eq!(tool["type"], "function");
        assert!(tool["function"]["name"].is_string());
        assert!(tool["function"]["description"].is_string());
        assert!(tool["function"]["parameters"].is_object());
    }
}

#[test]
fn no_duplicate_tool_names_across_full_catalog_with_subagents() {
    let mut names = tool_names(&get_all_tool_definitions(true));
    let original_len = names.len();
    names.sort();
    names.dedup();
    assert_eq!(
        names.len(),
        original_len,
        "PINS UNIQUENESS: no duplicate tool names across full catalog"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Determinism + idempotency
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn repeated_get_all_calls_return_same_count() {
    let counts: Vec<usize> = (0..5)
        .map(|_| get_all_tool_definitions(true).as_array().unwrap().len())
        .collect();
    let first = counts[0];
    assert!(counts.iter().all(|&c| c == first));
}

#[test]
fn repeated_get_all_calls_return_same_names_in_same_order() {
    let a = tool_names(&get_all_tool_definitions(true));
    let b = tool_names(&get_all_tool_definitions(true));
    assert_eq!(a, b, "tool order MUST be deterministic");
}

#[test]
fn get_tool_definitions_and_get_all_false_have_same_byte_serialization() {
    let base_json = serde_json::to_string(&get_tool_definitions()).expect("ser");
    let nosub_json = serde_json::to_string(&get_all_tool_definitions(false)).expect("ser");
    assert_eq!(base_json, nosub_json);
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Subagent tools wire shape
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn subagent_only_tools_have_unique_names_not_in_base_catalog() {
    let base_names: std::collections::HashSet<String> =
        tool_names(&get_tool_definitions()).into_iter().collect();
    let all_names: Vec<String> = tool_names(&get_all_tool_definitions(true));
    // Subagent tools are the names added when subagents=true.
    let subagent_only: Vec<&String> = all_names
        .iter()
        .filter(|n| !base_names.contains(*n))
        .collect();
    assert_eq!(
        subagent_only.len(),
        3,
        "PINS: exactly 3 subagent-only tools added"
    );
    // Each subagent tool name MUST be distinct.
    let mut deduped = subagent_only.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(deduped.len(), 3);
}

#[test]
fn subagent_tools_carry_function_envelope_too() {
    let base_names: std::collections::HashSet<String> =
        tool_names(&get_tool_definitions()).into_iter().collect();
    let defs = get_all_tool_definitions(true);
    let arr = defs.as_array().unwrap();
    for tool in arr {
        let name = tool["function"]["name"]
            .as_str()
            .expect("name string")
            .to_string();
        if !base_names.contains(&name) {
            // Subagent-only tool — verify the same envelope shape.
            assert_eq!(tool["type"], "function");
            assert!(tool["function"]["description"].is_string());
            assert!(tool["function"]["parameters"].is_object());
        }
    }
}
