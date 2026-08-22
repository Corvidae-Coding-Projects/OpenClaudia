//! End-to-end coverage for the host-owned progressive tool catalog.
//!
//! These tests deliberately enter through the canonical executor. They prove
//! that `tool_search` changes run-owned host state, returns typed receipts, and
//! cannot make a schema callable until a later provider-request snapshot.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]

use std::collections::HashMap;
use std::sync::Arc;

use openclaudia::tools::catalog::{
    ToolCatalogSnapshot, MAX_EXPLICIT_ACTIVE_TOOLS, MAX_TOOL_SEARCH_RESULTS,
};
use openclaudia::tools::{ToolFailureCode, ToolOutcome, ToolResult, ToolRunContext};
use serde_json::{json, Value};

mod support;

struct Fixture {
    _root: tempfile::TempDir,
    run: Arc<ToolRunContext>,
    definitions: Vec<Value>,
    snapshot: ToolCatalogSnapshot,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("tool catalog root");
        let run = support::test_run_context(root.path());
        let definitions = openclaudia::tools::get_all_tool_definitions(true)
            .as_array()
            .expect("tool definition array")
            .clone();
        let snapshot = run
            .tool_catalog()
            .snapshot(
                &run,
                &[json!({
                    "role": "user",
                    "content": "Inspect a Rust source file and fix its implementation"
                })],
                &definitions,
            )
            .expect("initial progressive snapshot");
        assert!(!snapshot.full_catalog_fallback);
        Self {
            _root: root,
            run,
            definitions,
            snapshot,
        }
    }

    fn search(&self, query: &str, max_results: Option<usize>) -> ToolResult {
        let mut args = HashMap::from([
            ("query".to_string(), json!(query)),
            (
                "catalog_generation".to_string(),
                json!(self.snapshot.generation.to_string()),
            ),
        ]);
        if let Some(max_results) = max_results {
            args.insert("max_results".to_string(), json!(max_results));
        }
        support::dispatch_canonical_tool_result_for_run(&self.run, "tool_search", &args)
    }

    fn deferred_names(&self) -> Vec<String> {
        self.definitions
            .iter()
            .filter_map(|definition| definition.pointer("/function/name").and_then(Value::as_str))
            .filter(|name| {
                !self
                    .snapshot
                    .active_names
                    .iter()
                    .any(|active| active == name)
            })
            .map(str::to_string)
            .collect()
    }

    fn republish(&mut self) {
        self.snapshot = self
            .run
            .tool_catalog()
            .snapshot(&self.run, &[], &self.definitions)
            .expect("next progressive snapshot");
    }
}

fn failure(result: &ToolResult) -> (&openclaudia::tools::ToolFailure, ToolFailureCode) {
    let ToolOutcome::Error { failure } = result.outcome() else {
        panic!("expected typed failure, got {result:#?}");
    };
    (failure, failure.code)
}

#[test]
fn canonical_search_requires_query_and_bound_generation() {
    let fixture = Fixture::new();
    let missing_query = HashMap::from([(
        "catalog_generation".to_string(),
        json!(fixture.snapshot.generation.to_string()),
    )]);
    let result = support::dispatch_canonical_tool_result_for_run(
        &fixture.run,
        "tool_search",
        &missing_query,
    );
    assert_eq!(failure(&result).1, ToolFailureCode::InvalidArguments);

    let missing_generation = HashMap::from([("query".to_string(), json!("memory"))]);
    let result = support::dispatch_canonical_tool_result_for_run(
        &fixture.run,
        "tool_search",
        &missing_generation,
    );
    assert_eq!(failure(&result).1, ToolFailureCode::InvalidArguments);
}

#[test]
fn malformed_and_oversized_queries_fail_before_catalog_mutation() {
    let fixture = Fixture::new();
    let malformed = HashMap::from([
        ("query".to_string(), json!(["memory"])),
        (
            "catalog_generation".to_string(),
            json!(fixture.snapshot.generation.to_string()),
        ),
    ]);
    let result =
        support::dispatch_canonical_tool_result_for_run(&fixture.run, "tool_search", &malformed);
    assert_eq!(failure(&result).1, ToolFailureCode::InvalidArguments);

    let result = fixture.search(&"x".repeat(513), None);
    assert_eq!(failure(&result).1, ToolFailureCode::InvalidArguments);

    let malformed_generation = HashMap::from([
        ("query".to_string(), json!("memory")),
        ("catalog_generation".to_string(), json!("x".repeat(4_096))),
    ]);
    let result = support::dispatch_canonical_tool_result_for_run(
        &fixture.run,
        "tool_search",
        &malformed_generation,
    );
    let (typed_failure, code) = failure(&result);
    assert_eq!(code, ToolFailureCode::InvalidArguments);
    assert!(typed_failure.message.len() < 256);

    let result = fixture.search("   ", None);
    assert_eq!(failure(&result).1, ToolFailureCode::InvalidArguments);
}

#[test]
fn max_results_rejects_every_out_of_contract_shape() {
    let fixture = Fixture::new();
    for value in [
        json!(0),
        json!(MAX_TOOL_SEARCH_RESULTS + 1),
        json!(-1),
        json!("2"),
    ] {
        let args = HashMap::from([
            ("query".to_string(), json!("memory")),
            (
                "catalog_generation".to_string(),
                json!(fixture.snapshot.generation.to_string()),
            ),
            ("max_results".to_string(), value),
        ]);
        let result =
            support::dispatch_canonical_tool_result_for_run(&fixture.run, "tool_search", &args);
        assert_eq!(failure(&result).1, ToolFailureCode::InvalidArguments);
    }
}

#[test]
fn stale_generation_is_a_typed_conflict_with_current_generation_recovery() {
    let fixture = Fixture::new();
    let args = HashMap::from([
        ("query".to_string(), json!("memory")),
        (
            "catalog_generation".to_string(),
            json!("sha256:0000000000000000000000000000000000000000000000000000000000000000"),
        ),
    ]);
    let result =
        support::dispatch_canonical_tool_result_for_run(&fixture.run, "tool_search", &args);
    let (failure, code) = failure(&result);
    assert_eq!(code, ToolFailureCode::Conflict);
    assert_eq!(
        failure
            .recovery
            .as_ref()
            .and_then(|value| value.get("catalog_generation")),
        Some(&json!(fixture.snapshot.generation.to_string()))
    );
}

#[test]
fn exact_selection_returns_metadata_not_xml_or_callable_schema_text() {
    let fixture = Fixture::new();
    let deferred = fixture
        .deferred_names()
        .into_iter()
        .next()
        .expect("deferred tool");
    let result = fixture.search(&format!("select:{deferred}"), None);
    assert!(!result.is_error(), "selection failed: {result:#?}");
    assert!(!result.content().contains("<functions>"));
    assert!(!result.content().contains("\"parameters\""));
    let receipt = &result.structured().expect("typed receipt")["tool_selection"];
    assert_eq!(
        receipt["catalog_generation"],
        fixture.snapshot.generation.to_string()
    );
    assert_eq!(
        receipt["valid_for_catalog_generation"],
        fixture.snapshot.generation.to_string()
    );
    assert_eq!(receipt["expires_on_catalog_generation_change"], true);
    assert_eq!(receipt["explicit_active_after_selection"], 1);
    assert_eq!(receipt["activated"][0]["name"], deferred);
    assert!(receipt["activated"][0]["schema_digest"].is_string());
    assert!(receipt["activated"][0]["effect"].is_string());
    assert!(receipt["activated"][0]["authorization_required"].is_boolean());
}

#[test]
fn exact_selection_is_case_insensitive_and_preserves_requested_order() {
    let fixture = Fixture::new();
    let deferred = fixture.deferred_names();
    assert!(deferred.len() >= 2);
    let requested = [&deferred[1], &deferred[0]];
    let query = format!(
        "select:{},{}",
        requested[0].to_ascii_uppercase(),
        requested[1].to_ascii_uppercase()
    );
    let result = fixture.search(&query, Some(2));
    assert!(!result.is_error(), "exact selection failed: {result:#?}");
    let activated = result.structured().expect("typed receipt")["tool_selection"]["activated"]
        .as_array()
        .expect("activated array");
    assert_eq!(activated[0]["name"], requested[0].as_str());
    assert_eq!(activated[1]["name"], requested[1].as_str());
}

#[test]
fn unknown_exact_name_rejects_the_whole_selection_with_explicit_miss() {
    let mut fixture = Fixture::new();
    let valid = fixture
        .deferred_names()
        .into_iter()
        .next()
        .expect("deferred tool");
    let result = fixture.search(&format!("select:{valid},not_a_real_tool"), None);
    let (failure, code) = failure(&result);
    assert_eq!(code, ToolFailureCode::Unavailable);
    assert_eq!(
        failure
            .recovery
            .as_ref()
            .and_then(|value| value.pointer("/misses/0")),
        Some(&json!("not_a_real_tool"))
    );

    fixture.republish();
    assert!(
        !fixture.snapshot.active_names.contains(&valid),
        "a partially valid direct selection must not mutate catalog state"
    );
}

#[test]
fn duplicate_exact_names_do_not_bypass_the_result_cap() {
    let fixture = Fixture::new();
    let deferred = fixture
        .deferred_names()
        .into_iter()
        .next()
        .expect("deferred tool");
    let result = fixture.search(&format!("select:{deferred},{deferred},{deferred}"), Some(1));
    assert!(!result.is_error());
    assert_eq!(
        result.structured().expect("typed receipt")["tool_selection"]["activated"]
            .as_array()
            .expect("activated array")
            .len(),
        1
    );
}

#[test]
fn over_cap_selection_is_rejected_atomically() {
    let mut fixture = Fixture::new();
    let deferred = fixture.deferred_names();
    assert!(deferred.len() > MAX_TOOL_SEARCH_RESULTS);
    let query = format!("select:{}", deferred[..=MAX_TOOL_SEARCH_RESULTS].join(","));
    let result = fixture.search(&query, Some(MAX_TOOL_SEARCH_RESULTS));
    assert_eq!(failure(&result).1, ToolFailureCode::InvalidArguments);

    fixture.republish();
    assert!(!fixture.snapshot.active_names.contains(&deferred[0]));
}

#[test]
fn cumulative_activation_cap_is_atomic_across_calls() {
    let mut fixture = Fixture::new();
    let deferred = fixture.deferred_names();
    assert!(deferred.len() > MAX_EXPLICIT_ACTIVE_TOOLS);

    let first = format!("select:{}", deferred[..MAX_TOOL_SEARCH_RESULTS].join(","));
    assert!(!fixture
        .search(&first, Some(MAX_TOOL_SEARCH_RESULTS))
        .is_error());
    let remaining = MAX_EXPLICIT_ACTIVE_TOOLS - MAX_TOOL_SEARCH_RESULTS + 1;
    let second = format!(
        "select:{}",
        deferred[MAX_TOOL_SEARCH_RESULTS..MAX_TOOL_SEARCH_RESULTS + remaining].join(",")
    );
    let result = fixture.search(&second, Some(remaining));
    assert_eq!(failure(&result).1, ToolFailureCode::InvalidArguments);

    fixture.republish();
    for name in &deferred[..MAX_TOOL_SEARCH_RESULTS] {
        assert!(fixture.snapshot.active_names.contains(name));
    }
    assert!(!fixture
        .snapshot
        .active_names
        .contains(&deferred[MAX_TOOL_SEARCH_RESULTS]));
}

#[test]
fn selection_is_not_callable_in_the_same_batch_but_is_on_the_next_request() {
    let mut fixture = Fixture::new();
    let deferred = ["task_list", "memory_list", "todo_read"]
        .into_iter()
        .find(|name| {
            !fixture
                .snapshot
                .active_names
                .iter()
                .any(|active| active == name)
        })
        .expect("safe deferred list tool");
    let result = fixture.search(&format!("select:{deferred}"), None);
    assert!(!result.is_error());

    let denied =
        support::dispatch_canonical_tool_result_for_run(&fixture.run, deferred, &HashMap::new());
    assert_eq!(failure(&denied).1, ToolFailureCode::Unavailable);
    assert!(denied.content().contains("was not active"));

    fixture.republish();
    assert!(fixture
        .snapshot
        .active_names
        .iter()
        .any(|name| name == deferred));
    let after_publish =
        support::dispatch_canonical_tool_result_for_run(&fixture.run, deferred, &HashMap::new());
    assert!(
        !after_publish.content().contains("was not active"),
        "normal resource, policy, and handler checks must run after catalog admission"
    );
}

#[test]
fn keyword_search_recalls_codebase_technical_memory_tools_with_a_bounded_receipt() {
    let fixture = Fixture::new();
    let result = fixture.search("retrieve technical lessons for this codebase", Some(3));
    assert!(!result.is_error(), "memory retrieval failed: {result:#?}");
    let activated = result.structured().expect("typed receipt")["tool_selection"]["activated"]
        .as_array()
        .expect("activated array");
    assert!(activated.len() <= 3);
    assert!(activated
        .iter()
        .any(|entry| entry["name"] == "memory_search"));
}

#[test]
fn required_keyword_terms_gate_every_selected_canonical_name() {
    let fixture = Fixture::new();
    let result = fixture.search("+memory technical lessons", Some(5));
    assert!(
        !result.is_error(),
        "required-name search failed: {result:#?}"
    );
    let activated = result.structured().expect("typed receipt")["tool_selection"]["activated"]
        .as_array()
        .expect("activated array");
    assert!(!activated.is_empty());
    assert!(activated.iter().all(|entry| entry["name"]
        .as_str()
        .is_some_and(|name| name.contains("memory"))));
}

#[test]
fn keyword_no_match_is_typed_unavailable_not_a_fake_success() {
    let fixture = Fixture::new();
    let result = fixture.search("xyzzy_completely_unrelated_marker", None);
    let (failure, code) = failure(&result);
    assert_eq!(code, ToolFailureCode::Unavailable);
    assert_eq!(
        failure
            .recovery
            .as_ref()
            .and_then(|value| value.get("query")),
        Some(&json!("xyzzy_completely_unrelated_marker"))
    );
}
