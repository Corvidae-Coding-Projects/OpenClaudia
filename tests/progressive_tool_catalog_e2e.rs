//! Provider-shape and retrieval-quality checks for progressive tool discovery.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]

use std::collections::{BTreeSet, HashMap};

use openclaudia::pipeline::{build_request_for_wire_for_run, WireApi};
use openclaudia::runtime::ContentDigest;
use openclaudia::tools::catalog::{
    MAX_ACTIVE_SCHEMA_BYTES, MAX_ACTIVE_TOOLS, MAX_TOOL_SEARCH_RESULTS,
};
use openclaudia::tools::ToolRunContext;
use serde_json::{json, Value};

mod support;

fn names(values: &[Value], pointer: &str) -> BTreeSet<String> {
    values
        .iter()
        .map(|value| {
            value
                .pointer(pointer)
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("missing tool name at {pointer}: {value}"))
                .to_string()
        })
        .collect()
}

fn tool_named<'a>(values: &'a [Value], pointer: &str, name: &str) -> &'a Value {
    values
        .iter()
        .find(|value| value.pointer(pointer).and_then(Value::as_str) == Some(name))
        .unwrap_or_else(|| panic!("missing tool {name}"))
}

fn activate_exact_in_chunks(run: &ToolRunContext, generation: ContentDigest, names: &[String]) {
    for selection in names.chunks(MAX_TOOL_SEARCH_RESULTS) {
        let args = HashMap::from([
            (
                "query".to_string(),
                json!(format!("select:{}", selection.join(","))),
            ),
            (
                "catalog_generation".to_string(),
                json!(generation.to_string()),
            ),
            ("max_results".to_string(), json!(selection.len())),
        ]);
        run.tool_catalog()
            .activate(run, &args)
            .expect("small explicit selection must fit");
    }
}

#[test]
fn every_provider_request_shape_publishes_the_same_exact_progressive_set() {
    let root = tempfile::tempdir().expect("provider catalog root");
    let run = support::test_run_context(root.path());
    let messages = vec![json!({
        "role": "user",
        "content": "Retrieve technical lessons about this Rust codebase"
    })];
    let expected = openclaudia::tools::get_progressive_tool_definitions(&run, &messages, true)
        .expect("expected snapshot");
    let expected_names: BTreeSet<String> = expected.active_names.iter().cloned().collect();

    let openai = build_request_for_wire_for_run(
        &run,
        WireApi::ChatCompletions,
        "openai",
        "gpt-5.5",
        &messages,
        "high",
        None,
        None,
    )
    .expect("OpenAI request");
    let openai_tools = openai["tools"].as_array().expect("OpenAI tools");
    assert_eq!(names(openai_tools, "/function/name"), expected_names);

    let responses = build_request_for_wire_for_run(
        &run,
        WireApi::OpenAiResponses,
        "openai",
        "gpt-5.5",
        &messages,
        "high",
        None,
        None,
    )
    .expect("Responses request");
    let responses_tools = responses["tools"].as_array().expect("Responses tools");
    assert_eq!(names(responses_tools, "/name"), expected_names);

    let anthropic = build_request_for_wire_for_run(
        &run,
        WireApi::ChatCompletions,
        "anthropic",
        "claude-sonnet-4-6",
        &messages,
        "high",
        None,
        None,
    )
    .expect("Anthropic request");
    let anthropic_tools = anthropic["tools"].as_array().expect("Anthropic tools");
    assert_eq!(names(anthropic_tools, "/name"), expected_names);

    let google = build_request_for_wire_for_run(
        &run,
        WireApi::ChatCompletions,
        "google",
        "gemini-3.5-pro",
        &messages,
        "high",
        None,
        None,
    )
    .expect("Gemini request");
    let google_tools = google
        .pointer("/tools/0/functionDeclarations")
        .and_then(Value::as_array)
        .expect("Gemini function declarations");
    assert_eq!(names(google_tools, "/name"), expected_names);

    let generation = expected.generation.to_string();
    assert_eq!(
        tool_named(openai_tools, "/function/name", "tool_search")
            .pointer("/function/parameters/properties/catalog_generation/enum"),
        Some(&json!([generation]))
    );
    assert_eq!(
        tool_named(responses_tools, "/name", "tool_search")
            .pointer("/parameters/properties/catalog_generation/enum"),
        Some(&json!([generation]))
    );
    assert_eq!(
        tool_named(anthropic_tools, "/name", "tool_search")
            .pointer("/input_schema/properties/catalog_generation/enum"),
        Some(&json!([generation]))
    );
    assert_eq!(
        tool_named(google_tools, "/name", "tool_search")
            .pointer("/parametersJsonSchema/properties/catalog_generation/enum"),
        Some(&json!([generation]))
    );
    assert!(
        tool_named(google_tools, "/name", "tool_search")
            .get("parameters")
            .is_none(),
        "Gemini must receive the current JSON Schema function-declaration field"
    );
}

#[test]
fn representative_tasks_recall_needed_tools_with_lower_schema_bytes() {
    let root = tempfile::tempdir().expect("recall catalog root");
    let run = support::test_run_context(root.path());
    let full = openclaudia::tools::get_all_tool_definitions(true);
    let full_schema_bytes = serde_json::to_vec(&full)
        .expect("serialize full catalog")
        .len();
    let scenarios: &[(&str, &[&str])] = &[
        (
            "Inspect a Rust source file, search for the bug, edit it, and run tests",
            &["read_file", "grep", "edit_file", "bash"],
        ),
        (
            "Retrieve technical lessons previously learned for this exact codebase",
            &["memory_search"],
        ),
        (
            "Launch a subagent to independently review this task",
            &["task"],
        ),
        (
            "Create a recurring schedule with a cron expression",
            &["cron_create"],
        ),
        (
            "Use language server code intelligence to go to definition",
            &["lsp"],
        ),
        (
            "List the available MCP resources from the connected integration",
            &["list_mcp_resources"],
        ),
        (
            "Load the user-authored skill named release-review",
            &["skill"],
        ),
    ];

    for (prompt, needed) in scenarios {
        let snapshot = openclaudia::tools::get_progressive_tool_definitions(
            &run,
            &[json!({"role": "user", "content": prompt})],
            true,
        )
        .unwrap_or_else(|error| panic!("catalog failed for {prompt:?}: {error}"));
        assert!(snapshot.active_names.len() <= MAX_ACTIVE_TOOLS);
        assert!(snapshot.active_names.len() <= 14);
        assert!(snapshot.schema_bytes <= MAX_ACTIVE_SCHEMA_BYTES);
        assert!(
            snapshot.schema_bytes.saturating_mul(2) < full_schema_bytes,
            "progressive catalog did not reduce schema bytes by at least 50% for {prompt:?}"
        );
        for name in *needed {
            assert!(
                snapshot.active_names.iter().any(|active| active == name),
                "needed tool {name} was not recalled for {prompt:?}; active={:?}",
                snapshot.active_names
            );
        }
    }
}

#[test]
fn progressive_publication_is_deterministic_for_identical_inputs() {
    let root = tempfile::tempdir().expect("deterministic catalog root");
    let run = support::test_run_context(root.path());
    let messages = [json!({
        "role": "user",
        "content": "Retrieve technical lessons for this codebase"
    })];
    let first = openclaudia::tools::get_progressive_tool_definitions(&run, &messages, true)
        .expect("first snapshot");
    let second = openclaudia::tools::get_progressive_tool_definitions(&run, &messages, true)
        .expect("second snapshot");
    assert_eq!(first.generation, second.generation);
    assert_eq!(first.active_names, second.active_names);
    assert_eq!(first.definitions, second.definitions);
    assert_eq!(first.schema_bytes, second.schema_bytes);
}

#[test]
fn historical_tool_continuity_cannot_crowd_out_the_current_task() {
    let root = tempfile::tempdir().expect("history catalog root");
    let run = support::test_run_context(root.path());
    let bootstrap = [
        "tool_search",
        "read_file",
        "grep",
        "glob",
        "bash",
        "edit_file",
        "write_file",
        "ask_user_question",
        "memory_search",
    ];
    let historical = openclaudia::tools::get_all_tool_definitions(true)
        .as_array()
        .expect("full catalog")
        .iter()
        .filter_map(|definition| definition.pointer("/function/name").and_then(Value::as_str))
        .filter(|name| !bootstrap.contains(name))
        .take(16)
        .enumerate()
        .map(|(index, name)| {
            json!({
                "id": format!("history-{index}"),
                "type": "function",
                "function": {"name": name, "arguments": "{}"}
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(historical.len(), 16);
    let messages = [
        json!({"role": "assistant", "content": "", "tool_calls": historical}),
        json!({
            "role": "user",
            "content": "Retrieve technical lessons previously learned for this exact codebase"
        }),
    ];
    let snapshot = openclaudia::tools::get_progressive_tool_definitions(&run, &messages, true)
        .expect("history-aware snapshot");
    assert!(snapshot
        .active_names
        .iter()
        .any(|name| name == "memory_search"));
}

#[test]
fn current_task_recall_precedes_stale_history_at_the_explicit_selection_cap() {
    let root = tempfile::tempdir().expect("priority catalog root");
    let run = support::test_run_context(root.path());
    let definitions = openclaudia::tools::get_all_tool_definitions(true)
        .as_array()
        .expect("full catalog")
        .clone();
    let first = run
        .tool_catalog()
        .snapshot(
            &run,
            &[json!({"role": "user", "content": "inspect source"})],
            &definitions,
        )
        .expect("initial snapshot");
    let bootstrap = [
        "tool_search",
        "read_file",
        "grep",
        "glob",
        "bash",
        "edit_file",
        "write_file",
        "ask_user_question",
        "memory_search",
    ];
    let mut candidates = definitions
        .iter()
        .filter_map(|definition| {
            let name = definition.pointer("/function/name")?.as_str()?;
            (!bootstrap.contains(&name)).then(|| {
                (
                    serde_json::to_vec(definition)
                        .expect("serialize candidate schema")
                        .len(),
                    name.to_string(),
                )
            })
        })
        .collect::<Vec<_>>();
    candidates.sort();
    let explicit = candidates
        .iter()
        .take(openclaudia::tools::catalog::MAX_EXPLICIT_ACTIVE_TOOLS)
        .map(|(_, name)| name.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        explicit.len(),
        openclaudia::tools::catalog::MAX_EXPLICIT_ACTIVE_TOOLS
    );
    activate_exact_in_chunks(&run, first.generation, &explicit);

    let historical = candidates
        .iter()
        .skip(explicit.len())
        .take(6)
        .enumerate()
        .map(|(index, (_, name))| {
            json!({
                "id": format!("stale-history-{index}"),
                "type": "function",
                "function": {"name": name, "arguments": "{}"}
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(historical.len(), 6);
    let snapshot = run
        .tool_catalog()
        .snapshot(
            &run,
            &[
                json!({"role": "assistant", "content": "", "tool_calls": historical}),
                json!({
                    "role": "user",
                    "content": "Retrieve technical lessons previously learned for this exact codebase"
                }),
            ],
            &definitions,
        )
        .expect("priority snapshot");
    for name in explicit {
        assert!(
            snapshot.active_names.contains(&name),
            "missing lease {name}"
        );
    }
    assert!(
        snapshot
            .active_names
            .iter()
            .any(|name| name == "memory_search"),
        "stale history crowded out current task recall: {:?}",
        snapshot.active_names
    );
}
