//! End-to-end tests for the core tool execution surface.
//!
//! Sprint 2 of the verification effort. Focus areas:
//!
//! - **Streaming tool-call accumulator** (`ToolCallAccumulator` and
//!   `AnthropicToolAccumulator`) — both had zero tests. Driven through
//!   realistic multi-chunk streaming sequences with proptest-generated
//!   chunk-boundary perturbations.
//! - **Task tool surface** (`execute_task_create` / `_update` / `_get` /
//!   `_list`) — also zero tests, even though `TaskManager` itself has
//!   25+. The execute_* layer's argument parsing, error rendering, and
//!   integration with the task manager are tested separately here.
//! - **Bash background-shell execution** — real subprocess execution
//!   against the live `BackgroundShellManager`, with timing-aware
//!   assertions about output capture, kill semantics, and stall
//!   detection.
//! - **File-tools end-to-end** — real tempdir, real reads/writes/edits,
//!   path-traversal defences, symlink-following defences, and the
//!   read-before-write gate (`READ_TRACKER`).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::print_stdout)]
#![allow(clippy::print_stderr)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::{AnthropicToolAccumulator, ToolCallAccumulator};
use proptest::prelude::*;
use serde_json::{json, Value};

// ───────────────────────────────────────────────────────────────────────────
// Section A — ToolCallAccumulator (OpenAI-format streaming)
// ───────────────────────────────────────────────────────────────────────────

/// Single-chunk delta with everything in one event. The simplest path.
#[test]
fn accumulator_handles_single_complete_chunk() {
    let mut acc = ToolCallAccumulator::new();
    acc.process_delta(&json!({
        "tool_calls": [{
            "index": 0,
            "id": "call_1",
            "type": "function",
            "function": {
                "name": "echo",
                "arguments": "{\"text\":\"hi\"}"
            }
        }]
    }));
    let finalized = acc.finalize();
    assert_eq!(finalized.len(), 1);
    assert_eq!(finalized[0].id, "call_1");
    assert_eq!(finalized[0].function.name, "echo");
    assert_eq!(finalized[0].function.arguments, "{\"text\":\"hi\"}");
}

/// Multi-chunk streaming: the `function.arguments` field arrives in
/// pieces, and the accumulator must concatenate them in order.
#[test]
fn accumulator_concatenates_argument_chunks_in_order() {
    let mut acc = ToolCallAccumulator::new();
    let chunks = [
        json!({"tool_calls":[{"index":0,"id":"call_1","type":"function",
            "function":{"name":"echo","arguments":"{\"text\":\""}}]}),
        json!({"tool_calls":[{"index":0,
            "function":{"arguments":"hel"}}]}),
        json!({"tool_calls":[{"index":0,
            "function":{"arguments":"lo\"}"}}]}),
    ];
    for c in &chunks {
        acc.process_delta(c);
    }
    let finalized = acc.finalize();
    assert_eq!(finalized.len(), 1);
    assert_eq!(finalized[0].function.arguments, "{\"text\":\"hello\"}");
}

/// Two parallel tool calls at distinct indices must remain separated.
#[test]
fn accumulator_keeps_parallel_tool_calls_separated() {
    let mut acc = ToolCallAccumulator::new();
    acc.process_delta(&json!({
        "tool_calls":[
            {"index":0,"id":"a","type":"function","function":{"name":"first","arguments":"{}"}},
            {"index":1,"id":"b","type":"function","function":{"name":"second","arguments":"[]"}}
        ]
    }));
    let finalized = acc.finalize();
    assert_eq!(finalized.len(), 2);
    let names: Vec<&str> = finalized.iter().map(|t| t.function.name.as_str()).collect();
    assert!(names.contains(&"first"));
    assert!(names.contains(&"second"));
}

/// Out-of-order index arrival (index=1 before index=0) must still work:
/// the accumulator grows the slot vec on demand.
#[test]
fn accumulator_handles_out_of_order_indices() {
    let mut acc = ToolCallAccumulator::new();
    // index=2 arrives first; slots 0 and 1 are implicit "padding".
    acc.process_delta(&json!({
        "tool_calls":[{"index":2,"id":"third","type":"function",
            "function":{"name":"third_fn","arguments":"{}"}}]
    }));
    acc.process_delta(&json!({
        "tool_calls":[{"index":0,"id":"first","type":"function",
            "function":{"name":"first_fn","arguments":"{}"}}]
    }));
    let finalized = acc.finalize();
    // Only entries with non-empty id+name are kept — the index=1 padding
    // slot stays empty and is filtered out.
    assert_eq!(finalized.len(), 2);
    let ids: Vec<&str> = finalized.iter().map(|t| t.id.as_str()).collect();
    assert!(ids.contains(&"first"));
    assert!(ids.contains(&"third"));
}

#[test]
fn accumulator_filters_empty_partials_on_finalize() {
    let mut acc = ToolCallAccumulator::new();
    // id arrives but name does not — this partial must be filtered.
    acc.process_delta(&json!({
        "tool_calls":[{"index":0,"id":"orphan"}]
    }));
    let finalized = acc.finalize();
    assert!(
        finalized.is_empty(),
        "partial with no function.name must be filtered, got {finalized:?}"
    );
    // has_tool_calls should remain false because id-only partials cannot
    // finalize into executable tool calls.
    assert!(!acc.has_tool_calls());
}

#[test]
fn accumulator_default_call_type_is_function() {
    // OpenAI streaming sometimes omits `type` on the first delta and
    // sets it on a later one. If it never arrives, the default must be
    // "function" (per OpenAI spec).
    let mut acc = ToolCallAccumulator::new();
    acc.process_delta(&json!({
        "tool_calls":[{"index":0,"id":"x","function":{"name":"f","arguments":""}}]
    }));
    let finalized = acc.finalize();
    assert_eq!(finalized[0].call_type, "function");
}

#[test]
fn accumulator_empty_arguments_finalize_as_empty_object() {
    let mut acc = ToolCallAccumulator::new();
    acc.process_delta(&json!({
        "tool_calls":[{"index":0,"id":"x","function":{"name":"todo_read","arguments":""}}]
    }));

    let finalized = acc.finalize();

    assert_eq!(finalized[0].function.arguments, "{}");
}

#[test]
fn accumulator_clear_resets_state_fully() {
    let mut acc = ToolCallAccumulator::new();
    acc.process_delta(&json!({
        "tool_calls":[{"index":0,"id":"x","type":"function","function":{"name":"f","arguments":"{}"}}]
    }));
    assert!(acc.has_tool_calls());
    acc.clear();
    assert!(!acc.has_tool_calls());
    assert!(acc.finalize().is_empty());
}

#[test]
fn accumulator_handles_missing_tool_calls_field() {
    // Many SSE deltas have only `content` (text-only response). They must
    // pass through cleanly without polluting the accumulator.
    let mut acc = ToolCallAccumulator::new();
    acc.process_delta(&json!({"content": "hello"}));
    acc.process_delta(&json!({}));
    assert!(!acc.has_tool_calls());
    assert!(acc.finalize().is_empty());
}

#[test]
fn accumulator_drops_deltas_past_parallel_slot_cap() {
    // A maliciously-large `index` on a streaming delta MUST NOT cause
    // the accumulator to pre-allocate slots up to that index. The
    // earlier revision of this test triggered a ~400 GiB allocation
    // attempt (index=u32::MAX × ~96-byte PartialToolCall = 400 GiB),
    // which got the test binary OOM-killed mid-run. The production
    // fix is `MAX_PARALLEL_TOOL_CALL_SLOTS = 512` in accumulator.rs;
    // this test pins both the cap behaviour AND the
    // smaller-than-cap path still working.
    //
    // We import the public cap so a future bump to the cap is caught
    // by a one-line edit here (the test fails until the assertion is
    // updated).
    use openclaudia::tools::MAX_PARALLEL_TOOL_CALL_SLOTS;

    // 1. Past the cap → silently dropped (the warn fires; the
    //    accumulator stays empty).
    let mut acc = ToolCallAccumulator::new();
    let past_cap = u64::try_from(MAX_PARALLEL_TOOL_CALL_SLOTS).unwrap();
    acc.process_delta(&json!({
        "tool_calls":[{"index": past_cap,
            "id":"x","type":"function",
            "function":{"name":"f","arguments":"{}"}}]
    }));
    assert!(
        acc.tool_calls.is_empty(),
        "index >= cap must NOT allocate any slot, got {} slots",
        acc.tool_calls.len(),
    );
    assert!(
        acc.finalize().is_empty(),
        "finalize must yield no calls when every delta was dropped"
    );

    // 2. Equal to cap-1 → admitted, allocates exactly cap slots
    //    (cap-1 indexed → vec length cap).
    let mut acc2 = ToolCallAccumulator::new();
    let last_valid = u64::try_from(MAX_PARALLEL_TOOL_CALL_SLOTS - 1).unwrap();
    acc2.process_delta(&json!({
        "tool_calls":[{"index": last_valid,
            "id":"y","type":"function",
            "function":{"name":"g","arguments":"{}"}}]
    }));
    assert_eq!(
        acc2.tool_calls.len(),
        MAX_PARALLEL_TOOL_CALL_SLOTS,
        "index == cap-1 must allocate exactly cap slots"
    );
    let finalized = acc2.finalize();
    assert_eq!(finalized.len(), 1, "the one real call must survive");
    assert_eq!(finalized[0].id, "y");

    // 3. Truly-evil u32::MAX → dropped, NO allocation.
    //    This is the exact value that previously OOM-killed the runner.
    let mut acc3 = ToolCallAccumulator::new();
    acc3.process_delta(&json!({
        "tool_calls":[{"index": u64::from(u32::MAX),
            "id":"z","type":"function",
            "function":{"name":"h","arguments":"{}"}}]
    }));
    assert!(
        acc3.tool_calls.is_empty(),
        "u32::MAX index must be dropped, not allocate; got {} slots",
        acc3.tool_calls.len(),
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — AnthropicToolAccumulator (SSE event sequence)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn anthropic_acc_text_only_message_collects_text() {
    let mut acc = AnthropicToolAccumulator::new();
    acc.process_event(&json!({
        "type": "content_block_start",
        "index": 0,
        "content_block": {"type": "text", "text": ""}
    }));
    let printed = acc.process_event(&json!({
        "type": "content_block_delta",
        "index": 0,
        "delta": {"type": "text_delta", "text": "hello "}
    }));
    assert_eq!(printed.as_deref(), Some("hello "));
    let printed = acc.process_event(&json!({
        "type": "content_block_delta",
        "index": 0,
        "delta": {"type": "text_delta", "text": "world"}
    }));
    assert_eq!(printed.as_deref(), Some("world"));
    assert_eq!(acc.get_text(), "hello world");
    assert!(
        !acc.has_tool_use(),
        "text-only message must not flag tool_use"
    );
}

#[test]
fn anthropic_acc_tool_use_block_assembles_input_json() {
    let mut acc = AnthropicToolAccumulator::new();
    acc.process_event(&json!({
        "type": "content_block_start",
        "index": 0,
        "content_block": {"type": "tool_use", "id": "tu_1", "name": "bash"}
    }));
    // Streaming JSON delta in three chunks split at non-token boundaries
    // — the accumulator must concatenate them byte-for-byte without any
    // JSON-aware tokenisation, because at this point the JSON is
    // half-formed and parsing would error.
    for chunk in ["{\"comm", "and\":\"l", "s -la\"}"] {
        acc.process_event(&json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "input_json_delta", "partial_json": chunk}
        }));
    }
    acc.process_event(&json!({"type": "content_block_stop", "index": 0}));
    acc.process_event(&json!({
        "type": "message_delta",
        "delta": {"stop_reason": "tool_use"}
    }));
    assert!(acc.has_tool_use());
    let tool_calls = acc.finalize_tool_calls();
    assert_eq!(tool_calls.len(), 1);
    assert_eq!(tool_calls[0].id, "tu_1");
    assert_eq!(tool_calls[0].function.name, "bash");
    assert_eq!(tool_calls[0].function.arguments, "{\"command\":\"ls -la\"}");
}

#[test]
fn anthropic_acc_no_input_json_finalizes_as_empty_object() {
    let mut acc = AnthropicToolAccumulator::new();
    acc.process_event(&json!({
        "type": "content_block_start",
        "index": 0,
        "content_block": {"type": "tool_use", "id": "tu_empty", "name": "todo_read"}
    }));
    acc.process_event(&json!({"type": "content_block_stop", "index": 0}));
    acc.process_event(&json!({
        "type": "message_delta",
        "delta": {"stop_reason": "tool_use"}
    }));

    let tool_calls = acc.finalize_tool_calls();
    let openai_json = acc.to_openai_tool_calls_json();

    assert_eq!(tool_calls[0].function.arguments, "{}");
    assert_eq!(openai_json[0]["function"]["arguments"], "{}");
}

#[test]
fn anthropic_acc_mixed_text_and_tool_use_blocks() {
    let mut acc = AnthropicToolAccumulator::new();
    // Block 0: text "Sure, let me run that:"
    acc.process_event(&json!({
        "type": "content_block_start", "index": 0,
        "content_block": {"type": "text", "text": ""}
    }));
    acc.process_event(&json!({
        "type": "content_block_delta", "index": 0,
        "delta": {"type": "text_delta", "text": "Sure, let me run that:"}
    }));
    // Block 1: tool_use bash
    acc.process_event(&json!({
        "type": "content_block_start", "index": 1,
        "content_block": {"type": "tool_use", "id": "tu_2", "name": "bash"}
    }));
    acc.process_event(&json!({
        "type": "content_block_delta", "index": 1,
        "delta": {"type": "input_json_delta", "partial_json": "{\"command\":\"echo hi\"}"}
    }));
    acc.process_event(&json!({
        "type": "message_delta",
        "delta": {"stop_reason": "tool_use"}
    }));
    assert!(acc.has_tool_use());
    assert_eq!(acc.get_text(), "Sure, let me run that:");
    let tools = acc.finalize_tool_calls();
    assert_eq!(tools.len(), 1);
    let openai_json = acc.to_openai_tool_calls_json();
    assert_eq!(openai_json.len(), 1);
    assert_eq!(
        openai_json[0].get("id").and_then(Value::as_str),
        Some("tu_2")
    );
    assert_eq!(
        openai_json[0]
            .get("function")
            .and_then(|f| f.get("name"))
            .and_then(Value::as_str),
        Some("bash")
    );
}

#[test]
fn anthropic_acc_unknown_event_type_is_ignored() {
    let mut acc = AnthropicToolAccumulator::new();
    let printed = acc.process_event(&json!({
        "type": "ping", "value": 42
    }));
    assert!(
        printed.is_none(),
        "unknown event type must not produce text"
    );
    assert!(
        acc.blocks.is_empty(),
        "no blocks created from unknown event"
    );
}

#[test]
fn anthropic_acc_has_tool_use_requires_both_stop_reason_and_block() {
    let mut acc = AnthropicToolAccumulator::new();
    // Stop reason without a tool_use block → false.
    acc.process_event(&json!({
        "type": "message_delta",
        "delta": {"stop_reason": "tool_use"}
    }));
    assert!(
        !acc.has_tool_use(),
        "stop_reason alone, no block, must not flag has_tool_use"
    );
    // tool_use block without stop_reason=tool_use → false.
    acc.clear();
    acc.process_event(&json!({
        "type": "content_block_start", "index": 0,
        "content_block": {"type": "tool_use", "id": "x", "name": "f"}
    }));
    assert!(
        !acc.has_tool_use(),
        "block alone, no matching stop_reason, must not flag has_tool_use"
    );
}

#[test]
fn anthropic_acc_clear_resets_blocks_and_stop_reason() {
    let mut acc = AnthropicToolAccumulator::new();
    acc.process_event(&json!({
        "type": "content_block_start", "index": 0,
        "content_block": {"type": "text", "text": ""}
    }));
    acc.process_event(&json!({
        "type": "content_block_delta", "index": 0,
        "delta": {"type": "text_delta", "text": "hi"}
    }));
    acc.process_event(&json!({
        "type": "message_delta",
        "delta": {"stop_reason": "end_turn"}
    }));
    assert!(!acc.blocks.is_empty());
    assert!(acc.stop_reason.is_some());
    acc.clear();
    assert!(acc.blocks.is_empty());
    assert!(acc.stop_reason.is_none());
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — proptest: streaming chunk boundaries
// ───────────────────────────────────────────────────────────────────────────

proptest! {
    /// Property: splitting a complete tool-call's argument string at any
    /// chunk boundary must produce the same final result. This is the
    /// streaming invariant the accumulator exists to guarantee.
    #[test]
    fn arguments_concatenation_is_chunk_boundary_invariant(
        args in "[{}\\[\\]a-zA-Z0-9:\",.\\s]{0,256}",
        split_at in 0usize..256,
    ) {
        // The regex `\s` matches multi-byte whitespace (U+1680 Ogham
        // space, U+3000 Ideographic space, etc.). split_at(byte_index)
        // panics if the index is not a char boundary, so walk forward
        // to the next boundary first.
        let mut split = split_at.min(args.len());
        while split < args.len() && !args.is_char_boundary(split) {
            split += 1;
        }
        let (head, tail) = args.split_at(split);

        let mut acc1 = ToolCallAccumulator::new();
        acc1.process_delta(&json!({
            "tool_calls":[{"index":0,"id":"c1","type":"function",
                "function":{"name":"f","arguments":args.clone()}}]
        }));
        let one_shot = acc1.finalize();

        let mut acc2 = ToolCallAccumulator::new();
        acc2.process_delta(&json!({
            "tool_calls":[{"index":0,"id":"c1","type":"function",
                "function":{"name":"f","arguments":head}}]
        }));
        acc2.process_delta(&json!({
            "tool_calls":[{"index":0,
                "function":{"arguments":tail}}]
        }));
        let chunked = acc2.finalize();

        prop_assert_eq!(one_shot.len(), chunked.len());
        prop_assert_eq!(
            &one_shot[0].function.arguments,
            &chunked[0].function.arguments,
        );
    }

    /// Property: the AnthropicToolAccumulator's input_json must also be
    /// chunk-boundary-invariant.
    #[test]
    fn anthropic_input_json_chunking_is_invariant(
        json_text in "[{}\\[\\]a-zA-Z0-9:\",.\\s]{0,128}",
        boundaries in proptest::collection::vec(0usize..128, 1..=5),
    ) {
        // Build a single-event reference.
        let mut single = AnthropicToolAccumulator::new();
        single.process_event(&json!({
            "type": "content_block_start", "index": 0,
            "content_block": {"type": "tool_use", "id": "t", "name": "f"}
        }));
        single.process_event(&json!({
            "type": "content_block_delta", "index": 0,
            "delta": {"type": "input_json_delta", "partial_json": json_text.as_str()}
        }));

        // Build a chunked version splitting at every boundary in order.
        let mut chunked = AnthropicToolAccumulator::new();
        chunked.process_event(&json!({
            "type": "content_block_start", "index": 0,
            "content_block": {"type": "tool_use", "id": "t", "name": "f"}
        }));
        let mut remaining = json_text.as_str();
        let mut sorted = boundaries;
        sorted.sort_unstable();
        for b in sorted {
            let b = b.min(remaining.len());
            // Walk to the next char boundary so we don't slice mid-codepoint.
            let mut adj = b;
            while adj < remaining.len() && !remaining.is_char_boundary(adj) {
                adj += 1;
            }
            let (head, rest) = remaining.split_at(adj);
            if !head.is_empty() {
                chunked.process_event(&json!({
                    "type": "content_block_delta", "index": 0,
                    "delta": {"type": "input_json_delta", "partial_json": head}
                }));
            }
            remaining = rest;
        }
        if !remaining.is_empty() {
            chunked.process_event(&json!({
                "type": "content_block_delta", "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": remaining}
            }));
        }

        // Compare via finalize_tool_calls to use the public surface.
        let single_finalized = single.finalize_tool_calls();
        let chunked_finalized = chunked.finalize_tool_calls();
        prop_assert_eq!(single_finalized.len(), chunked_finalized.len());
        if !single_finalized.is_empty() {
            prop_assert_eq!(
                &single_finalized[0].function.arguments,
                &chunked_finalized[0].function.arguments,
            );
        }
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Task tool surface (execute_task_create / _update / _get / _list)
// ───────────────────────────────────────────────────────────────────────────

use openclaudia::session::TaskManager;
use openclaudia::tools::task::{
    execute_task_create, execute_task_get, execute_task_list, execute_task_update,
};
use std::collections::HashMap;

fn args_from(pairs: &[(&str, Value)]) -> HashMap<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect()
}

#[test]
fn task_create_assigns_increasing_ids() {
    let mut mgr = TaskManager::new();
    let a = execute_task_create(
        &args_from(&[
            ("expected_generation", json!(0)),
            ("subject", json!("first")),
            ("description", json!("first body")),
        ]),
        &mut mgr,
    );
    let b = execute_task_create(
        &args_from(&[
            ("expected_generation", json!(1)),
            ("subject", json!("second")),
            ("description", json!("second body")),
        ]),
        &mut mgr,
    );
    assert!(!a.1, "first create must succeed: {}", a.0);
    assert!(!b.1, "second create must succeed: {}", b.0);
    // Output contains the assigned id; the IDs increment.
    assert!(a.0.contains("task-1"), "expected task-1 in {}", a.0);
    assert!(b.0.contains("task-2"), "expected task-2 in {}", b.0);
}

#[test]
fn task_create_with_missing_subject_returns_error() {
    let mut mgr = TaskManager::new();
    let (msg, is_err) = execute_task_create(
        &args_from(&[("description", json!("orphan body"))]),
        &mut mgr,
    );
    assert!(is_err, "missing subject must error: {msg}");
}

#[test]
fn task_update_status_round_trips_through_get() {
    let mut mgr = TaskManager::new();
    let (created, _) = execute_task_create(
        &args_from(&[
            ("expected_generation", json!(0)),
            ("subject", json!("update me")),
            ("description", json!("body")),
        ]),
        &mut mgr,
    );
    // Pull the id out of the create output.
    let id = created.find("task-").map_or_else(
        || "task-1".to_string(),
        |idx| {
            created[idx..]
                .split(|c: char| !c.is_alphanumeric() && c != '-')
                .next()
                .unwrap_or("task-1")
                .to_string()
        },
    );

    let (upd_msg, is_err) = execute_task_update(
        &args_from(&[
            ("task_id", json!(id)),
            ("expected_generation", json!(1)),
            ("expected_task_revision", json!(1)),
            ("status", json!("in_progress")),
        ]),
        &mut mgr,
    );
    assert!(!is_err, "status update must succeed: {upd_msg}");

    // After the update, re-derive the id and look it up. We pass a literal
    // here since the create output is deterministic (task-1 for first call
    // in a fresh manager) — and this also exercises that path.
    let (got, _) = execute_task_get(&args_from(&[("task_id", json!("task-1"))]), &mut mgr);
    assert!(
        got.contains("in_progress") || got.contains("InProgress"),
        "get must report the new status, got: {got}"
    );
}

#[test]
fn task_list_returns_all_created_tasks() {
    let mut mgr = TaskManager::new();
    for i in 1..=3 {
        execute_task_create(
            &args_from(&[
                ("expected_generation", json!(i - 1)),
                ("subject", json!(format!("task {i}"))),
                ("description", json!(format!("body {i}"))),
            ]),
            &mut mgr,
        );
    }
    let (listing, is_err) = execute_task_list(&HashMap::new(), &mut mgr);
    assert!(!is_err, "list must succeed: {listing}");
    for i in 1..=3 {
        let id = format!("task-{i}");
        assert!(
            listing.contains(&id),
            "list output must include {id}, got: {listing}"
        );
    }
}

#[test]
fn task_get_unknown_id_returns_error_message() {
    let mut mgr = TaskManager::new();
    let (got, _) = execute_task_get(&args_from(&[("task_id", json!("task-9999"))]), &mut mgr);
    // execute_task_get is documented to return null on not-found (per
    // #588) — verify either the null shape OR an explicit not-found
    // message; what we will NOT tolerate is a panic or a value pretending
    // the task existed.
    assert!(
        got.contains("null") || got.to_lowercase().contains("not found") || got == "null",
        "unknown id must return null or a not-found marker, got: {got}"
    );
}
