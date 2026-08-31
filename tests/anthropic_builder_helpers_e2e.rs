//! End-to-end tests for `providers::anthropic` builder helpers —
//! `build_system_blocks`, `build_system_blocks_from_string`,
//! `convert_messages_to_anthropic`, `convert_tools_to_anthropic`.
//!
//! Sprint 122 of the verification effort. Sprint 17
//! (`provider_transform_e2e`) covered the adapter trait
//! impls + response transforms; this file pins the bare
//! helper functions used by both the adapter and the
//! Anthropic-direct mode of the proxy.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::prompt::SystemPromptBlocks;
use openclaudia::providers::{
    build_system_blocks, build_system_blocks_from_string, convert_messages_to_anthropic,
    convert_tools_to_anthropic,
};
use serde_json::json;

fn typed_blocks(prefix: &str, suffix: &str) -> SystemPromptBlocks {
    let mut items = Vec::new();
    if !prefix.is_empty() {
        items.push(openclaudia::context::ContextItem::host_instruction(
            "test.stable",
            openclaudia::context::HostInstructionSource::CorePolicy,
            "compiled:test",
            prefix,
            openclaudia::context::ContextFreshness::Static,
            1,
        ));
    }
    if !suffix.is_empty() {
        items.push(openclaudia::context::ContextItem::host_instruction(
            "test.dynamic",
            openclaudia::context::HostInstructionSource::RuntimePolicy,
            "host:test",
            suffix,
            openclaudia::context::ContextFreshness::Turn,
            2,
        ));
    }
    SystemPromptBlocks::from_items(items, openclaudia::context::ContextBudget::default())
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — build_system_blocks (SystemPromptBlocks → Anthropic array)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn build_blocks_with_only_stable_prefix_returns_single_block_with_cache_control() {
    let blocks = typed_blocks("Stable identity + tools", "");
    let result = build_system_blocks(&blocks);
    let arr = result.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["type"], "text");
    assert_eq!(arr[0]["text"], "Stable identity + tools");
    // PINS CACHE-CONTROL: stable prefix MUST have ephemeral.
    assert_eq!(arr[0]["cache_control"]["type"], "ephemeral");
}

#[test]
fn build_blocks_with_dynamic_suffix_returns_two_blocks() {
    let blocks = typed_blocks("stable", "dynamic");
    let result = build_system_blocks(&blocks);
    let arr = result.as_array().expect("array");
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["text"], "stable");
    assert_eq!(arr[1]["text"], "dynamic");
}

#[test]
fn build_blocks_dynamic_suffix_has_no_cache_control() {
    // PINS DOC: dynamic suffix changes per-turn → NOT cached.
    let blocks = typed_blocks("s", "d");
    let result = build_system_blocks(&blocks);
    let arr = result.as_array().expect("array");
    assert!(
        arr[1].get("cache_control").is_none(),
        "dynamic suffix MUST NOT have cache_control; got {arr:?}"
    );
}

#[test]
fn build_blocks_with_only_dynamic_context_emits_one_uncached_block() {
    let blocks = typed_blocks("", "only-dynamic");
    let result = build_system_blocks(&blocks);
    let arr = result.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["text"], "only-dynamic");
    assert!(arr[0].get("cache_control").is_none());
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — build_system_blocks_from_string (legacy single-string)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn build_from_string_returns_single_block_with_cache_control() {
    let result = build_system_blocks_from_string("You are a helpful assistant.");
    let arr = result.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["type"], "text");
    assert_eq!(arr[0]["text"], "You are a helpful assistant.");
    assert_eq!(arr[0]["cache_control"]["type"], "ephemeral");
}

#[test]
fn build_from_string_with_empty_input_still_emits_block() {
    let result = build_system_blocks_from_string("");
    let arr = result.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["text"], "");
}

#[test]
fn build_from_string_handles_multi_line_input_verbatim() {
    let input = "Line 1\nLine 2\n\nLine 4";
    let result = build_system_blocks_from_string(input);
    let arr = result.as_array().expect("array");
    assert_eq!(arr[0]["text"], input);
}

#[test]
fn build_from_string_handles_unicode_input() {
    let input = "日本語システムプロンプト 🎉";
    let result = build_system_blocks_from_string(input);
    let arr = result.as_array().expect("array");
    assert_eq!(arr[0]["text"], input);
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — convert_messages_to_anthropic (OpenAI → Anthropic)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn convert_messages_filters_system_messages() {
    let messages = vec![
        json!({"role": "system", "content": "You are helpful"}),
        json!({"role": "user", "content": "Hello"}),
    ];
    let converted = convert_messages_to_anthropic(&messages);
    // System filtered out → 1 message.
    assert_eq!(converted.len(), 1);
    assert_eq!(converted[0]["role"], "user");
}

#[test]
fn convert_messages_passes_user_messages_through() {
    let messages = vec![json!({"role": "user", "content": "Hello"})];
    let converted = convert_messages_to_anthropic(&messages);
    assert_eq!(converted.len(), 1);
    assert_eq!(converted[0]["role"], "user");
}

#[test]
fn convert_messages_passes_assistant_messages_through() {
    let messages = vec![json!({"role": "assistant", "content": "Response"})];
    let converted = convert_messages_to_anthropic(&messages);
    assert_eq!(converted.len(), 1);
    assert_eq!(converted[0]["role"], "assistant");
}

#[test]
fn convert_messages_tool_role_becomes_user_with_tool_result_block() {
    // PINS OPENAI→ANTHROPIC MAPPING: tool role → user role
    // with type: "tool_result" content block.
    let messages = vec![json!({
        "role": "tool",
        "tool_call_id": "call-123",
        "content": "result body"
    })];
    let converted = convert_messages_to_anthropic(&messages);
    assert_eq!(converted.len(), 1);
    assert_eq!(converted[0]["role"], "user");
    let content = converted[0]["content"].as_array().expect("array");
    assert_eq!(content[0]["type"], "tool_result");
    assert_eq!(content[0]["tool_use_id"], "call-123");
    assert_eq!(content[0]["content"], "result body");
}

#[test]
fn convert_messages_tool_result_with_is_error_true_preserves_field() {
    let messages = vec![json!({
        "role": "tool",
        "tool_call_id": "call-1",
        "content": "failure",
        "is_error": true
    })];
    let converted = convert_messages_to_anthropic(&messages);
    let content = converted[0]["content"].as_array().expect("array");
    assert_eq!(content[0]["is_error"], true);
}

#[test]
fn convert_messages_tool_result_without_is_error_omits_field() {
    let messages = vec![json!({
        "role": "tool",
        "tool_call_id": "call-1",
        "content": "ok"
    })];
    let converted = convert_messages_to_anthropic(&messages);
    let content = converted[0]["content"].as_array().expect("array");
    assert!(
        content[0].get("is_error").is_none(),
        "default false is_error MUST NOT be emitted; got {content:?}"
    );
}

#[test]
fn convert_messages_assistant_with_tool_calls_becomes_tool_use_blocks() {
    let messages = vec![json!({
        "role": "assistant",
        "content": "Let me check",
        "tool_calls": [{
            "id": "call-x",
            "type": "function",
            "function": {
                "name": "bash",
                "arguments": "{\"command\": \"ls\"}"
            }
        }]
    })];
    let converted = convert_messages_to_anthropic(&messages);
    assert_eq!(converted.len(), 1);
    let content = converted[0]["content"].as_array().expect("array");
    // First block: text. Second block: tool_use.
    assert_eq!(content[0]["type"], "text");
    assert_eq!(content[0]["text"], "Let me check");
    assert_eq!(content[1]["type"], "tool_use");
    assert_eq!(content[1]["id"], "call-x");
    assert_eq!(content[1]["name"], "bash");
    // PINS PARSE: arguments STRING parsed into JSON OBJECT
    // on Anthropic side (input field).
    assert_eq!(content[1]["input"]["command"], "ls");
}

#[test]
fn convert_messages_assistant_tool_calls_with_null_content_omits_null_text() {
    let messages = vec![json!({
        "role": "assistant",
        "content": null,
        "tool_calls": [{
            "id": "call-null-content",
            "type": "function",
            "function": {
                "name": "bash",
                "arguments": "{\"command\":\"pwd\"}"
            }
        }]
    })];
    let converted = convert_messages_to_anthropic(&messages);
    assert_eq!(converted.len(), 1);
    let content = converted[0]["content"].as_array().expect("array");
    assert_eq!(
        content.len(),
        1,
        "null content must not become a text block"
    );
    assert_eq!(content[0]["type"], "tool_use");
    assert_eq!(content[0]["id"], "call-null-content");
    assert_eq!(content[0]["name"], "bash");
    assert_eq!(content[0]["input"]["command"], "pwd");
    assert!(
        content.iter().all(|block| block["type"] != "text"),
        "tool-call-only assistant message must not emit content:null or empty text: {content:?}"
    );
}

#[test]
fn convert_messages_assistant_with_empty_tool_calls_array_still_works() {
    let messages = vec![json!({
        "role": "assistant",
        "content": "text only",
        "tool_calls": []
    })];
    let converted = convert_messages_to_anthropic(&messages);
    assert_eq!(converted.len(), 1);
    let content = converted[0]["content"].as_array().expect("array");
    // Has the text block (no tool_use blocks).
    assert!(content
        .iter()
        .any(|b| b["type"] == "text" && b["text"] == "text only"));
}

#[test]
fn convert_messages_assistant_with_unparseable_args_falls_back_to_empty_object() {
    let messages = vec![json!({
        "role": "assistant",
        "tool_calls": [{
            "id": "x",
            "function": {"name": "tool", "arguments": "not valid json {{"}
        }]
    })];
    let converted = convert_messages_to_anthropic(&messages);
    let content = converted[0]["content"].as_array().expect("array");
    // PINS RESILIENCE: bad arguments → input = {}
    let tool_use = content
        .iter()
        .find(|b| b["type"] == "tool_use")
        .expect("present");
    assert_eq!(tool_use["input"], json!({}));
}

#[test]
fn convert_messages_empty_slice_returns_empty_vec() {
    let converted = convert_messages_to_anthropic(&[]);
    assert!(converted.is_empty());
}

#[test]
fn convert_messages_all_system_messages_returns_empty_vec() {
    let messages = vec![
        json!({"role": "system", "content": "a"}),
        json!({"role": "system", "content": "b"}),
    ];
    let converted = convert_messages_to_anthropic(&messages);
    assert!(converted.is_empty());
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — convert_tools_to_anthropic
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn convert_tools_openai_format_to_anthropic_format() {
    let tools = vec![json!({
        "type": "function",
        "function": {
            "name": "bash",
            "description": "Run a shell command",
            "parameters": {
                "type": "object",
                "properties": {"command": {"type": "string"}}
            }
        }
    })];
    let converted = convert_tools_to_anthropic(&tools);
    assert_eq!(converted.len(), 1);
    // PINS FORMAT: Anthropic tools have name/description/
    // input_schema at top level (no "function" wrapper).
    assert_eq!(converted[0]["name"], "bash");
    assert_eq!(converted[0]["description"], "Run a shell command");
    assert_eq!(converted[0]["input_schema"]["type"], "object");
}

#[test]
fn convert_tools_simplifies_top_level_schema_combinators_for_anthropic() {
    let tools = vec![json!({
        "type": "function",
        "function": {
            "name": "delete_thing",
            "description": "Delete by one identifier",
            "parameters": {
                "anyOf": [
                    {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"}
                        },
                        "required": ["name"]
                    },
                    {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"}
                        },
                        "required": ["id"]
                    }
                ]
            }
        }
    })];

    let converted = convert_tools_to_anthropic(&tools);
    let schema = &converted[0]["input_schema"];
    assert_eq!(schema["type"], "object");
    assert!(
        schema.get("anyOf").is_none(),
        "Anthropic rejects top-level anyOf in input_schema: {schema:?}"
    );
    assert!(schema["properties"].get("name").is_some());
    assert!(schema["properties"].get("id").is_some());
    assert!(
        schema["description"]
            .as_str()
            .is_some_and(|desc| desc.contains("Anthropic compatibility note")),
        "simplified schema should explain that runtime validation owns exact semantics: {schema:?}"
    );
}

#[test]
fn convert_tools_empty_slice_returns_empty_vec() {
    let converted = convert_tools_to_anthropic(&[]);
    assert!(converted.is_empty());
}

#[test]
fn convert_tools_multi_tool_preserves_count() {
    let tools = vec![
        json!({"type": "function", "function": {"name": "a", "parameters": {}}}),
        json!({"type": "function", "function": {"name": "b", "parameters": {}}}),
        json!({"type": "function", "function": {"name": "c", "parameters": {}}}),
    ];
    let converted = convert_tools_to_anthropic(&tools);
    assert_eq!(converted.len(), 3);
}
