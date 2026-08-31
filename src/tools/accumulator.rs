use super::{FunctionCall, ToolCall};
use serde_json::Value;

fn normalized_tool_arguments(arguments: &str) -> String {
    if arguments.trim().is_empty() {
        "{}".to_string()
    } else {
        arguments.to_string()
    }
}

/// Hard cap on parallel tool-call slots in a single streaming response.
///
/// The `OpenAI` Chat Completions API supports parallel tool calls keyed by
/// an `index` field on each streaming delta. The accumulator grows its
/// per-call slot vector to accommodate the highest `index` it observes.
/// Without a cap, an attacker-controlled (or buggy) upstream that emits
/// a delta with `"index": <huge>` would force the accumulator to
/// pre-allocate `<huge>` `PartialToolCall` slots — each ~96 bytes —
/// trivially exceeding host memory.
///
/// 512 is far more than any real model emits in one turn (`OpenAI`'s own
/// documented max parallel-call limit is in the low tens) and bounds
/// the worst-case allocation to ~48 KiB. Deltas with an out-of-bounds
/// index are silently dropped — the upstream-protocol surface has no
/// concept of "rejected slot," and the alternative is to error every
/// caller of the entire turn. A `tracing::warn!` lets operators see
/// when the cap actually fires.
pub const MAX_PARALLEL_TOOL_CALL_SLOTS: usize = 512;

/// Parse tool calls from a streaming response delta
/// Returns accumulated tool calls when complete
#[derive(Default, Debug)]
pub struct ToolCallAccumulator {
    pub tool_calls: Vec<PartialToolCall>,
}

#[derive(Default, Debug, Clone)]
pub struct PartialToolCall {
    pub index: usize,
    pub id: String,
    pub call_type: String,
    pub function_name: String,
    pub function_arguments: String,
}

impl ToolCallAccumulator {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            tool_calls: Vec::new(),
        }
    }

    /// Process a delta from streaming response
    pub fn process_delta(&mut self, delta: &Value) {
        if let Some(tool_calls) = delta.get("tool_calls").and_then(|v| v.as_array()) {
            for tc in tool_calls {
                let index = tc
                    .get("index")
                    .and_then(serde_json::Value::as_u64)
                    .map_or(0, |v| usize::try_from(v).unwrap_or(usize::MAX));

                // Cap-enforce the slot index. A delta with an
                // out-of-bounds index is dropped (with a warn) rather
                // than blindly pre-allocating slots up to it. See
                // `MAX_PARALLEL_TOOL_CALL_SLOTS` for the cap rationale.
                if index >= MAX_PARALLEL_TOOL_CALL_SLOTS {
                    tracing::warn!(
                        target: "openclaudia::accumulator",
                        observed_index = index,
                        cap = MAX_PARALLEL_TOOL_CALL_SLOTS,
                        "streaming tool-call delta with index past cap; \
                         dropping to avoid unbounded allocation"
                    );
                    continue;
                }

                // Ensure we have enough slots (bounded by the cap above).
                while self.tool_calls.len() <= index {
                    self.tool_calls.push(PartialToolCall::default());
                }

                let partial = &mut self.tool_calls[index];
                partial.index = index;

                if let Some(id) = tc.get("id").and_then(|v| v.as_str()) {
                    partial.id = id.to_string();
                }
                if let Some(t) = tc.get("type").and_then(|v| v.as_str()) {
                    partial.call_type = t.to_string();
                }
                if let Some(func) = tc.get("function") {
                    if let Some(name) = func.get("name").and_then(|v| v.as_str()) {
                        partial.function_name = name.to_string();
                    }
                    if let Some(args) = func.get("arguments").and_then(|v| v.as_str()) {
                        partial.function_arguments.push_str(args);
                    }
                }
            }
        }
    }

    /// Convert accumulated partials to complete tool calls
    #[must_use]
    pub fn finalize(&self) -> Vec<ToolCall> {
        self.tool_calls
            .iter()
            .filter(|tc| !tc.id.is_empty() && !tc.function_name.is_empty())
            .map(|tc| ToolCall {
                id: tc.id.clone(),
                call_type: if tc.call_type.is_empty() {
                    "function".to_string()
                } else {
                    tc.call_type.clone()
                },
                function: FunctionCall {
                    name: tc.function_name.clone(),
                    arguments: normalized_tool_arguments(&tc.function_arguments),
                },
            })
            .collect()
    }

    /// Convert every observed slot into a complete executable call.
    ///
    /// # Errors
    ///
    /// Returns an error when any streamed slot is incomplete, repeats an id,
    /// or contains arguments that are not valid JSON.
    pub fn finalize_checked(&self) -> Result<Vec<ToolCall>, String> {
        let mut ids = std::collections::HashSet::new();
        for partial in &self.tool_calls {
            if partial.id.is_empty() || partial.function_name.is_empty() {
                return Err(format!(
                    "Provider returned incomplete tool call at index {}",
                    partial.index
                ));
            }
            if !ids.insert(partial.id.as_str()) {
                return Err(format!("Provider repeated tool call id {:?}", partial.id));
            }
            serde_json::from_str::<Value>(&normalized_tool_arguments(&partial.function_arguments))
                .map_err(|error| {
                    format!(
                        "Provider returned invalid JSON arguments for tool call {:?}: {error}",
                        partial.id
                    )
                })?;
        }
        Ok(self.finalize())
    }

    /// Check if we have any complete tool calls.
    ///
    /// The accumulator may contain partial slots with only an id or only a
    /// function fragment. Those cannot be finalized into executable
    /// [`ToolCall`]s, so callers that use this as a loop condition must not
    /// treat them as pending work.
    #[must_use]
    pub fn has_tool_calls(&self) -> bool {
        self.tool_calls
            .iter()
            .any(|tc| !tc.id.is_empty() && !tc.function_name.is_empty())
    }

    /// Clear the accumulator
    pub fn clear(&mut self) {
        self.tool_calls.clear();
    }
}

// ==========================================================================
// Anthropic Streaming Tool Accumulator
// ==========================================================================

/// Content block types from Anthropic streaming responses
#[derive(Debug, Clone)]
pub enum AnthropicContentBlock {
    /// Text content block
    Text(String),
    /// Tool use content block
    ToolUse {
        id: String,
        name: String,
        input_json: String,
    },
}

/// Accumulates `tool_use` content blocks from Anthropic streaming responses.
///
/// When the Anthropic API receives tool definitions, it returns structured
/// `tool_use` content blocks instead of XML in text. This accumulator
/// processes the streaming events to collect those blocks.
///
/// Anthropic streaming event sequence for `tool_use`:
/// 1. `content_block_start` with `type: "tool_use"`, `id`, `name`
/// 2. `content_block_delta` with `type: "input_json_delta"`, `partial_json`
/// 3. `content_block_stop`
/// 4. `message_delta` with `stop_reason: "tool_use"`
#[derive(Debug)]
pub struct AnthropicToolAccumulator {
    /// Accumulated content blocks (text + `tool_use`)
    pub blocks: Vec<AnthropicContentBlock>,
    /// The stop reason from `message_delta`
    pub stop_reason: Option<String>,
}

impl Default for AnthropicToolAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl AnthropicToolAccumulator {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            blocks: Vec::new(),
            stop_reason: None,
        }
    }

    /// Process a streaming SSE event from the Anthropic API.
    /// Returns any text that should be printed to the terminal.
    pub fn process_event(&mut self, event: &Value) -> Option<String> {
        let event_type = event.get("type").and_then(|t| t.as_str())?;

        match event_type {
            "content_block_start" => {
                let block = event.get("content_block")?;
                let block_type = block.get("type").and_then(|t| t.as_str())?;

                match block_type {
                    "text" => {
                        self.blocks.push(AnthropicContentBlock::Text(String::new()));
                    }
                    "tool_use" => {
                        let id = block
                            .get("id")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        let name = block
                            .get("name")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        self.blocks.push(AnthropicContentBlock::ToolUse {
                            id,
                            name,
                            input_json: String::new(),
                        });
                    }
                    _ => {}
                }
                None
            }
            "content_block_delta" => {
                let delta = event.get("delta")?;
                let delta_type = delta.get("type").and_then(|t| t.as_str())?;

                match delta_type {
                    "text_delta" => {
                        let text = delta.get("text").and_then(|t| t.as_str()).unwrap_or("");
                        // Append to last text block
                        if let Some(AnthropicContentBlock::Text(ref mut s)) = self.blocks.last_mut()
                        {
                            s.push_str(text);
                        }
                        Some(text.to_string())
                    }
                    "input_json_delta" => {
                        let json_chunk = delta
                            .get("partial_json")
                            .and_then(|t| t.as_str())
                            .unwrap_or("");
                        // Append to last tool_use block's input
                        if let Some(AnthropicContentBlock::ToolUse {
                            ref mut input_json, ..
                        }) = self.blocks.last_mut()
                        {
                            input_json.push_str(json_chunk);
                        }
                        None
                    }
                    _ => None,
                }
            }
            "message_delta" => {
                if let Some(delta) = event.get("delta") {
                    if let Some(reason) = delta.get("stop_reason").and_then(|r| r.as_str()) {
                        self.stop_reason = Some(reason.to_string());
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Check if the model requested tool use
    #[must_use]
    pub fn has_tool_use(&self) -> bool {
        self.stop_reason.as_deref() == Some("tool_use")
            && self
                .blocks
                .iter()
                .any(|b| matches!(b, AnthropicContentBlock::ToolUse { .. }))
    }

    /// Get concatenated text from all text blocks
    #[must_use]
    pub fn get_text(&self) -> String {
        self.blocks
            .iter()
            .filter_map(|b| match b {
                AnthropicContentBlock::Text(s) => Some(s.as_str()),
                AnthropicContentBlock::ToolUse { .. } => None,
            })
            .collect::<Vec<_>>()
            .join("")
    }

    /// Convert accumulated `tool_use` blocks to `ToolCall` format for execution
    #[must_use]
    pub fn finalize_tool_calls(&self) -> Vec<ToolCall> {
        self.blocks
            .iter()
            .filter_map(|b| match b {
                AnthropicContentBlock::ToolUse {
                    id,
                    name,
                    input_json,
                } => Some(ToolCall {
                    id: id.clone(),
                    call_type: "function".to_string(),
                    function: FunctionCall {
                        name: name.clone(),
                        arguments: normalized_tool_arguments(input_json),
                    },
                }),
                AnthropicContentBlock::Text(_) => None,
            })
            .collect()
    }

    /// Convert every Anthropic `tool_use` block into a complete tool call.
    ///
    /// # Errors
    ///
    /// Returns an error for missing/repeated ids, missing names, or malformed
    /// streamed input JSON.
    pub fn finalize_tool_calls_checked(&self) -> Result<Vec<ToolCall>, String> {
        let mut ids = std::collections::HashSet::new();
        for block in &self.blocks {
            let AnthropicContentBlock::ToolUse {
                id,
                name,
                input_json,
            } = block
            else {
                continue;
            };
            if id.is_empty() || name.is_empty() {
                return Err("Provider returned incomplete Anthropic tool_use block".to_string());
            }
            if !ids.insert(id.as_str()) {
                return Err(format!("Provider repeated tool call id {id:?}"));
            }
            serde_json::from_str::<Value>(&normalized_tool_arguments(input_json)).map_err(
                |error| {
                    format!(
                        "Provider returned invalid JSON arguments for tool call {id:?}: {error}"
                    )
                },
            )?;
        }
        Ok(self.finalize_tool_calls())
    }

    /// Convert to OpenAI-format `tool_calls` JSON for storage in `chat_session`.
    /// This allows `convert_messages_to_anthropic` to handle the back-conversion.
    #[must_use]
    pub fn to_openai_tool_calls_json(&self) -> Vec<serde_json::Value> {
        self.blocks
            .iter()
            .filter_map(|b| match b {
                AnthropicContentBlock::ToolUse {
                    id,
                    name,
                    input_json,
                } => Some(serde_json::json!({
                    "id": id,
                    "type": "function",
                    "function": {
                        "name": name,
                        "arguments": normalized_tool_arguments(input_json)
                    }
                })),
                AnthropicContentBlock::Text(_) => None,
            })
            .collect()
    }

    /// Clear the accumulator for reuse
    pub fn clear(&mut self) {
        self.blocks.clear();
        self.stop_reason = None;
    }
}

#[cfg(test)]
mod terminal_tool_validation_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn openai_checked_finalize_rejects_partial_slot() {
        let mut accumulator = ToolCallAccumulator::new();
        accumulator.process_delta(&json!({
            "tool_calls": [{
                "index": 0,
                "id": "call_1",
                "type": "function",
                "function": {"arguments": "{}"}
            }]
        }));

        let error = accumulator
            .finalize_checked()
            .expect_err("missing function name must fail");
        assert!(error.contains("incomplete tool call"), "{error}");
    }

    #[test]
    fn openai_checked_finalize_rejects_malformed_arguments() {
        let mut accumulator = ToolCallAccumulator::new();
        accumulator.process_delta(&json!({
            "tool_calls": [{
                "index": 0,
                "id": "call_1",
                "type": "function",
                "function": {"name": "read_file", "arguments": "{"}
            }]
        }));

        let error = accumulator
            .finalize_checked()
            .expect_err("malformed arguments must fail");
        assert!(error.contains("invalid JSON arguments"), "{error}");
    }

    #[test]
    fn anthropic_checked_finalize_requires_closed_input_json() {
        let mut accumulator = AnthropicToolAccumulator::new();
        accumulator.process_event(&json!({
            "type": "content_block_start",
            "content_block": {"type": "tool_use", "id": "tool_1", "name": "read_file"}
        }));
        accumulator.process_event(&json!({
            "type": "content_block_delta",
            "delta": {"type": "input_json_delta", "partial_json": "{"}
        }));
        accumulator.process_event(&json!({
            "type": "message_delta",
            "delta": {"stop_reason": "tool_use"}
        }));

        let error = accumulator
            .finalize_tool_calls_checked()
            .expect_err("unterminated input_json must fail");
        assert!(error.contains("invalid JSON arguments"), "{error}");
    }
}
