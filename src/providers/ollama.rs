//! Ollama API adapter for local LLM inference.
//!
//! See: <https://github.com/ollama/ollama/blob/main/docs/api.md>

use async_trait::async_trait;
use base64::Engine as _;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use tracing::debug;

use crate::proxy::{ChatCompletionRequest, ChatMessage, ContentPart, MessageContent};
use crate::runtime::{
    ContinuationGeneration, ProviderNativeItem, ProviderNativeItemPurpose, ProviderNativeState,
    ProviderStateFacet, ProviderWireProtocol,
};
use crate::session::TokenUsage;
use crate::tools::{FunctionCall, ToolCall};

use super::{ProviderAdapter, ProviderError};

const OLLAMA_TURN_FORMAT: &str = "ollama_chat_turn_v1";
const OLLAMA_MESSAGE_FORMAT: &str = "ollama_chat_message_v1";
const OLLAMA_HISTORY_KEY: &str = "_openclaudia_ollama_portable_history";

fn provider_error(error: impl std::fmt::Display) -> ProviderError {
    ProviderError::InvalidResponse(error.to_string())
}

fn validate_portable_call_id(id: &str, context: &str) -> Result<(), ProviderError> {
    if id.is_empty() || id.len() > 512 || id.chars().any(char::is_control) {
        Err(provider_error(format!("{context} has an invalid call id")))
    } else {
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
struct OllamaCallBinding {
    portable_id: String,
    name: String,
    arguments: Value,
    position: usize,
    provider_index: Option<u64>,
}

impl OllamaCallBinding {
    fn to_value(&self) -> Value {
        json!({
            "portable_id": self.portable_id,
            "name": self.name,
            "arguments": self.arguments,
            "position": self.position,
            "provider_index": self.provider_index,
        })
    }

    fn from_value(value: &Value, index: usize) -> Result<Self, ProviderError> {
        let portable_id = value
            .get("portable_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                provider_error(format!("Ollama call binding {index} missing portable_id"))
            })?;
        validate_portable_call_id(portable_id, "Ollama portable call binding")?;
        let name = value
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| provider_error(format!("Ollama call binding {index} missing name")))?;
        let arguments = value
            .get("arguments")
            .filter(|arguments| arguments.is_object())
            .cloned()
            .ok_or_else(|| {
                provider_error(format!(
                    "Ollama call binding {index} has malformed arguments"
                ))
            })?;
        let position = value
            .get("position")
            .and_then(Value::as_u64)
            .and_then(|position| usize::try_from(position).ok())
            .ok_or_else(|| {
                provider_error(format!("Ollama call binding {index} has invalid position"))
            })?;
        let provider_index = match value.get("provider_index") {
            None | Some(Value::Null) => None,
            Some(value) => Some(value.as_u64().ok_or_else(|| {
                provider_error(format!(
                    "Ollama call binding {index} has invalid provider_index"
                ))
            })?),
        };
        Ok(Self {
            portable_id: portable_id.to_string(),
            name: name.to_string(),
            arguments,
            position,
            provider_index,
        })
    }
}

/// Exact provider-owned assistant message from one Ollama `/api/chat` turn.
///
/// The message may contain private `thinking` text, so this type deliberately
/// does not implement `Debug` and never enters portable transcript fields.
#[derive(Clone, PartialEq, Eq)]
pub struct OllamaChatTurnOutput {
    message: Value,
    done: bool,
}

impl OllamaChatTurnOutput {
    /// Capture and validate an Ollama response without flattening its native
    /// assistant message, tool-call indexes, arguments, order, or thinking.
    ///
    /// # Errors
    ///
    /// Returns a provider error for malformed response/message/tool fields.
    pub fn new(response: &Value) -> Result<Self, ProviderError> {
        response
            .get("model")
            .and_then(Value::as_str)
            .filter(|model| !model.is_empty())
            .ok_or_else(|| provider_error("Ollama response missing non-empty string 'model'"))?;
        let done = response
            .get("done")
            .and_then(Value::as_bool)
            .ok_or_else(|| provider_error("Ollama response missing boolean 'done'"))?;
        let message = response
            .get("message")
            .filter(|message| message.is_object())
            .cloned()
            .ok_or_else(|| provider_error("Ollama response missing object 'message'"))?;
        Self::from_message(message, done)
    }

    fn from_message(message: Value, done: bool) -> Result<Self, ProviderError> {
        match message.get("role") {
            Some(Value::String(role)) if role == "assistant" => {}
            Some(Value::String(role)) if !role.is_empty() => {
                return Err(provider_error(
                    "Ollama response message has unsupported role; expected 'assistant'",
                ))
            }
            _ => {
                return Err(provider_error(
                    "Ollama response message missing non-empty string 'role'",
                ))
            }
        }
        let has_calls = message
            .get("tool_calls")
            .and_then(Value::as_array)
            .is_some_and(|calls| !calls.is_empty());
        match message.get("content") {
            Some(Value::String(_)) => {}
            None if has_calls => {}
            _ => {
                return Err(provider_error(
                    "Ollama response message has invalid 'content'",
                ))
            }
        }
        if let Some(thinking) = message.get("thinking") {
            if !thinking.is_string() {
                return Err(provider_error(
                    "Ollama response message has non-string thinking",
                ));
            }
        }
        validate_ollama_native_calls(&message)?;
        Ok(Self { message, done })
    }

    /// Borrow the exact native assistant message.
    #[must_use]
    pub const fn message(&self) -> &Value {
        &self.message
    }

    /// Whether the native response declared a completed turn.
    #[must_use]
    pub const fn done(&self) -> bool {
        self.done
    }

    /// Visible assistant text, excluding native thinking.
    #[must_use]
    pub fn text(&self) -> &str {
        self.message
            .get("content")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    /// Build deterministic portable tool-call projections for this turn.
    ///
    /// # Errors
    ///
    /// Returns a provider error for malformed or duplicate native indexes.
    pub fn tool_calls(&self, assistant_ordinal: u64) -> Result<Vec<ToolCall>, ProviderError> {
        self.call_bindings(assistant_ordinal)?
            .into_iter()
            .map(|binding| {
                let arguments = serde_json::to_string(&binding.arguments).map_err(|error| {
                    provider_error(format!("Ollama arguments failed to serialize: {error}"))
                })?;
                Ok(ToolCall {
                    id: binding.portable_id,
                    call_type: "function".to_string(),
                    function: FunctionCall {
                        name: binding.name,
                        arguments,
                    },
                })
            })
            .collect()
    }

    fn call_bindings(
        &self,
        assistant_ordinal: u64,
    ) -> Result<Vec<OllamaCallBinding>, ProviderError> {
        let Some(calls) = self.message.get("tool_calls").and_then(Value::as_array) else {
            return Ok(Vec::new());
        };
        let mut bindings = Vec::with_capacity(calls.len());
        let mut indexes = BTreeSet::new();
        for (position, call) in calls.iter().enumerate() {
            let function = call
                .get("function")
                .and_then(Value::as_object)
                .expect("validated Ollama call retains function");
            let provider_index = function.get("index").and_then(Value::as_u64);
            if let Some(index) = provider_index {
                if !indexes.insert(index) {
                    return Err(provider_error(format!(
                        "Ollama completion repeats function index {index}"
                    )));
                }
            }
            let name = function
                .get("name")
                .and_then(Value::as_str)
                .expect("validated Ollama call retains name");
            let arguments = parse_ollama_arguments(position, &function["arguments"])?;
            bindings.push(OllamaCallBinding {
                portable_id: format!("call_ollama_{assistant_ordinal}_{position}"),
                name: name.to_string(),
                arguments,
                position,
                provider_index,
            });
        }
        Ok(bindings)
    }
}

fn validate_ollama_native_calls(message: &Value) -> Result<(), ProviderError> {
    let Some(calls) = message.get("tool_calls") else {
        return Ok(());
    };
    let calls = calls
        .as_array()
        .ok_or_else(|| provider_error("Ollama message.tool_calls must be an array"))?;
    for (index, call) in calls.iter().enumerate() {
        if let Some(call_type) = call.get("type") {
            if call_type.as_str() != Some("function") {
                return Err(provider_error(format!(
                    "Ollama tool_call at index {index} has unsupported type"
                )));
            }
        }
        let function = call
            .get("function")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                provider_error(format!(
                    "Ollama tool_call at index {index} missing function object"
                ))
            })?;
        function
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                provider_error(format!(
                    "Ollama tool_call at index {index} missing function.name"
                ))
            })?;
        if let Some(provider_index) = function.get("index") {
            provider_index.as_u64().ok_or_else(|| {
                provider_error(format!(
                    "Ollama tool_call at index {index} has invalid function.index"
                ))
            })?;
        }
        let arguments = function.get("arguments").ok_or_else(|| {
            provider_error(format!(
                "Ollama tool_call at index {index} missing function.arguments"
            ))
        })?;
        parse_ollama_arguments(index, arguments)?;
    }
    Ok(())
}

fn parse_ollama_arguments(index: usize, arguments: &Value) -> Result<Value, ProviderError> {
    let parsed = if let Some(arguments) = arguments.as_str() {
        serde_json::from_str::<Value>(arguments).map_err(|error| {
            provider_error(format!(
                "Ollama tool_call at index {index} has invalid JSON function.arguments: {error}"
            ))
        })?
    } else {
        arguments.clone()
    };
    if !parsed.is_object() {
        return Err(provider_error(format!(
            "Ollama tool_call at index {index} has non-object function.arguments: expected JSON object, got {}",
            json_value_type_name(&parsed)
        )));
    }
    Ok(parsed)
}

const fn json_value_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[derive(Clone)]
struct OllamaReplayGroup {
    message: Value,
    calls: Vec<OllamaCallBinding>,
}

fn ollama_message_facet(output: &OllamaChatTurnOutput, call_count: usize) -> ProviderStateFacet {
    if call_count > 1 {
        ProviderStateFacet::ParallelToolCalls
    } else if call_count == 1 {
        ProviderStateFacet::ToolCalls
    } else if output.message().get("thinking").is_some() {
        ProviderStateFacet::Reasoning
    } else {
        ProviderStateFacet::NativeMessage
    }
}

fn parse_ollama_turn_header(
    payload: &Value,
) -> Result<(u64, Vec<OllamaCallBinding>), ProviderError> {
    if payload.get("format").and_then(Value::as_str) != Some(OLLAMA_TURN_FORMAT) {
        return Err(provider_error("unrecognized Ollama turn evidence format"));
    }
    let ordinal = payload
        .get("assistant_ordinal")
        .and_then(Value::as_u64)
        .ok_or_else(|| provider_error("Ollama turn evidence missing assistant_ordinal"))?;
    if payload.get("message_count").and_then(Value::as_u64) != Some(1) {
        return Err(provider_error(
            "Ollama turn evidence must bind exactly one assistant message",
        ));
    }
    let calls = payload
        .get("tool_calls")
        .and_then(Value::as_array)
        .ok_or_else(|| provider_error("Ollama turn evidence missing tool_calls array"))?
        .iter()
        .enumerate()
        .map(|(index, value)| OllamaCallBinding::from_value(value, index))
        .collect::<Result<Vec<_>, _>>()?;
    for (expected, call) in calls.iter().enumerate() {
        if call.position != expected {
            return Err(provider_error(format!(
                "Ollama call binding position {} is reordered; expected {expected}",
                call.position
            )));
        }
    }
    Ok((ordinal, calls))
}

fn parse_ollama_replay_groups(
    state: &ProviderNativeState,
) -> Result<BTreeMap<u64, OllamaReplayGroup>, ProviderError> {
    let mut groups = BTreeMap::new();
    let mut pending: Option<(u64, Vec<OllamaCallBinding>)> = None;
    let mut all_call_ids = BTreeSet::new();
    let mut previous_ordinal = None;
    for item in state.items() {
        match item.purpose() {
            ProviderNativeItemPurpose::Evidence => {
                if pending.is_some() {
                    return Err(provider_error(
                        "Ollama turn evidence is missing its native message item",
                    ));
                }
                if item.facet() != ProviderStateFacet::NativeMessage {
                    return Err(provider_error(
                        "Ollama turn evidence has the wrong native-state facet",
                    ));
                }
                let (ordinal, calls) = parse_ollama_turn_header(item.payload())?;
                if previous_ordinal.is_some_and(|previous| previous >= ordinal) {
                    return Err(provider_error(format!(
                        "Ollama assistant ordinal {ordinal} is not ordered after the prior turn"
                    )));
                }
                for call in &calls {
                    if !all_call_ids.insert(call.portable_id.clone()) {
                        return Err(provider_error(format!(
                            "Ollama continuation repeats call id {:?}",
                            call.portable_id
                        )));
                    }
                }
                previous_ordinal = Some(ordinal);
                pending = Some((ordinal, calls));
            }
            ProviderNativeItemPurpose::Continuation => {
                let (ordinal, expected_calls) = pending.take().ok_or_else(|| {
                    provider_error("Ollama native message has no preceding turn evidence")
                })?;
                let payload = item.payload();
                if payload.get("format").and_then(Value::as_str) != Some(OLLAMA_MESSAGE_FORMAT) {
                    return Err(provider_error("unrecognized Ollama native message format"));
                }
                if payload.get("assistant_ordinal").and_then(Value::as_u64) != Some(ordinal) {
                    return Err(provider_error(format!(
                        "Ollama native message does not match assistant ordinal {ordinal}"
                    )));
                }
                let message = payload
                    .get("message")
                    .filter(|message| message.is_object())
                    .cloned()
                    .ok_or_else(|| provider_error("Ollama native message payload is malformed"))?;
                let output = OllamaChatTurnOutput::from_message(message.clone(), true)?;
                let actual_calls = output.call_bindings(ordinal)?;
                if actual_calls != expected_calls {
                    return Err(provider_error(format!(
                        "Ollama native message call mapping disagrees at assistant ordinal {ordinal}"
                    )));
                }
                let expected_facet = ollama_message_facet(&output, actual_calls.len());
                if item.facet() != expected_facet {
                    return Err(provider_error(format!(
                        "Ollama native message facet {:?} does not match {expected_facet:?}",
                        item.facet()
                    )));
                }
                if groups
                    .insert(
                        ordinal,
                        OllamaReplayGroup {
                            message,
                            calls: actual_calls,
                        },
                    )
                    .is_some()
                {
                    return Err(provider_error(format!(
                        "duplicate Ollama assistant ordinal {ordinal}"
                    )));
                }
            }
        }
    }
    if pending.is_some() {
        return Err(provider_error(
            "Ollama turn evidence is missing its native message item",
        ));
    }
    let turn_count = u64::try_from(groups.len())
        .map_err(|_| provider_error("Ollama continuation turn count overflow"))?;
    if turn_count != state.generation().get() {
        return Err(provider_error(format!(
            "Ollama continuation generation {} does not match its {turn_count} retained turns",
            state.generation().get()
        )));
    }
    Ok(groups)
}

/// Advance an Ollama chat continuation with one exact completed assistant turn.
///
/// # Errors
///
/// Returns a provider error for incomplete output, identity/protocol drift,
/// stale/duplicate turn identity, malformed native calls, generation
/// exhaustion, or S-044's native-state bounds.
pub fn advance_ollama_chat_state(
    provider: &str,
    model: &str,
    previous: Option<&ProviderNativeState>,
    assistant_ordinal: u64,
    output: &OllamaChatTurnOutput,
) -> Result<ProviderNativeState, ProviderError> {
    if !output.done() {
        return Err(provider_error(
            "Ollama continuation cannot advance from an incomplete response",
        ));
    }
    let mut items = if let Some(previous) = previous {
        previous
            .validate_binding(provider, model, ProviderWireProtocol::OllamaChat)
            .map_err(provider_error)?;
        super::OLLAMA_STATE_CONTRACT
            .validate_state(previous)
            .map_err(provider_error)?;
        let groups = parse_ollama_replay_groups(previous)?;
        if groups
            .last_key_value()
            .is_some_and(|(ordinal, _)| *ordinal >= assistant_ordinal)
        {
            return Err(provider_error(format!(
                "Ollama assistant ordinal {assistant_ordinal} does not advance the continuation"
            )));
        }
        previous.items().to_vec()
    } else {
        Vec::new()
    };
    let calls = output.call_bindings(assistant_ordinal)?;
    items.push(
        ProviderNativeItem::new(
            ProviderStateFacet::NativeMessage,
            ProviderNativeItemPurpose::Evidence,
            json!({
                "format": OLLAMA_TURN_FORMAT,
                "assistant_ordinal": assistant_ordinal,
                "message_count": 1,
                "tool_calls": calls.iter().map(OllamaCallBinding::to_value).collect::<Vec<_>>(),
            }),
        )
        .map_err(provider_error)?,
    );
    items.push(
        ProviderNativeItem::new(
            ollama_message_facet(output, calls.len()),
            ProviderNativeItemPurpose::Continuation,
            json!({
                "format": OLLAMA_MESSAGE_FORMAT,
                "assistant_ordinal": assistant_ordinal,
                "message": output.message(),
            }),
        )
        .map_err(provider_error)?,
    );
    let generation = match previous {
        Some(state) => state
            .generation()
            .get()
            .checked_add(1)
            .ok_or_else(|| provider_error("Ollama continuation generation exhausted"))?,
        None => 1,
    };
    let generation = ContinuationGeneration::new(generation)
        .ok_or_else(|| provider_error("Ollama continuation generation exhausted"))?;
    let state = ProviderNativeState::new(
        provider,
        model,
        ProviderWireProtocol::OllamaChat,
        generation,
        items,
    )
    .map_err(provider_error)?;
    super::OLLAMA_STATE_CONTRACT
        .validate_state(&state)
        .map_err(provider_error)?;
    parse_ollama_replay_groups(&state)?;
    Ok(state)
}

fn ollama_binding_wire_index(entry: &Value, ordinal: u64) -> Result<usize, ProviderError> {
    entry
        .get("wire_index")
        .and_then(Value::as_u64)
        .and_then(|index| usize::try_from(index).ok())
        .ok_or_else(|| {
            provider_error(format!(
                "Ollama portable history ordinal {ordinal} has invalid wire_index"
            ))
        })
}

fn validate_ollama_assistant_binding(
    entry: &Value,
    ordinal: u64,
    expected: &[OllamaCallBinding],
) -> Result<(), ProviderError> {
    let calls = entry
        .get("tool_calls")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            provider_error(format!(
                "Ollama assistant history binding {ordinal} missing tool_calls"
            ))
        })?;
    if calls.len() != expected.len() {
        return Err(provider_error(format!(
            "Ollama assistant history binding {ordinal} has {} calls; expected {}",
            calls.len(),
            expected.len()
        )));
    }
    for (index, (actual, expected)) in calls.iter().zip(expected).enumerate() {
        let id = actual.get("id").and_then(Value::as_str).ok_or_else(|| {
            provider_error(format!(
                "Ollama assistant binding {ordinal} call {index} missing id"
            ))
        })?;
        let name = actual.get("name").and_then(Value::as_str).ok_or_else(|| {
            provider_error(format!(
                "Ollama assistant binding {ordinal} call {index} missing name"
            ))
        })?;
        let arguments = actual
            .get("arguments")
            .filter(|arguments| arguments.is_object())
            .ok_or_else(|| {
                provider_error(format!(
                    "Ollama assistant binding {ordinal} call {index} has malformed arguments"
                ))
            })?;
        if id != expected.portable_id || name != expected.name || arguments != &expected.arguments {
            return Err(provider_error(format!(
                "Ollama assistant binding {ordinal} call {index} disagrees with native state"
            )));
        }
    }
    Ok(())
}

fn validate_ollama_tool_result(
    messages: &[Value],
    entry: &Value,
    ordinal: u64,
    expected: &OllamaCallBinding,
) -> Result<(), ProviderError> {
    let call_id = entry
        .get("tool_call_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            provider_error(format!(
                "Ollama tool history binding {ordinal} missing tool_call_id"
            ))
        })?;
    let name = entry.get("name").and_then(Value::as_str).ok_or_else(|| {
        provider_error(format!(
            "Ollama tool history binding {ordinal} missing name"
        ))
    })?;
    if call_id != expected.portable_id || name != expected.name {
        return Err(provider_error(format!(
            "Ollama tool result at ordinal {ordinal} is missing, duplicated, or reordered"
        )));
    }
    let wire_index = ollama_binding_wire_index(entry, ordinal)?;
    let message = messages.get(wire_index).ok_or_else(|| {
        provider_error(format!(
            "Ollama tool result ordinal {ordinal} references missing wire message"
        ))
    })?;
    if message.get("role").and_then(Value::as_str) != Some("tool")
        || message.get("tool_name").and_then(Value::as_str) != Some(name)
        || !message.get("content").is_some_and(Value::is_string)
    {
        return Err(provider_error(format!(
            "Ollama tool result at ordinal {ordinal} disagrees with portable history"
        )));
    }
    Ok(())
}

fn validate_contiguous_ollama_history(history: &[Value]) -> Result<(), ProviderError> {
    for (expected, entry) in history.iter().enumerate() {
        let expected = u64::try_from(expected)
            .map_err(|_| provider_error("Ollama portable history count overflow"))?;
        if entry.get("ordinal").and_then(Value::as_u64) != Some(expected) {
            return Err(provider_error(
                "Ollama portable history bindings are not contiguous",
            ));
        }
    }
    Ok(())
}

fn validate_complete_ollama_bindings(
    history: &[Value],
    bound_assistants: &BTreeSet<u64>,
    bound_results: &BTreeSet<u64>,
) -> Result<(), ProviderError> {
    for entry in history {
        let ordinal = entry
            .get("ordinal")
            .and_then(Value::as_u64)
            .expect("contiguous Ollama binding retains ordinal");
        match entry.get("role").and_then(Value::as_str) {
            Some("assistant") => {
                let has_calls = entry
                    .get("tool_calls")
                    .and_then(Value::as_array)
                    .is_some_and(|calls| !calls.is_empty());
                if has_calls && !bound_assistants.contains(&ordinal) {
                    return Err(provider_error(format!(
                        "Ollama assistant tool history at ordinal {ordinal} has no native state"
                    )));
                }
            }
            Some("tool") if !bound_results.contains(&ordinal) => {
                return Err(provider_error(format!(
                    "Ollama tool result at ordinal {ordinal} is orphaned"
                )));
            }
            Some("user" | "tool") => {}
            Some(role) => {
                return Err(provider_error(format!(
                    "Ollama portable history has unsupported binding role {role:?}"
                )));
            }
            None => return Err(provider_error("Ollama history binding missing role")),
        }
    }
    Ok(())
}

fn apply_ollama_state(
    request: &mut Value,
    state: &ProviderNativeState,
) -> Result<(), ProviderError> {
    super::OLLAMA_STATE_CONTRACT
        .validate_state(state)
        .map_err(provider_error)?;
    let history = request
        .as_object_mut()
        .ok_or_else(|| provider_error("Ollama request must be an object"))?
        .remove(OLLAMA_HISTORY_KEY)
        .ok_or_else(|| provider_error("Ollama request is missing portable history bindings"))?;
    let history = history
        .as_array()
        .ok_or_else(|| provider_error("Ollama portable history binding must be an array"))?;
    validate_contiguous_ollama_history(history)?;
    let groups = parse_ollama_replay_groups(state)?;
    let messages = request
        .get_mut("messages")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| provider_error("Ollama request messages must be an array"))?;
    let mut bound_assistants = BTreeSet::new();
    let mut bound_results = BTreeSet::new();
    for (ordinal, group) in &groups {
        let entry_index = usize::try_from(*ordinal)
            .map_err(|_| provider_error("Ollama assistant ordinal overflow"))?;
        let entry = history.get(entry_index).ok_or_else(|| {
            provider_error(format!(
                "Ollama native state references missing assistant ordinal {ordinal}"
            ))
        })?;
        if entry.get("role").and_then(Value::as_str) != Some("assistant") {
            return Err(provider_error(format!(
                "Ollama native turn at ordinal {ordinal} is not bound to an assistant message"
            )));
        }
        validate_ollama_assistant_binding(entry, *ordinal, &group.calls)?;
        let wire_index = ollama_binding_wire_index(entry, *ordinal)?;
        if messages
            .get(wire_index)
            .and_then(|message| message.get("role"))
            .and_then(Value::as_str)
            != Some("assistant")
        {
            return Err(provider_error(format!(
                "Ollama assistant ordinal {ordinal} lost its wire projection"
            )));
        }
        messages[wire_index] = group.message.clone();
        bound_assistants.insert(*ordinal);
        for (call_index, call) in group.calls.iter().enumerate() {
            let result_ordinal = ordinal
                .checked_add(1)
                .and_then(|ordinal| ordinal.checked_add(u64::try_from(call_index).ok()?))
                .ok_or_else(|| provider_error("Ollama tool result ordinal overflow"))?;
            let result_index = usize::try_from(result_ordinal)
                .map_err(|_| provider_error("Ollama tool result ordinal overflow"))?;
            let result_entry = history.get(result_index).ok_or_else(|| {
                provider_error(format!(
                    "Ollama call {:?} is missing its tool result",
                    call.portable_id
                ))
            })?;
            if result_entry.get("role").and_then(Value::as_str) != Some("tool") {
                return Err(provider_error(format!(
                    "Ollama call {:?} is missing its ordered tool result",
                    call.portable_id
                )));
            }
            validate_ollama_tool_result(messages, result_entry, result_ordinal, call)?;
            if !bound_results.insert(result_ordinal) {
                return Err(provider_error(format!(
                    "Ollama tool result ordinal {result_ordinal} is bound more than once"
                )));
            }
        }
    }
    validate_complete_ollama_bindings(history, &bound_assistants, &bound_results)
}

/// Ollama API adapter for local LLM inference
/// See: <https://github.com/ollama/ollama/blob/main/docs/api.md>
pub struct OllamaAdapter;

#[derive(Clone)]
struct PortableOllamaCall {
    id: String,
    name: String,
    arguments: Value,
}

fn parse_portable_ollama_calls(
    message: &ChatMessage,
    message_index: usize,
) -> Result<Vec<PortableOllamaCall>, ProviderError> {
    let Some(tool_calls) = message.tool_calls.as_ref() else {
        return Ok(Vec::new());
    };
    let mut calls = Vec::with_capacity(tool_calls.len());
    let mut ids = BTreeSet::new();
    for (call_index, call) in tool_calls.iter().enumerate() {
        let id = call
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                ProviderError::RequestFailed(format!(
                    "Ollama assistant message at index {message_index} tool_call[{call_index}] missing non-empty id"
                ))
            })?;
        validate_portable_call_id(id, "Ollama portable tool call")
            .map_err(|error| ProviderError::RequestFailed(error.to_string()))?;
        if !ids.insert(id.to_string()) {
            return Err(ProviderError::RequestFailed(format!(
                "Ollama assistant message at index {message_index} repeats tool call id {id:?}"
            )));
        }
        if call.get("type").and_then(Value::as_str) != Some("function") {
            return Err(ProviderError::RequestFailed(format!(
                "Ollama assistant message at index {message_index} tool_call[{call_index}] must have type 'function'"
            )));
        }
        let function = call
            .get("function")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                ProviderError::RequestFailed(format!(
                    "Ollama assistant message at index {message_index} tool_call[{call_index}] missing function object"
                ))
            })?;
        let name = function
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                ProviderError::RequestFailed(format!(
                    "Ollama assistant message at index {message_index} tool_call[{call_index}] missing function.name"
                ))
            })?;
        let arguments = function
            .get("arguments")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProviderError::RequestFailed(format!(
                    "Ollama assistant message at index {message_index} tool_call[{call_index}] missing string function.arguments"
                ))
            })?;
        let arguments = serde_json::from_str::<Value>(arguments).map_err(|error| {
            ProviderError::RequestFailed(format!(
                "Ollama assistant message at index {message_index} tool_call[{call_index}] has invalid JSON arguments: {error}"
            ))
        })?;
        if !arguments.is_object() {
            return Err(ProviderError::RequestFailed(format!(
                "Ollama assistant message at index {message_index} tool_call[{call_index}] arguments must encode an object"
            )));
        }
        calls.push(PortableOllamaCall {
            id: id.to_string(),
            name: name.to_string(),
            arguments,
        });
    }
    Ok(calls)
}

#[derive(Default)]
struct OllamaHistoryBuilder {
    converted: Vec<Value>,
    history: Vec<Value>,
    portable_ordinal: u64,
    pending_calls: VecDeque<PortableOllamaCall>,
}

impl OllamaHistoryBuilder {
    fn push(&mut self, message: &ChatMessage, message_index: usize) -> Result<(), ProviderError> {
        let content = match &message.content {
            MessageContent::Text(text) => text.clone(),
            MessageContent::Parts(parts) => {
                convert_multipart_message_content(message_index, &message.role, parts)?
            }
        };
        if message.role == "system" {
            return self.push_system(message, message_index, &content);
        }
        let ordinal = self.portable_ordinal;
        self.portable_ordinal = self.portable_ordinal.checked_add(1).ok_or_else(|| {
            ProviderError::RequestFailed("Ollama portable history ordinal overflow".to_string())
        })?;
        match message.role.as_str() {
            "user" => self.push_user(message, message_index, ordinal, &content),
            "assistant" => self.push_assistant(message, message_index, ordinal, &content),
            "tool" => self.push_tool(message, message_index, ordinal, &content),
            role => Err(ProviderError::RequestFailed(format!(
                "Ollama message at index {message_index} has unsupported role {role:?}"
            ))),
        }
    }

    fn push_system(
        &mut self,
        message: &ChatMessage,
        message_index: usize,
        content: &str,
    ) -> Result<(), ProviderError> {
        if !self.pending_calls.is_empty() {
            return Err(ProviderError::RequestFailed(format!(
                "Ollama system message at index {message_index} interrupts tool results"
            )));
        }
        if message.tool_calls.is_some() || message.tool_call_id.is_some() {
            return Err(ProviderError::RequestFailed(format!(
                "Ollama system message at index {message_index} carries tool protocol fields"
            )));
        }
        self.converted
            .push(json!({"role": "system", "content": content}));
        Ok(())
    }

    fn push_user(
        &mut self,
        message: &ChatMessage,
        message_index: usize,
        ordinal: u64,
        content: &str,
    ) -> Result<(), ProviderError> {
        if !self.pending_calls.is_empty() {
            return Err(ProviderError::RequestFailed(format!(
                "Ollama user message at index {message_index} arrived before all prior tool results"
            )));
        }
        if message.tool_calls.is_some() || message.tool_call_id.is_some() {
            return Err(ProviderError::RequestFailed(format!(
                "Ollama user message at index {message_index} carries tool protocol fields"
            )));
        }
        let wire_index = self.converted.len();
        self.converted
            .push(json!({"role": "user", "content": content}));
        self.history.push(json!({
            "ordinal": ordinal,
            "wire_index": wire_index,
            "role": "user",
        }));
        Ok(())
    }

    fn push_assistant(
        &mut self,
        message: &ChatMessage,
        message_index: usize,
        ordinal: u64,
        content: &str,
    ) -> Result<(), ProviderError> {
        if !self.pending_calls.is_empty() {
            return Err(ProviderError::RequestFailed(format!(
                "Ollama assistant message at index {message_index} arrived before all prior tool results"
            )));
        }
        if message.tool_call_id.is_some() {
            return Err(ProviderError::RequestFailed(format!(
                "Ollama assistant message at index {message_index} carries tool_call_id"
            )));
        }
        let calls = parse_portable_ollama_calls(message, message_index)?;
        let mut native = json!({"role": "assistant", "content": content});
        if !calls.is_empty() {
            native["tool_calls"] = Value::Array(
                calls
                    .iter()
                    .enumerate()
                    .map(|(position, call)| {
                        json!({
                            "type": "function",
                            "function": {
                                "index": position,
                                "name": call.name,
                                "arguments": call.arguments,
                            }
                        })
                    })
                    .collect(),
            );
        }
        let wire_index = self.converted.len();
        self.converted.push(native);
        self.history.push(json!({
            "ordinal": ordinal,
            "wire_index": wire_index,
            "role": "assistant",
            "tool_calls": calls.iter().map(|call| json!({
                "id": call.id,
                "name": call.name,
                "arguments": call.arguments,
            })).collect::<Vec<_>>(),
        }));
        self.pending_calls.extend(calls);
        Ok(())
    }

    fn push_tool(
        &mut self,
        message: &ChatMessage,
        message_index: usize,
        ordinal: u64,
        content: &str,
    ) -> Result<(), ProviderError> {
        if message.tool_calls.is_some() {
            return Err(ProviderError::RequestFailed(format!(
                "Ollama tool message at index {message_index} carries tool_calls"
            )));
        }
        let call_id = message
            .tool_call_id
            .as_deref()
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                ProviderError::RequestFailed(format!(
                    "Ollama tool message at index {message_index} missing tool_call_id"
                ))
            })?;
        let expected = self.pending_calls.front().ok_or_else(|| {
            ProviderError::RequestFailed(format!(
                "Ollama tool message at index {message_index} is orphaned"
            ))
        })?;
        if expected.id != call_id {
            return Err(ProviderError::RequestFailed(format!(
                "Ollama tool result at index {message_index} is reordered: expected {:?}, found {call_id:?}",
                expected.id
            )));
        }
        if message
            .name
            .as_deref()
            .is_some_and(|name| name != expected.name)
        {
            return Err(ProviderError::RequestFailed(format!(
                "Ollama tool result at index {message_index} name does not match call {call_id:?}"
            )));
        }
        let (attachments, attachment_diagnostic) = match crate::tools::resolve_tool_attachments(
            message
                .extra
                .get(crate::tools::TOOL_ATTACHMENTS_MESSAGE_KEY),
        ) {
            Ok(attachments) => (attachments, None),
            Err(error) => (Vec::new(), Some(error)),
        };
        let mut native_content = content.to_string();
        if let Some(diagnostic) = attachment_diagnostic {
            let _ = std::fmt::Write::write_fmt(
                &mut native_content,
                format_args!("\nNative tool attachment unavailable: {diagnostic}"),
            );
        }
        let (supported, unsupported): (Vec<_>, Vec<_>) = attachments
            .into_iter()
            .partition(|attachment| attachment.media_type.starts_with("image/"));
        for attachment in unsupported {
            let _ = std::fmt::Write::write_fmt(
                &mut native_content,
                format_args!(
                    "\nOllama cannot replay {} tool attachment {}",
                    attachment.media_type, attachment.digest
                ),
            );
        }
        let wire_index = self.converted.len();
        let mut native = json!({
            "role": "tool",
            "tool_name": expected.name,
            "content": native_content,
        });
        if !supported.is_empty() {
            native["images"] = Value::Array(
                supported
                    .into_iter()
                    .map(|attachment| {
                        Value::String(
                            base64::engine::general_purpose::STANDARD
                                .encode(attachment.bytes.as_ref()),
                        )
                    })
                    .collect(),
            );
        }
        self.converted.push(native);
        self.history.push(json!({
            "ordinal": ordinal,
            "wire_index": wire_index,
            "role": "tool",
            "tool_call_id": expected.id,
            "name": expected.name,
        }));
        self.pending_calls.pop_front();
        Ok(())
    }

    fn finish(self) -> Result<(Vec<Value>, Vec<Value>), ProviderError> {
        if let Some(call) = self.pending_calls.front() {
            return Err(ProviderError::RequestFailed(format!(
                "Ollama history is missing result for tool call {:?}",
                call.id
            )));
        }
        Ok((self.converted, self.history))
    }
}

impl OllamaAdapter {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Convert `OpenAI` messages to Ollama format
    fn convert_messages(
        messages: &[ChatMessage],
    ) -> Result<(Vec<Value>, Vec<Value>), ProviderError> {
        let mut builder = OllamaHistoryBuilder::default();
        for (message_index, message) in messages.iter().enumerate() {
            builder.push(message, message_index)?;
        }
        builder.finish()
    }

    pub(crate) fn transform_request_draft(
        request: &ChatCompletionRequest,
    ) -> Result<Value, ProviderError> {
        let (messages, history) = Self::convert_messages(&request.messages)?;
        let mut body = json!({
            "model": &request.model,
            "messages": messages,
            "stream": request.stream.unwrap_or(false),
            OLLAMA_HISTORY_KEY: history,
        });

        let mut options = json!({});
        if let Some(temperature) = request.temperature {
            options["temperature"] = json!(temperature);
        }
        if let Some(max_tokens) = request.max_tokens {
            options["num_predict"] = json!(max_tokens);
        }
        if options != json!({}) {
            body["options"] = options;
        }
        if let Some(tools) = &request.tools {
            let tools = convert_tools_checked(tools)?;
            if !tools.is_empty() {
                body["tools"] = json!(tools);
            }
        }
        Ok(body)
    }

    pub(crate) fn finalize_request(request: &mut Value) -> Result<(), ProviderError> {
        let history = request
            .as_object_mut()
            .ok_or_else(|| provider_error("Ollama request must be an object"))?
            .remove(OLLAMA_HISTORY_KEY);
        let Some(history) = history else {
            return Ok(());
        };
        let history = history
            .as_array()
            .ok_or_else(|| provider_error("Ollama portable history binding must be an array"))?;
        let has_unbound_tool_history = history.iter().any(|entry| {
            entry.get("role").and_then(Value::as_str) == Some("tool")
                || entry
                    .get("tool_calls")
                    .and_then(Value::as_array)
                    .is_some_and(|calls| !calls.is_empty())
        });
        if has_unbound_tool_history {
            return Err(ProviderError::Unsupported(
                "Ollama tool history requires its provider-native state; exact assistant message, thinking, and tool-call indexes are unavailable"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

fn convert_multipart_message_content(
    msg_index: usize,
    _role: &str,
    parts: &[ContentPart],
) -> Result<String, ProviderError> {
    let mut text_parts = Vec::new();

    for (part_index, part) in parts.iter().enumerate() {
        if let Some(text) = &part.text {
            text_parts.push(text.clone());
            continue;
        }

        if part.content_type == "text" {
            return Err(ProviderError::RequestFailed(format!(
                "Ollama message at index {msg_index} has text content part at \
                 index {part_index} without string 'text'"
            )));
        }

        if part.content_type == "image_url" || part.image_url.is_some() {
            return Err(ProviderError::Unsupported(format!(
                "Ollama adapter does not support image content parts; message index {msg_index}, \
                 part index {part_index}"
            )));
        }

        return Err(ProviderError::Unsupported(format!(
            "Ollama adapter does not support this content part type at message index \
             {msg_index}, part index {part_index}"
        )));
    }

    Ok(text_parts.join("\n"))
}

impl Default for OllamaAdapter {
    fn default() -> Self {
        Self::new()
    }
}

fn convert_tools_checked(tools: &[Value]) -> Result<Vec<Value>, ProviderError> {
    let mut out = Vec::with_capacity(tools.len());

    for (index, tool) in tools.iter().enumerate() {
        let func = tool
            .get("function")
            .filter(|value| value.is_object())
            .ok_or_else(|| {
                ProviderError::RequestFailed(format!(
                    "Tool at index {index} missing required 'function' object"
                ))
            })?;

        let name = func
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                ProviderError::RequestFailed(format!(
                    "Tool at index {index} missing non-empty string 'function.name'"
                ))
            })?;

        let description = match func.get("description") {
            None => json!(""),
            Some(value @ Value::String(_)) => value.clone(),
            Some(_) => {
                return Err(ProviderError::RequestFailed(format!(
                    "Tool at index {index} has non-string 'function.description'"
                )));
            }
        };

        let parameters = match func.get("parameters") {
            None => json!({}),
            Some(value @ Value::Object(_)) => value.clone(),
            Some(_) => {
                return Err(ProviderError::RequestFailed(format!(
                    "Tool at index {index} has non-object 'function.parameters'"
                )));
            }
        };

        out.push(json!({
            "type": "function",
            "function": {
                "name": name,
                "description": description,
                "parameters": parameters
            }
        }));
    }

    Ok(out)
}

#[async_trait]
impl ProviderAdapter for OllamaAdapter {
    fn name(&self) -> &'static str {
        "ollama"
    }

    fn state_contract(
        &self,
        protocol: crate::runtime::ProviderWireProtocol,
    ) -> Result<&'static crate::runtime::ProviderStateContract, ProviderError> {
        match protocol {
            crate::runtime::ProviderWireProtocol::OllamaChat => Ok(&super::OLLAMA_STATE_CONTRACT),
            other => Err(super::unsupported_state_protocol(self.name(), other)),
        }
    }

    fn apply_provider_native_state(
        &self,
        request: &mut Value,
        state: &ProviderNativeState,
    ) -> Result<(), ProviderError> {
        match state.protocol() {
            ProviderWireProtocol::OllamaChat => apply_ollama_state(request, state),
            other => Err(super::unsupported_state_protocol(self.name(), other)),
        }
    }

    fn transform_request(&self, request: &ChatCompletionRequest) -> Result<Value, ProviderError> {
        let mut body = Self::transform_request_draft(request)?;
        Self::finalize_request(&mut body)?;
        debug!("Transformed request for Ollama");
        Ok(body)
    }

    fn transform_response(&self, response: Value, _stream: bool) -> Result<Value, ProviderError> {
        // Ollama response format:
        // {"model": "...", "message": {"role": "assistant", "content": "..."}, "done": true, ...}
        let model = response
            .get("model")
            .and_then(Value::as_str)
            .filter(|model| !model.is_empty())
            .ok_or_else(|| {
                ProviderError::InvalidResponse(
                    "Ollama response missing non-empty string 'model'".to_string(),
                )
            })?;
        let output = OllamaChatTurnOutput::new(&response)?;
        let tool_calls = output.tool_calls(0)?;

        let mut openai_message = json!({
            "role": "assistant",
            "content": output.text()
        });
        if !tool_calls.is_empty() {
            openai_message["tool_calls"] = json!(tool_calls);
        }

        // Determine finish reason
        let finish_reason = if !output.done() {
            "length"
        } else if !tool_calls.is_empty() {
            "tool_calls"
        } else {
            "stop"
        };

        // Extract token counts if available
        let prompt_tokens = response
            .get("prompt_eval_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let completion_tokens = response
            .get("eval_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);

        Ok(json!({
            "id": format!("ollama-{}", uuid::Uuid::new_v4()),
            "object": "chat.completion",
            "created": chrono::Utc::now().timestamp(),
            "model": model,
            "choices": [{
                "index": 0,
                "message": openai_message,
                "finish_reason": finish_reason
            }],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens
            }
        }))
    }

    fn chat_endpoint(&self, _model: &str) -> String {
        "/api/chat".to_string()
    }

    fn get_headers(&self, _api_key: &super::ApiKey) -> crate::secrets::SensitiveHeaders {
        // Ollama doesn't require authentication by default
        let mut headers = crate::secrets::SensitiveHeaders::new();
        headers.insert_static_literal(reqwest::header::CONTENT_TYPE, "application/json");
        headers
    }

    fn supports_model_listing(&self) -> bool {
        true
    }

    fn models_endpoint(&self) -> &'static str {
        "/api/tags"
    }

    fn model_catalog_format(&self) -> Option<super::ModelCatalogFormat> {
        Some(super::ModelCatalogFormat::Ollama)
    }

    /// Ollama native shape: `message.content`. The default `OpenAI`
    /// extractor would return `None` here because Ollama does not wrap
    /// responses in `choices[]`. See crosslink #479.
    fn extract_response_text(&self, response: &Value) -> Option<String> {
        response
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .map(std::string::ToString::to_string)
    }

    /// Ollama native usage envelope: token counters live at the top
    /// level (`prompt_eval_count` / `eval_count`), not under `usage`.
    /// Ollama has no cache layer, so cache counters are zero.
    /// See crosslink #479.
    fn extract_token_usage(&self, response: &Value) -> Option<TokenUsage> {
        // Require at least one counter to declare "usage was reported"
        // — otherwise an unrelated response with no token data would
        // become an indistinguishable 0/0 record.
        let prompt = response.get("prompt_eval_count").and_then(Value::as_u64);
        let completion = response.get("eval_count").and_then(Value::as_u64);
        if prompt.is_none() && completion.is_none() {
            return None;
        }
        Some(TokenUsage {
            input_tokens: prompt.unwrap_or(0),
            output_tokens: completion.unwrap_or(0),
            cache_read_tokens: 0,
            cache_write_tokens: 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn request_with_messages(messages: Vec<ChatMessage>) -> ChatCompletionRequest {
        ChatCompletionRequest {
            model: "llama3".to_string(),
            messages,
            temperature: None,
            max_tokens: None,
            stream: None,
            tools: None,
            tool_choice: None,
            extra: HashMap::new(),
        }
    }

    fn request_with_tools(tools: Vec<Value>) -> ChatCompletionRequest {
        let mut request = request_with_messages(vec![ChatMessage {
            role: "user".to_string(),
            content: MessageContent::Text("hello".to_string()),
            name: None,
            tool_calls: None,
            tool_call_id: None,
            extra: std::collections::HashMap::new(),
        }]);
        request.tools = Some(tools);
        request
    }

    fn message_with_parts(parts: Vec<ContentPart>) -> ChatMessage {
        ChatMessage {
            role: "user".to_string(),
            content: MessageContent::Parts(parts),
            name: None,
            tool_calls: None,
            tool_call_id: None,
            extra: std::collections::HashMap::new(),
        }
    }

    fn text_part(text: Option<&str>) -> ContentPart {
        ContentPart {
            content_type: "text".to_string(),
            text: text.map(str::to_string),
            image_url: None,
        }
    }

    fn text_message(role: &str, content: &str) -> ChatMessage {
        ChatMessage {
            role: role.to_string(),
            content: MessageContent::Text(content.to_string()),
            name: None,
            tool_calls: None,
            tool_call_id: None,
            extra: HashMap::new(),
        }
    }

    fn assistant_message(content: &str, calls: &[ToolCall]) -> ChatMessage {
        let tool_calls = calls
            .iter()
            .map(|call| {
                json!({
                    "id": call.id,
                    "type": call.call_type,
                    "function": {
                        "name": call.function.name,
                        "arguments": call.function.arguments,
                    }
                })
            })
            .collect();
        ChatMessage {
            role: "assistant".to_string(),
            content: MessageContent::Text(content.to_string()),
            name: None,
            tool_calls: Some(tool_calls),
            tool_call_id: None,
            extra: HashMap::new(),
        }
    }

    fn tool_message(call: &ToolCall, content: &str) -> ChatMessage {
        ChatMessage {
            role: "tool".to_string(),
            content: MessageContent::Text(content.to_string()),
            name: Some(call.function.name.clone()),
            tool_calls: None,
            tool_call_id: Some(call.id.clone()),
            extra: HashMap::new(),
        }
    }

    fn ollama_output(message: &Value, done: bool) -> OllamaChatTurnOutput {
        OllamaChatTurnOutput::new(&json!({
            "model": "qwen3",
            "message": message,
            "done": done
        }))
        .expect("recorded Ollama output must be valid")
    }

    #[test]
    fn transform_request_concatenates_text_content_parts() {
        let request = request_with_messages(vec![message_with_parts(vec![
            text_part(Some("hello")),
            text_part(Some("world")),
        ])]);

        let body = OllamaAdapter::new()
            .transform_request(&request)
            .expect("text parts should convert");

        assert_eq!(body["messages"][0]["content"], "hello\nworld");
    }

    #[test]
    fn typed_tool_image_becomes_one_native_ollama_image() {
        let bytes = b"typed-ollama-image".to_vec();
        let expected = base64::engine::general_purpose::STANDARD.encode(&bytes);
        let attachment = crate::tools::register_transient_attachment(
            "image/png",
            bytes,
            crate::tools::ToolSensitivity::Workspace,
        )
        .expect("register image attachment");
        let call = ToolCall {
            id: "ollama-image-call".to_string(),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "read_file".to_string(),
                arguments: "{}".to_string(),
            },
        };
        let mut result = tool_message(&call, "typed image metadata");
        result.extra.insert(
            crate::tools::TOOL_ATTACHMENTS_MESSAGE_KEY.to_string(),
            serde_json::to_value([attachment]).expect("serialize attachment metadata"),
        );
        let request = request_with_messages(vec![assistant_message("", &[call]), result]);
        let body = OllamaAdapter::transform_request_draft(&request)
            .expect("transform typed Ollama tool image");
        assert_eq!(body["messages"][1]["images"][0], expected);
        assert_eq!(
            serde_json::to_string(&body)
                .expect("serialize Ollama body")
                .matches(&expected)
                .count(),
            1
        );
    }

    #[test]
    fn transform_request_errors_on_text_part_missing_text() {
        let request = request_with_messages(vec![message_with_parts(vec![text_part(None)])]);

        let err = OllamaAdapter::new()
            .transform_request(&request)
            .expect_err("text part without text must fail");

        match err {
            ProviderError::RequestFailed(msg) => assert!(msg.contains("without string"), "{msg}"),
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn transform_request_rejects_image_content_parts() {
        let request = request_with_messages(vec![message_with_parts(vec![ContentPart {
            content_type: "image_url".to_string(),
            text: None,
            image_url: Some(json!({"url": "data:image/png;base64,abc"})),
        }])]);

        let err = OllamaAdapter::new()
            .transform_request(&request)
            .expect_err("image content must not be dropped");

        match err {
            ProviderError::Unsupported(msg) => assert!(msg.contains("image content"), "{msg}"),
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn transform_request_rejects_unknown_content_part_type() {
        let request = request_with_messages(vec![message_with_parts(vec![ContentPart {
            content_type: "input_audio".to_string(),
            text: None,
            image_url: None,
        }])]);

        let err = OllamaAdapter::new()
            .transform_request(&request)
            .expect_err("unknown content part must not be dropped");

        match err {
            ProviderError::Unsupported(msg) => {
                assert!(msg.contains("content part type"), "{msg}");
                assert!(!msg.contains("input_audio"), "{msg}");
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    fn base_tool_response(arguments: &Value) -> Value {
        json!({
            "model": "llama3",
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{
                    "function": {
                        "name": "bash",
                        "arguments": arguments
                    }
                }]
            },
            "done": true
        })
    }

    fn base_text_response() -> Value {
        json!({
            "model": "llama3",
            "message": {
                "role": "assistant",
                "content": "hello"
            },
            "done": true
        })
    }

    #[test]
    fn transform_request_converts_valid_tools() {
        let request = request_with_tools(vec![json!({
            "type": "function",
            "function": {
                "name": "bash",
                "description": "Run a shell command",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string"}
                    }
                }
            }
        })]);

        let body = OllamaAdapter::new()
            .transform_request(&request)
            .expect("valid tool should convert");

        let tool = &body["tools"][0];
        assert_eq!(tool["type"], "function");
        assert_eq!(tool["function"]["name"], "bash");
        assert_eq!(tool["function"]["description"], "Run a shell command");
        assert_eq!(tool["function"]["parameters"]["type"], "object");
    }

    #[test]
    fn transform_request_defaults_optional_tool_fields() {
        let request = request_with_tools(vec![json!({
            "type": "function",
            "function": {"name": "bash"}
        })]);

        let body = OllamaAdapter::new()
            .transform_request(&request)
            .expect("tool without optional fields should convert");

        let function = &body["tools"][0]["function"];
        assert_eq!(function["name"], "bash");
        assert_eq!(function["description"], "");
        assert_eq!(function["parameters"], json!({}));
    }

    #[test]
    fn transform_request_errors_on_tool_missing_function_object() {
        let request = request_with_tools(vec![json!({
            "type": "function",
            "credential": "ollama-tool-secret-sentinel"
        })]);

        let err = OllamaAdapter::new()
            .transform_request(&request)
            .expect_err("missing function object must fail");

        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("function"), "{msg}");
                assert!(!msg.contains("ollama-tool-secret-sentinel"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn transform_request_errors_on_tool_missing_function_name() {
        let request = request_with_tools(vec![json!({
            "type": "function",
            "function": {"description": "no name"}
        })]);

        let err = OllamaAdapter::new()
            .transform_request(&request)
            .expect_err("missing function.name must fail");

        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("function.name"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn transform_request_errors_on_tool_with_empty_function_name() {
        let request = request_with_tools(vec![json!({
            "type": "function",
            "function": {"name": ""}
        })]);

        let err = OllamaAdapter::new()
            .transform_request(&request)
            .expect_err("empty function.name must fail");

        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("function.name"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn transform_request_errors_on_malformed_optional_tool_fields() {
        let bad_description = request_with_tools(vec![json!({
            "type": "function",
            "function": {"name": "bash", "description": {"not": "a string"}}
        })]);
        let err = OllamaAdapter::new()
            .transform_request(&bad_description)
            .expect_err("non-string description must fail");
        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("function.description"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }

        let bad_parameters = request_with_tools(vec![json!({
            "type": "function",
            "function": {"name": "bash", "parameters": []}
        })]);
        let err = OllamaAdapter::new()
            .transform_request(&bad_parameters)
            .expect_err("non-object parameters must fail");
        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("function.parameters"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_serializes_object_tool_arguments() {
        let response = base_tool_response(&json!({"command": "pwd"}));
        let out = OllamaAdapter::new()
            .transform_response(response, false)
            .expect("valid tool call should transform");
        let call = &out["choices"][0]["message"]["tool_calls"][0];
        assert_eq!(call["function"]["name"], "bash");
        assert_eq!(call["function"]["arguments"], r#"{"command":"pwd"}"#);
        assert_eq!(out["choices"][0]["finish_reason"], "tool_calls");
    }

    #[test]
    fn transform_response_errors_on_missing_model() {
        let mut response = base_text_response();
        response.as_object_mut().expect("object").remove("model");

        let err = OllamaAdapter::new()
            .transform_response(response, false)
            .expect_err("missing model must fail");

        match err {
            ProviderError::InvalidResponse(msg) => assert!(msg.contains("'model'"), "{msg}"),
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_errors_on_missing_message_object() {
        let response = json!({
            "model": "llama3",
            "message": null,
            "done": true
        });

        let err = OllamaAdapter::new()
            .transform_response(response, false)
            .expect_err("missing message object must fail");

        match err {
            ProviderError::InvalidResponse(msg) => assert!(msg.contains("'message'"), "{msg}"),
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_errors_on_missing_or_malformed_role() {
        for message in [
            json!({"content": "hello"}),
            json!({"role": "", "content": "hello"}),
            json!({"role": 7, "content": "hello"}),
        ] {
            let response = json!({
                "model": "llama3",
                "message": message,
                "done": true
            });

            let err = OllamaAdapter::new()
                .transform_response(response, false)
                .expect_err("missing or malformed role must fail");

            match err {
                ProviderError::InvalidResponse(msg) => assert!(msg.contains("'role'"), "{msg}"),
                other => panic!("expected InvalidResponse, got {other:?}"),
            }
        }
    }

    #[test]
    fn transform_response_errors_on_unsupported_role() {
        let response = json!({
            "model": "llama3",
            "message": {
                "role": "user",
                "content": "hello"
            },
            "done": true
        });

        let err = OllamaAdapter::new()
            .transform_response(response, false)
            .expect_err("unsupported response role must fail");

        match err {
            ProviderError::InvalidResponse(msg) => {
                assert!(msg.contains("unsupported role"), "{msg}");
                assert!(msg.contains("assistant"), "{msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_errors_on_missing_or_malformed_content() {
        for message in [
            json!({"role": "assistant"}),
            json!({"role": "assistant", "content": null}),
            json!({"role": "assistant", "content": ["not", "a", "string"]}),
        ] {
            let response = json!({
                "model": "llama3",
                "message": message,
                "done": true
            });

            let err = OllamaAdapter::new()
                .transform_response(response, false)
                .expect_err("missing or malformed content must fail");

            match err {
                ProviderError::InvalidResponse(msg) => assert!(msg.contains("'content'"), "{msg}"),
                other => panic!("expected InvalidResponse, got {other:?}"),
            }
        }
    }

    #[test]
    fn transform_response_errors_on_missing_done() {
        let mut response = base_text_response();
        response.as_object_mut().expect("object").remove("done");

        let err = OllamaAdapter::new()
            .transform_response(response, false)
            .expect_err("missing done must fail");

        match err {
            ProviderError::InvalidResponse(msg) => assert!(msg.contains("'done'"), "{msg}"),
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_accepts_stringified_object_tool_arguments() {
        let response = base_tool_response(&json!(r#"{"command":"pwd"}"#));
        let out = OllamaAdapter::new()
            .transform_response(response, false)
            .expect("stringified object arguments should transform");
        let call = &out["choices"][0]["message"]["tool_calls"][0];
        assert_eq!(call["function"]["arguments"], r#"{"command":"pwd"}"#);
    }

    #[test]
    fn transform_response_errors_on_malformed_tool_argument_string() {
        let response = base_tool_response(&json!("{not json"));
        let err = OllamaAdapter::new()
            .transform_response(response, false)
            .expect_err("malformed tool arguments must fail");
        match err {
            ProviderError::InvalidResponse(msg) => {
                assert!(msg.contains("function.arguments"), "{msg}");
                assert!(msg.contains("invalid JSON"), "{msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_errors_on_non_object_tool_arguments() {
        let response = base_tool_response(&json!([]));
        let err = OllamaAdapter::new()
            .transform_response(response, false)
            .expect_err("non-object tool arguments must fail");
        match err {
            ProviderError::InvalidResponse(msg) => {
                assert!(msg.contains("function.arguments"), "{msg}");
                assert!(msg.contains("expected JSON object"), "{msg}");
                assert!(msg.contains("array"), "{msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_errors_on_missing_tool_function_name() {
        let response = json!({
            "model": "llama3",
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [{
                    "function": {"arguments": {"command": "pwd"}}
                }]
            },
            "done": true
        });
        let err = OllamaAdapter::new()
            .transform_response(response, false)
            .expect_err("missing tool name must fail");
        match err {
            ProviderError::InvalidResponse(msg) => {
                assert!(msg.contains("function.name"), "{msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn native_state_replays_two_parallel_tool_rounds_exactly() {
        let first_message = json!({
            "role": "assistant",
            "content": "checking",
            "thinking": "private reasoning retained only in native state",
            "tool_calls": [
                {
                    "type": "function",
                    "function": {
                        "index": 7,
                        "name": "bash",
                        "arguments": {"command": "pwd"}
                    }
                },
                {
                    "type": "function",
                    "function": {
                        "index": 9,
                        "name": "read",
                        "arguments": {"path": "Cargo.toml"}
                    }
                }
            ],
            "provider_extension": {"must_survive": true}
        });
        let first = ollama_output(&first_message, true);
        let first_calls = first.tool_calls(1).expect("first calls project");
        let state = advance_ollama_chat_state("ollama", "qwen3", None, 1, &first)
            .expect("first native turn advances");

        let second_message = json!({
            "role": "assistant",
            "content": "",
            "thinking": "second private reasoning",
            "tool_calls": [{
                "function": {
                    "index": 3,
                    "name": "bash",
                    "arguments": {"command": "cargo metadata --no-deps"}
                }
            }]
        });
        let second = ollama_output(&second_message, true);
        let second_calls = second.tool_calls(4).expect("second calls project");
        let state = advance_ollama_chat_state("ollama", "qwen3", Some(&state), 4, &second)
            .expect("second native turn advances");

        let request = request_with_messages(vec![
            text_message("user", "inspect the repository"),
            assistant_message("checking", &first_calls),
            tool_message(&first_calls[0], r#"{"cwd":"/workspace"}"#),
            tool_message(&first_calls[1], r#"{"text":"manifest"}"#),
            assistant_message("", &second_calls),
            tool_message(&second_calls[0], r#"{"packages":1}"#),
        ]);
        let adapter = OllamaAdapter::new();
        let mut body =
            OllamaAdapter::transform_request_draft(&request).expect("portable history converts");
        adapter
            .apply_provider_native_state(&mut body, &state)
            .expect("native state applies");
        OllamaAdapter::finalize_request(&mut body).expect("request finalizes");

        assert!(body.get(OLLAMA_HISTORY_KEY).is_none());
        let messages = body["messages"].as_array().expect("Ollama messages");
        assert_eq!(messages[1], first_message);
        assert_eq!(messages[4], second_message);
        assert_eq!(messages[2]["role"], "tool");
        assert_eq!(messages[2]["tool_name"], "bash");
        assert_eq!(messages[3]["tool_name"], "read");
        assert_eq!(messages[5]["tool_name"], "bash");
    }

    #[test]
    fn native_history_rejects_incomplete_duplicate_reordered_and_mismatched_calls() {
        let incomplete = ollama_output(
            &json!({"role": "assistant", "content": "still streaming"}),
            false,
        );
        let error = advance_ollama_chat_state("ollama", "qwen3", None, 1, &incomplete)
            .expect_err("incomplete response cannot advance state");
        assert!(error.to_string().contains("incomplete response"));

        let duplicate_indexes = ollama_output(
            &json!({
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {"function": {"index": 4, "name": "bash", "arguments": {}}},
                    {"function": {"index": 4, "name": "read", "arguments": {}}}
                ]
            }),
            true,
        );
        let error = duplicate_indexes
            .tool_calls(1)
            .expect_err("duplicate native indexes must fail");
        assert!(error.to_string().contains("repeats function index"));

        let output = ollama_output(
            &json!({
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {"function": {"index": 0, "name": "bash", "arguments": {"command": "pwd"}}},
                    {"function": {"index": 1, "name": "read", "arguments": {"path": "Cargo.toml"}}}
                ]
            }),
            true,
        );
        let calls = output.tool_calls(1).expect("calls project");
        let missing = request_with_messages(vec![
            text_message("user", "inspect"),
            assistant_message("", &calls),
            tool_message(&calls[0], "first"),
        ]);
        let error =
            OllamaAdapter::transform_request_draft(&missing).expect_err("missing result must fail");
        assert!(error.to_string().contains("missing result"));

        for invalid_results in [
            vec![
                tool_message(&calls[1], "second"),
                tool_message(&calls[0], "first"),
            ],
            vec![
                tool_message(&calls[0], "first"),
                tool_message(&calls[0], "duplicate"),
            ],
        ] {
            let mut messages = vec![
                text_message("user", "inspect"),
                assistant_message("", &calls),
            ];
            messages.extend(invalid_results);
            let error = OllamaAdapter::transform_request_draft(&request_with_messages(messages))
                .expect_err("reordered or duplicate results must fail");
            assert!(error.to_string().contains("reordered"));
        }

        let state = advance_ollama_chat_state("ollama", "qwen3", None, 1, &output)
            .expect("native turn advances");
        let mut mismatched_assistant = assistant_message("", &calls);
        mismatched_assistant
            .tool_calls
            .as_mut()
            .expect("tool calls")[0]["function"]["arguments"] =
            Value::String(r#"{"command":"different"}"#.to_string());
        let mismatched = request_with_messages(vec![
            text_message("user", "inspect"),
            mismatched_assistant,
            tool_message(&calls[0], "first"),
            tool_message(&calls[1], "second"),
        ]);
        let adapter = OllamaAdapter::new();
        let mut body = OllamaAdapter::transform_request_draft(&mismatched)
            .expect("mismatched projection remains structurally valid");
        let error = adapter
            .apply_provider_native_state(&mut body, &state)
            .expect_err("projection/native argument drift must fail");
        assert!(error.to_string().contains("disagrees with native state"));
    }
}
