//! Google Gemini API adapter.

use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use tracing::debug;

use crate::config::ThinkingConfig;
use crate::proxy::{ChatCompletionRequest, ChatMessage, ContentPart, MessageContent};
use crate::runtime::{
    ContinuationGeneration, ProviderNativeItem, ProviderNativeItemPurpose, ProviderNativeState,
    ProviderStateFacet, ProviderWireProtocol,
};
use crate::session::TokenUsage;
use crate::tools::{FunctionCall, ToolCall};

use super::{ProviderAdapter, ProviderError};

const GEMINI_TURN_FORMAT: &str = "gemini_generate_content_turn_v1";
const GEMINI_CONTENT_FORMAT: &str = "gemini_generate_content_content_v1";
const GEMINI_HISTORY_KEY: &str = "_openclaudia_gemini_portable_history";

/// Build a deterministic local identity for older Gemini responses that omit
/// the provider-owned `functionCall.id` field.
fn gemini_tool_call_id(assistant_ordinal: u64, call_index: usize) -> String {
    format!("call_gemini_{assistant_ordinal}_{call_index}")
}

fn provider_error(error: impl std::fmt::Display) -> ProviderError {
    ProviderError::InvalidResponse(error.to_string())
}

fn validate_call_id(id: &str, context: &str) -> Result<(), ProviderError> {
    if id.is_empty() || id.len() > 512 || id.chars().any(char::is_control) {
        Err(provider_error(format!("{context} has an invalid call id")))
    } else {
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
struct GeminiCallBinding {
    portable_id: String,
    provider_id: Option<String>,
    name: String,
    arguments: Value,
    part_index: usize,
}

impl GeminiCallBinding {
    fn to_value(&self) -> Value {
        json!({
            "portable_id": self.portable_id,
            "provider_id": self.provider_id,
            "name": self.name,
            "arguments": self.arguments,
            "part_index": self.part_index,
        })
    }

    fn from_value(value: &Value, index: usize) -> Result<Self, ProviderError> {
        let portable_id = value
            .get("portable_id")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                provider_error(format!("Gemini call binding {index} missing portable_id"))
            })?;
        validate_call_id(portable_id, "Gemini portable call binding")?;
        let provider_id = match value.get("provider_id") {
            None | Some(Value::Null) => None,
            Some(Value::String(id)) => {
                validate_call_id(id, "Gemini provider call binding")?;
                Some(id.clone())
            }
            Some(_) => {
                return Err(provider_error(format!(
                    "Gemini call binding {index} has malformed provider_id"
                )))
            }
        };
        let name = value
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| provider_error(format!("Gemini call binding {index} missing name")))?;
        let arguments = value
            .get("arguments")
            .filter(|arguments| arguments.is_object())
            .cloned()
            .ok_or_else(|| {
                provider_error(format!(
                    "Gemini call binding {index} has malformed arguments"
                ))
            })?;
        let part_index = value
            .get("part_index")
            .and_then(Value::as_u64)
            .and_then(|part_index| usize::try_from(part_index).ok())
            .ok_or_else(|| {
                provider_error(format!(
                    "Gemini call binding {index} has invalid part_index"
                ))
            })?;
        Ok(Self {
            portable_id: portable_id.to_string(),
            provider_id,
            name: name.to_string(),
            arguments,
            part_index,
        })
    }
}

/// Exact provider-owned content from one completed Gemini `GenerateContent` turn.
///
/// The content is retained only in the provider-native state lane. It may
/// contain opaque thought signatures and therefore deliberately does not
/// implement `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct GeminiGenerateContentTurnOutput {
    content: Value,
}

impl GeminiGenerateContentTurnOutput {
    /// Capture and validate `candidates[0].content` without flattening native
    /// parts, call ids, ordering, or thought signatures.
    ///
    /// # Errors
    ///
    /// Returns a typed provider error for a missing/malformed candidate or an
    /// unsupported part that the portable projection cannot represent safely.
    pub fn new(response: &Value) -> Result<Self, ProviderError> {
        let content = response
            .get("candidates")
            .and_then(|candidates| candidates.get(0))
            .and_then(|candidate| candidate.get("content"))
            .filter(|content| content.is_object())
            .cloned()
            .ok_or_else(|| provider_error("Gemini response missing candidates[0].content"))?;
        Self::from_content(content)
    }

    fn from_content(content: Value) -> Result<Self, ProviderError> {
        match content.get("role") {
            None => {}
            Some(Value::String(role)) if role == "model" => {}
            Some(Value::String(_)) => {
                return Err(provider_error(
                    "Gemini candidate content has unsupported role; expected 'model'",
                ))
            }
            Some(_) => {
                return Err(provider_error(
                    "Gemini candidate content has non-string 'role'",
                ))
            }
        }
        let parts = content
            .get("parts")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                provider_error("Gemini candidate content missing 'content.parts' array")
            })?;
        if parts.is_empty() {
            return Err(provider_error("Gemini candidate content has no parts"));
        }
        validate_gemini_parts(parts)?;
        Ok(Self { content })
    }

    /// Borrow the exact native content object.
    #[must_use]
    pub const fn content(&self) -> &Value {
        &self.content
    }

    /// Extract visible text while retaining all native parts separately.
    ///
    /// # Errors
    ///
    /// Returns a provider error for malformed text parts.
    pub fn text(&self) -> Result<String, ProviderError> {
        let parts = self
            .content
            .get("parts")
            .and_then(Value::as_array)
            .ok_or_else(|| provider_error("validated Gemini output lost its parts array"))?;
        extract_gemini_text_content(parts)
    }

    /// Build deterministic portable tool-call projections for this exact turn.
    ///
    /// # Errors
    ///
    /// Returns a provider error for duplicate/invalid native ids or malformed
    /// function-call arguments.
    pub fn tool_calls(&self, assistant_ordinal: u64) -> Result<Vec<ToolCall>, ProviderError> {
        self.call_bindings(assistant_ordinal)?
            .into_iter()
            .map(|binding| {
                let arguments = serde_json::to_string(&binding.arguments).map_err(|error| {
                    provider_error(format!("Gemini arguments failed to serialize: {error}"))
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
    ) -> Result<Vec<GeminiCallBinding>, ProviderError> {
        let parts = self
            .content
            .get("parts")
            .and_then(Value::as_array)
            .expect("validated Gemini output retains parts");
        let mut bindings = Vec::new();
        let mut ids = BTreeSet::new();
        for (part_index, part) in parts.iter().enumerate() {
            let Some(call) = part.get("functionCall") else {
                continue;
            };
            let name = call
                .get("name")
                .and_then(Value::as_str)
                .filter(|name| !name.is_empty())
                .expect("validated Gemini function call retains name");
            let arguments = call
                .get("args")
                .filter(|arguments| arguments.is_object())
                .cloned()
                .expect("validated Gemini function call retains arguments");
            let provider_id = call.get("id").and_then(Value::as_str).map(str::to_string);
            let portable_id = provider_id
                .clone()
                .unwrap_or_else(|| gemini_tool_call_id(assistant_ordinal, bindings.len()));
            validate_call_id(&portable_id, "Gemini functionCall")?;
            if !ids.insert(portable_id.clone()) {
                return Err(provider_error(format!(
                    "Gemini completion repeated function call id {portable_id:?}"
                )));
            }
            bindings.push(GeminiCallBinding {
                portable_id,
                provider_id,
                name: name.to_string(),
                arguments,
                part_index,
            });
        }
        Ok(bindings)
    }
}

fn validate_gemini_parts(parts: &[Value]) -> Result<(), ProviderError> {
    for (index, part) in parts.iter().enumerate() {
        let object = part.as_object().ok_or_else(|| {
            provider_error(format!(
                "Gemini content part at index {index} is not an object"
            ))
        })?;
        if let Some(signature) = object.get("thoughtSignature") {
            if signature.as_str().is_none_or(str::is_empty) {
                return Err(provider_error(format!(
                    "Gemini content part at index {index} has invalid thoughtSignature"
                )));
            }
        }
        if let Some(thought) = object.get("thought") {
            if !thought.is_boolean() {
                return Err(provider_error(format!(
                    "Gemini content part at index {index} has non-boolean thought"
                )));
            }
        }
        match (object.get("text"), object.get("functionCall")) {
            (Some(Value::String(_)), None) => {}
            (Some(_), None) => {
                return Err(provider_error(format!(
                    "Gemini content part at index {index} has non-string 'text'"
                )))
            }
            (None, Some(Value::Object(call))) => {
                let name = call
                    .get("name")
                    .and_then(Value::as_str)
                    .filter(|name| !name.is_empty())
                    .ok_or_else(|| {
                        provider_error(format!(
                            "Gemini functionCall at part {index} missing non-empty name"
                        ))
                    })?;
                let _ = name;
                if !call.get("args").is_some_and(Value::is_object) {
                    return Err(provider_error(format!(
                        "Gemini functionCall at part {index} missing object args"
                    )));
                }
                if let Some(id) = call.get("id") {
                    let id = id.as_str().ok_or_else(|| {
                        provider_error(format!(
                            "Gemini functionCall at part {index} has non-string id"
                        ))
                    })?;
                    validate_call_id(id, "Gemini functionCall")?;
                }
            }
            (None, Some(_)) => {
                return Err(provider_error(format!(
                    "Gemini functionCall at part {index} is not an object"
                )))
            }
            (Some(_), Some(_)) => {
                return Err(provider_error(format!(
                    "Gemini content part at index {index} mixes text and functionCall"
                )))
            }
            (None, None) => {
                return Err(provider_error(format!(
                "Gemini content part at index {index} has no supported text or functionCall field"
            )))
            }
        }
    }
    Ok(())
}

#[derive(Clone)]
struct GeminiReplayGroup {
    content: Value,
    calls: Vec<GeminiCallBinding>,
}

fn gemini_content_facet(
    output: &GeminiGenerateContentTurnOutput,
    call_count: usize,
) -> ProviderStateFacet {
    if call_count > 1 {
        ProviderStateFacet::ParallelToolCalls
    } else if call_count == 1 {
        ProviderStateFacet::ToolCalls
    } else if output
        .content()
        .get("parts")
        .and_then(Value::as_array)
        .is_some_and(|parts| {
            parts
                .iter()
                .any(|part| part.get("thoughtSignature").is_some())
        })
    {
        ProviderStateFacet::Reasoning
    } else {
        ProviderStateFacet::NativeMessage
    }
}

fn parse_gemini_turn_header(
    payload: &Value,
) -> Result<(u64, Vec<GeminiCallBinding>), ProviderError> {
    if payload.get("format").and_then(Value::as_str) != Some(GEMINI_TURN_FORMAT) {
        return Err(provider_error("unrecognized Gemini turn evidence format"));
    }
    let ordinal = payload
        .get("assistant_ordinal")
        .and_then(Value::as_u64)
        .ok_or_else(|| provider_error("Gemini turn evidence missing assistant_ordinal"))?;
    if payload.get("content_count").and_then(Value::as_u64) != Some(1) {
        return Err(provider_error(
            "Gemini turn evidence must bind exactly one content object",
        ));
    }
    let calls = payload
        .get("tool_calls")
        .and_then(Value::as_array)
        .ok_or_else(|| provider_error("Gemini turn evidence missing tool_calls array"))?
        .iter()
        .enumerate()
        .map(|(index, value)| GeminiCallBinding::from_value(value, index))
        .collect::<Result<Vec<_>, _>>()?;
    let mut ids = BTreeSet::new();
    for call in &calls {
        if !ids.insert(call.portable_id.clone()) {
            return Err(provider_error(format!(
                "Gemini turn evidence repeats portable call id {:?}",
                call.portable_id
            )));
        }
    }
    Ok((ordinal, calls))
}

fn parse_gemini_replay_groups(
    state: &ProviderNativeState,
) -> Result<BTreeMap<u64, GeminiReplayGroup>, ProviderError> {
    let mut groups = BTreeMap::new();
    let mut pending: Option<(u64, Vec<GeminiCallBinding>)> = None;
    let mut all_call_ids = BTreeSet::new();
    let mut previous_ordinal = None;

    for item in state.items() {
        match item.purpose() {
            ProviderNativeItemPurpose::Evidence => {
                if pending.is_some() {
                    return Err(provider_error(
                        "Gemini turn evidence is missing its native content item",
                    ));
                }
                if item.facet() != ProviderStateFacet::NativeMessage {
                    return Err(provider_error(
                        "Gemini turn evidence has the wrong native-state facet",
                    ));
                }
                let (ordinal, calls) = parse_gemini_turn_header(item.payload())?;
                if previous_ordinal.is_some_and(|previous| previous >= ordinal) {
                    return Err(provider_error(format!(
                        "Gemini assistant ordinal {ordinal} is not ordered after the prior turn"
                    )));
                }
                for call in &calls {
                    if !all_call_ids.insert(call.portable_id.clone()) {
                        return Err(provider_error(format!(
                            "Gemini continuation repeats call id {:?}",
                            call.portable_id
                        )));
                    }
                }
                previous_ordinal = Some(ordinal);
                pending = Some((ordinal, calls));
            }
            ProviderNativeItemPurpose::Continuation => {
                let (ordinal, expected_calls) = pending.take().ok_or_else(|| {
                    provider_error("Gemini native content has no preceding turn evidence")
                })?;
                let payload = item.payload();
                if payload.get("format").and_then(Value::as_str) != Some(GEMINI_CONTENT_FORMAT) {
                    return Err(provider_error("unrecognized Gemini native content format"));
                }
                if payload.get("assistant_ordinal").and_then(Value::as_u64) != Some(ordinal) {
                    return Err(provider_error(format!(
                        "Gemini native content does not match assistant ordinal {ordinal}"
                    )));
                }
                let content = payload
                    .get("content")
                    .filter(|content| content.is_object())
                    .cloned()
                    .ok_or_else(|| provider_error("Gemini native content payload is malformed"))?;
                let output = GeminiGenerateContentTurnOutput::from_content(content.clone())?;
                let actual_calls = output.call_bindings(ordinal)?;
                if actual_calls != expected_calls {
                    return Err(provider_error(format!(
                        "Gemini native content call mapping disagrees at assistant ordinal {ordinal}"
                    )));
                }
                let expected_facet = gemini_content_facet(&output, actual_calls.len());
                if item.facet() != expected_facet {
                    return Err(provider_error(format!(
                        "Gemini native content facet {:?} does not match {expected_facet:?}",
                        item.facet()
                    )));
                }
                if groups
                    .insert(
                        ordinal,
                        GeminiReplayGroup {
                            content,
                            calls: actual_calls,
                        },
                    )
                    .is_some()
                {
                    return Err(provider_error(format!(
                        "duplicate Gemini assistant ordinal {ordinal}"
                    )));
                }
            }
        }
    }
    if pending.is_some() {
        return Err(provider_error(
            "Gemini turn evidence is missing its native content item",
        ));
    }
    let turn_count = u64::try_from(groups.len())
        .map_err(|_| provider_error("Gemini continuation turn count overflow"))?;
    if turn_count != state.generation().get() {
        return Err(provider_error(format!(
            "Gemini continuation generation {} does not match its {turn_count} retained turns",
            state.generation().get()
        )));
    }
    Ok(groups)
}

/// Advance a Gemini `GenerateContent` continuation with one exact completed turn.
///
/// # Errors
///
/// Returns a provider error for identity/protocol drift, duplicate or stale
/// assistant/call identity, malformed native output, generation exhaustion, or
/// the S-044 item/byte bounds.
pub fn advance_gemini_generate_content_state(
    provider: &str,
    model: &str,
    previous: Option<&ProviderNativeState>,
    assistant_ordinal: u64,
    output: &GeminiGenerateContentTurnOutput,
) -> Result<ProviderNativeState, ProviderError> {
    let mut items = if let Some(previous) = previous {
        previous
            .validate_binding(provider, model, ProviderWireProtocol::GeminiGenerateContent)
            .map_err(provider_error)?;
        super::GEMINI_GENERATE_CONTENT_STATE_CONTRACT
            .validate_state(previous)
            .map_err(provider_error)?;
        let groups = parse_gemini_replay_groups(previous)?;
        if groups
            .last_key_value()
            .is_some_and(|(ordinal, _)| *ordinal >= assistant_ordinal)
        {
            return Err(provider_error(format!(
                "Gemini assistant ordinal {assistant_ordinal} does not advance the continuation"
            )));
        }
        previous.items().to_vec()
    } else {
        Vec::new()
    };

    let calls = output.call_bindings(assistant_ordinal)?;
    if let Some(previous) = previous {
        let previous_groups = parse_gemini_replay_groups(previous)?;
        let previous_ids = previous_groups
            .values()
            .flat_map(|group| group.calls.iter().map(|call| call.portable_id.as_str()))
            .collect::<BTreeSet<_>>();
        if let Some(duplicate) = calls
            .iter()
            .find(|call| previous_ids.contains(call.portable_id.as_str()))
        {
            return Err(provider_error(format!(
                "Gemini call id {:?} was already captured",
                duplicate.portable_id
            )));
        }
    }

    items.push(
        ProviderNativeItem::new(
            ProviderStateFacet::NativeMessage,
            ProviderNativeItemPurpose::Evidence,
            json!({
                "format": GEMINI_TURN_FORMAT,
                "assistant_ordinal": assistant_ordinal,
                "content_count": 1,
                "tool_calls": calls.iter().map(GeminiCallBinding::to_value).collect::<Vec<_>>(),
            }),
        )
        .map_err(provider_error)?,
    );
    items.push(
        ProviderNativeItem::new(
            gemini_content_facet(output, calls.len()),
            ProviderNativeItemPurpose::Continuation,
            json!({
                "format": GEMINI_CONTENT_FORMAT,
                "assistant_ordinal": assistant_ordinal,
                "content": output.content(),
            }),
        )
        .map_err(provider_error)?,
    );

    let generation = match previous {
        Some(state) => state
            .generation()
            .get()
            .checked_add(1)
            .ok_or_else(|| provider_error("Gemini continuation generation exhausted"))?,
        None => 1,
    };
    let generation = ContinuationGeneration::new(generation)
        .ok_or_else(|| provider_error("Gemini continuation generation exhausted"))?;
    let state = ProviderNativeState::new(
        provider,
        model,
        ProviderWireProtocol::GeminiGenerateContent,
        generation,
        items,
    )
    .map_err(provider_error)?;
    super::GEMINI_GENERATE_CONTENT_STATE_CONTRACT
        .validate_state(&state)
        .map_err(provider_error)?;
    parse_gemini_replay_groups(&state)?;
    Ok(state)
}

fn binding_wire_index(entry: &Value, ordinal: u64) -> Result<usize, ProviderError> {
    entry
        .get("wire_index")
        .and_then(Value::as_u64)
        .and_then(|index| usize::try_from(index).ok())
        .ok_or_else(|| {
            provider_error(format!(
                "Gemini portable history ordinal {ordinal} has invalid wire_index"
            ))
        })
}

fn validate_bound_assistant_calls(
    entry: &Value,
    ordinal: u64,
    expected: &[GeminiCallBinding],
) -> Result<(), ProviderError> {
    let calls = entry
        .get("tool_calls")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            provider_error(format!(
                "Gemini assistant history binding {ordinal} missing tool_calls"
            ))
        })?;
    if calls.len() != expected.len() {
        return Err(provider_error(format!(
            "Gemini assistant history binding {ordinal} has {} calls; expected {}",
            calls.len(),
            expected.len()
        )));
    }
    for (index, (actual, expected)) in calls.iter().zip(expected).enumerate() {
        let id = actual.get("id").and_then(Value::as_str).ok_or_else(|| {
            provider_error(format!(
                "Gemini assistant binding {ordinal} call {index} missing id"
            ))
        })?;
        let name = actual.get("name").and_then(Value::as_str).ok_or_else(|| {
            provider_error(format!(
                "Gemini assistant binding {ordinal} call {index} missing name"
            ))
        })?;
        let arguments = actual
            .get("arguments")
            .filter(|arguments| arguments.is_object())
            .ok_or_else(|| {
                provider_error(format!(
                    "Gemini assistant binding {ordinal} call {index} has malformed arguments"
                ))
            })?;
        if id != expected.portable_id || name != expected.name || arguments != &expected.arguments {
            return Err(provider_error(format!(
                "Gemini assistant binding {ordinal} call {index} disagrees with native state"
            )));
        }
    }
    Ok(())
}

fn rewrite_bound_function_response(
    contents: &mut [Value],
    entry: &Value,
    ordinal: u64,
    expected: &GeminiCallBinding,
) -> Result<(), ProviderError> {
    let call_id = entry
        .get("tool_call_id")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            provider_error(format!(
                "Gemini tool history binding {ordinal} missing tool_call_id"
            ))
        })?;
    let name = entry.get("name").and_then(Value::as_str).ok_or_else(|| {
        provider_error(format!(
            "Gemini tool history binding {ordinal} missing name"
        ))
    })?;
    if call_id != expected.portable_id || name != expected.name {
        return Err(provider_error(format!(
            "Gemini tool result at ordinal {ordinal} is missing, duplicated, or reordered"
        )));
    }
    let wire_index = binding_wire_index(entry, ordinal)?;
    let part_index = entry
        .get("part_index")
        .and_then(Value::as_u64)
        .and_then(|index| usize::try_from(index).ok())
        .ok_or_else(|| {
            provider_error(format!(
                "Gemini tool history binding {ordinal} has invalid part_index"
            ))
        })?;
    let response = contents
        .get_mut(wire_index)
        .and_then(|content| content.get_mut("parts"))
        .and_then(Value::as_array_mut)
        .and_then(|parts| parts.get_mut(part_index))
        .and_then(|part| part.get_mut("functionResponse"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| {
            provider_error(format!(
                "Gemini tool result at ordinal {ordinal} lost its functionResponse projection"
            ))
        })?;
    if response.get("id").and_then(Value::as_str) != Some(call_id)
        || response.get("name").and_then(Value::as_str) != Some(name)
        || !response.get("response").is_some_and(Value::is_object)
    {
        return Err(provider_error(format!(
            "Gemini functionResponse at ordinal {ordinal} disagrees with portable history"
        )));
    }
    if let Some(provider_id) = &expected.provider_id {
        response.insert("id".to_string(), Value::String(provider_id.clone()));
    } else {
        response.remove("id");
    }
    Ok(())
}

fn validate_contiguous_gemini_history(history: &[Value]) -> Result<(), ProviderError> {
    for (expected, entry) in history.iter().enumerate() {
        let expected = u64::try_from(expected)
            .map_err(|_| provider_error("Gemini portable history count overflow"))?;
        if entry.get("ordinal").and_then(Value::as_u64) != Some(expected) {
            return Err(provider_error(
                "Gemini portable history bindings are not contiguous",
            ));
        }
    }
    Ok(())
}

fn validate_complete_gemini_bindings(
    history: &[Value],
    bound_assistants: &BTreeSet<u64>,
    bound_results: &BTreeSet<u64>,
) -> Result<(), ProviderError> {
    for entry in history {
        let ordinal = entry
            .get("ordinal")
            .and_then(Value::as_u64)
            .expect("contiguous history binding retains ordinal");
        match entry.get("role").and_then(Value::as_str) {
            Some("assistant") => {
                let has_calls = entry
                    .get("tool_calls")
                    .and_then(Value::as_array)
                    .is_some_and(|calls| !calls.is_empty());
                if has_calls && !bound_assistants.contains(&ordinal) {
                    return Err(provider_error(format!(
                        "Gemini assistant tool history at ordinal {ordinal} has no native state"
                    )));
                }
            }
            Some("tool") if !bound_results.contains(&ordinal) => {
                return Err(provider_error(format!(
                    "Gemini tool result at ordinal {ordinal} is orphaned"
                )));
            }
            Some("user" | "tool") => {}
            Some(role) => {
                return Err(provider_error(format!(
                    "Gemini portable history has unsupported binding role {role:?}"
                )));
            }
            None => return Err(provider_error("Gemini history binding missing role")),
        }
    }
    Ok(())
}

fn apply_gemini_state(
    request: &mut Value,
    state: &ProviderNativeState,
) -> Result<(), ProviderError> {
    super::GEMINI_GENERATE_CONTENT_STATE_CONTRACT
        .validate_state(state)
        .map_err(provider_error)?;
    let history = request
        .as_object_mut()
        .ok_or_else(|| provider_error("Gemini request must be an object"))?
        .remove(GEMINI_HISTORY_KEY)
        .ok_or_else(|| provider_error("Gemini request is missing portable history bindings"))?;
    let history = history
        .as_array()
        .ok_or_else(|| provider_error("Gemini portable history binding must be an array"))?;
    validate_contiguous_gemini_history(history)?;

    let groups = parse_gemini_replay_groups(state)?;
    let contents = request
        .get_mut("contents")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| provider_error("Gemini request contents must be an array"))?;
    let mut bound_assistants = BTreeSet::new();
    let mut bound_results = BTreeSet::new();

    for (ordinal, group) in &groups {
        let entry_index = usize::try_from(*ordinal)
            .map_err(|_| provider_error("Gemini assistant ordinal overflow"))?;
        let entry = history.get(entry_index).ok_or_else(|| {
            provider_error(format!(
                "Gemini native state references missing assistant ordinal {ordinal}"
            ))
        })?;
        if entry.get("role").and_then(Value::as_str) != Some("assistant") {
            return Err(provider_error(format!(
                "Gemini native turn at ordinal {ordinal} is not bound to an assistant message"
            )));
        }
        validate_bound_assistant_calls(entry, *ordinal, &group.calls)?;
        let wire_index = binding_wire_index(entry, *ordinal)?;
        let projected = contents.get(wire_index).ok_or_else(|| {
            provider_error(format!(
                "Gemini assistant ordinal {ordinal} references missing wire message"
            ))
        })?;
        if projected.get("role").and_then(Value::as_str) != Some("model") {
            return Err(provider_error(format!(
                "Gemini assistant ordinal {ordinal} lost its model projection"
            )));
        }
        contents[wire_index] = group.content.clone();
        bound_assistants.insert(*ordinal);

        for (call_index, call) in group.calls.iter().enumerate() {
            let result_ordinal = ordinal
                .checked_add(1)
                .and_then(|ordinal| ordinal.checked_add(u64::try_from(call_index).ok()?))
                .ok_or_else(|| provider_error("Gemini tool result ordinal overflow"))?;
            let result_index = usize::try_from(result_ordinal)
                .map_err(|_| provider_error("Gemini tool result ordinal overflow"))?;
            let result_entry = history.get(result_index).ok_or_else(|| {
                provider_error(format!(
                    "Gemini call {:?} is missing its tool result",
                    call.portable_id
                ))
            })?;
            if result_entry.get("role").and_then(Value::as_str) != Some("tool") {
                return Err(provider_error(format!(
                    "Gemini call {:?} is missing its ordered tool result",
                    call.portable_id
                )));
            }
            rewrite_bound_function_response(contents, result_entry, result_ordinal, call)?;
            if !bound_results.insert(result_ordinal) {
                return Err(provider_error(format!(
                    "Gemini tool result ordinal {result_ordinal} is bound more than once"
                )));
            }
        }
    }

    validate_complete_gemini_bindings(history, &bound_assistants, &bound_results)
}

/// Adapt the JSON Schema keywords used by the canonical registry to Gemini's
/// `parametersJsonSchema` dialect.
///
/// Gemini does not accept JSON Schema's `const` keyword for function
/// declarations. A one-element `enum` has the same model-facing constraint;
/// canonical host validation remains authoritative when the call returns.
fn normalize_gemini_json_schema(schema: &mut Value) {
    let Some(object) = schema.as_object_mut() else {
        return;
    };

    if let Some(constant) = object.remove("const") {
        object.insert("enum".to_string(), Value::Array(vec![constant]));
    }

    for map_key in ["properties", "$defs", "definitions", "patternProperties"] {
        if let Some(children) = object.get_mut(map_key).and_then(Value::as_object_mut) {
            for child in children.values_mut() {
                normalize_gemini_json_schema(child);
            }
        }
    }

    for schema_key in [
        "items",
        "additionalProperties",
        "not",
        "contains",
        "propertyNames",
        "if",
        "then",
        "else",
    ] {
        if let Some(child) = object.get_mut(schema_key) {
            normalize_gemini_json_schema(child);
        }
    }

    for schema_array_key in ["anyOf", "oneOf", "allOf", "prefixItems"] {
        if let Some(children) = object
            .get_mut(schema_array_key)
            .and_then(Value::as_array_mut)
        {
            for child in children {
                normalize_gemini_json_schema(child);
            }
        }
    }
}

/// Convert `OpenAI` tools to Gemini function declarations.
///
/// # Errors
///
/// Returns [`ProviderError::RequestFailed`] when a tool definition is missing
/// a `function` object, a non-empty `function.name`, or contains malformed
/// optional `function.description` / `function.parameters` fields.
pub fn convert_tools_to_gemini_functions(tools: &[Value]) -> Result<Vec<Value>, ProviderError> {
    let mut functions = Vec::with_capacity(tools.len());

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

        let mut parameters_json_schema = match func.get("parameters") {
            None => json!({}),
            Some(value @ Value::Object(_)) => value.clone(),
            Some(_) => {
                return Err(ProviderError::RequestFailed(format!(
                    "Tool at index {index} has non-object 'function.parameters'"
                )));
            }
        };
        normalize_gemini_json_schema(&mut parameters_json_schema);

        functions.push(json!({
            "name": name,
            "description": description,
            "parametersJsonSchema": parameters_json_schema
        }));
    }

    Ok(functions)
}

/// Convert `OpenAI` tools to Gemini's top-level `tools` array.
///
/// # Errors
///
/// Returns [`ProviderError::RequestFailed`] when any tool definition is
/// malformed.
pub fn convert_tools_to_gemini(tools: &[Value]) -> Result<Value, ProviderError> {
    let functions = convert_tools_to_gemini_functions(tools)?;
    Ok(json!([{"functionDeclarations": functions}]))
}

/// Google Gemini API adapter
pub struct GoogleAdapter;

#[derive(Clone)]
struct PortableGeminiCall {
    id: String,
    name: String,
    arguments: Value,
}

fn parse_portable_gemini_calls(
    message: &ChatMessage,
    message_index: usize,
) -> Result<Vec<PortableGeminiCall>, ProviderError> {
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
                    "Google assistant message at index {message_index} tool_call[{call_index}] missing non-empty id"
                ))
            })?;
        validate_call_id(id, "Google portable tool call")
            .map_err(|error| ProviderError::RequestFailed(error.to_string()))?;
        if !ids.insert(id.to_string()) {
            return Err(ProviderError::RequestFailed(format!(
                "Google assistant message at index {message_index} repeats tool call id {id:?}"
            )));
        }
        if call.get("type").and_then(Value::as_str) != Some("function") {
            return Err(ProviderError::RequestFailed(format!(
                "Google assistant message at index {message_index} tool_call[{call_index}] must have type 'function'"
            )));
        }
        let function = call
            .get("function")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                ProviderError::RequestFailed(format!(
                    "Google assistant message at index {message_index} tool_call[{call_index}] missing function object"
                ))
            })?;
        let name = function
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| {
                ProviderError::RequestFailed(format!(
                    "Google assistant message at index {message_index} tool_call[{call_index}] missing function.name"
                ))
            })?;
        let arguments_text = function
            .get("arguments")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProviderError::RequestFailed(format!(
                    "Google assistant message at index {message_index} tool_call[{call_index}] missing string function.arguments"
                ))
            })?;
        let arguments = serde_json::from_str::<Value>(arguments_text).map_err(|error| {
            ProviderError::RequestFailed(format!(
                "Google assistant message at index {message_index} tool_call[{call_index}] has invalid JSON arguments: {error}"
            ))
        })?;
        if !arguments.is_object() {
            return Err(ProviderError::RequestFailed(format!(
                "Google assistant message at index {message_index} tool_call[{call_index}] arguments must encode an object"
            )));
        }
        calls.push(PortableGeminiCall {
            id: id.to_string(),
            name: name.to_string(),
            arguments,
        });
    }
    Ok(calls)
}

fn gemini_tool_result_payload(
    message: &ChatMessage,
    message_index: usize,
) -> Result<Value, ProviderError> {
    let MessageContent::Text(content) = &message.content else {
        return Err(ProviderError::Unsupported(format!(
            "Google tool message at index {message_index} must use text content"
        )));
    };
    match serde_json::from_str::<Value>(content) {
        Ok(Value::Object(object)) => Ok(Value::Object(object)),
        Ok(value) => Ok(json!({"result": value})),
        Err(_) => Ok(json!({"result": content})),
    }
}

#[derive(Default)]
struct GeminiHistoryBuilder {
    converted: Vec<Value>,
    history: Vec<Value>,
    portable_ordinal: u64,
    pending_calls: VecDeque<PortableGeminiCall>,
    tool_result_wire_index: Option<usize>,
}

impl GeminiHistoryBuilder {
    fn push(&mut self, message: &ChatMessage, message_index: usize) -> Result<(), ProviderError> {
        if message.role == "system" {
            return self.validate_system(message, message_index);
        }
        let ordinal = self.portable_ordinal;
        self.portable_ordinal = self.portable_ordinal.checked_add(1).ok_or_else(|| {
            ProviderError::RequestFailed("Google portable history ordinal overflow".to_string())
        })?;
        match message.role.as_str() {
            "assistant" => self.push_assistant(message, message_index, ordinal),
            "tool" => self.push_tool(message, message_index, ordinal),
            _ => self.push_user(message, message_index, ordinal),
        }
    }

    fn validate_system(
        &self,
        message: &ChatMessage,
        message_index: usize,
    ) -> Result<(), ProviderError> {
        if !self.pending_calls.is_empty() {
            return Err(ProviderError::RequestFailed(format!(
                "Google system message at index {message_index} interrupts tool results"
            )));
        }
        if message.tool_calls.is_some() || message.tool_call_id.is_some() {
            return Err(ProviderError::RequestFailed(format!(
                "Google system message at index {message_index} carries tool protocol fields"
            )));
        }
        Ok(())
    }

    fn push_user(
        &mut self,
        message: &ChatMessage,
        message_index: usize,
        ordinal: u64,
    ) -> Result<(), ProviderError> {
        if !self.pending_calls.is_empty() {
            return Err(ProviderError::RequestFailed(format!(
                "Google message at index {message_index} arrived before all prior tool results"
            )));
        }
        if message.tool_calls.is_some() || message.tool_call_id.is_some() {
            return Err(ProviderError::RequestFailed(format!(
                "Google user message at index {message_index} carries tool protocol fields"
            )));
        }
        let parts = match &message.content {
            MessageContent::Text(text) => vec![json!({"text": text})],
            MessageContent::Parts(parts) => {
                GoogleAdapter::convert_content_parts(message_index, &message.role, parts)?
            }
        };
        let wire_index = self.converted.len();
        self.converted.push(json!({"role": "user", "parts": parts}));
        self.history.push(json!({
            "ordinal": ordinal,
            "wire_index": wire_index,
            "role": "user",
        }));
        self.tool_result_wire_index = None;
        Ok(())
    }

    fn push_assistant(
        &mut self,
        message: &ChatMessage,
        message_index: usize,
        ordinal: u64,
    ) -> Result<(), ProviderError> {
        if !self.pending_calls.is_empty() {
            return Err(ProviderError::RequestFailed(format!(
                "Google assistant message at index {message_index} arrived before all prior tool results"
            )));
        }
        if message.tool_call_id.is_some() {
            return Err(ProviderError::RequestFailed(format!(
                "Google assistant message at index {message_index} carries tool_call_id"
            )));
        }
        let calls = parse_portable_gemini_calls(message, message_index)?;
        let mut parts = match &message.content {
            MessageContent::Text(text) => (!text.is_empty())
                .then(|| json!({"text": text}))
                .into_iter()
                .collect(),
            MessageContent::Parts(parts) => {
                GoogleAdapter::convert_content_parts(message_index, &message.role, parts)?
            }
        };
        parts.extend(calls.iter().map(|call| {
            json!({
                "functionCall": {
                    "id": call.id,
                    "name": call.name,
                    "args": call.arguments,
                }
            })
        }));
        if parts.is_empty() {
            parts.push(json!({"text": ""}));
        }
        let wire_index = self.converted.len();
        self.converted
            .push(json!({"role": "model", "parts": parts}));
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
        self.tool_result_wire_index = None;
        Ok(())
    }

    fn push_tool(
        &mut self,
        message: &ChatMessage,
        message_index: usize,
        ordinal: u64,
    ) -> Result<(), ProviderError> {
        if message.tool_calls.is_some() {
            return Err(ProviderError::RequestFailed(format!(
                "Google tool message at index {message_index} carries tool_calls"
            )));
        }
        let call_id = message
            .tool_call_id
            .as_deref()
            .filter(|id| !id.is_empty())
            .ok_or_else(|| {
                ProviderError::RequestFailed(format!(
                    "Google tool message at index {message_index} missing tool_call_id"
                ))
            })?;
        let expected = self.pending_calls.front().ok_or_else(|| {
            ProviderError::RequestFailed(format!(
                "Google tool message at index {message_index} is orphaned"
            ))
        })?;
        if expected.id != call_id {
            return Err(ProviderError::RequestFailed(format!(
                "Google tool result at index {message_index} is reordered: expected {:?}, found {call_id:?}",
                expected.id
            )));
        }
        if message
            .name
            .as_deref()
            .is_some_and(|name| name != expected.name)
        {
            return Err(ProviderError::RequestFailed(format!(
                "Google tool result at index {message_index} name does not match call {call_id:?}"
            )));
        }
        let response = gemini_tool_result_payload(message, message_index)?;
        let wire_index = self.tool_result_wire_index.unwrap_or_else(|| {
            let wire_index = self.converted.len();
            self.converted.push(json!({"role": "user", "parts": []}));
            self.tool_result_wire_index = Some(wire_index);
            wire_index
        });
        let parts = self.converted[wire_index]
            .get_mut("parts")
            .and_then(Value::as_array_mut)
            .expect("tool result batch owns parts array");
        let part_index = parts.len();
        parts.push(json!({
            "functionResponse": {
                "id": expected.id,
                "name": expected.name,
                "response": response,
            }
        }));
        self.history.push(json!({
            "ordinal": ordinal,
            "wire_index": wire_index,
            "part_index": part_index,
            "role": "tool",
            "tool_call_id": expected.id,
            "name": expected.name,
        }));
        self.pending_calls.pop_front();
        if self.pending_calls.is_empty() {
            self.tool_result_wire_index = None;
        }
        Ok(())
    }

    fn finish(self) -> Result<(Vec<Value>, Vec<Value>), ProviderError> {
        if let Some(call) = self.pending_calls.front() {
            return Err(ProviderError::RequestFailed(format!(
                "Google history is missing result for tool call {:?}",
                call.id
            )));
        }
        Ok((self.converted, self.history))
    }
}

impl GoogleAdapter {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Convert `OpenAI` messages to Gemini format
    fn convert_messages(
        messages: &[ChatMessage],
    ) -> Result<(Vec<Value>, Vec<Value>), ProviderError> {
        let mut builder = GeminiHistoryBuilder::default();
        for (message_index, message) in messages.iter().enumerate() {
            builder.push(message, message_index)?;
        }
        builder.finish()
    }

    fn convert_content_parts(
        msg_index: usize,
        _role: &str,
        parts: &[ContentPart],
    ) -> Result<Vec<Value>, ProviderError> {
        let mut converted = Vec::with_capacity(parts.len());

        for (part_index, part) in parts.iter().enumerate() {
            match part.content_type.as_str() {
                "text" => {
                    let text = part.text.as_ref().ok_or_else(|| {
                        ProviderError::RequestFailed(format!(
                            "Google message at index {msg_index} text part at \
                             index {part_index} missing 'text'"
                        ))
                    })?;
                    converted.push(json!({"text": text}));
                }
                "image" | "image_url" => {
                    let image = part.image_url.as_ref().ok_or_else(|| {
                        ProviderError::RequestFailed(format!(
                            "Google message at index {msg_index} image part at \
                             index {part_index} missing 'image_url'"
                        ))
                    })?;
                    converted.push(json!({"inlineData": image}));
                }
                _ => {
                    return Err(ProviderError::RequestFailed(format!(
                        "Unsupported Google content part type at message index {msg_index}, \
                         part index {part_index}"
                    )));
                }
            }
        }

        if converted.is_empty() {
            return Err(ProviderError::RequestFailed(format!(
                "Google message at index {msg_index} has no content parts"
            )));
        }

        Ok(converted)
    }

    fn transform_request_draft(request: &ChatCompletionRequest) -> Result<Value, ProviderError> {
        let (contents, history) = Self::convert_messages(&request.messages)?;
        let mut body = json!({
            "contents": contents,
            GEMINI_HISTORY_KEY: history,
        });

        if let Some(system) = Self::extract_system(&request.messages) {
            body["systemInstruction"] = system;
        }

        let mut generation_config = json!({});
        if let Some(temperature) = request.temperature {
            generation_config["temperature"] = json!(temperature);
        }
        if let Some(max_tokens) = request.max_tokens {
            generation_config["maxOutputTokens"] = json!(max_tokens);
        }
        if generation_config != json!({}) {
            body["generationConfig"] = generation_config;
        }

        if let Some(tools) = &request.tools {
            body["tools"] = convert_tools_to_gemini(tools)?;
        }
        Ok(body)
    }

    pub(crate) fn transform_request_draft_with_thinking(
        request: &ChatCompletionRequest,
        thinking: Option<&ThinkingConfig>,
    ) -> Result<Value, ProviderError> {
        let mut body = Self::transform_request_draft(request)?;
        if let Some(thinking) = thinking.filter(|thinking| thinking.enabled) {
            let profile = super::resolve_model("google", &request.model)
                .capabilities()
                .reasoning_profile;
            if profile == super::ReasoningProfile::GeminiThinking {
                let budget = thinking.effective_budget(8192).min(32768);
                if body.get("generationConfig").is_none() {
                    body["generationConfig"] = json!({});
                }
                body["generationConfig"]["thinkingConfig"] = json!({
                    "thinkingBudget": budget
                });
            } else {
                tracing::warn!(
                    model = %request.model,
                    "thinking requested without current Gemini model-capability evidence; omitting thinkingConfig",
                );
            }
        }
        Ok(body)
    }

    pub(crate) fn finalize_request(request: &mut Value) -> Result<(), ProviderError> {
        let history = request
            .as_object_mut()
            .ok_or_else(|| provider_error("Gemini request must be an object"))?
            .remove(GEMINI_HISTORY_KEY);
        let Some(history) = history else {
            return Ok(());
        };
        let history = history
            .as_array()
            .ok_or_else(|| provider_error("Gemini portable history binding must be an array"))?;
        let has_unbound_tool_history = history.iter().any(|entry| {
            entry.get("role").and_then(Value::as_str) == Some("tool")
                || entry
                    .get("tool_calls")
                    .and_then(Value::as_array)
                    .is_some_and(|calls| !calls.is_empty())
        });
        if has_unbound_tool_history {
            return Err(ProviderError::Unsupported(
                "Gemini tool history requires its provider-native state; exact call ids and thought signatures are unavailable"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Extract system instruction.
    ///
    /// Crosslink #924: previously `.iter().find(...)` returned only the
    /// FIRST `system` role message. Gemini accepts a single
    /// `systemInstruction.parts[]`, so we concatenate every system-role
    /// text with `\n\n` separators rather than silently dropping later
    /// ones. Non-text parts surface a `warn!`.
    fn extract_system(messages: &[ChatMessage]) -> Option<Value> {
        let mut pieces: Vec<String> = Vec::new();
        let mut non_text_seen = false;
        for m in messages.iter().filter(|m| m.role == "system") {
            match &m.content {
                MessageContent::Text(t) => {
                    if !t.is_empty() {
                        pieces.push(t.clone());
                    }
                }
                MessageContent::Parts(parts) => {
                    for p in parts {
                        if let Some(text) = &p.text {
                            if !text.is_empty() {
                                pieces.push(text.clone());
                            }
                        } else {
                            non_text_seen = true;
                        }
                    }
                }
            }
        }
        if non_text_seen {
            tracing::warn!("google::extract_system dropped non-text parts from a system message");
        }
        if pieces.is_empty() {
            None
        } else {
            let text = pieces.join("\n\n");
            Some(json!({"parts": [{"text": text}]}))
        }
    }
}

impl Default for GoogleAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderAdapter for GoogleAdapter {
    fn name(&self) -> &'static str {
        "google"
    }

    fn state_contract(
        &self,
        protocol: crate::runtime::ProviderWireProtocol,
    ) -> Result<&'static crate::runtime::ProviderStateContract, ProviderError> {
        match protocol {
            crate::runtime::ProviderWireProtocol::GeminiGenerateContent => {
                Ok(&super::GEMINI_GENERATE_CONTENT_STATE_CONTRACT)
            }
            crate::runtime::ProviderWireProtocol::GeminiInteractions => {
                Ok(&super::GEMINI_INTERACTIONS_STATE_CONTRACT)
            }
            other => Err(super::unsupported_state_protocol(self.name(), other)),
        }
    }

    fn apply_provider_native_state(
        &self,
        request: &mut Value,
        state: &ProviderNativeState,
    ) -> Result<(), ProviderError> {
        match state.protocol() {
            ProviderWireProtocol::GeminiGenerateContent => apply_gemini_state(request, state),
            other => Err(super::unsupported_state_protocol(self.name(), other)),
        }
    }

    fn transform_request(&self, request: &ChatCompletionRequest) -> Result<Value, ProviderError> {
        let mut body = Self::transform_request_draft_with_thinking(request, None)?;
        Self::finalize_request(&mut body)?;
        debug!("Transformed request for Google");
        Ok(body)
    }

    fn transform_request_with_thinking(
        &self,
        request: &ChatCompletionRequest,
        thinking: &ThinkingConfig,
    ) -> Result<Value, ProviderError> {
        let mut body = Self::transform_request_draft_with_thinking(request, Some(thinking))?;
        Self::finalize_request(&mut body)?;
        Ok(body)
    }

    fn transform_response(&self, response: Value, _stream: bool) -> Result<Value, ProviderError> {
        // Check for API error responses before extracting candidates
        if let Some(error) = response.get("error") {
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .filter(|message| !message.is_empty())
                .ok_or_else(|| {
                    ProviderError::InvalidResponse(
                        "Gemini API error missing non-empty string 'message'".to_string(),
                    )
                })?;
            let code = error
                .get("code")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let _ = message;
            return Err(ProviderError::InvalidResponse(format!(
                "Gemini API returned error code {code}"
            )));
        }

        // Extract content from Gemini response
        let candidate = response
            .get("candidates")
            .and_then(|c| c.get(0))
            .ok_or_else(|| {
                ProviderError::InvalidResponse("No candidates in response".to_string())
            })?;

        let output = GeminiGenerateContentTurnOutput::new(&response)?;
        let content = output.text()?;
        let portable_calls = output.tool_calls(0)?;

        let mut message = json!({
            "role": "assistant",
            "content": content
        });

        if !portable_calls.is_empty() {
            message["tool_calls"] = Value::Array(
                portable_calls
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
                    .collect(),
            );
        }

        let finish_reason = candidate
            .get("finishReason")
            .and_then(|r| r.as_str())
            .map_or("stop", |r| match r {
                "MAX_TOKENS" => "length",
                "SAFETY" => "content_filter",
                _ => "stop",
            });

        Ok(json!({
            "id": format!("gemini-{}", uuid::Uuid::new_v4()),
            "object": "chat.completion",
            "created": chrono::Utc::now().timestamp(),
            "model": "gemini",
            "choices": [{
                "index": 0,
                "message": message,
                "finish_reason": finish_reason
            }],
            "usage": {
                "prompt_tokens": response.get("usageMetadata").and_then(|u| u.get("promptTokenCount")).cloned().unwrap_or_else(|| json!(0)),
                "completion_tokens": response.get("usageMetadata").and_then(|u| u.get("candidatesTokenCount")).cloned().unwrap_or_else(|| json!(0)),
                "total_tokens": response.get("usageMetadata").and_then(|u| u.get("totalTokenCount")).cloned().unwrap_or_else(|| json!(0))
            }
        }))
    }

    fn chat_endpoint(&self, model: &str) -> String {
        // Gemini uses model name in the URL path
        format!("/v1beta/models/{model}:generateContent")
    }

    /// Gemini exposes streaming on a distinct URL path
    /// (`:streamGenerateContent?alt=sse`) rather than via a request-body
    /// `stream` flag. The pipeline switches to this endpoint when
    /// streaming is requested. See crosslink #602.
    fn stream_endpoint(&self, model: &str) -> Option<String> {
        Some(format!(
            "/v1beta/models/{model}:streamGenerateContent?alt=sse"
        ))
    }

    fn get_headers(&self, api_key: &super::ApiKey) -> crate::secrets::SensitiveHeaders {
        let mut headers = crate::secrets::SensitiveHeaders::new();
        headers.insert_header_secret(
            reqwest::header::HeaderName::from_static("x-goog-api-key"),
            api_key.secret(),
        );
        headers.insert_static_literal(reqwest::header::CONTENT_TYPE, "application/json");
        headers
    }

    fn supports_model_listing(&self) -> bool {
        true
    }

    fn model_catalog_format(&self) -> Option<super::ModelCatalogFormat> {
        Some(super::ModelCatalogFormat::Gemini)
    }

    fn models_endpoint(&self) -> &'static str {
        "/v1beta/models?pageSize=1000"
    }

    /// Gemini native shape: `candidates[0].content.parts[].text`. Text
    /// parts are concatenated so the result matches what
    /// [`Self::transform_response`] would surface to the proxy hot
    /// path. See crosslink #479.
    fn extract_response_text(&self, response: &Value) -> Option<String> {
        let parts = response
            .get("candidates")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("content"))
            .and_then(|c| c.get("parts"))
            .and_then(|p| p.as_array())?;
        let joined: String = parts
            .iter()
            .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
            .collect();
        if joined.is_empty() {
            None
        } else {
            Some(joined)
        }
    }

    /// Gemini `usageMetadata` envelope: `promptTokenCount`,
    /// `candidatesTokenCount`, `cachedContentTokenCount` (mapped to
    /// `cache_read_tokens`). Gemini exposes no cache-write counter, so
    /// that field is reported as zero rather than fabricated.
    /// See crosslink #479.
    fn extract_token_usage(&self, response: &Value) -> Option<TokenUsage> {
        let usage = response.get("usageMetadata")?;
        Some(TokenUsage {
            input_tokens: usage
                .get("promptTokenCount")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            output_tokens: usage
                .get("candidatesTokenCount")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            cache_read_tokens: usage
                .get("cachedContentTokenCount")
                .and_then(Value::as_u64)
                .unwrap_or(0),
            cache_write_tokens: 0,
        })
    }
}

/// Extract and concatenate text from Gemini `content.parts`.
///
/// Text parts must contain string `text`; native `functionCall` parts are
/// allowed and skipped. Any other part shape is rejected so malformed provider
/// payloads do not become silent empty assistant messages.
///
/// # Errors
///
/// Returns [`ProviderError::InvalidResponse`] when a text part is not a string
/// or when a part has neither supported text nor native function-call content.
pub fn extract_gemini_text_content(parts: &[Value]) -> Result<String, ProviderError> {
    let mut content = String::new();

    for (index, part) in parts.iter().enumerate() {
        if let Some(text_value) = part.get("text") {
            let text = text_value.as_str().ok_or_else(|| {
                ProviderError::InvalidResponse(format!(
                    "Gemini content part at index {index} has non-string 'text'"
                ))
            })?;
            content.push_str(text);
            continue;
        }

        if part.get("functionCall").is_some() {
            continue;
        }

        return Err(ProviderError::InvalidResponse(format!(
            "Gemini content part at index {index} has no supported text or functionCall field"
        )));
    }

    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{ChatCompletionRequest, ChatMessage, ContentPart, MessageContent};

    fn google_request_with_tools(tools: Vec<Value>) -> ChatCompletionRequest {
        ChatCompletionRequest {
            model: "gemini-2.5-pro".to_string(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: MessageContent::Text("run a tool".to_string()),
                name: None,
                tool_calls: None,
                tool_call_id: None,
                extra: std::collections::HashMap::new(),
            }],
            max_tokens: Some(64),
            temperature: None,
            tools: Some(tools),
            stream: None,
            tool_choice: None,
            extra: std::collections::HashMap::new(),
        }
    }

    fn google_request_with_messages(messages: Vec<ChatMessage>) -> ChatCompletionRequest {
        ChatCompletionRequest {
            model: "gemini-3.5-pro".to_string(),
            messages,
            max_tokens: Some(64),
            temperature: None,
            tools: None,
            stream: None,
            tool_choice: None,
            extra: std::collections::HashMap::new(),
        }
    }

    fn text_message(role: &str, content: &str) -> ChatMessage {
        ChatMessage {
            role: role.to_string(),
            content: MessageContent::Text(content.to_string()),
            name: None,
            tool_calls: None,
            tool_call_id: None,
            extra: std::collections::HashMap::new(),
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
            extra: std::collections::HashMap::new(),
        }
    }

    fn tool_message(call: &ToolCall, content: &str) -> ChatMessage {
        ChatMessage {
            role: "tool".to_string(),
            content: MessageContent::Text(content.to_string()),
            name: Some(call.function.name.clone()),
            tool_calls: None,
            tool_call_id: Some(call.id.clone()),
            extra: std::collections::HashMap::new(),
        }
    }

    fn gemini_output(content: &Value) -> GeminiGenerateContentTurnOutput {
        GeminiGenerateContentTurnOutput::new(&json!({
            "candidates": [{"content": content, "finishReason": "STOP"}]
        }))
        .expect("recorded Gemini output must be valid")
    }

    #[test]
    fn convert_tools_to_gemini_functions_accepts_valid_tool() {
        let tools = vec![json!({
            "type": "function",
            "function": {
                "name": "bash",
                "description": "run shell",
                "parameters": {"type": "object"}
            }
        })];

        let functions =
            convert_tools_to_gemini_functions(&tools).expect("valid tool should convert");

        assert_eq!(functions.len(), 1);
        assert_eq!(functions[0]["name"], "bash");
        assert_eq!(functions[0]["description"], "run shell");
        assert_eq!(functions[0]["parametersJsonSchema"]["type"], "object");
        assert!(functions[0].get("parameters").is_none());
    }

    #[test]
    fn convert_tools_to_gemini_rewrites_nested_const_constraints() {
        let tools = vec![json!({
            "type": "function",
            "function": {
                "name": "tool_search",
                "parameters": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "catalog_generation": {
                            "type": "string",
                            "const": "sha256:bound"
                        },
                        "policy": {
                            "oneOf": [
                                {"const": "private"},
                                {"const": "team"}
                            ]
                        },
                        "const": {"type": "string"}
                    }
                }
            }
        })];

        let functions =
            convert_tools_to_gemini_functions(&tools).expect("valid tool should convert");
        let schema = &functions[0]["parametersJsonSchema"];

        assert_eq!(
            schema["properties"]["catalog_generation"]["enum"],
            json!(["sha256:bound"])
        );
        assert_eq!(
            schema["properties"]["policy"]["oneOf"][0]["enum"],
            json!(["private"])
        );
        assert_eq!(schema["properties"]["const"]["type"], "string");
        assert!(
            schema
                .pointer("/properties/catalog_generation/const")
                .is_none(),
            "Gemini schema must not retain unsupported const"
        );
        assert_eq!(schema["additionalProperties"], false);
    }

    #[test]
    fn transform_request_errors_on_tool_missing_function_object() {
        let request = google_request_with_tools(vec![json!({
            "type": "function",
            "credential": "google-tool-secret-sentinel"
        })]);
        let err = GoogleAdapter::new()
            .transform_request(&request)
            .expect_err("missing function object must fail");

        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("'function' object"), "{msg}");
                assert!(msg.contains("index 0"), "{msg}");
                assert!(!msg.contains("google-tool-secret-sentinel"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn transform_request_errors_on_tool_missing_function_name() {
        let request = google_request_with_tools(vec![json!({
            "type": "function",
            "function": {"parameters": {}}
        })]);
        let err = GoogleAdapter::new()
            .transform_request(&request)
            .expect_err("missing function.name must fail");

        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("function.name"), "{msg}");
                assert!(msg.contains("index 0"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn transform_request_errors_on_tool_with_malformed_optional_fields() {
        let request = google_request_with_tools(vec![json!({
            "type": "function",
            "function": {"name": "bad", "description": 123}
        })]);
        let err = GoogleAdapter::new()
            .transform_request(&request)
            .expect_err("non-string function.description must fail");
        match err {
            ProviderError::RequestFailed(msg) => assert!(msg.contains("description"), "{msg}"),
            other => panic!("expected RequestFailed, got {other:?}"),
        }

        let request = google_request_with_tools(vec![json!({
            "type": "function",
            "function": {"name": "bad", "parameters": []}
        })]);
        let err = GoogleAdapter::new()
            .transform_request(&request)
            .expect_err("non-object function.parameters must fail");
        match err {
            ProviderError::RequestFailed(msg) => assert!(msg.contains("parameters"), "{msg}"),
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_concatenates_text_parts_and_keeps_tool_calls() {
        let body = json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"text": "hello "},
                        {"functionCall": {"name": "bash", "args": {"command": "pwd"}}},
                        {"text": "world"}
                    ]
                },
                "finishReason": "STOP"
            }]
        });

        let parsed = GoogleAdapter::new()
            .transform_response(body, false)
            .expect("valid mixed response should parse");

        assert_eq!(parsed["choices"][0]["message"]["content"], "hello world");
        let calls = parsed["choices"][0]["message"]["tool_calls"]
            .as_array()
            .expect("tool calls should be preserved");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["function"]["name"], "bash");
    }

    #[test]
    fn transform_response_errors_on_missing_content_parts() {
        let body = json!({
            "candidates": [{
                "content": {}
            }]
        });

        let err = GoogleAdapter::new()
            .transform_response(body, false)
            .expect_err("missing content.parts must fail");

        match err {
            ProviderError::InvalidResponse(msg) => assert!(msg.contains("content.parts"), "{msg}"),
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_errors_on_non_string_text_part() {
        let body = json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"text": 123}
                    ]
                }
            }]
        });

        let err = GoogleAdapter::new()
            .transform_response(body, false)
            .expect_err("non-string text part must fail");

        match err {
            ProviderError::InvalidResponse(msg) => assert!(msg.contains("'text'"), "{msg}"),
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_errors_on_unsupported_part_shape() {
        let body = json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"inlineData": {"mimeType": "image/png", "data": "..."}}
                    ]
                }
            }]
        });

        let err = GoogleAdapter::new()
            .transform_response(body, false)
            .expect_err("unsupported response part must fail");

        match err {
            ProviderError::InvalidResponse(msg) => {
                assert!(msg.contains("supported text or functionCall"), "{msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    /// #785: parsing the same Gemini response twice must yield identical
    /// `tool_calls[*].id` so callers can correlate / cache / diff across
    /// re-parses. The pre-fix code generated a fresh `Uuid::new_v4()`
    /// every time, so two parses of the same payload never matched.
    #[test]
    fn tool_call_ids_are_deterministic_across_reparses() {
        let body = json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"functionCall": {"name": "bash", "args": {"command": "ls"}}},
                        {"functionCall": {"name": "read", "args": {"path": "src/lib.rs"}}}
                    ]
                }
            }]
        });
        let adapter = GoogleAdapter::new();
        let a = adapter.transform_response(body.clone(), false).unwrap();
        let b = adapter.transform_response(body, false).unwrap();
        let ids_a: Vec<&str> = a["choices"][0]["message"]["tool_calls"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["id"].as_str().unwrap())
            .collect();
        let ids_b: Vec<&str> = b["choices"][0]["message"]["tool_calls"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["id"].as_str().unwrap())
            .collect();
        assert_eq!(ids_a, ids_b, "#785: re-parse must yield identical ids");
        // The assistant ordinal and in-turn position prevent collisions when
        // older Gemini models omit provider call ids across multiple rounds.
        assert_eq!(ids_a, vec!["call_gemini_0_0", "call_gemini_0_1"]);
    }

    /// #785: two consecutive calls to the same function in a single turn
    /// must produce distinct ids — the ordinal disambiguates.
    #[test]
    fn repeated_function_calls_get_distinct_ordinal_ids() {
        let body = json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"functionCall": {"name": "bash", "args": {"command": "ls"}}},
                        {"functionCall": {"name": "bash", "args": {"command": "pwd"}}}
                    ]
                }
            }]
        });
        let parsed = GoogleAdapter::new()
            .transform_response(body, false)
            .unwrap();
        let calls = parsed["choices"][0]["message"]["tool_calls"]
            .as_array()
            .unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0]["id"], "call_gemini_0_0");
        assert_eq!(calls[1]["id"], "call_gemini_0_1");
        assert_ne!(calls[0]["id"], calls[1]["id"]);
    }

    #[test]
    fn transform_response_errors_on_function_call_missing_name() {
        let body = json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"functionCall": {"args": {"command": "ls"}}}
                    ]
                }
            }]
        });

        let err = GoogleAdapter::new()
            .transform_response(body, false)
            .expect_err("missing Gemini functionCall name must fail");
        match err {
            ProviderError::InvalidResponse(msg) => {
                assert!(msg.contains("functionCall"), "{msg}");
                assert!(msg.contains("name"), "{msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_errors_on_function_call_missing_args() {
        let body = json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"functionCall": {"name": "bash"}}
                    ]
                }
            }]
        });

        let err = GoogleAdapter::new()
            .transform_response(body, false)
            .expect_err("missing Gemini functionCall args must fail");
        match err {
            ProviderError::InvalidResponse(msg) => {
                assert!(msg.contains("functionCall"), "{msg}");
                assert!(msg.contains("args"), "{msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn transform_response_errors_on_non_object_function_call_args() {
        let body = json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"functionCall": {"name": "bash", "args": []}}
                    ]
                }
            }]
        });

        let err = GoogleAdapter::new()
            .transform_response(body, false)
            .expect_err("non-object Gemini functionCall args must fail");
        match err {
            ProviderError::InvalidResponse(msg) => {
                assert!(msg.contains("args"), "{msg}");
                assert!(msg.contains("object"), "{msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    /// #850: a `ContentPart` with neither `text` nor `image_url` used to be
    /// silently coerced or dropped. The request boundary now rejects it so the
    /// caller sees the unsupported multimodal contract immediately.
    #[test]
    fn transform_request_converts_text_and_image_parts() {
        let request = ChatCompletionRequest {
            model: "gemini-2.5-pro".to_string(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: MessageContent::Parts(vec![
                    ContentPart {
                        content_type: "text".to_string(),
                        text: Some("describe this".to_string()),
                        image_url: None,
                    },
                    ContentPart {
                        content_type: "image_url".to_string(),
                        text: None,
                        image_url: Some(json!({
                            "mimeType": "image/png",
                            "data": "iVBORw..."
                        })),
                    },
                ]),
                name: None,
                tool_calls: None,
                tool_call_id: None,
                extra: std::collections::HashMap::new(),
            }],
            max_tokens: Some(64),
            temperature: None,
            tools: None,
            stream: None,
            tool_choice: None,
            extra: std::collections::HashMap::new(),
        };

        let body = GoogleAdapter::new()
            .transform_request(&request)
            .expect("valid multimodal Gemini request should transform");
        let parts = body["contents"][0]["parts"]
            .as_array()
            .expect("parts array");
        assert_eq!(parts[0], json!({"text": "describe this"}));
        assert_eq!(parts[1]["inlineData"]["mimeType"], "image/png");
        assert_eq!(parts[1]["inlineData"]["data"], "iVBORw...");
    }

    #[test]
    fn transform_request_errors_on_unknown_content_part_type() {
        let msg = ChatMessage {
            role: "user".to_string(),
            content: MessageContent::Parts(vec![
                ContentPart {
                    content_type: "text".to_string(),
                    text: Some("hello".to_string()),
                    image_url: None,
                },
                ContentPart {
                    // Unrecognized variant — neither text nor image_url set.
                    content_type: "video_url".to_string(),
                    text: None,
                    image_url: None,
                },
            ]),
            name: None,
            tool_calls: None,
            tool_call_id: None,
            extra: std::collections::HashMap::new(),
        };
        let request = ChatCompletionRequest {
            model: "gemini-2.5-pro".to_string(),
            messages: vec![msg],
            max_tokens: Some(64),
            temperature: None,
            tools: None,
            stream: None,
            tool_choice: None,
            extra: std::collections::HashMap::new(),
        };

        let err = GoogleAdapter::new()
            .transform_request(&request)
            .expect_err("unknown Google content part must fail request conversion");

        match err {
            ProviderError::RequestFailed(msg) => {
                assert!(msg.contains("content part type"), "{msg}");
                assert!(!msg.contains("video_url"), "{msg}");
            }
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn transform_request_errors_on_text_part_missing_text() {
        let request = ChatCompletionRequest {
            model: "gemini-2.5-pro".to_string(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: MessageContent::Parts(vec![ContentPart {
                    content_type: "text".to_string(),
                    text: None,
                    image_url: None,
                }]),
                name: None,
                tool_calls: None,
                tool_call_id: None,
                extra: std::collections::HashMap::new(),
            }],
            max_tokens: Some(64),
            temperature: None,
            tools: None,
            stream: None,
            tool_choice: None,
            extra: std::collections::HashMap::new(),
        };

        let err = GoogleAdapter::new()
            .transform_request(&request)
            .expect_err("missing Google text part text must fail request conversion");

        match err {
            ProviderError::RequestFailed(msg) => assert!(msg.contains("missing 'text'"), "{msg}"),
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    #[test]
    fn transform_request_errors_on_image_part_missing_image_url() {
        let request = ChatCompletionRequest {
            model: "gemini-2.5-pro".to_string(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: MessageContent::Parts(vec![ContentPart {
                    content_type: "image_url".to_string(),
                    text: None,
                    image_url: None,
                }]),
                name: None,
                tool_calls: None,
                tool_call_id: None,
                extra: std::collections::HashMap::new(),
            }],
            max_tokens: Some(64),
            temperature: None,
            tools: None,
            stream: None,
            tool_choice: None,
            extra: std::collections::HashMap::new(),
        };

        let err = GoogleAdapter::new()
            .transform_request(&request)
            .expect_err("missing Google image_url must fail request conversion");

        match err {
            ProviderError::RequestFailed(msg) => assert!(msg.contains("image_url"), "{msg}"),
            other => panic!("expected RequestFailed, got {other:?}"),
        }
    }

    // ── crosslink #602 — stream_endpoint / supports_streaming overrides ─────

    /// `#602-a`: Google overrides `stream_endpoint` with the SSE-specific
    /// path (`:streamGenerateContent?alt=sse`) and embeds the model name.
    /// Pins the URL shape so the pipeline can switch endpoints when
    /// streaming is requested.
    #[test]
    fn issue_602_google_stream_endpoint_uses_sse_path() {
        let adapter = GoogleAdapter::new();
        let endpoint = adapter
            .stream_endpoint("gemini-2.5-pro")
            .expect("Google must expose a streaming endpoint");
        assert_eq!(
            endpoint, "/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse",
            "Google streaming URL must include model + :streamGenerateContent + alt=sse"
        );
    }

    /// `#602-b`: the streaming URL is distinct from the non-streaming
    /// `chat_endpoint`, and `supports_streaming` is true.
    #[test]
    fn issue_602_google_streaming_distinct_from_chat_endpoint() {
        let adapter = GoogleAdapter::new();
        let chat = adapter.chat_endpoint("gemini-2.5-flash");
        let stream = adapter.stream_endpoint("gemini-2.5-flash").unwrap();
        assert_ne!(chat, stream, "stream and non-stream endpoints must differ");
        assert!(chat.ends_with(":generateContent"));
        assert!(stream.contains(":streamGenerateContent"));
        assert!(adapter.supports_streaming());
    }

    /// `#602-c`: other providers inherit the default — `stream_endpoint`
    /// returns None, signalling "use the same URL with stream:true".
    /// Pins that Google is the only override.
    #[test]
    fn issue_602_other_providers_default_to_none_stream_endpoint() {
        use crate::providers::{
            AnthropicAdapter, DeepSeekAdapter, KimiAdapter, MiniMaxAdapter, OllamaAdapter,
            OpenAIAdapter, ProviderAdapter, QwenAdapter, ZaiAdapter,
        };
        let anthropic = AnthropicAdapter::new();
        let openai = OpenAIAdapter::new();
        let deepseek = DeepSeekAdapter::new();
        let qwen = QwenAdapter::new();
        let zai = ZaiAdapter::new();
        let kimi = KimiAdapter::new();
        let minimax = MiniMaxAdapter::new();
        let ollama = OllamaAdapter::new();
        let cases: Vec<(&str, &dyn ProviderAdapter)> = vec![
            ("anthropic", &anthropic),
            ("openai", &openai),
            ("deepseek", &deepseek),
            ("qwen", &qwen),
            ("zai", &zai),
            ("kimi", &kimi),
            ("minimax", &minimax),
            ("ollama", &ollama),
        ];
        for (name, adapter) in cases {
            assert!(
                adapter.stream_endpoint("any-model").is_none(),
                "{name}: default stream_endpoint must be None — only Google overrides (#602)"
            );
            assert!(
                adapter.supports_streaming(),
                "{name}: every wired provider must report supports_streaming=true"
            );
        }
    }

    #[test]
    fn native_state_replays_two_parallel_tool_rounds_exactly() {
        let first_content = json!({
            "role": "model",
            "parts": [
                {"text": "checking"},
                {
                    "functionCall": {
                        "id": "native-a",
                        "name": "bash",
                        "args": {"command": "pwd"}
                    },
                    "thoughtSignature": "opaque-signature-a"
                },
                {
                    "functionCall": {
                        "id": "native-b",
                        "name": "read",
                        "args": {"path": "Cargo.toml"}
                    }
                }
            ],
            "providerMetadata": {"must_survive": true}
        });
        let first = gemini_output(&first_content);
        let first_calls = first.tool_calls(1).expect("first calls project");
        let state =
            advance_gemini_generate_content_state("google", "gemini-3.5-pro", None, 1, &first)
                .expect("first native turn advances");

        let second_content = json!({
            "role": "model",
            "parts": [{
                "functionCall": {
                    "id": "native-c",
                    "name": "bash",
                    "args": {"command": "cargo metadata --no-deps"}
                },
                "thoughtSignature": "opaque-signature-b"
            }]
        });
        let second = gemini_output(&second_content);
        let second_calls = second.tool_calls(4).expect("second calls project");
        let state = advance_gemini_generate_content_state(
            "google",
            "gemini-3.5-pro",
            Some(&state),
            4,
            &second,
        )
        .expect("second native turn advances");

        let request = google_request_with_messages(vec![
            text_message("user", "inspect the repository"),
            assistant_message("checking", &first_calls),
            tool_message(&first_calls[0], r#"{"cwd":"/workspace"}"#),
            tool_message(&first_calls[1], r#"{"text":"manifest"}"#),
            assistant_message("", &second_calls),
            tool_message(&second_calls[0], r#"{"packages":1}"#),
        ]);
        let adapter = GoogleAdapter::new();
        let mut body =
            GoogleAdapter::transform_request_draft(&request).expect("portable history converts");
        adapter
            .apply_provider_native_state(&mut body, &state)
            .expect("native state applies");
        GoogleAdapter::finalize_request(&mut body).expect("request finalizes");

        assert!(body.get(GEMINI_HISTORY_KEY).is_none());
        let contents = body["contents"].as_array().expect("Gemini contents");
        assert_eq!(contents[1], first_content);
        assert_eq!(contents[3], second_content);
        let first_results = contents[2]["parts"]
            .as_array()
            .expect("parallel results are one ordered batch");
        assert_eq!(first_results.len(), 2);
        assert_eq!(first_results[0]["functionResponse"]["id"], "native-a");
        assert_eq!(first_results[1]["functionResponse"]["id"], "native-b");
        assert_eq!(
            contents[4]["parts"][0]["functionResponse"]["id"],
            "native-c"
        );
    }

    #[test]
    fn native_state_omits_synthetic_ids_for_older_gemini_rounds() {
        let exact_content = json!({
            "role": "model",
            "parts": [{
                "functionCall": {"name": "bash", "args": {"command": "pwd"}},
                "thoughtSignature": "older-model-signature"
            }]
        });
        let output = gemini_output(&exact_content);
        let calls = output.tool_calls(1).expect("portable call projects");
        assert_eq!(calls[0].id, "call_gemini_1_0");
        let state =
            advance_gemini_generate_content_state("google", "gemini-2.5-pro", None, 1, &output)
                .expect("native turn advances");
        let request = google_request_with_messages(vec![
            text_message("user", "where am I"),
            assistant_message("", &calls),
            tool_message(&calls[0], r#"{"cwd":"/workspace"}"#),
        ]);
        let adapter = GoogleAdapter::new();
        let mut body =
            GoogleAdapter::transform_request_draft(&request).expect("portable history converts");
        adapter
            .apply_provider_native_state(&mut body, &state)
            .expect("native state applies");
        GoogleAdapter::finalize_request(&mut body).expect("request finalizes");

        assert_eq!(body["contents"][1], exact_content);
        assert!(body["contents"][2]["parts"][0]["functionResponse"]
            .get("id")
            .is_none());
    }

    #[test]
    fn native_history_rejects_missing_duplicate_reordered_and_mismatched_calls() {
        let output = gemini_output(&json!({
            "role": "model",
            "parts": [
                {"functionCall": {"id": "dup", "name": "bash", "args": {"command": "pwd"}}},
                {"functionCall": {"id": "dup", "name": "read", "args": {"path": "Cargo.toml"}}}
            ]
        }));
        let error = output
            .tool_calls(1)
            .expect_err("duplicate provider call ids must fail");
        assert!(error.to_string().contains("repeated function call id"));

        let output = gemini_output(&json!({
            "role": "model",
            "parts": [
                {"functionCall": {"id": "call-a", "name": "bash", "args": {"command": "pwd"}}},
                {"functionCall": {"id": "call-b", "name": "read", "args": {"path": "Cargo.toml"}}}
            ]
        }));
        let calls = output.tool_calls(1).expect("calls project");
        let missing = google_request_with_messages(vec![
            text_message("user", "inspect"),
            assistant_message("", &calls),
            tool_message(&calls[0], "first"),
        ]);
        let error =
            GoogleAdapter::transform_request_draft(&missing).expect_err("missing result must fail");
        assert!(error.to_string().contains("missing result"));

        let reordered = google_request_with_messages(vec![
            text_message("user", "inspect"),
            assistant_message("", &calls),
            tool_message(&calls[1], "second"),
            tool_message(&calls[0], "first"),
        ]);
        let error = GoogleAdapter::transform_request_draft(&reordered)
            .expect_err("reordered results must fail");
        assert!(error.to_string().contains("reordered"));

        let state =
            advance_gemini_generate_content_state("google", "gemini-3.5-pro", None, 1, &output)
                .expect("native turn advances");
        let mut mismatched_assistant = assistant_message("", &calls);
        mismatched_assistant
            .tool_calls
            .as_mut()
            .expect("tool calls")[0]["function"]["arguments"] =
            Value::String(r#"{"command":"different"}"#.to_string());
        let mismatched = google_request_with_messages(vec![
            text_message("user", "inspect"),
            mismatched_assistant,
            tool_message(&calls[0], "first"),
            tool_message(&calls[1], "second"),
        ]);
        let adapter = GoogleAdapter::new();
        let mut body = GoogleAdapter::transform_request_draft(&mismatched)
            .expect("mismatched projection remains structurally valid");
        let error = adapter
            .apply_provider_native_state(&mut body, &state)
            .expect_err("projection/native argument drift must fail");
        assert!(error.to_string().contains("disagrees with native state"));
    }

    #[test]
    fn system_messages_cannot_interrupt_or_forge_tool_history() {
        let output = gemini_output(&json!({
            "role": "model",
            "parts": [{"functionCall": {"id": "call-a", "name": "bash", "args": {}}}]
        }));
        let calls = output.tool_calls(1).expect("call projects");
        let interrupted = google_request_with_messages(vec![
            text_message("user", "run"),
            assistant_message("", &calls),
            text_message("system", "late policy"),
            tool_message(&calls[0], "done"),
        ]);
        let error = GoogleAdapter::transform_request_draft(&interrupted)
            .expect_err("system interruption must fail");
        assert!(error.to_string().contains("interrupts tool results"));

        let mut forged = text_message("system", "policy");
        forged.tool_call_id = Some("call-a".to_string());
        let forged = google_request_with_messages(vec![forged]);
        let error = GoogleAdapter::transform_request_draft(&forged)
            .expect_err("system tool protocol fields must fail");
        assert!(error.to_string().contains("tool protocol fields"));
    }
}
