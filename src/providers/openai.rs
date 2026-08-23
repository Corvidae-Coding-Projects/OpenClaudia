//! `OpenAI` Chat Completions and Responses API adapter.
//!
//! Chat Completions remains a thin newtype around [`OpenAiCompatibleAdapter`].
//! Responses additionally owns the fail-closed stateless replay contract for
//! exact provider output items captured with `store:false`.
//!
//! See crosslink #281 for the Stovepipe-de-duplication that introduced
//! this shape.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

use crate::config::ThinkingConfig;
use crate::proxy::ChatCompletionRequest;
use crate::runtime::{
    ContinuationGeneration, ProviderNativeItem, ProviderNativeItemPurpose, ProviderNativeState,
    ProviderStateFacet, ProviderWireProtocol,
};

use super::openai_compat::{OpenAiCompatibleAdapter, ThinkingInjector};
use super::{ApiKey, ProviderAdapter, ProviderError};

const RESPONSES_TURN_FORMAT: &str = "openai_responses_turn_v1";
const RESPONSES_OUTPUT_ITEM_FORMAT: &str = "openai_responses_output_item_v1";
const RESPONSES_HISTORY_KEY: &str = "_openclaudia_responses_history";
const RESPONSES_ORDINAL_KEY: &str = "_openclaudia_message_ordinal";

fn validate_response_id(response_id: &str) -> Result<(), String> {
    if response_id.is_empty()
        || response_id.len() > 512
        || response_id.chars().any(char::is_control)
    {
        Err("Responses completion has an invalid response id".to_string())
    } else {
        Ok(())
    }
}

fn validate_output_item(index: usize, item: &Value) -> Result<(), String> {
    if !item.is_object() {
        return Err(format!("Responses output item {index} is not an object"));
    }
    if item
        .get("type")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(format!(
            "Responses output item {index} is missing a non-empty type"
        ));
    }
    Ok(())
}

/// Exact provider-owned output from one completed Responses turn.
///
/// This value never enters the user-visible transcript. It exists only long
/// enough to advance the bounded provider-native continuation envelope before
/// any returned tool call is dispatched.
#[derive(Clone, PartialEq, Eq)]
pub struct OpenAiResponsesTurnOutput {
    response_id: String,
    output_items: Vec<Value>,
}

impl OpenAiResponsesTurnOutput {
    /// Construct a validated completed-turn capture.
    ///
    /// # Errors
    ///
    /// Returns an error for a missing response identity or malformed output
    /// item. The item objects otherwise remain byte-for-byte JSON-equivalent
    /// to the provider response, including encrypted reasoning and `phase`.
    pub fn new(response_id: impl Into<String>, output_items: Vec<Value>) -> Result<Self, String> {
        let response_id = response_id.into();
        validate_response_id(&response_id)?;
        for (index, item) in output_items.iter().enumerate() {
            validate_output_item(index, item)?;
        }
        Ok(Self {
            response_id,
            output_items,
        })
    }

    /// Provider response identity retained for audit correlation.
    #[must_use]
    pub fn response_id(&self) -> &str {
        &self.response_id
    }

    /// Exact ordered provider output items.
    #[must_use]
    pub fn output_items(&self) -> &[Value] {
        &self.output_items
    }
}

fn provider_error(error: impl std::fmt::Display) -> ProviderError {
    ProviderError::InvalidResponse(error.to_string())
}

fn output_item_facet(item: &Value, parallel_tool_calls: bool) -> ProviderStateFacet {
    match item.get("type").and_then(Value::as_str) {
        Some("reasoning") => ProviderStateFacet::Reasoning,
        Some("compaction") => ProviderStateFacet::Compaction,
        Some("function_call") if parallel_tool_calls => ProviderStateFacet::ParallelToolCalls,
        Some("function_call") => ProviderStateFacet::ToolCalls,
        // Messages and future provider output item variants are retained as
        // exact native messages. The adapter never interprets their contents;
        // it only replays the provider-owned object unchanged.
        _ => ProviderStateFacet::NativeMessage,
    }
}

fn validate_next_turn_identity(
    items: &[ProviderNativeItem],
    response_id: &str,
    assistant_ordinal: u64,
) -> Result<(), ProviderError> {
    let mut response_ids = BTreeSet::new();
    let mut assistant_ordinals = BTreeSet::new();
    for item in items {
        if item.payload().get("format").and_then(Value::as_str) != Some(RESPONSES_TURN_FORMAT) {
            continue;
        }
        if let Some(existing) = item.payload().get("response_id").and_then(Value::as_str) {
            if !response_ids.insert(existing.to_string()) {
                return Err(provider_error(format!(
                    "Responses response id {existing:?} occurs more than once"
                )));
            }
        }
        if let Some(ordinal) = item
            .payload()
            .get("assistant_ordinal")
            .and_then(Value::as_u64)
        {
            assistant_ordinals.insert(ordinal);
        }
    }
    if !response_ids.insert(response_id.to_string()) {
        return Err(provider_error(format!(
            "Responses response id {response_id:?} was already captured"
        )));
    }
    let previous_assistant_ordinal = assistant_ordinals.last().copied();
    if !assistant_ordinals.insert(assistant_ordinal) {
        return Err(provider_error(format!(
            "Responses assistant ordinal {assistant_ordinal} was already captured"
        )));
    }
    if previous_assistant_ordinal.is_some_and(|previous| previous >= assistant_ordinal) {
        return Err(provider_error(format!(
            "Responses assistant ordinal {assistant_ordinal} does not advance the continuation"
        )));
    }
    Ok(())
}

/// Advance a stateless `OpenAI` Responses continuation with one completed turn.
///
/// `assistant_ordinal` is the position of the turn's portable assistant
/// projection among non-system conversation messages. System prompt,
/// grounding, and VDD reference injection therefore cannot shift the binding.
///
/// # Errors
///
/// Returns an error for provider/model/protocol drift, duplicate response or
/// assistant identity, generation exhaustion, malformed output, or S-044's
/// item/byte bounds. Callers must invoke this before dispatching tool effects.
pub fn advance_openai_responses_state(
    provider: &str,
    model: &str,
    previous: Option<&ProviderNativeState>,
    assistant_ordinal: u64,
    output: &OpenAiResponsesTurnOutput,
) -> Result<ProviderNativeState, ProviderError> {
    let compacted = output
        .output_items
        .iter()
        .any(|item| item.get("type").and_then(Value::as_str) == Some("compaction"));
    let previous_items = if let Some(previous) = previous {
        previous
            .validate_binding(provider, model, ProviderWireProtocol::OpenAiResponses)
            .map_err(provider_error)?;
        super::OPENAI_RESPONSES_STATE_CONTRACT
            .validate_state(previous)
            .map_err(provider_error)?;
        parse_replay_groups(previous)?;
        previous.items().to_vec()
    } else {
        Vec::new()
    };

    validate_next_turn_identity(&previous_items, output.response_id(), assistant_ordinal)?;
    // An opaque compaction item supersedes all earlier provider-owned output
    // items. Portable user messages remain in the canonical transcript and
    // are selected during replay; retaining old native turns here would undo
    // the provider's token reduction.
    let mut items = if compacted {
        Vec::new()
    } else {
        previous_items
    };

    items.push(
        ProviderNativeItem::new(
            ProviderStateFacet::ServerContinuation,
            ProviderNativeItemPurpose::Evidence,
            serde_json::json!({
                "format": RESPONSES_TURN_FORMAT,
                "response_id": output.response_id(),
                "assistant_ordinal": assistant_ordinal,
                "output_item_count": output.output_items.len(),
                "store": false
            }),
        )
        .map_err(provider_error)?,
    );

    let function_call_count = output
        .output_items
        .iter()
        .filter(|item| item.get("type").and_then(Value::as_str) == Some("function_call"))
        .count();
    for output_item in &output.output_items {
        items.push(
            ProviderNativeItem::new(
                output_item_facet(output_item, function_call_count > 1),
                ProviderNativeItemPurpose::Continuation,
                serde_json::json!({
                    "format": RESPONSES_OUTPUT_ITEM_FORMAT,
                    "response_id": output.response_id(),
                    "assistant_ordinal": assistant_ordinal,
                    "item": output_item
                }),
            )
            .map_err(provider_error)?,
        );
    }

    let generation = match previous {
        None => 1,
        Some(state) => state
            .generation()
            .get()
            .checked_add(1)
            .ok_or_else(|| provider_error("Responses continuation generation exhausted"))?,
    };
    let generation = ContinuationGeneration::new(generation)
        .ok_or_else(|| provider_error("Responses continuation generation exhausted"))?;
    let state = ProviderNativeState::new(
        provider,
        model,
        ProviderWireProtocol::OpenAiResponses,
        generation,
        items,
    )
    .map_err(provider_error)?;
    super::OPENAI_RESPONSES_STATE_CONTRACT
        .validate_state(&state)
        .map_err(provider_error)?;
    Ok(state)
}

struct ReplayGroup {
    response_id: String,
    expected_items: usize,
    items: Vec<(ProviderStateFacet, Value)>,
}

fn parse_turn_evidence(payload: &Value) -> Result<(&str, u64, usize), ProviderError> {
    let response_id = payload
        .get("response_id")
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| provider_error("Responses turn evidence is missing response_id"))?;
    validate_response_id(response_id).map_err(provider_error)?;
    let ordinal = payload
        .get("assistant_ordinal")
        .and_then(Value::as_u64)
        .ok_or_else(|| provider_error("Responses turn evidence is missing assistant_ordinal"))?;
    let expected_items = payload
        .get("output_item_count")
        .and_then(Value::as_u64)
        .and_then(|count| usize::try_from(count).ok())
        .ok_or_else(|| provider_error("Responses turn evidence has invalid output_item_count"))?;
    if payload.get("store").and_then(Value::as_bool) != Some(false) {
        return Err(provider_error(
            "Responses continuation evidence is not stateless",
        ));
    }
    Ok((response_id, ordinal, expected_items))
}

fn ensure_replay_group_complete(
    groups: &BTreeMap<u64, ReplayGroup>,
    ordinal: u64,
) -> Result<(), ProviderError> {
    let group = groups
        .get(&ordinal)
        .ok_or_else(|| provider_error("Responses continuation lost its active turn"))?;
    if group.items.len() != group.expected_items {
        return Err(provider_error(format!(
            "Responses assistant ordinal {ordinal} retained {} of {} output items",
            group.items.len(),
            group.expected_items
        )));
    }
    Ok(())
}

fn append_replay_output_item(
    native: &ProviderNativeItem,
    groups: &mut BTreeMap<u64, ReplayGroup>,
    active_ordinal: Option<u64>,
) -> Result<(), ProviderError> {
    let payload = native.payload();
    let ordinal = payload
        .get("assistant_ordinal")
        .and_then(Value::as_u64)
        .ok_or_else(|| provider_error("Responses output item is missing assistant_ordinal"))?;
    if active_ordinal != Some(ordinal) {
        return Err(provider_error(format!(
            "Responses output item for assistant ordinal {ordinal} is not contiguous with its turn evidence"
        )));
    }
    let response_id = payload
        .get("response_id")
        .and_then(Value::as_str)
        .ok_or_else(|| provider_error("Responses output item is missing response_id"))?;
    validate_response_id(response_id).map_err(provider_error)?;
    let output_item = payload
        .get("item")
        .filter(|item| item.is_object())
        .cloned()
        .ok_or_else(|| provider_error("Responses output item payload is malformed"))?;
    validate_output_item(native.sequence() as usize, &output_item).map_err(provider_error)?;
    let group = groups.get_mut(&ordinal).ok_or_else(|| {
        provider_error(format!(
            "Responses output item has no turn evidence at assistant ordinal {ordinal}"
        ))
    })?;
    if group.response_id != response_id {
        return Err(provider_error(format!(
            "Responses output item response id {response_id:?} does not match turn {:?}",
            group.response_id
        )));
    }
    if group.items.len() >= group.expected_items {
        return Err(provider_error(format!(
            "Responses assistant ordinal {ordinal} retained more than {} output items",
            group.expected_items
        )));
    }
    group.items.push((native.facet(), output_item));
    Ok(())
}

fn validate_replay_groups(
    groups: &BTreeMap<u64, ReplayGroup>,
    generation: u64,
) -> Result<(), ProviderError> {
    for (ordinal, group) in groups {
        ensure_replay_group_complete(groups, *ordinal)?;
        let function_call_count = group
            .items
            .iter()
            .filter(|(_, item)| item.get("type").and_then(Value::as_str) == Some("function_call"))
            .count();
        for (facet, item) in &group.items {
            let expected = output_item_facet(item, function_call_count > 1);
            if *facet != expected {
                return Err(provider_error(format!(
                    "Responses assistant ordinal {ordinal} output item facet {facet:?} does not match {expected:?}"
                )));
            }
        }
    }
    let retained_turn_count = u64::try_from(groups.len())
        .map_err(|_| provider_error("Responses continuation turn count overflow"))?;
    let begins_with_compaction = groups.first_key_value().is_some_and(|(_, group)| {
        group
            .items
            .iter()
            .any(|(facet, _)| *facet == ProviderStateFacet::Compaction)
    });
    if retained_turn_count > generation
        || (retained_turn_count < generation && !begins_with_compaction)
    {
        return Err(provider_error(format!(
            "Responses continuation generation {generation} does not match its {retained_turn_count} retained turns"
        )));
    }
    Ok(())
}

fn parse_replay_groups(
    state: &ProviderNativeState,
) -> Result<BTreeMap<u64, ReplayGroup>, ProviderError> {
    let mut groups: BTreeMap<u64, ReplayGroup> = BTreeMap::new();
    let mut response_ids = BTreeSet::new();
    let mut active_ordinal = None;
    let mut previous_ordinal = None;
    for native in state.items() {
        let payload = native.payload();
        match (
            native.purpose(),
            payload.get("format").and_then(Value::as_str),
        ) {
            (ProviderNativeItemPurpose::Evidence, Some(RESPONSES_TURN_FORMAT)) => {
                if native.facet() != ProviderStateFacet::ServerContinuation {
                    return Err(provider_error(
                        "Responses turn evidence has the wrong native-state facet",
                    ));
                }
                if let Some(active) = active_ordinal {
                    ensure_replay_group_complete(&groups, active)?;
                }
                let (response_id, ordinal, expected_items) = parse_turn_evidence(payload)?;
                if previous_ordinal.is_some_and(|previous| previous >= ordinal) {
                    return Err(provider_error(format!(
                        "Responses assistant ordinal {ordinal} is not ordered after the prior turn"
                    )));
                }
                if !response_ids.insert(response_id.to_string()) {
                    return Err(provider_error(format!(
                        "duplicate Responses response id {response_id:?}"
                    )));
                }
                if groups
                    .insert(
                        ordinal,
                        ReplayGroup {
                            response_id: response_id.to_string(),
                            expected_items,
                            items: Vec::new(),
                        },
                    )
                    .is_some()
                {
                    return Err(provider_error(format!(
                        "duplicate Responses assistant ordinal {ordinal}"
                    )));
                }
                active_ordinal = Some(ordinal);
                previous_ordinal = Some(ordinal);
            }
            (ProviderNativeItemPurpose::Continuation, Some(RESPONSES_OUTPUT_ITEM_FORMAT)) => {
                append_replay_output_item(native, &mut groups, active_ordinal)?;
            }
            (ProviderNativeItemPurpose::Evidence, _) => {
                return Err(provider_error(
                    "unrecognized OpenAI Responses evidence item format",
                ));
            }
            (ProviderNativeItemPurpose::Continuation, _) => {
                return Err(provider_error(
                    "unrecognized OpenAI Responses continuation item format",
                ));
            }
        }
    }
    validate_replay_groups(&groups, state.generation().get())?;
    Ok(groups)
}

// Ordered replay is one validation state machine; splitting boundary selection
// from ordinal consumption would duplicate mutable maps and weaken reviewability.
#[allow(clippy::too_many_lines)]
fn apply_responses_state(
    request: &mut Value,
    state: &ProviderNativeState,
) -> Result<(), ProviderError> {
    super::OPENAI_RESPONSES_STATE_CONTRACT
        .validate_state(state)
        .map_err(provider_error)?;
    if request.get("store").and_then(Value::as_bool) != Some(false) {
        return Err(provider_error(
            "OpenAI Responses native replay requires store:false",
        ));
    }
    if request.get("previous_response_id").is_some() || request.get("conversation").is_some() {
        return Err(provider_error(
            "stateless Responses replay cannot be mixed with server-managed continuation",
        ));
    }

    let history_value = request
        .as_object_mut()
        .ok_or_else(|| provider_error("Responses request must be an object"))?
        .remove(RESPONSES_HISTORY_KEY)
        .ok_or_else(|| provider_error("Responses request is missing portable history bindings"))?;
    let history = history_value
        .as_array()
        .ok_or_else(|| provider_error("Responses portable history binding must be an array"))?;
    let raw_input = request
        .get_mut("input")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| provider_error("Responses request input must be an array"))?;

    let mut portable_by_ordinal: BTreeMap<u64, Vec<Value>> = BTreeMap::new();
    for mut item in std::mem::take(raw_input) {
        let ordinal = item
            .as_object_mut()
            .and_then(|object| object.remove(RESPONSES_ORDINAL_KEY))
            .and_then(|value| value.as_u64())
            .ok_or_else(|| provider_error("Responses input item is missing its history binding"))?;
        portable_by_ordinal.entry(ordinal).or_default().push(item);
    }

    let mut roles = BTreeMap::new();
    for (expected, entry) in history.iter().enumerate() {
        let ordinal = entry
            .get("ordinal")
            .and_then(Value::as_u64)
            .ok_or_else(|| provider_error("Responses history binding is missing ordinal"))?;
        let expected = u64::try_from(expected)
            .map_err(|_| provider_error("Responses history binding count overflow"))?;
        if ordinal != expected {
            return Err(provider_error(
                "Responses history bindings are not contiguous",
            ));
        }
        let role = entry
            .get("role")
            .and_then(Value::as_str)
            .ok_or_else(|| provider_error("Responses history binding is missing role"))?;
        roles.insert(ordinal, role.to_string());
    }
    if portable_by_ordinal
        .keys()
        .any(|ordinal| !roles.contains_key(ordinal))
    {
        return Err(provider_error(
            "Responses input contains an item outside portable history",
        ));
    }

    let mut groups = parse_replay_groups(state)?;
    let compaction_ordinals = groups
        .iter()
        .filter(|(_, group)| {
            group
                .items
                .iter()
                .any(|(facet, _)| *facet == ProviderStateFacet::Compaction)
        })
        .map(|(ordinal, _)| *ordinal)
        .collect::<Vec<_>>();
    if compaction_ordinals.len() > 1 {
        return Err(provider_error(
            "Responses continuation contains multiple active compaction boundaries",
        ));
    }
    let compaction_ordinal = compaction_ordinals.first().copied();
    let mut replayed = Vec::new();
    for (ordinal, role) in roles {
        if compaction_ordinal.is_some_and(|boundary| ordinal < boundary) {
            portable_by_ordinal.remove(&ordinal);
            groups.remove(&ordinal);
            continue;
        }
        if let Some(group) = groups.remove(&ordinal) {
            if role != "assistant" {
                return Err(provider_error(format!(
                    "Responses native turn at ordinal {ordinal} is bound to role {role:?}"
                )));
            }
            portable_by_ordinal.remove(&ordinal);
            replayed.extend(group.items.into_iter().map(|(_, item)| item));
        } else if let Some(items) = portable_by_ordinal.remove(&ordinal) {
            replayed.extend(items);
        }
    }
    if let Some((ordinal, _)) = groups.first_key_value() {
        return Err(provider_error(format!(
            "Responses native turn references missing assistant ordinal {ordinal}"
        )));
    }
    if let Some((ordinal, _)) = portable_by_ordinal.first_key_value() {
        return Err(provider_error(format!(
            "Responses portable input references missing history ordinal {ordinal}"
        )));
    }
    *raw_input = replayed;
    Ok(())
}

/// Remove request-construction-only ordinal metadata before transport.
pub fn finalize_responses_request(request: &mut Value) -> Result<(), String> {
    let had_construction_metadata = request
        .as_object_mut()
        .ok_or_else(|| "Responses request must be an object".to_string())?
        .remove(RESPONSES_HISTORY_KEY)
        .is_some();
    if !had_construction_metadata {
        // Native replay already consumed the private construction markers.
        // Do not scan provider-owned output objects here: a future provider
        // field with the same spelling must survive exact replay unchanged.
        return Ok(());
    }
    let input = request
        .get_mut("input")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| "Responses request input must be an array".to_string())?;
    for item in input {
        if let Some(object) = item.as_object_mut() {
            object.remove(RESPONSES_ORDINAL_KEY);
        }
    }
    Ok(())
}

/// `OpenAI` API adapter for Chat Completions and stateless Responses replay.
pub struct OpenAIAdapter(OpenAiCompatibleAdapter);

impl OpenAIAdapter {
    #[must_use]
    pub const fn new() -> Self {
        Self(OpenAiCompatibleAdapter::new(
            "openai",
            "/v1/chat/completions",
            ThinkingInjector::OpenAiReasoningEffort,
            true,
        ))
    }
}

impl Default for OpenAIAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProviderAdapter for OpenAIAdapter {
    fn name(&self) -> &str {
        self.0.name()
    }

    fn state_contract(
        &self,
        protocol: crate::runtime::ProviderWireProtocol,
    ) -> Result<&'static crate::runtime::ProviderStateContract, ProviderError> {
        match protocol {
            crate::runtime::ProviderWireProtocol::OpenAiChatCompletions => {
                self.0.state_contract(protocol)
            }
            crate::runtime::ProviderWireProtocol::OpenAiResponses => {
                Ok(&super::OPENAI_RESPONSES_STATE_CONTRACT)
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
            ProviderWireProtocol::OpenAiResponses => apply_responses_state(request, state),
            ProviderWireProtocol::OpenAiChatCompletions => {
                self.0.apply_provider_native_state(request, state)
            }
            other => Err(super::unsupported_state_protocol(self.name(), other)),
        }
    }

    fn transform_request(&self, request: &ChatCompletionRequest) -> Result<Value, ProviderError> {
        self.0.transform_request(request)
    }

    fn transform_request_with_thinking(
        &self,
        request: &ChatCompletionRequest,
        thinking: &ThinkingConfig,
    ) -> Result<Value, ProviderError> {
        self.0.transform_request_with_thinking(request, thinking)
    }

    fn transform_response(&self, response: Value, stream: bool) -> Result<Value, ProviderError> {
        self.0.transform_response(response, stream)
    }

    fn chat_endpoint(&self, model: &str) -> String {
        self.0.chat_endpoint(model)
    }

    fn get_headers(&self, api_key: &ApiKey) -> crate::secrets::SensitiveHeaders {
        self.0.get_headers(api_key)
    }

    fn supports_model_listing(&self) -> bool {
        self.0.supports_model_listing()
    }
}
