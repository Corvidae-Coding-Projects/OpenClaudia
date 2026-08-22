//! Bounded, provider-owned continuation state.
//!
//! Neutral conversation messages remain the portable history used by the
//! frontends.  This module provides a separate lane for native protocol items
//! that cannot be flattened without losing continuation semantics (for
//! example thought signatures, response identifiers, or native tool-call
//! ordering).

use std::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use thiserror::Error;

use super::{ContentDigest, ContinuationGeneration, ProviderContinuation, ProviderId};

/// Schema emitted for newly constructed provider-native state envelopes.
pub const PROVIDER_NATIVE_STATE_SCHEMA_VERSION: u32 = 1;
/// Maximum number of ordered native items retained for one continuation.
pub const MAX_PROVIDER_NATIVE_ITEMS: usize = 256;
/// Maximum encoded size of one native item payload.
pub const MAX_PROVIDER_NATIVE_ITEM_BYTES: usize = 256 * 1024;
/// Maximum nesting depth of one native item payload.
pub const MAX_PROVIDER_NATIVE_ITEM_DEPTH: usize = 64;
/// Maximum encoded size of all native item payloads in one envelope.
pub const MAX_PROVIDER_NATIVE_STATE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum model identity length retained in a continuation binding.
pub const MAX_PROVIDER_NATIVE_MODEL_BYTES: usize = 256;

/// Concrete upstream protocol that owns the opaque state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderWireProtocol {
    AnthropicMessages,
    OpenAiChatCompletions,
    OpenAiResponses,
    GeminiGenerateContent,
    GeminiInteractions,
    OllamaChat,
}

impl fmt::Display for ProviderWireProtocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AnthropicMessages => "anthropic_messages",
            Self::OpenAiChatCompletions => "openai_chat_completions",
            Self::OpenAiResponses => "openai_responses",
            Self::GeminiGenerateContent => "gemini_generate_content",
            Self::GeminiInteractions => "gemini_interactions",
            Self::OllamaChat => "ollama_chat",
        })
    }
}

/// Native state feature represented by an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStateFacet {
    NativeMessage,
    ToolCalls,
    ParallelToolCalls,
    Reasoning,
    Refusal,
    Usage,
    CacheMetadata,
    Compaction,
    ServerContinuation,
    TerminalState,
}

/// Whether an item must be replayed or is retained only as evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderNativeItemPurpose {
    Continuation,
    Evidence,
}

/// Adapter behavior for one native-state facet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderStateSupport {
    /// The adapter can reproduce this item on a subsequent provider request.
    RoundTrip,
    /// The item may be persisted losslessly but is never provider input.
    EvidenceOnly,
    /// The adapter deliberately does not support this facet.
    Unsupported(&'static str),
}

/// Complete native-state declaration for one provider wire protocol.
///
/// Named fields make omissions impossible when a new adapter is added or a
/// provider-specific slice upgrades one facet from unsupported to round-trip.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderStateContract {
    pub protocol: ProviderWireProtocol,
    pub native_message: ProviderStateSupport,
    pub tool_calls: ProviderStateSupport,
    pub parallel_tool_calls: ProviderStateSupport,
    pub reasoning: ProviderStateSupport,
    pub refusal: ProviderStateSupport,
    pub usage: ProviderStateSupport,
    pub cache_metadata: ProviderStateSupport,
    pub compaction: ProviderStateSupport,
    pub server_continuation: ProviderStateSupport,
    pub terminal_state: ProviderStateSupport,
}

impl ProviderStateContract {
    /// Return the declared behavior for `facet`.
    #[must_use]
    pub const fn support(self, facet: ProviderStateFacet) -> ProviderStateSupport {
        match facet {
            ProviderStateFacet::NativeMessage => self.native_message,
            ProviderStateFacet::ToolCalls => self.tool_calls,
            ProviderStateFacet::ParallelToolCalls => self.parallel_tool_calls,
            ProviderStateFacet::Reasoning => self.reasoning,
            ProviderStateFacet::Refusal => self.refusal,
            ProviderStateFacet::Usage => self.usage,
            ProviderStateFacet::CacheMetadata => self.cache_metadata,
            ProviderStateFacet::Compaction => self.compaction,
            ProviderStateFacet::ServerContinuation => self.server_continuation,
            ProviderStateFacet::TerminalState => self.terminal_state,
        }
    }

    /// Validate that every item can be handled without lossy fallback.
    ///
    /// # Errors
    ///
    /// Returns an error for a protocol mismatch, an unsupported item, or an
    /// evidence-only facet incorrectly marked as required continuation input.
    pub fn validate_state(
        self,
        state: &ProviderNativeState,
    ) -> Result<(), ProviderStateContractError> {
        if self.protocol != state.protocol {
            return Err(ProviderStateContractError::ProtocolMismatch {
                contract: self.protocol,
                state: state.protocol,
            });
        }
        for item in &state.items {
            match (self.support(item.facet), item.purpose) {
                (ProviderStateSupport::RoundTrip, _)
                | (ProviderStateSupport::EvidenceOnly, ProviderNativeItemPurpose::Evidence) => {}
                (ProviderStateSupport::EvidenceOnly, ProviderNativeItemPurpose::Continuation) => {
                    return Err(ProviderStateContractError::EvidenceOnlyContinuation {
                        facet: item.facet,
                    });
                }
                (ProviderStateSupport::Unsupported(reason), _) => {
                    return Err(ProviderStateContractError::UnsupportedFacet {
                        facet: item.facet,
                        reason,
                    });
                }
            }
        }
        Ok(())
    }
}

/// Failure to apply a provider adapter's native-state contract.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProviderStateContractError {
    #[error("native-state contract is for {contract}, but state is for {state}")]
    ProtocolMismatch {
        contract: ProviderWireProtocol,
        state: ProviderWireProtocol,
    },
    #[error("native-state facet {facet:?} is evidence-only and cannot be replayed")]
    EvidenceOnlyContinuation { facet: ProviderStateFacet },
    #[error("native-state facet {facet:?} is unsupported: {reason}")]
    UnsupportedFacet {
        facet: ProviderStateFacet,
        reason: &'static str,
    },
}

/// One ordered opaque provider item.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderNativeItem {
    sequence: u32,
    facet: ProviderStateFacet,
    purpose: ProviderNativeItemPurpose,
    payload: Value,
}

impl<'de> Deserialize<'de> for ProviderNativeItem {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct PersistedItem {
            sequence: u32,
            facet: ProviderStateFacet,
            purpose: ProviderNativeItemPurpose,
            payload: Value,
        }

        let raw = PersistedItem::deserialize(deserializer)?;
        let item = Self {
            sequence: raw.sequence,
            facet: raw.facet,
            purpose: raw.purpose,
            payload: raw.payload,
        };
        item.validate_payload().map_err(D::Error::custom)?;
        Ok(item)
    }
}

impl ProviderNativeItem {
    /// Construct an unsequenced native item.  The enclosing state constructor
    /// assigns a deterministic sequence number.
    ///
    /// # Errors
    ///
    /// Returns an error when `payload` is not an object or exceeds the per-item
    /// bound.
    pub fn new(
        facet: ProviderStateFacet,
        purpose: ProviderNativeItemPurpose,
        payload: Value,
    ) -> Result<Self, ProviderStateError> {
        let item = Self {
            sequence: 0,
            facet,
            purpose,
            payload,
        };
        item.validate_payload()?;
        Ok(item)
    }

    /// Zero-based position of this item in its native stream.
    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Native feature carried by this item.
    #[must_use]
    pub const fn facet(&self) -> ProviderStateFacet {
        self.facet
    }

    /// Whether the item is required for continuation or retained as evidence.
    #[must_use]
    pub const fn purpose(&self) -> ProviderNativeItemPurpose {
        self.purpose
    }

    /// Borrow the opaque structured provider payload.
    #[must_use]
    pub const fn payload(&self) -> &Value {
        &self.payload
    }

    fn validate_payload(&self) -> Result<usize, ProviderStateError> {
        if !self.payload.is_object() {
            return Err(ProviderStateError::PayloadMustBeObject {
                sequence: self.sequence,
            });
        }
        validate_payload_depth(&self.payload, 0, self.sequence)?;
        let bytes = serde_json::to_vec(&self.payload)
            .map_err(ProviderStateError::PayloadSerialization)?
            .len();
        if bytes > MAX_PROVIDER_NATIVE_ITEM_BYTES {
            return Err(ProviderStateError::ItemTooLarge {
                sequence: self.sequence,
                bytes,
                maximum: MAX_PROVIDER_NATIVE_ITEM_BYTES,
            });
        }
        Ok(bytes)
    }
}

impl fmt::Debug for ProviderNativeItem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderNativeItem")
            .field("sequence", &self.sequence)
            .field("facet", &self.facet)
            .field("purpose", &self.purpose)
            .field("payload", &"<redacted>")
            .finish()
    }
}

/// Versioned provider-native state persisted alongside portable conversation
/// messages.  The digest binds identity, protocol, generation, and all ordered
/// payloads.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderNativeState {
    schema_version: u32,
    provider: ProviderId,
    model: String,
    protocol: ProviderWireProtocol,
    generation: ContinuationGeneration,
    items: Vec<ProviderNativeItem>,
    digest: ContentDigest,
}

impl ProviderNativeState {
    /// Construct and digest a validated provider-native state envelope.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid identity, malformed or oversized items, or
    /// a state envelope above the total bound.
    pub fn new(
        provider: impl Into<String>,
        model: impl Into<String>,
        protocol: ProviderWireProtocol,
        generation: ContinuationGeneration,
        mut items: Vec<ProviderNativeItem>,
    ) -> Result<Self, ProviderStateError> {
        let provider_value = provider.into();
        let provider = ProviderId::new(provider_value.to_ascii_lowercase())
            .map_err(|error| ProviderStateError::InvalidProvider(error.to_string()))?;
        let model = model.into();
        validate_model(&model)?;
        if items.len() > MAX_PROVIDER_NATIVE_ITEMS {
            return Err(ProviderStateError::TooManyItems {
                count: items.len(),
                maximum: MAX_PROVIDER_NATIVE_ITEMS,
            });
        }
        let item_count = items.len();
        for (sequence, item) in items.iter_mut().enumerate() {
            item.sequence =
                u32::try_from(sequence).map_err(|_| ProviderStateError::TooManyItems {
                    count: item_count,
                    maximum: MAX_PROVIDER_NATIVE_ITEMS,
                })?;
        }
        let mut state = Self {
            schema_version: PROVIDER_NATIVE_STATE_SCHEMA_VERSION,
            provider,
            model,
            protocol,
            generation,
            items,
            digest: ContentDigest::sha256([]),
        };
        state.validate_shape()?;
        state.digest = state.calculate_digest()?;
        Ok(state)
    }

    /// Provider identity bound to this state.
    #[must_use]
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// Exact model identity bound to this state.
    #[must_use]
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Upstream protocol that owns this state.
    #[must_use]
    pub const fn protocol(&self) -> ProviderWireProtocol {
        self.protocol
    }

    /// Monotonic native-state generation.
    #[must_use]
    pub const fn generation(&self) -> ContinuationGeneration {
        self.generation
    }

    /// Ordered native state items.
    #[must_use]
    pub fn items(&self) -> &[ProviderNativeItem] {
        &self.items
    }

    /// Digest binding this exact state envelope.
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.digest
    }

    /// Whether this envelope contains provider input needed on resume.
    #[must_use]
    pub fn has_continuation_items(&self) -> bool {
        self.items
            .iter()
            .any(|item| item.purpose == ProviderNativeItemPurpose::Continuation)
    }

    /// Produce the immutable runtime continuation binding for this envelope.
    #[must_use]
    pub fn continuation_binding(&self) -> ProviderContinuation {
        ProviderContinuation::Resume {
            provider: self.provider.clone(),
            generation: self.generation,
            state_digest: self.digest,
        }
    }

    /// Validate the envelope's own structure and digest.
    ///
    /// # Errors
    ///
    /// Returns an error when persisted state was malformed or tampered with.
    pub fn validate(&self) -> Result<(), ProviderStateError> {
        self.validate_shape()?;
        let actual = self.calculate_digest()?;
        if actual != self.digest {
            return Err(ProviderStateError::DigestMismatch {
                expected: self.digest,
                actual,
            });
        }
        Ok(())
    }

    /// Validate the provider, model, and protocol selected for a request.
    ///
    /// # Errors
    ///
    /// Returns an error rather than permitting native state to cross an
    /// incompatible provider, model, or wire-protocol boundary.
    pub fn validate_binding(
        &self,
        provider: &str,
        model: &str,
        protocol: ProviderWireProtocol,
    ) -> Result<(), ProviderStateError> {
        self.validate_identity(provider, model)?;
        if self.protocol != protocol {
            return Err(ProviderStateError::ProtocolMismatch {
                stored: self.protocol,
                requested: protocol,
            });
        }
        Ok(())
    }

    /// Validate only the persisted provider/model identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the state belongs to another provider or model.
    pub fn validate_identity(&self, provider: &str, model: &str) -> Result<(), ProviderStateError> {
        if !self.provider.as_str().eq_ignore_ascii_case(provider.trim()) {
            return Err(ProviderStateError::ProviderMismatch {
                stored: self.provider.as_str().to_string(),
                requested: provider.to_string(),
            });
        }
        if self.model != model {
            return Err(ProviderStateError::ModelMismatch {
                stored: self.model.clone(),
                requested: model.to_string(),
            });
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ProviderStateError> {
        if self.schema_version != PROVIDER_NATIVE_STATE_SCHEMA_VERSION {
            return Err(ProviderStateError::UnsupportedSchema {
                found: self.schema_version,
                supported: PROVIDER_NATIVE_STATE_SCHEMA_VERSION,
            });
        }
        ProviderId::new(self.provider.as_str().to_string())
            .map_err(|error| ProviderStateError::InvalidProvider(error.to_string()))?;
        validate_model(&self.model)?;
        if self.items.len() > MAX_PROVIDER_NATIVE_ITEMS {
            return Err(ProviderStateError::TooManyItems {
                count: self.items.len(),
                maximum: MAX_PROVIDER_NATIVE_ITEMS,
            });
        }
        let mut total = 0_usize;
        for (expected, item) in self.items.iter().enumerate() {
            let expected =
                u32::try_from(expected).map_err(|_| ProviderStateError::TooManyItems {
                    count: self.items.len(),
                    maximum: MAX_PROVIDER_NATIVE_ITEMS,
                })?;
            if item.sequence != expected {
                return Err(ProviderStateError::InvalidSequence {
                    expected,
                    found: item.sequence,
                });
            }
            total = total.checked_add(item.validate_payload()?).ok_or(
                ProviderStateError::StateTooLarge {
                    bytes: usize::MAX,
                    maximum: MAX_PROVIDER_NATIVE_STATE_BYTES,
                },
            )?;
            if total > MAX_PROVIDER_NATIVE_STATE_BYTES {
                return Err(ProviderStateError::StateTooLarge {
                    bytes: total,
                    maximum: MAX_PROVIDER_NATIVE_STATE_BYTES,
                });
            }
        }
        Ok(())
    }

    fn calculate_digest(&self) -> Result<ContentDigest, ProviderStateError> {
        #[derive(Serialize)]
        struct DigestInput<'a> {
            schema_version: u32,
            provider: &'a ProviderId,
            model: &'a str,
            protocol: ProviderWireProtocol,
            generation: ContinuationGeneration,
            items: Vec<CanonicalDigestItem>,
        }

        #[derive(Serialize)]
        struct CanonicalDigestItem {
            sequence: u32,
            facet: ProviderStateFacet,
            purpose: ProviderNativeItemPurpose,
            payload: Value,
        }

        let items = self
            .items
            .iter()
            .map(|item| CanonicalDigestItem {
                sequence: item.sequence,
                facet: item.facet,
                purpose: item.purpose,
                payload: canonical_json(&item.payload),
            })
            .collect();
        let input = DigestInput {
            schema_version: self.schema_version,
            provider: &self.provider,
            model: &self.model,
            protocol: self.protocol,
            generation: self.generation,
            items,
        };
        let bytes = serde_json::to_vec(&input).map_err(ProviderStateError::DigestSerialization)?;
        Ok(ContentDigest::sha256(bytes))
    }
}

impl fmt::Debug for ProviderNativeState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded_bytes = self
            .items
            .iter()
            .filter_map(|item| serde_json::to_vec(&item.payload).ok())
            .map(|payload| payload.len())
            .sum::<usize>();
        formatter
            .debug_struct("ProviderNativeState")
            .field("schema_version", &self.schema_version)
            .field("provider", &self.provider)
            .field("model", &self.model)
            .field("protocol", &self.protocol)
            .field("generation", &self.generation)
            .field("item_count", &self.items.len())
            .field("encoded_payload_bytes", &encoded_bytes)
            .field("digest", &self.digest)
            .finish()
    }
}

impl<'de> Deserialize<'de> for ProviderNativeState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct PersistedState {
            schema_version: u32,
            provider: ProviderId,
            model: String,
            protocol: ProviderWireProtocol,
            generation: ContinuationGeneration,
            items: Vec<ProviderNativeItem>,
            digest: ContentDigest,
        }

        let raw = PersistedState::deserialize(deserializer)?;
        let state = Self {
            schema_version: raw.schema_version,
            provider: raw.provider,
            model: raw.model,
            protocol: raw.protocol,
            generation: raw.generation,
            items: raw.items,
            digest: raw.digest,
        };
        state.validate().map_err(D::Error::custom)?;
        Ok(state)
    }
}

/// Provider-native state validation failure.
#[derive(Debug, Error)]
pub enum ProviderStateError {
    #[error(
        "provider-native state schema {found} is unsupported; maximum supported is {supported}"
    )]
    UnsupportedSchema { found: u32, supported: u32 },
    #[error("invalid provider identity: {0}")]
    InvalidProvider(String),
    #[error("provider-native state model must be 1-{MAX_PROVIDER_NATIVE_MODEL_BYTES} bytes without control characters")]
    InvalidModel,
    #[error("provider-native state contains {count} items; maximum is {maximum}")]
    TooManyItems { count: usize, maximum: usize },
    #[error("provider-native item sequence mismatch: expected {expected}, found {found}")]
    InvalidSequence { expected: u32, found: u32 },
    #[error("provider-native item {sequence} payload must be a JSON object")]
    PayloadMustBeObject { sequence: u32 },
    #[error("provider-native item {sequence} payload exceeds maximum nesting depth {maximum}")]
    PayloadTooDeep { sequence: u32, maximum: usize },
    #[error("provider-native item {sequence} is {bytes} bytes; maximum is {maximum}")]
    ItemTooLarge {
        sequence: u32,
        bytes: usize,
        maximum: usize,
    },
    #[error("provider-native state payloads total {bytes} bytes; maximum is {maximum}")]
    StateTooLarge { bytes: usize, maximum: usize },
    #[error("could not encode provider-native item payload: {0}")]
    PayloadSerialization(serde_json::Error),
    #[error("could not encode provider-native state digest: {0}")]
    DigestSerialization(serde_json::Error),
    #[error("provider-native state digest mismatch: stored {expected}, calculated {actual}")]
    DigestMismatch {
        expected: ContentDigest,
        actual: ContentDigest,
    },
    #[error("provider-native state belongs to provider {stored:?}, not {requested:?}")]
    ProviderMismatch { stored: String, requested: String },
    #[error("provider-native state belongs to model {stored:?}, not {requested:?}")]
    ModelMismatch { stored: String, requested: String },
    #[error("provider-native state uses {stored}, not requested protocol {requested}")]
    ProtocolMismatch {
        stored: ProviderWireProtocol,
        requested: ProviderWireProtocol,
    },
    #[error(
        "provider-native state generation {attempted} is stale; current generation is {current}"
    )]
    StaleGeneration {
        current: ContinuationGeneration,
        attempted: ContinuationGeneration,
    },
    #[error(
        "provider-native state generation {generation} conflicts with the current state digest"
    )]
    GenerationConflict { generation: ContinuationGeneration },
}

fn validate_model(model: &str) -> Result<(), ProviderStateError> {
    if model.is_empty()
        || model.len() > MAX_PROVIDER_NATIVE_MODEL_BYTES
        || model.chars().any(char::is_control)
    {
        Err(ProviderStateError::InvalidModel)
    } else {
        Ok(())
    }
}

fn validate_payload_depth(
    value: &Value,
    depth: usize,
    sequence: u32,
) -> Result<(), ProviderStateError> {
    if depth > MAX_PROVIDER_NATIVE_ITEM_DEPTH {
        return Err(ProviderStateError::PayloadTooDeep {
            sequence,
            maximum: MAX_PROVIDER_NATIVE_ITEM_DEPTH,
        });
    }
    match value {
        Value::Array(values) => {
            for value in values {
                validate_payload_depth(value, depth + 1, sequence)?;
            }
        }
        Value::Object(map) => {
            for value in map.values() {
                validate_payload_depth(value, depth + 1, sequence)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

fn canonical_json(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonical_json).collect()),
        Value::Object(map) => {
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_unstable_by_key(|(key, _)| *key);
            let mut canonical = serde_json::Map::new();
            for (key, value) in entries {
                canonical.insert(key.clone(), canonical_json(value));
            }
            Value::Object(canonical)
        }
        scalar => scalar.clone(),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn generation() -> ContinuationGeneration {
        ContinuationGeneration::new(1).expect("non-zero test generation")
    }

    fn fixture_state() -> ProviderNativeState {
        ProviderNativeState::new(
            "anthropic",
            "claude-test",
            ProviderWireProtocol::AnthropicMessages,
            generation(),
            vec![
                ProviderNativeItem::new(
                    ProviderStateFacet::Reasoning,
                    ProviderNativeItemPurpose::Continuation,
                    json!({
                        "type": "thinking",
                        "thinking": "private reasoning",
                        "signature": "signature-secret"
                    }),
                )
                .expect("valid item"),
                ProviderNativeItem::new(
                    ProviderStateFacet::Reasoning,
                    ProviderNativeItemPurpose::Continuation,
                    json!({"type": "redacted_thinking", "data": "redacted-secret"}),
                )
                .expect("valid item"),
                ProviderNativeItem::new(
                    ProviderStateFacet::ToolCalls,
                    ProviderNativeItemPurpose::Continuation,
                    json!({
                        "thoughtSignature": "gemini-signature",
                        "functionCall": {"id": "call-native-1", "name": "read_file"}
                    }),
                )
                .expect("valid item"),
                ProviderNativeItem::new(
                    ProviderStateFacet::ServerContinuation,
                    ProviderNativeItemPurpose::Continuation,
                    json!({"previous_response_id": "resp_native_1"}),
                )
                .expect("valid item"),
                ProviderNativeItem::new(
                    ProviderStateFacet::Refusal,
                    ProviderNativeItemPurpose::Evidence,
                    json!({"refusal": "policy refusal"}),
                )
                .expect("valid item"),
                ProviderNativeItem::new(
                    ProviderStateFacet::Usage,
                    ProviderNativeItemPurpose::Evidence,
                    json!({"input_tokens": 41, "output_tokens": 7}),
                )
                .expect("valid item"),
                ProviderNativeItem::new(
                    ProviderStateFacet::CacheMetadata,
                    ProviderNativeItemPurpose::Evidence,
                    json!({"cache_read_input_tokens": 23}),
                )
                .expect("valid item"),
            ],
        )
        .expect("valid state")
    }

    #[test]
    fn native_payloads_round_trip_without_flattening() {
        let state = fixture_state();
        let encoded = serde_json::to_string(&state).expect("serialize state");
        let decoded: ProviderNativeState = serde_json::from_str(&encoded).expect("deserialize");

        assert_eq!(decoded, state);
        assert_eq!(decoded.items()[0].sequence(), 0);
        assert_eq!(
            decoded.items()[2].payload()["functionCall"]["id"],
            "call-native-1"
        );
        assert_eq!(
            decoded.items()[3].payload()["previous_response_id"],
            "resp_native_1"
        );
    }

    #[test]
    fn debug_redacts_opaque_payloads() {
        let rendered = format!("{:?}", fixture_state());
        assert!(!rendered.contains("private reasoning"));
        assert!(!rendered.contains("signature-secret"));
        assert!(!rendered.contains("redacted-secret"));
        assert!(rendered.contains("item_count"));
    }

    #[test]
    fn deserialization_rejects_tampered_payload() {
        let mut encoded = serde_json::to_value(fixture_state()).expect("serialize state");
        encoded["items"][0]["payload"]["signature"] = json!("tampered");
        let error = serde_json::from_value::<ProviderNativeState>(encoded)
            .expect_err("digest must reject tampering");
        assert!(error.to_string().contains("digest mismatch"));
    }

    #[test]
    fn deserialization_rejects_non_contiguous_sequence() {
        let mut encoded = serde_json::to_value(fixture_state()).expect("serialize state");
        encoded["items"][1]["sequence"] = json!(8);
        let error = serde_json::from_value::<ProviderNativeState>(encoded)
            .expect_err("sequence must be contiguous");
        assert!(error.to_string().contains("sequence mismatch"));
    }

    #[test]
    fn item_requires_bounded_structured_payload() {
        assert!(matches!(
            ProviderNativeItem::new(
                ProviderStateFacet::NativeMessage,
                ProviderNativeItemPurpose::Continuation,
                json!("not structured")
            ),
            Err(ProviderStateError::PayloadMustBeObject { .. })
        ));
        assert!(matches!(
            ProviderNativeItem::new(
                ProviderStateFacet::NativeMessage,
                ProviderNativeItemPurpose::Continuation,
                json!({"data": "x".repeat(MAX_PROVIDER_NATIVE_ITEM_BYTES)})
            ),
            Err(ProviderStateError::ItemTooLarge { .. })
        ));

        let mut nested = json!(null);
        for _ in 0..=MAX_PROVIDER_NATIVE_ITEM_DEPTH {
            nested = json!({"child": nested});
        }
        assert!(matches!(
            ProviderNativeItem::new(
                ProviderStateFacet::NativeMessage,
                ProviderNativeItemPurpose::Continuation,
                nested
            ),
            Err(ProviderStateError::PayloadTooDeep { .. })
        ));

        let persisted = json!({
            "sequence": 0,
            "facet": "native_message",
            "purpose": "continuation",
            "payload": "not structured"
        });
        assert!(serde_json::from_value::<ProviderNativeItem>(persisted).is_err());
    }

    #[test]
    fn binding_rejects_provider_model_and_protocol_drift() {
        let state = fixture_state();
        assert!(state
            .validate_binding(
                "anthropic",
                "claude-test",
                ProviderWireProtocol::AnthropicMessages
            )
            .is_ok());
        assert!(matches!(
            state.validate_binding(
                "openai",
                "claude-test",
                ProviderWireProtocol::AnthropicMessages
            ),
            Err(ProviderStateError::ProviderMismatch { .. })
        ));
        assert!(matches!(
            state.validate_binding(
                "anthropic",
                "claude-other",
                ProviderWireProtocol::AnthropicMessages
            ),
            Err(ProviderStateError::ModelMismatch { .. })
        ));
        assert!(matches!(
            state.validate_binding(
                "anthropic",
                "claude-test",
                ProviderWireProtocol::OpenAiResponses
            ),
            Err(ProviderStateError::ProtocolMismatch { .. })
        ));
    }

    #[test]
    fn envelope_enforces_schema_identity_and_count_bounds() {
        let item = || {
            ProviderNativeItem::new(
                ProviderStateFacet::Usage,
                ProviderNativeItemPurpose::Evidence,
                json!({"tokens": 1}),
            )
            .expect("valid item")
        };
        assert!(matches!(
            ProviderNativeState::new(
                "openai",
                "gpt-test",
                ProviderWireProtocol::OpenAiResponses,
                generation(),
                (0..=MAX_PROVIDER_NATIVE_ITEMS).map(|_| item()).collect(),
            ),
            Err(ProviderStateError::TooManyItems { .. })
        ));

        let mut encoded = serde_json::to_value(fixture_state()).expect("serialize state");
        encoded["schema_version"] = json!(PROVIDER_NATIVE_STATE_SCHEMA_VERSION + 1);
        let error = serde_json::from_value::<ProviderNativeState>(encoded)
            .expect_err("future schema must fail");
        assert!(error.to_string().contains("schema"));

        let mut encoded = serde_json::to_value(fixture_state()).expect("serialize state");
        encoded["provider"] = json!("invalid/provider");
        let error = serde_json::from_value::<ProviderNativeState>(encoded)
            .expect_err("invalid provider identity must fail");
        assert!(error.to_string().contains("invalid provider"));
    }

    #[test]
    fn continuation_binding_uses_exact_generation_and_digest() {
        let state = fixture_state();
        assert_eq!(
            state.continuation_binding(),
            ProviderContinuation::Resume {
                provider: state.provider().clone(),
                generation: state.generation(),
                state_digest: state.digest(),
            }
        );
    }
}
