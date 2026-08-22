//! Provider-native continuation views over canonical typed tool results.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{ToolCall, ToolResult};

/// Current continuation schema.
pub const TOOL_CONTINUATION_SCHEMA_VERSION: u16 = 1;

/// One call/result pair in provider order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolExchange {
    pub ordinal: usize,
    pub call: ToolCall,
    pub result: ToolResult,
}

/// Ordered, serializable continuation state retained by the host while a
/// provider receives its native projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolContinuation {
    schema_version: u16,
    parallel: bool,
    exchanges: Vec<ToolExchange>,
}

impl ToolContinuation {
    /// Bind calls and results without reordering or correlating by content.
    ///
    /// # Errors
    ///
    /// Rejects length, ID, handler, argument, ordinal, and duplicate-ID
    /// mismatches, as well as a pending frontend follow-up.
    pub fn new(
        calls: Vec<ToolCall>,
        results: Vec<ToolResult>,
        parallel: bool,
    ) -> Result<Self, ToolContinuationError> {
        if calls.len() != results.len() {
            return Err(ToolContinuationError::LengthMismatch {
                calls: calls.len(),
                results: results.len(),
            });
        }

        let mut ids = HashSet::with_capacity(calls.len());
        let mut exchanges = Vec::with_capacity(calls.len());
        for (ordinal, (call, result)) in calls.into_iter().zip(results).enumerate() {
            if call.id != result.tool_call_id() {
                return Err(ToolContinuationError::CallIdMismatch {
                    ordinal,
                    call: call.id,
                    result: result.tool_call_id().to_string(),
                });
            }
            if call.function.name != result.handler() {
                return Err(ToolContinuationError::HandlerMismatch {
                    ordinal,
                    call: call.function.name,
                    result: result.handler().to_string(),
                });
            }
            if call.function.arguments != result.invocation().raw_arguments {
                return Err(ToolContinuationError::ArgumentsMismatch { ordinal });
            }
            if !ids.insert(call.id.clone()) {
                return Err(ToolContinuationError::DuplicateCallId(call.id));
            }
            if result.follow_up().is_pending() {
                return Err(ToolContinuationError::PendingFollowUp {
                    ordinal,
                    call_id: call.id,
                });
            }
            exchanges.push(ToolExchange {
                ordinal,
                call,
                result,
            });
        }

        Ok(Self {
            schema_version: TOOL_CONTINUATION_SCHEMA_VERSION,
            parallel,
            exchanges,
        })
    }

    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version
    }

    #[must_use]
    pub const fn is_parallel(&self) -> bool {
        self.parallel
    }

    #[must_use]
    pub fn exchanges(&self) -> &[ToolExchange] {
        &self.exchanges
    }

    /// OpenAI-compatible ordered tool messages.
    #[must_use]
    pub fn openai_messages(&self) -> Vec<Value> {
        self.exchanges
            .iter()
            .map(|exchange| exchange.result.openai_message())
            .collect()
    }

    /// Anthropic-native user message with ordered `tool_result` blocks.
    #[must_use]
    pub fn anthropic_message(&self) -> Value {
        let content: Vec<Value> = self
            .exchanges
            .iter()
            .map(|exchange| {
                json!({
                    "type": "tool_result",
                    "tool_use_id": exchange.result.tool_call_id(),
                    "content": exchange.result.provider_content(),
                    "is_error": exchange.result.is_error(),
                })
            })
            .collect();
        json!({"role": "user", "content": content})
    }

    /// Gemini-native ordered `functionResponse` parts.  Gemini accepts an
    /// object response, so the typed envelope does not need a text encoding.
    #[must_use]
    pub fn gemini_parts(&self) -> Vec<Value> {
        self.exchanges
            .iter()
            .map(|exchange| {
                json!({
                    "functionResponse": {
                        "id": exchange.result.tool_call_id(),
                        "name": exchange.result.handler(),
                        "response": exchange.result.model_payload(),
                    }
                })
            })
            .collect()
    }
}

/// A call/result continuation violated its causal binding.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ToolContinuationError {
    #[error("tool continuation call/result length mismatch: {calls} calls, {results} results")]
    LengthMismatch { calls: usize, results: usize },
    #[error("tool continuation call ID mismatch at ordinal {ordinal}: {call:?} != {result:?}")]
    CallIdMismatch {
        ordinal: usize,
        call: String,
        result: String,
    },
    #[error("tool continuation handler mismatch at ordinal {ordinal}: {call:?} != {result:?}")]
    HandlerMismatch {
        ordinal: usize,
        call: String,
        result: String,
    },
    #[error("tool continuation arguments mismatch at ordinal {ordinal}")]
    ArgumentsMismatch { ordinal: usize },
    #[error("duplicate tool call ID in continuation: {0:?}")]
    DuplicateCallId(String),
    #[error("tool call {call_id:?} at ordinal {ordinal} still has a pending frontend follow-up")]
    PendingFollowUp { ordinal: usize, call_id: String },
}
