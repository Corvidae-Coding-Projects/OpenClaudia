//! Privacy boundary for provider reasoning data.
//!
//! Provider continuation, user-visible summaries, and protected monitoring are
//! deliberately different capabilities.  A provider-native item may carry an
//! opaque continuation, [`ReasoningSummary`] is the only reasoning text a
//! normal frontend may render, and [`ProtectedReasoningObservation`] can be
//! opened only by the exact unexpired monitoring grant that captured it.

use std::fmt;
use std::time::{Duration, SystemTime};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

use super::RunId;

/// Maximum UTF-8 bytes retained for one provider-sanctioned summary.
pub const MAX_REASONING_SUMMARY_BYTES: usize = 64 * 1024;
/// Maximum raw compatibility continuation retained for one in-flight
/// OpenAI-compatible tool-loop hop.
pub const MAX_PROVIDER_REASONING_CONTINUATION_BYTES: usize = super::MAX_PROVIDER_NATIVE_ITEM_BYTES;
/// Maximum lifetime of a protected monitoring observation.
pub const MAX_REASONING_MONITORING_RETENTION: Duration = Duration::from_mins(15);

/// The three non-interchangeable reasoning channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReasoningChannel {
    /// Provider-owned encrypted or otherwise opaque protocol continuation.
    ProviderContinuation,
    /// Provider-sanctioned summary intended for the session user.
    UserSummary,
    /// Raw observation visible only to a declared monitoring control plane.
    ProtectedMonitoring,
}

/// Consent authority required by a reasoning channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasoningConsent {
    /// The exact provider protocol requires the value for correct continuation.
    ProviderProtocol,
    /// The provider explicitly labels the value as a user-facing summary.
    ProviderSanctionedSummary,
    /// A user explicitly granted bounded monitoring for one run.
    ExplicitMonitoringGrant,
}

/// Principal allowed to open a reasoning channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasoningAccess {
    /// Only the same provider, model, and wire protocol may consume it.
    BoundProvider,
    /// The user who owns the interactive session may view it.
    SessionUser,
    /// Only the run-bound monitoring control plane may open it.
    MonitoringControlPlane,
}

/// Durable-storage rule for a reasoning channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasoningStorage {
    /// Store only provider-encrypted/opaque bytes in provider-native state.
    OpaqueProviderState,
    /// Store as a typed, bounded summary in the normal session document.
    TypedTranscriptSummary,
    /// Never serialize; an encrypted control-plane store is required for any
    /// future durable monitoring implementation.
    MemoryOnlyUntilEncryptedStore,
}

/// Retention/deletion rule for a reasoning channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasoningRetention {
    /// Delete when provider continuation is invalidated or the session ends.
    ContinuationLifetime,
    /// Retain and delete with the user-owned transcript.
    TranscriptLifetime,
    /// Never persist; zeroize when the owning control-plane value is dropped.
    ProcessMemoryUntilDrop,
}

/// Export rule for a reasoning channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasoningExport {
    /// Never include the value in transcript exports.
    Redacted,
    /// Include only as a clearly labeled summary in a user-requested export.
    UserRequestedSummary,
}

/// Frontend rendering rule for a reasoning channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasoningRendering {
    /// Never project the channel into ordinary frontend events.
    Hidden,
    /// Render only with a summary label, never as raw model thinking.
    LabeledSummary,
}

/// Complete static policy for one reasoning channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReasoningPolicy {
    pub consent: ReasoningConsent,
    pub access: ReasoningAccess,
    pub storage: ReasoningStorage,
    pub retention: ReasoningRetention,
    pub export: ReasoningExport,
    pub rendering: ReasoningRendering,
}

impl ReasoningChannel {
    /// Return the mandatory policy for this channel.
    #[must_use]
    pub const fn policy(self) -> ReasoningPolicy {
        match self {
            Self::ProviderContinuation => ReasoningPolicy {
                consent: ReasoningConsent::ProviderProtocol,
                access: ReasoningAccess::BoundProvider,
                storage: ReasoningStorage::OpaqueProviderState,
                retention: ReasoningRetention::ContinuationLifetime,
                export: ReasoningExport::Redacted,
                rendering: ReasoningRendering::Hidden,
            },
            Self::UserSummary => ReasoningPolicy {
                consent: ReasoningConsent::ProviderSanctionedSummary,
                access: ReasoningAccess::SessionUser,
                storage: ReasoningStorage::TypedTranscriptSummary,
                retention: ReasoningRetention::TranscriptLifetime,
                export: ReasoningExport::UserRequestedSummary,
                rendering: ReasoningRendering::LabeledSummary,
            },
            Self::ProtectedMonitoring => ReasoningPolicy {
                consent: ReasoningConsent::ExplicitMonitoringGrant,
                access: ReasoningAccess::MonitoringControlPlane,
                storage: ReasoningStorage::MemoryOnlyUntilEncryptedStore,
                retention: ReasoningRetention::ProcessMemoryUntilDrop,
                export: ReasoningExport::Redacted,
                rendering: ReasoningRendering::Hidden,
            },
        }
    }
}

/// A bounded provider-sanctioned summary that may be shown to the user.
///
/// Debug output remains opaque so adding the value to a diagnostic cannot
/// accidentally create an unreviewed transcript or log surface.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReasoningSummary {
    schema_version: u32,
    text: String,
}

impl ReasoningSummary {
    /// Validate a provider-sanctioned summary.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, or terminal-control-bearing
    /// text. Newlines and tabs remain valid summary formatting.
    pub fn try_from_provider(value: impl Into<String>) -> Result<Self, ReasoningPrivacyError> {
        let value = value.into();
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(ReasoningPrivacyError::EmptySummary);
        }
        if trimmed.len() > MAX_REASONING_SUMMARY_BYTES {
            return Err(ReasoningPrivacyError::SummaryTooLarge {
                bytes: trimmed.len(),
                maximum: MAX_REASONING_SUMMARY_BYTES,
            });
        }
        if trimmed
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        {
            return Err(ReasoningPrivacyError::SummaryContainsTerminalControl);
        }
        Ok(Self {
            schema_version: 1,
            text: trimmed.to_string(),
        })
    }

    /// Borrow the user-visible summary text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl fmt::Debug for ReasoningSummary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReasoningSummary")
            .field("bytes", &self.text.len())
            .finish_non_exhaustive()
    }
}

impl<'de> Deserialize<'de> for ReasoningSummary {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct PersistedSummary {
            schema_version: u32,
            text: String,
        }

        let value = PersistedSummary::deserialize(deserializer)?;
        if value.schema_version != 1 {
            return Err(D::Error::custom("unsupported reasoning summary schema"));
        }
        Self::try_from_provider(value.text).map_err(D::Error::custom)
    }
}

/// Raw reasoning required by some OpenAI-compatible providers for the next
/// tool-loop request only.
///
/// This value is intentionally non-serializable, opaque to `Debug`, zeroized
/// on drop, and has no text accessor. Its only operation installs the bytes on
/// the immediately preceding assistant tool-call message in an outbound wire
/// request.
pub struct ProviderReasoningContinuation {
    text: Zeroizing<String>,
}

impl ProviderReasoningContinuation {
    /// Capture one bounded provider continuation from a streamed response.
    ///
    /// # Errors
    ///
    /// Returns an error when the continuation exceeds its in-memory bound.
    pub fn try_from_provider(
        text: impl Into<String>,
    ) -> Result<Option<Self>, ReasoningPrivacyError> {
        let text = text.into();
        if text.is_empty() {
            return Ok(None);
        }
        if text.len() > MAX_PROVIDER_REASONING_CONTINUATION_BYTES {
            return Err(ReasoningPrivacyError::ProviderContinuationTooLarge {
                bytes: text.len(),
                maximum: MAX_PROVIDER_REASONING_CONTINUATION_BYTES,
            });
        }
        Ok(Some(Self {
            text: Zeroizing::new(text),
        }))
    }

    /// Install the continuation on the most recent assistant tool-call
    /// message in an OpenAI-compatible request.
    ///
    /// # Errors
    ///
    /// Returns an error rather than attaching the value to an ambiguous or
    /// unrelated message.
    pub fn apply_to_openai_chat_request(
        &self,
        request: &mut serde_json::Value,
    ) -> Result<(), ReasoningPrivacyError> {
        let messages = request
            .get_mut("messages")
            .and_then(serde_json::Value::as_array_mut)
            .ok_or(ReasoningPrivacyError::ProviderContinuationTargetMissing)?;
        let assistant = messages
            .iter_mut()
            .rev()
            .find(|message| {
                message.get("role").and_then(serde_json::Value::as_str) == Some("assistant")
                    && message
                        .get("tool_calls")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|calls| !calls.is_empty())
            })
            .ok_or(ReasoningPrivacyError::ProviderContinuationTargetMissing)?;
        assistant["reasoning_content"] = serde_json::Value::String(self.text.as_str().to_string());
        Ok(())
    }
}

impl fmt::Debug for ProviderReasoningContinuation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderReasoningContinuation")
            .field("bytes", &self.text.len())
            .finish_non_exhaustive()
    }
}

/// Explicit, run-bound consent for protected reasoning monitoring.
///
/// The grant is intentionally not serializable. Restarting the process or
/// resuming a session therefore requires a new affirmative grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReasoningMonitoringGrant {
    run_id: RunId,
    expires_at: SystemTime,
}

impl ReasoningMonitoringGrant {
    /// Create an explicit monitoring grant with a bounded lifetime.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero or over-limit lifetime or a clock overflow.
    pub fn explicit(run_id: RunId, lifetime: Duration) -> Result<Self, ReasoningPrivacyError> {
        if lifetime.is_zero() || lifetime > MAX_REASONING_MONITORING_RETENTION {
            return Err(ReasoningPrivacyError::InvalidMonitoringRetention);
        }
        let expires_at = SystemTime::now()
            .checked_add(lifetime)
            .ok_or(ReasoningPrivacyError::MonitoringDeadlineOverflow)?;
        Ok(Self { run_id, expires_at })
    }

    fn permits(self, run_id: RunId, expires_at: SystemTime) -> bool {
        self.run_id == run_id
            && self.expires_at == expires_at
            && SystemTime::now() < self.expires_at
    }
}

/// Grant-gated raw monitoring observation.
///
/// This type has no serialization implementation, no plaintext formatter, and
/// zeroizes its owned text on drop. A future persistent monitor must first add
/// a separately reviewed encrypted store rather than serializing this value.
pub struct ProtectedReasoningObservation {
    run_id: RunId,
    expires_at: SystemTime,
    text: Zeroizing<String>,
}

impl ProtectedReasoningObservation {
    /// Capture raw provider material under one exact monitoring grant.
    ///
    /// # Errors
    ///
    /// Returns an error when the grant is already expired or the observation
    /// exceeds the native-item bound.
    pub fn capture(
        grant: ReasoningMonitoringGrant,
        text: impl Into<String>,
    ) -> Result<Self, ReasoningPrivacyError> {
        if !grant.permits(grant.run_id, grant.expires_at) {
            return Err(ReasoningPrivacyError::MonitoringGrantExpired);
        }
        let text = text.into();
        if text.len() > super::MAX_PROVIDER_NATIVE_ITEM_BYTES {
            return Err(ReasoningPrivacyError::MonitoringObservationTooLarge {
                bytes: text.len(),
                maximum: super::MAX_PROVIDER_NATIVE_ITEM_BYTES,
            });
        }
        Ok(Self {
            run_id: grant.run_id,
            expires_at: grant.expires_at,
            text: Zeroizing::new(text),
        })
    }

    /// Open the observation only through its exact live grant.
    ///
    /// # Errors
    ///
    /// Returns an error for the wrong run/generation of consent or expiration.
    pub fn expose<R>(
        &self,
        grant: ReasoningMonitoringGrant,
        operation: impl FnOnce(&str) -> R,
    ) -> Result<R, ReasoningPrivacyError> {
        if !grant.permits(self.run_id, self.expires_at) {
            return Err(ReasoningPrivacyError::MonitoringAccessDenied);
        }
        Ok(operation(&self.text))
    }
}

impl fmt::Debug for ProtectedReasoningObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtectedReasoningObservation")
            .field("run_id", &self.run_id)
            .field("expires_at", &self.expires_at)
            .field("bytes", &self.text.len())
            .finish_non_exhaustive()
    }
}

/// Reasoning privacy boundary failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReasoningPrivacyError {
    #[error("provider reasoning summary is empty")]
    EmptySummary,
    #[error("provider reasoning summary is {bytes} bytes; maximum is {maximum}")]
    SummaryTooLarge { bytes: usize, maximum: usize },
    #[error("provider reasoning summary contains a terminal control character")]
    SummaryContainsTerminalControl,
    #[error("provider reasoning continuation is {bytes} bytes; maximum is {maximum}")]
    ProviderContinuationTooLarge { bytes: usize, maximum: usize },
    #[error("provider reasoning continuation has no assistant tool-call target")]
    ProviderContinuationTargetMissing,
    #[error("reasoning monitoring retention must be between one second and fifteen minutes")]
    InvalidMonitoringRetention,
    #[error("reasoning monitoring deadline overflowed the system clock")]
    MonitoringDeadlineOverflow,
    #[error("reasoning monitoring grant has expired")]
    MonitoringGrantExpired,
    #[error("reasoning monitoring observation is {bytes} bytes; maximum is {maximum}")]
    MonitoringObservationTooLarge { bytes: usize, maximum: usize },
    #[error("reasoning monitoring access requires the exact live run grant")]
    MonitoringAccessDenied,
}

/// Remove legacy raw-reasoning fields from one portable transcript message.
///
/// Returns whether anything was removed. Provider-sanctioned summaries use the
/// separate `reasoning_summary` key and are validated independently.
pub fn redact_legacy_portable_reasoning(message: &mut serde_json::Value) -> bool {
    if message.get("role").and_then(serde_json::Value::as_str) != Some("assistant") {
        return false;
    }
    let Some(object) = message.as_object_mut() else {
        return false;
    };
    ["reasoning_content", "reasoning", "thinking"]
        .into_iter()
        .filter_map(|key| object.remove(key))
        .count()
        > 0
}

/// Enforce the portable transcript reasoning boundary in place.
///
/// Raw compatibility fields are removed, and only a valid typed summary on an
/// assistant message is retained.
pub fn sanitize_portable_reasoning(message: &mut serde_json::Value) -> bool {
    let mut changed = redact_legacy_portable_reasoning(message);
    let role_is_assistant =
        message.get("role").and_then(serde_json::Value::as_str) == Some("assistant");
    let summary_is_valid = role_is_assistant && message_reasoning_summary(message).is_some();
    if !summary_is_valid
        && message
            .as_object_mut()
            .and_then(|object| object.remove("reasoning_summary"))
            .is_some()
    {
        changed = true;
    }
    changed
}

/// Remove every reasoning display field before portable history crosses a
/// provider boundary. Continuation is supplied only by the separately bound
/// provider-native state, never by transcript extras.
pub fn redact_reasoning_for_provider_request(message: &mut serde_json::Value) -> bool {
    let sanitized = sanitize_portable_reasoning(message);
    let summary_removed = message
        .as_object_mut()
        .and_then(|object| object.remove("reasoning_summary"))
        .is_some();
    sanitized || summary_removed
}

/// Attach one validated user-visible summary to an assistant projection.
pub fn attach_reasoning_summary(message: &mut serde_json::Value, summary: &ReasoningSummary) {
    if message.get("role").and_then(serde_json::Value::as_str) != Some("assistant") {
        return;
    }
    message["reasoning_summary"] = serde_json::json!({
        "schema_version": 1,
        "text": summary.as_str(),
    });
}

/// Read and validate the typed summary projection from a portable message.
#[must_use]
pub fn message_reasoning_summary(message: &serde_json::Value) -> Option<ReasoningSummary> {
    message
        .get("reasoning_summary")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn transient_continuation_targets_only_latest_assistant_tool_call() {
        let continuation = ProviderReasoningContinuation::try_from_provider("private chain")
            .expect("bounded continuation")
            .expect("non-empty continuation");
        let mut request = json!({
            "messages": [
                {"role": "assistant", "content": "old", "tool_calls": [{"id": "old"}]},
                {"role": "tool", "content": "old result"},
                {"role": "assistant", "content": "", "tool_calls": [{"id": "new"}]},
                {"role": "tool", "content": "new result"}
            ]
        });

        continuation
            .apply_to_openai_chat_request(&mut request)
            .expect("exact target");
        assert!(request["messages"][0].get("reasoning_content").is_none());
        assert_eq!(request["messages"][2]["reasoning_content"], "private chain");
    }

    #[test]
    fn portable_sanitizer_removes_raw_reasoning_but_keeps_typed_summary() {
        let summary = ReasoningSummary::try_from_provider("safe summary").expect("summary");
        let mut message = json!({
            "role": "assistant",
            "content": "answer",
            "reasoning_content": "private chain"
        });
        attach_reasoning_summary(&mut message, &summary);

        assert!(sanitize_portable_reasoning(&mut message));
        assert!(message.get("reasoning_content").is_none());
        assert_eq!(message_reasoning_summary(&message), Some(summary));
    }
}
