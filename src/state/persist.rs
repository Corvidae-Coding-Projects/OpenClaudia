//! On-disk serialization shape for [`super::SessionState`].
//!
//! The ratatui TUI and legacy line REPL historically wrote divergent shapes.
//! Both now serialize through [`SessionDocument`], which stores picker
//! metadata next to one required [`SessionStateV1`] payload. Legacy top-level
//! fields remain read-only input handled by the migration decoder; new writes
//! never duplicate identity or conversation state.
//!
//! This module is intentionally thin — a `SessionStateV1` is
//! equivalent to a [`super::SessionState`] plus a schema version
//! tag. The serde layout is what serde derives by default; no
//! custom adapters. Future schema bumps ship their own `V2` struct
//! + a `From<V1> for V2` impl + an entry in the migrations framework.

use serde::{Deserialize, Serialize};

use std::path::{Path, PathBuf};

use super::{AgentMode, SessionId, SessionState};

/// Canonical session document shared by every interactive frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDocument {
    pub title: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub model: String,
    pub provider: String,
    pub session_state: SessionStateV1,
    /// Transitional Phase 1–4 documents carried a duplicated top-level id.
    /// Accept it long enough to verify that it agrees with canonical state,
    /// but never write it again.
    #[serde(default, rename = "id", skip_serializing)]
    compatibility_id: Option<String>,
}

impl SessionDocument {
    /// Build a compatibility document from canonical session state.
    #[must_use]
    pub const fn from_state(
        title: String,
        created_at: chrono::DateTime<chrono::Utc>,
        updated_at: chrono::DateTime<chrono::Utc>,
        model: String,
        provider: String,
        state: SessionState,
    ) -> Self {
        Self {
            title,
            created_at,
            updated_at,
            model,
            provider,
            session_state: SessionStateV1::wrap(state),
            compatibility_id: None,
        }
    }

    /// Recover canonical state from the required V1 payload.
    ///
    /// # Errors
    ///
    /// Returns [`PersistError::FutureSchema`] when the document was written by
    /// a newer binary, or [`PersistError::InconsistentSessionId`] when a
    /// transitional file carries conflicting identities.
    pub fn into_state(self) -> Result<SessionState, PersistError> {
        if self.session_state.version > SessionStateV1::CURRENT_VERSION {
            return Err(PersistError::FutureSchema {
                found: self.session_state.version,
                supported: SessionStateV1::CURRENT_VERSION,
            });
        }
        let state = self.session_state.into_state();
        if let Some(legacy) = self.compatibility_id {
            if state.identity.session_id.as_str() != legacy {
                return Err(PersistError::InconsistentSessionId {
                    legacy,
                    canonical: state.identity.session_id.to_string(),
                });
            }
        }
        if let Some(native) = &state.conversation.provider_native_state {
            native
                .validate_identity(&self.provider, &self.model)
                .map_err(|error| PersistError::InvalidProviderNativeState(error.to_string()))?;
        }
        Ok(state)
    }
}

/// Pre-V1 top-level session layout. Read-only: new files are never emitted in
/// this shape. Defaults cover both the old TUI and line-REPL variants.
#[derive(Debug, Deserialize)]
struct LegacySessionDocument {
    id: String,
    title: String,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    model: String,
    provider: String,
    #[serde(default)]
    mode: AgentMode,
    #[serde(default)]
    behavior_mode: crate::modes::BehaviorMode,
    #[serde(default)]
    messages: Vec<serde_json::Value>,
    #[serde(default)]
    undo_stack: Vec<(serde_json::Value, serde_json::Value)>,
    #[serde(default)]
    plan_mode: Option<crate::session::PlanModeState>,
    #[serde(default)]
    approved_plan: Option<String>,
    #[serde(default)]
    working_dirs: Vec<PathBuf>,
}

impl LegacySessionDocument {
    fn upgrade(self, cwd: &Path) -> SessionDocument {
        let mut state = SessionState::new(cwd.to_path_buf());
        state.identity.session_id = SessionId::from_raw_unchecked(self.id);
        state.identity.additional_directories_for_claude_md = self.working_dirs;
        state.conversation.messages = self.messages;
        state.conversation.undo_stack = self.undo_stack;
        state.conversation.approved_plan = self.approved_plan;
        state.conversation.plan_mode = self.plan_mode;
        state.conversation.behavior_mode = self.behavior_mode;
        state.modes.agent_mode = self.mode;
        SessionDocument::from_state(
            self.title,
            self.created_at,
            self.updated_at,
            self.model,
            self.provider,
            state,
        )
    }
}

/// Decode either the canonical document or a pre-V1 top-level document.
pub(crate) fn decode_document_value(
    value: serde_json::Value,
    cwd: &Path,
) -> Result<SessionDocument, PersistError> {
    if value.get("session_state").is_some() {
        let document: SessionDocument = serde_json::from_value(value)?;
        // Validate future versions and transitional duplicated identities now,
        // before a caller can use the session id in a path.
        let state = document.clone().into_state()?;
        let mut canonical = document;
        canonical.compatibility_id = None;
        canonical.session_state = SessionStateV1::wrap(state);
        return Ok(canonical);
    }
    let legacy: LegacySessionDocument = serde_json::from_value(value)?;
    Ok(legacy.upgrade(cwd))
}

/// Decode a session document and report whether it already used the canonical
/// non-duplicated V1 layout.
///
/// # Errors
///
/// Returns [`PersistError::Json`] for malformed or structurally invalid JSON,
/// [`PersistError::FutureSchema`] for a newer state version, or
/// [`PersistError::InconsistentSessionId`] for conflicting transitional ids.
pub fn decode_document_for_migration(
    raw: &str,
    cwd: &Path,
) -> Result<(SessionDocument, bool), PersistError> {
    let value: serde_json::Value = serde_json::from_str(raw)?;
    let canonical = value
        .get("session_state")
        .and_then(|state| state.get("version"))
        .and_then(serde_json::Value::as_u64)
        == Some(u64::from(SessionStateV1::CURRENT_VERSION))
        && [
            "id",
            "mode",
            "behavior_mode",
            "messages",
            "undo_stack",
            "plan_mode",
            "approved_plan",
            "working_dirs",
        ]
        .iter()
        .all(|key| value.get(key).is_none());
    Ok((decode_document_value(value, cwd)?, canonical))
}

/// Schema version 1 — matches [`super::SessionState`] field-for-field.
/// Shipping the version tag from day one gives future migrations a
/// sentinel to dispatch on (see crosslink #506 migrations framework).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStateV1 {
    /// Schema version number. Always `1` for this type — a future
    /// `SessionStateV2` would have `version: 2` and its own struct.
    pub version: u32,
    /// The actual payload.
    #[serde(flatten)]
    pub state: SessionState,
}

impl SessionStateV1 {
    /// The value of `version` this type corresponds to. Callers
    /// that read on-disk files compare the decoded `version` field
    /// against this before deserializing the rest — a mismatch
    /// triggers the migration path.
    pub const CURRENT_VERSION: u32 = 1;

    /// Wrap a `SessionState` in the versioned envelope.
    #[must_use]
    pub const fn wrap(state: SessionState) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            state,
        }
    }

    /// Unwrap, discarding the version tag. Use only after checking
    /// `version == CURRENT_VERSION`; for older versions, route
    /// through the migrations framework first.
    #[must_use]
    pub fn into_state(self) -> SessionState {
        self.state
    }
}

/// Persist errors — short enum so callers don't need to understand
/// serde / `std::io` error hierarchies.
#[derive(Debug, thiserror::Error)]
pub enum PersistError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error(
        "schema version {found} is newer than the max supported ({supported}); upgrade your harness"
    )]
    FutureSchema { found: u32, supported: u32 },
    #[error(
        "session id mismatch between compatibility field '{legacy}' and canonical state '{canonical}'"
    )]
    InconsistentSessionId { legacy: String, canonical: String },
    #[error("invalid provider-native session state: {0}")]
    InvalidProviderNativeState(String),
}

/// Encode a [`SessionState`] as pretty-printed JSON ready to write.
/// Pretty-printing so `git diff`s on committed-state dumps stay
/// readable — the cost is negligible at session-save frequency.
///
/// # Errors
///
/// Returns `PersistError::Json` if serialization fails (should be
/// impossible for the current struct; wired for future additions).
pub fn encode(state: &SessionState) -> Result<String, PersistError> {
    let wrapped = SessionStateV1::wrap(state.clone());
    Ok(serde_json::to_string_pretty(&wrapped)?)
}

/// Decode a JSON string written by [`encode`].
///
/// Checks the version tag first; future schemas that outrank `CURRENT_VERSION`
/// return `FutureSchema` so a newer harness doesn't clobber a downgrade user's
/// file on save.
///
/// # Errors
///
/// Returns `PersistError::Json` on malformed JSON, or
/// `PersistError::FutureSchema` when the on-disk version is newer
/// than this binary understands.
pub fn decode(raw: &str) -> Result<SessionState, PersistError> {
    // Peek at the version tag before deserializing the full shape —
    // lets us give a precise error without tripping on unknown fields.
    let peek: VersionPeek = serde_json::from_str(raw)?;
    if peek.version > SessionStateV1::CURRENT_VERSION {
        return Err(PersistError::FutureSchema {
            found: peek.version,
            supported: SessionStateV1::CURRENT_VERSION,
        });
    }
    let v1: SessionStateV1 = serde_json::from_str(raw)?;
    Ok(v1.into_state())
}

#[derive(Deserialize)]
struct VersionPeek {
    #[serde(default = "default_version")]
    version: u32,
}

const fn default_version() -> u32 {
    // A bare state file written before the version tag existed decodes to
    // version 0 so a caller can identify it as pre-V1.
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{
        ContinuationGeneration, ProviderNativeItem, ProviderNativeItemPurpose, ProviderNativeState,
        ProviderStateFacet, ProviderWireProtocol,
    };
    use std::path::PathBuf;

    #[test]
    fn encode_round_trips() {
        let state = SessionState::new(PathBuf::from("/tmp/x"));
        let encoded = encode(&state).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.identity.session_id, state.identity.session_id);
        assert_eq!(decoded.identity.cwd, state.identity.cwd);
    }

    #[test]
    fn encoded_payload_carries_version_tag() {
        let mut state = SessionState::default();
        state.permissions.bypass_mode = true;
        let encoded = encode(&state).unwrap();
        assert!(
            encoded.contains("\"version\""),
            "encoded payload should include the version tag: {encoded}"
        );
        assert!(encoded.contains("\"version\": 1"));
        assert!(
            !encoded.contains("\"permissions\""),
            "persisted state must omit live permission authority: {encoded}"
        );
    }

    #[test]
    fn pre_phase_three_payload_defaults_missing_ide_state() {
        let state = SessionState::new(PathBuf::from("/tmp/legacy-v1"));
        let mut payload = serde_json::to_value(SessionStateV1::wrap(state)).unwrap();
        payload
            .as_object_mut()
            .expect("versioned state is an object")
            .remove("ide");

        let decoded = decode(&serde_json::to_string(&payload).unwrap()).unwrap();

        assert!(decoded.ide.active_file.is_none());
        assert!(decoded.ide.recent_files.is_empty());
        assert!(decoded.ide.selection.is_none());
        assert!(decoded.ide.diagnostics.is_empty());
    }

    #[test]
    fn legacy_permission_fields_cannot_restore_authority() {
        let state = SessionState::new(PathBuf::from("/tmp/legacy-authority"));
        let mut payload = serde_json::to_value(SessionStateV1::wrap(state)).unwrap();
        payload.as_object_mut().unwrap().insert(
            "permissions".to_string(),
            serde_json::json!({
                "bypass_mode": true,
                "trust_accepted": true,
                "persistence_disabled": false
            }),
        );

        let decoded = decode(&payload.to_string()).unwrap();
        assert!(!decoded.permissions.bypass_mode);
        assert!(!decoded.permissions.trust_accepted);
        assert!(!decoded.permissions.persistence_disabled);
    }

    #[test]
    fn future_schema_is_rejected() {
        // Simulate a file written by a newer harness version.
        let payload = serde_json::json!({
            "version": 999,
            "identity": {
                "session_id": "x",
                "original_cwd": "/x",
                "cwd": "/x",
                "project_root": "/x",
                "session_project_dir": "/x"
            },
            "conversation": {},
            "ui": {},
            "modes": {},
            "permissions": {},
            "budgets": {},
            "ide": {},
            "transcript": {}
        })
        .to_string();

        match decode(&payload) {
            Err(PersistError::FutureSchema { found, supported }) => {
                assert_eq!(found, 999);
                assert_eq!(supported, 1);
            }
            other => panic!("expected FutureSchema, got {other:?}"),
        }
    }

    #[test]
    fn missing_version_decodes_as_zero() {
        // A bare state blob without the `version` tag is pre-V1.
        let payload = serde_json::json!({
            "identity": {
                "session_id": "legacy-id",
                "original_cwd": "/x",
                "cwd": "/x",
                "project_root": "/x",
                "session_project_dir": "/x"
            },
            "conversation": {},
            "ui": {},
            "modes": {},
            "permissions": {},
            "budgets": {},
            "ide": {},
            "transcript": {}
        })
        .to_string();
        let peek: VersionPeek = serde_json::from_str(&payload).unwrap();
        assert_eq!(peek.version, 0);
    }

    #[test]
    fn malformed_json_is_a_json_error() {
        let err = decode("{not valid").unwrap_err();
        assert!(matches!(err, PersistError::Json(_)));
    }

    #[test]
    fn session_document_round_trips_canonical_state() {
        let mut state = SessionState::new(PathBuf::from("/tmp/project"));
        state.modes.agent_mode = AgentMode::Refactor;
        state
            .conversation
            .messages
            .push(serde_json::json!({"role": "user", "content": "hello"}));
        state.conversation.approved_plan = Some("keep this plan".to_string());
        state
            .identity
            .additional_directories_for_claude_md
            .push(PathBuf::from("/tmp/shared"));
        let expected_id = state.identity.session_id.clone();

        let document = SessionDocument::from_state(
            "title".to_string(),
            chrono::Utc::now(),
            chrono::Utc::now(),
            "model".to_string(),
            "provider".to_string(),
            state,
        );
        let encoded = serde_json::to_string(&document).unwrap();
        let decoded: SessionDocument = serde_json::from_str(&encoded).unwrap();
        let restored = decoded.into_state().unwrap();

        assert_eq!(restored.identity.session_id, expected_id);
        assert_eq!(restored.modes.agent_mode, AgentMode::Refactor);
        assert_eq!(restored.conversation.messages.len(), 1);
        assert_eq!(
            restored.conversation.approved_plan.as_deref(),
            Some("keep this plan")
        );
        assert_eq!(
            restored.identity.additional_directories_for_claude_md,
            vec![PathBuf::from("/tmp/shared")]
        );
    }

    #[test]
    fn legacy_session_document_migrates_top_level_fields() {
        let encoded = serde_json::json!({
            "id": "legacy-session-id",
            "title": "legacy",
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2025-01-01T00:00:00Z",
            "model": "model",
            "provider": "provider",
            "mode": "Extend",
            "messages": [{"role": "assistant", "content": "remember me"}],
            "working_dirs": ["/tmp/legacy-extra"]
        })
        .to_string();

        let value = serde_json::from_str(&encoded).unwrap();
        let document = decode_document_value(value, Path::new("/tmp/current")).unwrap();
        let restored = document.into_state().unwrap();

        assert_eq!(restored.identity.session_id.as_str(), "legacy-session-id");
        assert_eq!(restored.identity.cwd, PathBuf::from("/tmp/current"));
        assert_eq!(restored.modes.agent_mode, AgentMode::Extend);
        assert_eq!(restored.conversation.messages.len(), 1);
        assert_eq!(
            restored.identity.additional_directories_for_claude_md,
            vec![PathBuf::from("/tmp/legacy-extra")]
        );
    }

    #[test]
    fn session_document_rejects_conflicting_identity_fields() {
        let state = SessionState::default();
        let mut document = SessionDocument::from_state(
            "title".to_string(),
            chrono::Utc::now(),
            chrono::Utc::now(),
            "model".to_string(),
            "provider".to_string(),
            state,
        );
        document.compatibility_id = Some("different-id".to_string());

        assert!(matches!(
            document.into_state(),
            Err(PersistError::InconsistentSessionId { .. })
        ));
    }

    #[test]
    fn session_document_rejects_native_state_bound_to_other_metadata() {
        let mut state = SessionState::default();
        state.conversation.provider_native_state = Some(
            ProviderNativeState::new(
                "openai",
                "gpt-test",
                ProviderWireProtocol::OpenAiResponses,
                ContinuationGeneration::new(1).expect("non-zero generation"),
                vec![ProviderNativeItem::new(
                    ProviderStateFacet::Usage,
                    ProviderNativeItemPurpose::Evidence,
                    serde_json::json!({"input_tokens": 1}),
                )
                .expect("valid item")],
            )
            .expect("valid provider state"),
        );
        let document = SessionDocument::from_state(
            "title".to_string(),
            chrono::Utc::now(),
            chrono::Utc::now(),
            "claude-test".to_string(),
            "anthropic".to_string(),
            state,
        );

        assert!(matches!(
            document.into_state(),
            Err(PersistError::InvalidProviderNativeState(_))
        ));
    }
}
