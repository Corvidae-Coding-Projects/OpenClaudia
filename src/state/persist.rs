//! On-disk serialization shape for [`super::SessionState`].
//!
//! The ratatui TUI and legacy line REPL historically wrote divergent shapes.
//! They now serialize through [`SessionDocument`], which keeps the legacy
//! top-level field layout readable and embeds [`SessionStateV1`] as the
//! canonical payload. Phase 5 of the migration (see
//! `docs/designs/510-session-state.md`) retires the compatibility wrappers.
//!
//! This module is intentionally thin — a `SessionStateV1` is
//! equivalent to a [`super::SessionState`] plus a schema version
//! tag. The serde layout is what serde derives by default; no
//! custom adapters. Future schema bumps ship their own `V2` struct
//! + a `From<V1> for V2` impl + an entry in the migrations framework.

use serde::{Deserialize, Serialize};

use std::path::{Path, PathBuf};

use super::{AgentMode, SessionId, SessionState};

/// Compatibility document shared by the TUI and legacy line REPL.
///
/// The top-level fields let current readers migrate pre-Phase-1 JSON.
/// `session_state` is the canonical V1 payload used for new round trips. The
/// duplicated compatibility fields can be removed together with the frontend
/// wrappers in Phase 5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionDocument {
    pub id: String,
    pub title: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub model: String,
    pub provider: String,
    #[serde(default)]
    pub mode: AgentMode,
    #[serde(default)]
    pub behavior_mode: crate::modes::BehaviorMode,
    #[serde(default)]
    pub messages: Vec<serde_json::Value>,
    #[serde(default)]
    pub undo_stack: Vec<(serde_json::Value, serde_json::Value)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_mode: Option<crate::session::PlanModeState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_plan: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub working_dirs: Vec<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_state: Option<SessionStateV1>,
}

impl SessionDocument {
    /// Build a compatibility document from canonical session state.
    #[must_use]
    pub fn from_state(
        title: String,
        created_at: chrono::DateTime<chrono::Utc>,
        updated_at: chrono::DateTime<chrono::Utc>,
        model: String,
        provider: String,
        state: SessionState,
    ) -> Self {
        Self {
            id: state.identity.session_id.to_string(),
            title,
            created_at,
            updated_at,
            model,
            provider,
            mode: state.modes.agent_mode,
            behavior_mode: state.conversation.behavior_mode.clone(),
            messages: state.conversation.messages.clone(),
            undo_stack: state.conversation.undo_stack.clone(),
            plan_mode: state.conversation.plan_mode.clone(),
            approved_plan: state.conversation.approved_plan.clone(),
            working_dirs: state.identity.additional_directories_for_claude_md.clone(),
            session_state: Some(SessionStateV1::wrap(state)),
        }
    }

    /// Recover canonical state, preferring the embedded V1 payload and
    /// falling back to the legacy top-level fields for older session files.
    ///
    /// `cwd` supplies the directory capabilities absent from legacy files.
    /// The caller remains responsible for validating the recovered identifier
    /// before using it as a filename.
    ///
    /// # Errors
    ///
    /// Returns [`PersistError::InconsistentSessionId`] when a new-format file
    /// carries different identifiers in its compatibility and canonical
    /// sections.
    pub fn into_state(self, cwd: &Path) -> Result<SessionState, PersistError> {
        if let Some(versioned) = self.session_state {
            if versioned.version > SessionStateV1::CURRENT_VERSION {
                return Err(PersistError::FutureSchema {
                    found: versioned.version,
                    supported: SessionStateV1::CURRENT_VERSION,
                });
            }
            let state = versioned.into_state();
            if state.identity.session_id.as_str() != self.id {
                return Err(PersistError::InconsistentSessionId {
                    legacy: self.id,
                    canonical: state.identity.session_id.to_string(),
                });
            }
            return Ok(state);
        }

        let mut state = SessionState::new(cwd.to_path_buf());
        // Legacy session IDs were already validated as filename-safe by both
        // frontends but were not required to be UUIDs. Preserve those files
        // losslessly while new sessions continue to generate UUIDs.
        state.identity.session_id = SessionId::from_raw_unchecked(self.id);
        state.identity.additional_directories_for_claude_md = self.working_dirs;
        state.conversation.messages = self.messages;
        state.conversation.undo_stack = self.undo_stack;
        state.conversation.approved_plan = self.approved_plan;
        state.conversation.plan_mode = self.plan_mode;
        state.conversation.behavior_mode = self.behavior_mode;
        state.modes.agent_mode = self.mode;
        Ok(state)
    }
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
    // A file written BEFORE the version tag existed (TuiSession /
    // ChatSession legacy shape) decodes to version 0. That steers
    // callers through the migrations framework when we ship Phase 5.
    0
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let state = SessionState::default();
        let encoded = encode(&state).unwrap();
        assert!(
            encoded.contains("\"version\""),
            "encoded payload should include the version tag: {encoded}"
        );
        assert!(encoded.contains("\"version\": 1"));
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
        // A blob without the `version` tag is the legacy shape —
        // Phase 5's migration path lives on the version=0 branch.
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
        let restored = decoded.into_state(Path::new("/unused")).unwrap();

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

        let document: SessionDocument = serde_json::from_str(&encoded).unwrap();
        let restored = document.into_state(Path::new("/tmp/current")).unwrap();

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
        document.id = "different-id".to_string();

        assert!(matches!(
            document.into_state(Path::new(".")),
            Err(PersistError::InconsistentSessionId { .. })
        ));
    }
}
