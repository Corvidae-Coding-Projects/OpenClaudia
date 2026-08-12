//! Centralized session state — crosslink #510.
//!
//! Migration strategy is phased (see `docs/designs/510-session-state.md`).
//! Phase 1 is complete: both interactive frontends keep identity and
//! conversation data here, while `TuiSession` and `ChatSession` remain thin
//! compatibility wrappers for frontend metadata. Later phases move the
//! remaining UI, budget, permission, and transcript fields.
//!
//! The per-session fields live here. Process-scoped handles
//! (`memory_db`, `permission_mgr`, `hook_engine`, …) stay on the
//! owning subsystems — they are not per-session state and keeping
//! them out of [`SessionState`] keeps the serde shape bounded.

pub mod categories;
pub mod persist;
pub mod store;

pub use categories::{
    AgentMode, BudgetsState, Conversation, EffortLevel, Identity, ModesState, PermissionsState,
    SessionId, TranscriptState, UiState,
};
pub use persist::{SessionDocument, SessionStateV1};
pub use store::{StateEvent, StateStore};

use serde::{Deserialize, Serialize};

/// The single source of truth for one session, grouped by concern.
///
/// Adding a new field lands inside the right sub-struct rather than a flat
/// list of 98 fields. Each sub-struct is plain data (no `Arc`s), so the whole
/// thing is cheap to clone for snapshots and `/rewind` backups.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub identity: Identity,
    pub conversation: Conversation,
    pub ui: UiState,
    pub modes: ModesState,
    pub permissions: PermissionsState,
    pub budgets: BudgetsState,
    pub transcript: TranscriptState,
}

impl SessionState {
    /// A blank session rooted at `cwd`. Generates a fresh UUID for
    /// `identity.session_id` and leaves every other category at its
    /// default. Matches the behavior of the existing
    /// `TuiSession::new` / `ChatSession::new` constructors.
    #[must_use]
    pub fn new(cwd: std::path::PathBuf) -> Self {
        Self {
            identity: Identity::rooted_at(cwd),
            conversation: Conversation::default(),
            ui: UiState::default(),
            modes: ModesState::default(),
            permissions: PermissionsState::default(),
            budgets: BudgetsState::default(),
            transcript: TranscriptState::default(),
        }
    }
}

impl Default for SessionState {
    fn default() -> Self {
        // Default session is rooted at `.` — useful for tests and
        // the `Default` derives on upstream structs that embed
        // `SessionState`. Real sessions supply an absolute cwd.
        Self::new(std::path::PathBuf::from("."))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_constructible() {
        let state = SessionState::default();
        assert!(!state.identity.session_id.as_str().is_empty());
        assert!(state.conversation.messages.is_empty());
        assert_eq!(state.transcript.watermark, 0);
    }

    #[test]
    fn new_uses_supplied_cwd() {
        let cwd = std::path::PathBuf::from("/tmp/some-project");
        let state = SessionState::new(cwd.clone());
        assert_eq!(state.identity.cwd, cwd);
        assert_eq!(state.identity.original_cwd, cwd);
    }

    #[test]
    fn distinct_sessions_have_distinct_ids() {
        let a = SessionState::default();
        let b = SessionState::default();
        assert_ne!(a.identity.session_id, b.identity.session_id);
    }

    #[test]
    fn serde_roundtrip_is_lossless() {
        let mut state = SessionState::new(std::path::PathBuf::from("/x"));
        state.conversation.messages.push(serde_json::json!({
            "role": "user",
            "content": "hello"
        }));
        state.budgets.effort_level = categories::EffortLevel::High;
        state.ui.plan_mode.has_exited = true;

        let json = serde_json::to_string(&state).unwrap();
        let round: SessionState = serde_json::from_str(&json).unwrap();
        assert_eq!(round.identity.session_id, state.identity.session_id);
        assert_eq!(round.conversation.messages, state.conversation.messages);
        assert_eq!(round.budgets.effort_level, state.budgets.effort_level);
        assert!(round.ui.plan_mode.has_exited);
    }
}
