//! Canonical interactive session handle shared by every frontend.
//!
//! Metadata that is useful to session pickers lives next to the clone-cheap
//! [`StateStore`]. Conversation, identity, budgets, permissions, and other
//! mutable per-session data remain inside [`SessionState`]. This replaces the
//! former TUI- and REPL-specific compatibility wrappers with one API and one
//! serialization path.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

#[cfg(test)]
use super::SessionId;
use super::{AgentMode, EffortLevel, SessionDocument, SessionState, StateEvent, StateStore};

/// Validate an interactive-session id before using it as a file name.
///
/// Legacy sessions were not guaranteed to contain a strictly parsed UUID, so
/// migration accepts their historical ASCII letter/number/hyphen domain while
/// still rejecting path separators, dot segments, empty ids, and unreasonable
/// names.
///
/// # Errors
///
/// Returns a static explanation when `id` is empty, too long, or contains a
/// character outside the historical filename-safe set.
pub fn validate_session_id(id: &str) -> Result<(), &'static str> {
    if id.is_empty() {
        return Err("session id must not be empty");
    }
    if id.len() > 128 {
        return Err("session id must be 128 bytes or fewer");
    }
    if id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        Ok(())
    } else {
        Err("session id contains invalid characters; use only ASCII letters, numbers, or '-'")
    }
}

/// Validate both a stored id and the file name that contains it.
///
/// Requiring `<id>.json` to agree with the canonical payload prevents a copied
/// or tampered file from being loaded under one name and later saved over a
/// different session.
///
/// # Errors
///
/// Returns an explanation when `id` is unsafe, the file stem is not UTF-8, or
/// the stem does not equal `id`.
pub fn validate_session_file(path: &Path, id: &str) -> Result<(), String> {
    validate_session_id(id).map_err(str::to_string)?;
    let Some(stem) = path.file_stem().and_then(std::ffi::OsStr::to_str) else {
        return Err("session file name must be valid UTF-8 and end in .json".to_string());
    };
    if stem == id {
        Ok(())
    } else {
        Err(format!(
            "session id {id:?} does not match file name {stem:?}"
        ))
    }
}

#[derive(Debug, Clone)]
pub struct Session {
    pub title: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub model: String,
    pub provider: String,
    state: StateStore,
}

impl Session {
    #[must_use]
    pub fn new(model: &str, provider: &str) -> Self {
        Self::new_with_behavior_mode(model, provider, crate::modes::BehaviorMode::default())
    }

    #[must_use]
    pub fn new_with_behavior_mode(
        model: &str,
        provider: &str,
        behavior_mode: crate::modes::BehaviorMode,
    ) -> Self {
        let now = chrono::Utc::now();
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let mut state = SessionState::new(cwd);
        state.conversation.behavior_mode = behavior_mode;
        Self {
            title: "New conversation".to_string(),
            created_at: now,
            updated_at: now,
            model: model.to_string(),
            provider: provider.to_string(),
            state: StateStore::new(state),
        }
    }

    #[must_use]
    pub fn id(&self) -> String {
        self.state
            .inspect(|state| state.identity.session_id.to_string())
    }

    #[cfg(test)]
    pub fn set_id(&self, id: String) {
        self.state.update(|state, _| {
            state.identity.session_id = SessionId::from_raw_unchecked(id);
        });
    }

    #[must_use]
    pub fn state_snapshot(&self) -> SessionState {
        self.state.snapshot()
    }

    pub fn inspect_state<R>(&self, inspect: impl FnOnce(&SessionState) -> R) -> R {
        self.state.inspect(inspect)
    }

    pub fn update_state<R>(
        &self,
        update: impl FnOnce(&mut SessionState, &mut Vec<StateEvent>) -> R,
    ) -> R {
        self.state.update(update)
    }

    #[must_use]
    pub fn state_store(&self) -> StateStore {
        self.state.clone()
    }

    pub fn apply_loaded(&mut self, loaded: &Self) {
        self.title.clone_from(&loaded.title);
        self.created_at = loaded.created_at;
        self.updated_at = loaded.updated_at;
        self.model.clone_from(&loaded.model);
        self.provider.clone_from(&loaded.provider);
        self.state.replace(loaded.state_snapshot());
    }

    #[must_use]
    pub fn detached_clone(&self) -> Self {
        Self {
            title: self.title.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            model: self.model.clone(),
            provider: self.provider.clone(),
            state: StateStore::new(self.state_snapshot()),
        }
    }

    #[must_use]
    pub fn messages_snapshot(&self) -> Vec<Value> {
        self.state
            .inspect(|state| state.conversation.messages.clone())
    }

    #[must_use]
    pub fn message_count(&self) -> usize {
        self.state
            .inspect(|state| state.conversation.messages.len())
    }

    pub fn push_message(&self, message: Value) {
        let role = message
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        self.state.update(|state, events| {
            state.conversation.messages.push(message);
            events.push(StateEvent::MessageAppended { role });
        });
    }

    pub fn replace_messages(&self, messages: Vec<Value>) {
        self.state.update(|state, events| {
            let previous_len = state.conversation.messages.len();
            state.conversation.messages = messages;
            if previous_len > 0 && state.conversation.messages.is_empty() {
                events.push(StateEvent::Cleared);
            }
            events.extend(
                state
                    .conversation
                    .messages
                    .iter()
                    .skip(previous_len)
                    .map(|message| {
                        message
                            .get("role")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown")
                            .to_string()
                    })
                    .map(|role| StateEvent::MessageAppended { role }),
            );
        });
    }

    pub fn update_messages<R>(&self, update: impl FnOnce(&mut Vec<Value>) -> R) -> R {
        self.state
            .update(|state, _| update(&mut state.conversation.messages))
    }

    #[must_use]
    pub fn behavior_mode(&self) -> crate::modes::BehaviorMode {
        self.state
            .inspect(|state| state.conversation.behavior_mode.clone())
    }

    pub fn set_behavior_mode(&self, mode: crate::modes::BehaviorMode) {
        self.state.update(|state, events| {
            state.conversation.behavior_mode = mode.clone();
            events.push(StateEvent::ModeChanged { new: mode });
        });
    }

    #[must_use]
    pub fn effort_level(&self) -> EffortLevel {
        self.state.inspect(|state| state.budgets.effort_level)
    }

    pub fn set_effort_level(&self, level: EffortLevel) {
        self.state.update(|state, events| {
            state.budgets.effort_level = level;
            events.push(StateEvent::EffortChanged { new: level });
        });
    }

    #[must_use]
    pub fn estimated_tokens(&self) -> usize {
        self.state.inspect(|state| state.budgets.estimated_tokens)
    }

    #[must_use]
    pub fn refresh_estimated_tokens(&self) -> usize {
        self.state.update(|state, _| {
            let estimated = state
                .conversation
                .messages
                .iter()
                .map(|message| {
                    message
                        .get("content")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .len()
                        / 4
                        + 4
                })
                .sum();
            state.budgets.estimated_tokens = estimated;
            estimated
        })
    }

    #[must_use]
    pub fn permission_bypass_enabled(&self) -> bool {
        self.state.inspect(|state| state.permissions.bypass_mode)
    }

    pub fn set_permission_bypass(&self, enabled: bool) {
        self.state.update(|state, events| {
            if state.permissions.bypass_mode != enabled {
                state.permissions.bypass_mode = enabled;
                events.push(StateEvent::PermissionsMutated);
            }
        });
    }

    pub fn set_transcript_position(&self, cwd: PathBuf, watermark: usize) {
        self.state.update(|state, _| {
            state.transcript.transcript_cwd = cwd;
            state.transcript.watermark = watermark;
        });
    }

    #[must_use]
    pub fn transcript_cwd(&self) -> PathBuf {
        self.state
            .inspect(|state| state.transcript.transcript_cwd.clone())
    }

    pub fn touch(&mut self) {
        self.updated_at = chrono::Utc::now();
    }

    pub fn update_title(&mut self) {
        let title = self.state.inspect(|state| {
            state
                .conversation
                .messages
                .iter()
                .find(|message| message.get("role").and_then(Value::as_str) == Some("user"))
                .and_then(|message| message.get("content").and_then(Value::as_str))
                .map(|content| {
                    if content.len() > 50 {
                        format!("{}...", crate::tools::safe_truncate(content, 47))
                    } else {
                        content.to_string()
                    }
                })
        });
        if let Some(title) = title {
            self.title = title;
        }
    }

    pub fn toggle_mode(&self) {
        self.state.update(|state, _| {
            state.modes.agent_mode = state.modes.agent_mode.toggled();
        });
    }

    #[must_use]
    pub fn agent_mode(&self) -> AgentMode {
        self.state.inspect(|state| state.modes.agent_mode)
    }

    pub fn set_agent_mode(&self, mode: AgentMode) {
        self.state.update(|state, _| state.modes.agent_mode = mode);
    }

    #[must_use]
    pub fn mode_description(&self) -> &'static str {
        self.agent_mode().description()
    }

    pub fn undo(&mut self) -> bool {
        let changed = self.state.update(|state, _| {
            let conversation = &mut state.conversation;
            if conversation.messages.len() >= 2 {
                if let (Some(assistant), Some(user)) =
                    (conversation.messages.pop(), conversation.messages.pop())
                {
                    conversation.undo_stack.push((user, assistant));
                    return true;
                }
            }
            false
        });
        if changed {
            self.touch();
        }
        changed
    }

    pub fn redo(&mut self) -> bool {
        let changed = self.state.update(|state, events| {
            let conversation = &mut state.conversation;
            if let Some((user, assistant)) = conversation.undo_stack.pop() {
                let user_role = user
                    .get("role")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                let assistant_role = assistant
                    .get("role")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                conversation.messages.push(user);
                conversation.messages.push(assistant);
                events.push(StateEvent::MessageAppended { role: user_role });
                events.push(StateEvent::MessageAppended {
                    role: assistant_role,
                });
                true
            } else {
                false
            }
        });
        if changed {
            self.touch();
        }
        changed
    }

    pub fn clear_undo_stack(&self) {
        self.state
            .update(|state, _| state.conversation.undo_stack.clear());
    }

    pub fn add_working_dir(&mut self, path: PathBuf) -> bool {
        let added = self.state.update(|state, _| {
            let directories = &mut state.identity.additional_directories_for_claude_md;
            if directories.contains(&path) {
                false
            } else {
                directories.push(path);
                true
            }
        });
        if added {
            self.touch();
        }
        added
    }

    pub(crate) fn from_document(
        document: SessionDocument,
    ) -> Result<Self, super::persist::PersistError> {
        let title = document.title.clone();
        let created_at = document.created_at;
        let updated_at = document.updated_at;
        let model = document.model.clone();
        let provider = document.provider.clone();
        let state = document.into_state()?;
        Ok(Self {
            title,
            created_at,
            updated_at,
            model,
            provider,
            state: StateStore::new(state),
        })
    }
}

impl Serialize for Session {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SessionDocument::from_state(
            self.title.clone(),
            self.created_at,
            self.updated_at,
            self.model.clone(),
            self.provider.clone(),
            self.state_snapshot(),
        )
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Session {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error as _;

        let value = Value::deserialize(deserializer)?;
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let document =
            super::persist::decode_document_value(value, &cwd).map_err(D::Error::custom)?;
        Self::from_document(document).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_mode_has_one_canonical_runtime_location() {
        let session = Session::new("model", "provider");
        session.set_agent_mode(AgentMode::Extend);
        assert_eq!(session.agent_mode(), AgentMode::Extend);
        assert_eq!(session.state_snapshot().modes.agent_mode, AgentMode::Extend);

        session.toggle_mode();
        assert_eq!(session.agent_mode(), AgentMode::Plan);
        assert_eq!(session.state_snapshot().modes.agent_mode, AgentMode::Plan);
    }

    #[test]
    fn serialized_session_has_no_legacy_conversation_duplicates() {
        let session = Session::new("model", "provider");
        let value = serde_json::to_value(session).unwrap();

        assert!(value.get("session_state").is_some());
        for legacy in [
            "id",
            "mode",
            "behavior_mode",
            "messages",
            "undo_stack",
            "plan_mode",
            "approved_plan",
            "working_dirs",
        ] {
            assert!(value.get(legacy).is_none(), "legacy duplicate {legacy}");
        }
    }

    #[test]
    fn session_file_validation_requires_safe_matching_identity() {
        assert!(validate_session_file(Path::new("safe-id.json"), "safe-id").is_ok());
        assert!(validate_session_file(Path::new("other.json"), "safe-id").is_err());
        assert!(validate_session_file(Path::new("unsafe.json"), "../unsafe").is_err());
        assert!(validate_session_id(&"a".repeat(129)).is_err());
    }
}
