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
        self.state.update(|state, events| {
            let native_history_prefix = state
                .conversation
                .provider_native_state
                .as_ref()
                .map(|_| state.conversation.messages.clone());
            let result = update(state, events);
            if native_history_prefix
                .as_ref()
                .is_some_and(|prefix| !state.conversation.messages.starts_with(prefix.as_slice()))
            {
                state.conversation.provider_native_state = None;
            }
            result
        })
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
        let live_permissions = self.state.inspect(|state| state.permissions.clone());
        let mut loaded_state = loaded.state_snapshot();
        loaded_state.permissions = live_permissions;
        self.state.replace(loaded_state);
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

    /// Clone the provider-native lane without holding the state lock across
    /// request construction or network awaits.
    #[must_use]
    pub fn provider_native_state_snapshot(&self) -> Option<crate::runtime::ProviderNativeState> {
        self.state
            .inspect(|state| state.conversation.provider_native_state.clone())
    }

    /// Install validated native state for this session's exact provider/model.
    ///
    /// # Errors
    ///
    /// Returns an error when the state belongs to another provider or model.
    pub fn install_provider_native_state(
        &self,
        provider_state: crate::runtime::ProviderNativeState,
    ) -> Result<(), crate::runtime::ProviderStateError> {
        provider_state.validate_identity(&self.provider, &self.model)?;
        self.state.update(|state, _| {
            let Some(current) = &state.conversation.provider_native_state else {
                state.conversation.provider_native_state = Some(provider_state);
                return Ok(());
            };
            if current.protocol() != provider_state.protocol() {
                return Err(crate::runtime::ProviderStateError::ProtocolMismatch {
                    stored: current.protocol(),
                    requested: provider_state.protocol(),
                });
            }
            match provider_state.generation().cmp(&current.generation()) {
                std::cmp::Ordering::Less => {
                    Err(crate::runtime::ProviderStateError::StaleGeneration {
                        current: current.generation(),
                        attempted: provider_state.generation(),
                    })
                }
                std::cmp::Ordering::Equal if provider_state == *current => Ok(()),
                std::cmp::Ordering::Equal => {
                    Err(crate::runtime::ProviderStateError::GenerationConflict {
                        generation: current.generation(),
                    })
                }
                std::cmp::Ordering::Greater => {
                    state.conversation.provider_native_state = Some(provider_state);
                    Ok(())
                }
            }
        })
    }

    /// Remove provider-native state while retaining portable conversation
    /// history.
    pub fn clear_provider_native_state(&self) {
        self.state.update(|state, _| {
            state.conversation.provider_native_state = None;
        });
    }

    /// Change the model and invalidate native continuation state if identity
    /// changed.
    pub fn set_model(&mut self, model: impl Into<String>) {
        let model = model.into();
        if self.model != model {
            self.model = model;
            self.clear_provider_native_state();
            self.touch();
        }
    }

    /// Change provider/model as one state transition and invalidate native
    /// continuation state if either identity changed.
    pub fn set_provider_and_model(
        &mut self,
        provider: impl Into<String>,
        model: impl Into<String>,
    ) {
        let provider = provider.into();
        let model = model.into();
        if self.provider != provider || self.model != model {
            self.provider = provider;
            self.model = model;
            self.clear_provider_native_state();
            self.touch();
        }
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
            let preserves_native_state = state
                .conversation
                .provider_native_state
                .as_ref()
                .is_none_or(|_| messages.starts_with(&state.conversation.messages));
            let previous_len = state.conversation.messages.len();
            state.conversation.messages = messages;
            if !preserves_native_state {
                state.conversation.provider_native_state = None;
            }
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

    /// Atomically commit the portable transcript and the provider-native
    /// continuation that was captured from the same completed turn.
    ///
    /// # Errors
    ///
    /// Returns an error without mutating either lane when identity, protocol,
    /// generation, or digest continuity is invalid.
    pub fn replace_messages_and_provider_native_state(
        &self,
        messages: Vec<Value>,
        provider_state: Option<crate::runtime::ProviderNativeState>,
    ) -> Result<(), crate::runtime::ProviderStateError> {
        if let Some(next) = &provider_state {
            next.validate()?;
            next.validate_identity(&self.provider, &self.model)?;
        }
        self.state.update(|state, events| {
            if let (Some(current), Some(next)) = (
                state.conversation.provider_native_state.as_ref(),
                provider_state.as_ref(),
            ) {
                if current.protocol() != next.protocol() {
                    return Err(crate::runtime::ProviderStateError::ProtocolMismatch {
                        stored: current.protocol(),
                        requested: next.protocol(),
                    });
                }
                match next.generation().cmp(&current.generation()) {
                    std::cmp::Ordering::Less => {
                        return Err(crate::runtime::ProviderStateError::StaleGeneration {
                            current: current.generation(),
                            attempted: next.generation(),
                        });
                    }
                    std::cmp::Ordering::Equal if next != current => {
                        return Err(crate::runtime::ProviderStateError::GenerationConflict {
                            generation: current.generation(),
                        });
                    }
                    std::cmp::Ordering::Equal | std::cmp::Ordering::Greater => {}
                }
            }
            if provider_state.is_some()
                && !messages.starts_with(state.conversation.messages.as_slice())
            {
                return Err(
                    crate::runtime::ProviderStateError::PortableHistoryConflict {
                        current_messages: state.conversation.messages.len(),
                        attempted_messages: messages.len(),
                    },
                );
            }

            let previous_len = state.conversation.messages.len();
            state.conversation.messages = messages;
            state.conversation.provider_native_state = provider_state;
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
            Ok(())
        })
    }

    /// Mutate portable history while preserving native continuation state only
    /// when the previous history remains an exact prefix. Appending new input
    /// can continue a provider turn; rewriting prior input creates a branch and
    /// invalidates opaque provider state tied to the old history.
    pub fn update_messages<R>(&self, update: impl FnOnce(&mut Vec<Value>) -> R) -> R {
        self.state.update(|state, _| {
            let native_history_prefix = state
                .conversation
                .provider_native_state
                .as_ref()
                .map(|_| state.conversation.messages.clone());
            let result = update(&mut state.conversation.messages);
            if native_history_prefix
                .as_ref()
                .is_some_and(|prefix| !state.conversation.messages.starts_with(prefix.as_slice()))
            {
                state.conversation.provider_native_state = None;
            }
            result
        })
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
                    conversation.provider_native_state = None;
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
                conversation.provider_native_state = None;
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
        use serde::ser::Error as _;

        let state = self.state_snapshot();
        if let Some(native) = &state.conversation.provider_native_state {
            native
                .validate_identity(&self.provider, &self.model)
                .map_err(S::Error::custom)?;
        }
        SessionDocument::from_state(
            self.title.clone(),
            self.created_at,
            self.updated_at,
            self.model.clone(),
            self.provider.clone(),
            state,
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
    use crate::runtime::{
        ContinuationGeneration, ProviderNativeItem, ProviderNativeItemPurpose, ProviderNativeState,
        ProviderStateFacet, ProviderWireProtocol,
    };
    use serde_json::json;

    fn provider_state_at(
        provider: &str,
        model: &str,
        generation: u64,
        tokens: u64,
    ) -> ProviderNativeState {
        ProviderNativeState::new(
            provider,
            model,
            ProviderWireProtocol::OpenAiResponses,
            ContinuationGeneration::new(generation).expect("non-zero generation"),
            vec![ProviderNativeItem::new(
                ProviderStateFacet::Usage,
                ProviderNativeItemPurpose::Evidence,
                json!({"input_tokens": tokens, "cached_tokens": 4}),
            )
            .expect("valid item")],
        )
        .expect("valid provider state")
    }

    fn provider_state(provider: &str, model: &str) -> ProviderNativeState {
        provider_state_at(provider, model, 1, 10)
    }

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
    fn provider_native_state_persists_with_session() {
        let session = Session::new("gpt-test", "openai");
        let expected = provider_state("openai", "gpt-test");
        session
            .install_provider_native_state(expected.clone())
            .expect("matching state");

        let encoded = serde_json::to_string(&session).expect("serialize session");
        let decoded: Session = serde_json::from_str(&encoded).expect("deserialize session");
        assert_eq!(decoded.provider_native_state_snapshot(), Some(expected));
    }

    #[test]
    fn provider_native_state_rejects_mismatch_and_clears_on_switch() {
        let mut session = Session::new("gpt-test", "openai");
        assert!(session
            .install_provider_native_state(provider_state("openai", "other-model"))
            .is_err());
        session
            .install_provider_native_state(provider_state("openai", "gpt-test"))
            .expect("matching state");
        session.set_model("gpt-other");
        assert!(session.provider_native_state_snapshot().is_none());

        session
            .install_provider_native_state(provider_state("openai", "gpt-other"))
            .expect("matching replacement state");
        session.set_provider_and_model("anthropic", "claude-test");
        assert!(session.provider_native_state_snapshot().is_none());
    }

    #[test]
    fn provider_native_state_prevents_persisting_direct_identity_drift() {
        let mut session = Session::new("gpt-test", "openai");
        session
            .install_provider_native_state(provider_state("openai", "gpt-test"))
            .expect("matching state");
        session.model = "gpt-other".to_string();

        let error = serde_json::to_string(&session).expect_err("identity drift must fail closed");
        assert!(error.to_string().contains("belongs to model"));
    }

    #[test]
    fn provider_native_state_install_is_monotonic_and_idempotent() {
        let session = Session::new("gpt-test", "openai");
        let generation_two = provider_state_at("openai", "gpt-test", 2, 20);
        session
            .install_provider_native_state(generation_two.clone())
            .expect("initial state");
        session
            .install_provider_native_state(generation_two.clone())
            .expect("exact replay is idempotent");

        let stale = provider_state_at("openai", "gpt-test", 1, 10);
        assert!(matches!(
            session.install_provider_native_state(stale),
            Err(crate::runtime::ProviderStateError::StaleGeneration { .. })
        ));
        let conflict = provider_state_at("openai", "gpt-test", 2, 99);
        assert!(matches!(
            session.install_provider_native_state(conflict),
            Err(crate::runtime::ProviderStateError::GenerationConflict { .. })
        ));
        assert_eq!(
            session.provider_native_state_snapshot(),
            Some(generation_two)
        );

        let generation_three = provider_state_at("openai", "gpt-test", 3, 30);
        session
            .install_provider_native_state(generation_three.clone())
            .expect("newer generation advances atomically");
        assert_eq!(
            session.provider_native_state_snapshot(),
            Some(generation_three)
        );
    }

    #[test]
    fn portable_and_native_turn_state_commit_atomically() {
        let session = Session::new("gpt-test", "openai");
        let generation_two = provider_state_at("openai", "gpt-test", 2, 20);
        let messages_two = vec![
            json!({"role": "user", "content": "inspect"}),
            json!({"role": "assistant", "content": "checking"}),
        ];
        let mut messages_three = messages_two.clone();
        messages_three.push(json!({"role": "user", "content": "continue"}));
        messages_three.push(json!({"role": "assistant", "content": "done"}));
        session
            .replace_messages_and_provider_native_state(messages_two, Some(generation_two))
            .expect("first atomic sync");

        let generation_three = provider_state_at("openai", "gpt-test", 3, 30);
        session
            .replace_messages_and_provider_native_state(
                messages_three.clone(),
                Some(generation_three.clone()),
            )
            .expect("new generation atomically advances both lanes");
        assert_eq!(session.messages_snapshot(), messages_three);
        assert_eq!(
            session.provider_native_state_snapshot(),
            Some(generation_three)
        );

        let stale_messages = vec![json!({"role": "user", "content": "stale overwrite"})];
        let error = session
            .replace_messages_and_provider_native_state(
                stale_messages,
                Some(provider_state_at("openai", "gpt-test", 1, 10)),
            )
            .expect_err("stale native state must reject the entire sync");
        assert!(matches!(
            error,
            crate::runtime::ProviderStateError::StaleGeneration { .. }
        ));
        assert_eq!(session.messages_snapshot(), messages_three);
        assert_eq!(
            session
                .provider_native_state_snapshot()
                .expect("state retained")
                .generation()
                .get(),
            3
        );

        let rewritten = vec![json!({"role": "user", "content": "different history"})];
        let error = session
            .replace_messages_and_provider_native_state(
                rewritten,
                Some(provider_state_at("openai", "gpt-test", 4, 40)),
            )
            .expect_err("advanced native state cannot overwrite a different portable history");
        assert!(matches!(
            error,
            crate::runtime::ProviderStateError::PortableHistoryConflict { .. }
        ));
        assert_eq!(session.messages_snapshot(), messages_three);
    }

    #[test]
    fn provider_native_state_survives_append_only_history_changes() {
        let session = Session::new("gpt-test", "openai");
        session.push_message(json!({"role": "assistant", "content": "ready"}));
        let expected = provider_state("openai", "gpt-test");
        session
            .install_provider_native_state(expected.clone())
            .expect("matching state");

        session.push_message(json!({"role": "user", "content": "continue"}));
        session.update_messages(|messages| {
            messages.push(json!({"role": "system", "content": "new input"}));
        });
        session.update_state(|state, _| {
            state
                .conversation
                .messages
                .push(json!({"role": "user", "content": "one more"}));
        });

        assert_eq!(session.provider_native_state_snapshot(), Some(expected));
    }

    #[test]
    fn provider_native_state_clears_when_history_is_rewritten() {
        let session = Session::new("gpt-test", "openai");
        let original = json!({"role": "assistant", "content": "original"});
        session.push_message(original.clone());
        session
            .install_provider_native_state(provider_state_at("openai", "gpt-test", 1, 10))
            .expect("matching state");

        session.update_messages(|messages| messages[0]["content"] = json!("edited"));
        assert!(session.provider_native_state_snapshot().is_none());

        session.replace_messages(vec![original.clone()]);
        session
            .install_provider_native_state(provider_state_at("openai", "gpt-test", 2, 20))
            .expect("matching state");
        session.replace_messages(vec![json!({"role": "system", "content": "compacted"})]);
        assert!(session.provider_native_state_snapshot().is_none());

        session.replace_messages(vec![original]);
        session
            .install_provider_native_state(provider_state_at("openai", "gpt-test", 3, 30))
            .expect("matching state");
        session.update_state(|state, _| state.conversation.messages.clear());
        assert!(session.provider_native_state_snapshot().is_none());
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
        assert!(
            value["session_state"]["state"].get("permissions").is_none(),
            "conversation documents must not serialize live permission authority"
        );
    }

    #[test]
    fn applying_loaded_session_preserves_current_invocation_permissions() {
        let mut active = Session::new("active-model", "active-provider");
        active.update_state(|state, _| {
            state.permissions.bypass_mode = false;
            state.permissions.trust_accepted = false;
            state.permissions.persistence_disabled = true;
        });

        let loaded = Session::new("loaded-model", "loaded-provider");
        loaded.update_state(|state, _| {
            state.permissions.bypass_mode = true;
            state.permissions.trust_accepted = true;
            state.permissions.persistence_disabled = false;
        });

        active.apply_loaded(&loaded);
        active.inspect_state(|state| {
            assert!(!state.permissions.bypass_mode);
            assert!(!state.permissions.trust_accepted);
            assert!(state.permissions.persistence_disabled);
        });
    }

    #[test]
    fn session_file_validation_requires_safe_matching_identity() {
        assert!(validate_session_file(Path::new("safe-id.json"), "safe-id").is_ok());
        assert!(validate_session_file(Path::new("other.json"), "safe-id").is_err());
        assert!(validate_session_file(Path::new("unsafe.json"), "../unsafe").is_err());
        assert!(validate_session_id(&"a".repeat(129)).is_err());
    }
}
