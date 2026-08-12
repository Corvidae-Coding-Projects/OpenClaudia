pub mod command_registry;
pub mod input;
pub mod keybindings;
pub mod models;
pub mod permissions;
pub mod plan_mode;
pub mod review;
pub mod session_io;
pub mod slash;
pub mod vim;

use anyhow::{bail, Context};
pub use openclaudia::state::AgentMode;
use openclaudia::tools::safe_truncate;
use std::fs;
use std::path::{Path, PathBuf};

/// Get the data directory for `OpenClaudia`
pub fn get_data_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("openclaudia")
}

/// Get the history file path for rustyline
pub fn get_history_path() -> PathBuf {
    get_data_dir().join("history.txt")
}

/// Get the chat sessions directory
pub fn get_sessions_dir() -> PathBuf {
    get_data_dir().join("chat_sessions")
}

/// A saved chat session with messages
#[derive(Debug, Clone)]
pub struct ChatSession {
    /// Session title (first user message or default)
    pub title: String,
    /// When the session was created
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// When the session was last updated
    pub updated_at: chrono::DateTime<chrono::Utc>,
    /// The model used
    pub model: String,
    /// The provider used
    pub provider: String,
    /// Agent mode (Build or Plan)
    pub mode: AgentMode,
    state: openclaudia::state::StateStore,
}

impl ChatSession {
    pub fn new(
        model: &str,
        provider: &str,
        behavior_mode: openclaudia::modes::BehaviorMode,
    ) -> Self {
        let now = chrono::Utc::now();
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let mut state = openclaudia::state::SessionState::new(cwd);
        state.conversation.behavior_mode = behavior_mode;
        Self {
            title: "New conversation".to_string(),
            created_at: now,
            updated_at: now,
            model: model.to_string(),
            provider: provider.to_string(),
            mode: AgentMode::default(),
            state: openclaudia::state::StateStore::new(state),
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
            state.identity.session_id = openclaudia::state::SessionId::from_raw_unchecked(id);
        });
    }

    #[cfg(test)]
    #[must_use]
    pub fn state_snapshot(&self) -> openclaudia::state::SessionState {
        self.state.snapshot()
    }

    pub fn inspect_state<R>(
        &self,
        inspect: impl FnOnce(&openclaudia::state::SessionState) -> R,
    ) -> R {
        self.state.inspect(inspect)
    }

    pub fn update_state<R>(
        &self,
        update: impl FnOnce(
            &mut openclaudia::state::SessionState,
            &mut Vec<openclaudia::state::StateEvent>,
        ) -> R,
    ) -> R {
        self.state.update(update)
    }

    #[must_use]
    pub fn messages_snapshot(&self) -> Vec<serde_json::Value> {
        self.inspect_state(|state| state.conversation.messages.clone())
    }

    #[must_use]
    pub fn message_count(&self) -> usize {
        self.inspect_state(|state| state.conversation.messages.len())
    }

    pub fn push_message(&self, message: serde_json::Value) {
        let role = message
            .get("role")
            .and_then(|role| role.as_str())
            .unwrap_or("unknown")
            .to_string();
        self.update_state(|state, events| {
            state.conversation.messages.push(message);
            events.push(openclaudia::state::StateEvent::MessageAppended { role });
        });
    }

    pub fn replace_messages(&self, messages: Vec<serde_json::Value>) {
        self.update_state(|state, events| {
            let was_non_empty = !state.conversation.messages.is_empty();
            state.conversation.messages = messages;
            if was_non_empty && state.conversation.messages.is_empty() {
                events.push(openclaudia::state::StateEvent::Cleared);
            }
        });
    }

    pub fn update_messages<R>(&self, update: impl FnOnce(&mut Vec<serde_json::Value>) -> R) -> R {
        self.update_state(|state, _| update(&mut state.conversation.messages))
    }

    #[must_use]
    pub fn behavior_mode(&self) -> openclaudia::modes::BehaviorMode {
        self.inspect_state(|state| state.conversation.behavior_mode.clone())
    }

    pub fn set_behavior_mode(&self, mode: openclaudia::modes::BehaviorMode) {
        self.update_state(|state, events| {
            state.conversation.behavior_mode = mode.clone();
            events.push(openclaudia::state::StateEvent::ModeChanged { new: mode });
        });
    }

    #[must_use]
    pub fn effort_level(&self) -> openclaudia::state::EffortLevel {
        self.inspect_state(|state| state.budgets.effort_level)
    }

    pub fn set_effort_level(&self, level: openclaudia::state::EffortLevel) {
        self.update_state(|state, events| {
            state.budgets.effort_level = level;
            events.push(openclaudia::state::StateEvent::EffortChanged { new: level });
        });
    }

    #[must_use]
    pub fn permission_bypass_enabled(&self) -> bool {
        self.inspect_state(|state| state.permissions.bypass_mode)
    }

    /// Apply the process-launch permission posture to this session.
    ///
    /// Although the flag is serialized as part of a coherent snapshot, a
    /// resumed session must never silently inherit a previous process's
    /// dangerous bypass choice. Startup calls this after resume selection so
    /// the current command line always wins.
    pub fn set_permission_bypass(&self, enabled: bool) {
        self.update_state(|state, events| {
            if state.permissions.bypass_mode != enabled {
                state.permissions.bypass_mode = enabled;
                events.push(openclaudia::state::StateEvent::PermissionsMutated);
            }
        });
    }

    pub fn refresh_estimated_tokens(&self) -> usize {
        self.update_state(|state, _| {
            let estimated = state
                .conversation
                .messages
                .iter()
                .map(|message| {
                    message
                        .get("content")
                        .and_then(|content| content.as_str())
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

    /// Undo the last user+assistant message pair
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

    /// Redo the last undone message pair
    pub fn redo(&mut self) -> bool {
        let changed = self.state.update(|state, _| {
            let conversation = &mut state.conversation;
            if let Some((user, assistant)) = conversation.undo_stack.pop() {
                conversation.messages.push(user);
                conversation.messages.push(assistant);
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

    /// Clear undo stack (call when new messages are added)
    pub fn clear_undo_stack(&self) {
        self.state
            .update(|state, _| state.conversation.undo_stack.clear());
    }

    /// Add a working directory to the session scope (deduplicates by canonical path).
    ///
    /// Returns `true` if the directory was added, `false` if it was already present.
    pub fn add_working_dir(&mut self, path: std::path::PathBuf) -> bool {
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

    pub fn update_title(&mut self) {
        let title = self.state.inspect(|state| {
            state
                .conversation
                .messages
                .iter()
                .find(|message| message.get("role").and_then(|role| role.as_str()) == Some("user"))
                .and_then(|message| message.get("content").and_then(|content| content.as_str()))
                .map(|content| {
                    if content.len() > 50 {
                        format!("{}...", safe_truncate(content, 47))
                    } else {
                        content.to_string()
                    }
                })
        });
        if let Some(title) = title {
            self.title = title;
        }
    }

    pub fn touch(&mut self) {
        self.updated_at = chrono::Utc::now();
    }
}

impl serde::Serialize for ChatSession {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = self.state.snapshot();
        state.modes.agent_mode = self.mode;
        serde::Serialize::serialize(
            &openclaudia::state::SessionDocument::from_state(
                self.title.clone(),
                self.created_at,
                self.updated_at,
                self.model.clone(),
                self.provider.clone(),
                state,
            ),
            serializer,
        )
    }
}

impl<'de> serde::Deserialize<'de> for ChatSession {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        let document =
            <openclaudia::state::SessionDocument as serde::Deserialize>::deserialize(deserializer)?;
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let title = document.title.clone();
        let created_at = document.created_at;
        let updated_at = document.updated_at;
        let model = document.model.clone();
        let provider = document.provider.clone();
        let state = document.into_state(&cwd).map_err(D::Error::custom)?;
        let mode = state.modes.agent_mode;
        Ok(Self {
            title,
            created_at,
            updated_at,
            model,
            provider,
            mode,
            state: openclaudia::state::StateStore::new(state),
        })
    }
}

/// Save a chat session to disk
pub fn save_chat_session(session: &ChatSession) -> anyhow::Result<()> {
    let path = chat_session_path(&session.id())?;
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    session.refresh_estimated_tokens();
    let json = serde_json::to_string_pretty(session)?;
    fs::write(path, json)?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatSessionLoadIssue {
    pub path: PathBuf,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ChatSessionList {
    pub sessions: Vec<ChatSession>,
    pub issues: Vec<ChatSessionLoadIssue>,
}

fn validate_chat_session_id(id: &str) -> anyhow::Result<()> {
    if id.is_empty() {
        bail!("chat session id must not be empty");
    }

    if id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        Ok(())
    } else {
        bail!("chat session id contains invalid characters: {id:?}");
    }
}

fn chat_session_path(id: &str) -> anyhow::Result<PathBuf> {
    validate_chat_session_id(id)?;
    Ok(get_sessions_dir().join(format!("{id}.json")))
}

fn read_chat_session_file(path: &Path) -> anyhow::Result<ChatSession> {
    let json = fs::read_to_string(path)
        .with_context(|| format!("failed to read chat session {}", path.display()))?;
    let session: ChatSession = serde_json::from_str(&json)
        .with_context(|| format!("failed to parse chat session {}", path.display()))?;
    validate_chat_session_id(&session.id())
        .with_context(|| format!("invalid chat session id in {}", path.display()))?;
    Ok(session)
}

/// Load a chat session by ID
pub fn load_chat_session(id: &str) -> anyhow::Result<Option<ChatSession>> {
    let path = chat_session_path(id)?;
    let json = match fs::read_to_string(&path) {
        Ok(json) => json,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(e)
                .with_context(|| format!("failed to read chat session {}", path.display()));
        }
    };

    let session: ChatSession = serde_json::from_str(&json)
        .with_context(|| format!("failed to parse chat session {}", path.display()))?;
    validate_chat_session_id(&session.id())
        .with_context(|| format!("invalid chat session id in {}", path.display()))?;
    Ok(Some(session))
}

fn list_chat_sessions_in_dir(dir: &Path) -> ChatSessionList {
    let mut sessions = Vec::new();
    let mut issues = Vec::new();

    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return ChatSessionList { sessions, issues };
        }
        Err(e) => {
            issues.push(ChatSessionLoadIssue {
                path: dir.to_path_buf(),
                message: format!("failed to read chat sessions directory: {e}"),
            });
            return ChatSessionList { sessions, issues };
        }
    };

    for entry_result in entries {
        let entry = match entry_result {
            Ok(entry) => entry,
            Err(e) => {
                issues.push(ChatSessionLoadIssue {
                    path: dir.to_path_buf(),
                    message: format!("failed to read chat session directory entry: {e}"),
                });
                continue;
            }
        };

        let path = entry.path();
        if path.extension().is_none_or(|e| e != "json") {
            continue;
        }

        match read_chat_session_file(&path) {
            Ok(session) => sessions.push(session),
            Err(e) => issues.push(ChatSessionLoadIssue {
                path,
                message: e.to_string(),
            }),
        }
    }

    sessions.sort_by_key(|s| std::cmp::Reverse(s.updated_at));
    ChatSessionList { sessions, issues }
}

/// List all chat sessions with any files skipped due to IO or parse errors.
pub fn list_chat_sessions_with_issues() -> ChatSessionList {
    list_chat_sessions_in_dir(&get_sessions_dir())
}

/// List all chat sessions, sorted by most recent
pub fn list_chat_sessions() -> Vec<ChatSession> {
    let listed = list_chat_sessions_with_issues();
    for issue in &listed.issues {
        tracing::warn!(
            path = %issue.path.display(),
            error = %issue.message,
            "Skipped unreadable chat session"
        );
        eprintln!(
            "Warning: skipped saved session {}: {}",
            issue.path.display(),
            issue.message
        );
    }

    listed.sessions
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_session() -> ChatSession {
        ChatSession::new(
            "test-model",
            "anthropic",
            openclaudia::modes::BehaviorMode::default(),
        )
    }

    #[test]
    fn load_chat_session_rejects_path_segments() {
        let err = load_chat_session("../outside").expect_err("path traversal must be rejected");
        assert!(
            err.to_string().contains("invalid characters"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn save_chat_session_rejects_path_segments() {
        let session = test_session();
        session.set_id("../outside".to_string());

        let err = save_chat_session(&session).expect_err("path traversal must be rejected");

        assert!(
            err.to_string().contains("invalid characters"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn budget_state_is_owned_by_the_session_store() {
        let session = test_session();
        session.set_effort_level(openclaudia::state::EffortLevel::Minimal);
        session.push_message(serde_json::json!({
            "role": "user",
            "content": "12345678"
        }));

        assert_eq!(session.refresh_estimated_tokens(), 6);
        let state = session.state_snapshot();
        assert_eq!(
            state.budgets.effort_level,
            openclaudia::state::EffortLevel::Minimal
        );
        assert_eq!(state.budgets.estimated_tokens, 6);
    }

    #[test]
    fn permission_bypass_is_owned_by_the_session_store() {
        let session = test_session();
        session.set_permission_bypass(true);

        assert!(session.permission_bypass_enabled());
        assert!(session.state_snapshot().permissions.bypass_mode);

        session.set_permission_bypass(false);
        assert!(!session.permission_bypass_enabled());
    }

    #[test]
    fn read_chat_session_file_reports_malformed_json() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("bad.json");
        fs::write(&path, "{not-json").unwrap();

        let err = read_chat_session_file(&path).expect_err("malformed JSON must be an error");

        assert!(
            err.to_string().contains("failed to parse chat session"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn read_chat_session_file_reports_invalid_stored_id() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("invalid-id.json");
        let session = test_session();
        session.set_id("../outside".to_string());
        fs::write(&path, serde_json::to_string(&session).unwrap()).unwrap();

        let err = read_chat_session_file(&path).expect_err("invalid stored id must be an error");

        assert!(
            err.to_string().contains("invalid chat session id"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn list_chat_sessions_reports_corrupt_files_without_hiding_valid_sessions() {
        let tmp = tempfile::tempdir().unwrap();
        let valid_path = tmp.path().join("valid.json");
        let corrupt_path = tmp.path().join("corrupt.json");
        fs::write(&valid_path, serde_json::to_string(&test_session()).unwrap()).unwrap();
        fs::write(&corrupt_path, "{not-json").unwrap();

        let listed = list_chat_sessions_in_dir(tmp.path());

        assert_eq!(listed.sessions.len(), 1);
        assert_eq!(listed.issues.len(), 1);
        assert_eq!(listed.issues[0].path, corrupt_path);
        assert!(
            listed.issues[0]
                .message
                .contains("failed to parse chat session"),
            "unexpected issue: {:?}",
            listed.issues[0]
        );
    }
}
