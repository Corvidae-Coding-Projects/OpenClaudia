pub mod command_registry;
pub mod input;
pub mod keybindings;
pub mod models;
pub mod permissions;
pub mod plan_mode;
pub mod review;
pub mod session_io;
pub mod slash;

use anyhow::Context;
pub use openclaudia::state::Session;
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

/// Save a chat session to disk
pub fn save_chat_session(session: &Session) -> anyhow::Result<()> {
    save_chat_session_in_dir(session, &get_sessions_dir())
}

fn save_chat_session_in_dir(session: &Session, directory: &Path) -> anyhow::Result<()> {
    validate_chat_session_id(&session.id())?;
    openclaudia::file_error::create_dir_all(directory)?;
    let path = directory.join(format!("{}.json", session.id()));
    let _ = session.refresh_estimated_tokens();
    openclaudia::file_error::write_json_pretty_atomic(path, session)?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatSessionLoadIssue {
    pub path: PathBuf,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ChatSessionList {
    pub sessions: Vec<Session>,
    pub issues: Vec<ChatSessionLoadIssue>,
}

fn validate_chat_session_id(id: &str) -> anyhow::Result<()> {
    openclaudia::state::validate_session_id(id)
        .map_err(|reason| anyhow::anyhow!("invalid chat session id {id:?}: {reason}"))
}

fn chat_session_path(id: &str) -> anyhow::Result<PathBuf> {
    validate_chat_session_id(id)?;
    Ok(get_sessions_dir().join(format!("{id}.json")))
}

fn reject_chat_session_symlink(path: &Path) -> anyhow::Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect chat session {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        anyhow::bail!(
            "saved chat session {} must not be a symlink",
            path.display()
        );
    }
    Ok(())
}

fn read_chat_session_file(path: &Path) -> anyhow::Result<Session> {
    reject_chat_session_symlink(path)?;
    let json = fs::read_to_string(path)
        .with_context(|| format!("failed to read chat session {}", path.display()))?;
    let session: Session = serde_json::from_str(&json)
        .with_context(|| format!("failed to parse chat session {}", path.display()))?;
    openclaudia::state::validate_session_file(path, &session.id())
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("invalid chat session id in {}", path.display()))?;
    Ok(session)
}

/// Load a chat session by ID
pub fn load_chat_session(id: &str) -> anyhow::Result<Option<Session>> {
    let path = chat_session_path(id)?;
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            anyhow::bail!(
                "saved chat session {} must not be a symlink",
                path.display()
            );
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to inspect chat session {}", path.display()));
        }
    }
    let json = match fs::read_to_string(&path) {
        Ok(json) => json,
        Err(e) => {
            return Err(e)
                .with_context(|| format!("failed to read chat session {}", path.display()));
        }
    };

    let session: Session = serde_json::from_str(&json)
        .with_context(|| format!("failed to parse chat session {}", path.display()))?;
    openclaudia::state::validate_session_file(&path, &session.id())
        .map_err(anyhow::Error::msg)
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
pub fn list_chat_sessions() -> Vec<Session> {
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

    fn test_session() -> Session {
        Session::new_with_behavior_mode(
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
        session.update_state(|state, _| {
            state.identity.session_id =
                openclaudia::state::SessionId::from_raw_unchecked("../outside");
        });

        let err = save_chat_session(&session).expect_err("path traversal must be rejected");

        assert!(
            err.to_string().contains("invalid characters"),
            "unexpected error: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn first_session_save_creates_the_missing_compatibility_directory() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("session parent");
        let directory = root.path().join("missing/chat_sessions");
        let session = test_session();
        save_chat_session_in_dir(&session, &directory).expect("first session save");

        let path = directory.join(format!("{}.json", session.id()));
        assert!(path.is_file());
        assert_eq!(
            std::fs::metadata(path)
                .expect("session metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o600
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
    fn apply_loaded_keeps_subscribers_and_emits_session_boundary() {
        let mut current = test_session();
        current.update_state(|state, _| {
            state.identity.session_id =
                openclaudia::state::SessionId::from_raw_unchecked("current");
        });
        current.push_message(serde_json::json!({"role": "user"}));
        let mut subscription = current.state_store().subscribe_log_lag();

        let loaded = test_session();
        loaded.update_state(|state, _| {
            state.identity.session_id = openclaudia::state::SessionId::from_raw_unchecked("loaded");
        });
        current.apply_loaded(&loaded);

        assert!(matches!(
            subscription.try_recv(),
            Some(openclaudia::state::StateEvent::SessionSwitched {
                from,
                to,
                from_messages: 1,
            }) if from.as_str() == "current" && to.as_str() == "loaded"
        ));
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
    fn read_chat_session_file_rejects_invalid_stored_id_during_decode() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("invalid-id.json");
        let session = test_session();
        let mut invalid = serde_json::to_value(&session).expect("serialize valid fixture");
        invalid["session_state"]["identity"]["session_id"] = serde_json::json!("../outside");
        fs::write(&path, serde_json::to_string(&invalid).unwrap()).unwrap();

        let err = read_chat_session_file(&path).expect_err("invalid stored id must be an error");

        assert!(
            err.to_string().contains("failed to parse chat session"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn list_chat_sessions_reports_corrupt_files_without_hiding_valid_sessions() {
        let tmp = tempfile::tempdir().unwrap();
        let valid_path = tmp.path().join("valid.json");
        let corrupt_path = tmp.path().join("corrupt.json");
        let valid = test_session();
        valid.update_state(|state, _| {
            state.identity.session_id = openclaudia::state::SessionId::from_raw_unchecked("valid");
        });
        fs::write(&valid_path, serde_json::to_string(&valid).unwrap()).unwrap();
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

    #[cfg(unix)]
    #[test]
    fn read_chat_session_file_refuses_symlink() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        let link = tmp.path().join("linked.json");
        let session = test_session();
        session.update_state(|state, _| {
            state.identity.session_id = openclaudia::state::SessionId::from_raw_unchecked("linked");
        });
        fs::write(&target, serde_json::to_vec(&session).unwrap()).unwrap();
        symlink(target, &link).unwrap();

        let error = read_chat_session_file(&link).expect_err("symlinks must be rejected");
        assert!(error.to_string().contains("must not be a symlink"));
    }
}
