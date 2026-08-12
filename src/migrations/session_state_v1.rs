//! Rewrite interactive chat sessions into the canonical V1 document shape.
//!
//! Older TUI and line-REPL releases stored conversation fields at the top
//! level. Transitional releases also wrote those fields twice: once at the top
//! level and once inside `session_state`. This idempotent migration removes
//! both layouts using an atomic sibling-file replacement.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context as _};

use super::{Migration, MigrationContext, MigrationOutcome};

pub struct MigrateSessionStateV1;

impl MigrateSessionStateV1 {
    fn sessions_dir(ctx: &MigrationContext) -> PathBuf {
        ctx.openclaudia_data.join("chat_sessions")
    }

    fn migrate_file(path: &Path, cwd: &Path) -> anyhow::Result<bool> {
        let metadata = std::fs::symlink_metadata(path)
            .with_context(|| format!("failed to inspect session {}", path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(anyhow!(
                "refusing to migrate non-regular session file {}",
                path.display()
            ));
        }

        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read session {}", path.display()))?;
        let (document, canonical) = crate::state::persist::decode_document_for_migration(&raw, cwd)
            .with_context(|| format!("failed to decode session {}", path.display()))?;
        crate::state::validate_session_file(
            path,
            document.session_state.state.identity.session_id.as_str(),
        )
        .map_err(|reason| anyhow!(reason))
        .with_context(|| format!("invalid session file {}", path.display()))?;

        if canonical {
            return Ok(false);
        }

        crate::file_error::write_json_pretty_atomic(path, &document)
            .with_context(|| format!("failed to atomically rewrite session {}", path.display()))?;
        Ok(true)
    }
}

impl Migration for MigrateSessionStateV1 {
    fn id(&self) -> &'static str {
        "m001-session-state-v1"
    }

    fn description(&self) -> &'static str {
        "Rewrite saved interactive sessions into canonical state V1"
    }

    fn run(&self, ctx: &MigrationContext) -> MigrationOutcome {
        let directory = Self::sessions_dir(ctx);
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return MigrationOutcome::Skipped;
            }
            Err(error) => {
                return MigrationOutcome::Failed(format!(
                    "failed to read session directory {}: {error}",
                    directory.display()
                ));
            }
        };

        let mut paths = Vec::new();
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    return MigrationOutcome::Failed(format!(
                        "failed to read an entry in {}: {error}",
                        directory.display()
                    ));
                }
            };
            let path = entry.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                paths.push(path);
            }
        }
        paths.sort();

        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let mut migrated = 0usize;
        let mut failures = Vec::new();
        for path in paths {
            match Self::migrate_file(&path, &cwd) {
                Ok(true) => migrated += 1,
                Ok(false) => {}
                Err(error) => failures.push(format!("{error:#}")),
            }
        }

        if !failures.is_empty() {
            return MigrationOutcome::Failed(format!(
                "rewrote {migrated} session(s), but {} file(s) failed: {}",
                failures.len(),
                failures.join("; ")
            ));
        }
        if migrated == 0 {
            MigrationOutcome::Skipped
        } else {
            MigrationOutcome::Applied(format!(
                "rewrote {migrated} saved session{} to V1",
                if migrated == 1 { "" } else { "s" }
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{AgentMode, Session, SessionStateV1};

    fn context() -> (tempfile::TempDir, MigrationContext) {
        let root = tempfile::tempdir().unwrap();
        let context = MigrationContext::with_paths(
            root.path().join("claude"),
            root.path().join("openclaudia"),
        );
        std::fs::create_dir_all(context.openclaudia_data.join("chat_sessions")).unwrap();
        (root, context)
    }

    fn session_path(context: &MigrationContext, id: &str) -> PathBuf {
        context
            .openclaudia_data
            .join("chat_sessions")
            .join(format!("{id}.json"))
    }

    fn legacy_fixture(id: &str) -> String {
        include_str!("../../tests/fixtures/session_legacy_tui.json").replace("legacy-session", id)
    }

    #[test]
    fn legacy_tui_shape_is_rewritten_losslessly() {
        let (_root, context) = context();
        let path = session_path(&context, "legacy-session");
        std::fs::write(&path, legacy_fixture("legacy-session")).unwrap();

        let outcome = MigrateSessionStateV1.run(&context);
        assert!(matches!(outcome, MigrationOutcome::Applied(_)));

        let raw = std::fs::read_to_string(&path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(value["session_state"]["version"], 1);
        for duplicate in [
            "id",
            "mode",
            "behavior_mode",
            "messages",
            "undo_stack",
            "approved_plan",
            "working_dirs",
        ] {
            assert!(value.get(duplicate).is_none(), "duplicate key {duplicate}");
        }

        let restored: Session = serde_json::from_str(&raw).unwrap();
        let state = restored.state_snapshot();
        assert_eq!(restored.id(), "legacy-session");
        assert_eq!(restored.title, "legacy title");
        assert_eq!(restored.model, "legacy-model");
        assert_eq!(restored.provider, "legacy-provider");
        assert_eq!(restored.agent_mode(), AgentMode::Extend);
        assert_eq!(state.conversation.messages[0]["content"], "remember me");
        assert_eq!(state.conversation.undo_stack.len(), 1);
        assert_eq!(state.conversation.approved_plan.as_deref(), Some("ship it"));
        assert_eq!(
            state.identity.additional_directories_for_claude_md,
            vec![PathBuf::from("/tmp/shared")]
        );
    }

    #[test]
    fn transitional_document_loses_only_duplicated_fields() {
        let (_root, context) = context();
        let path = session_path(&context, "transitional");
        let session = Session::new("model", "provider");
        session.update_state(|state, _| {
            state.identity.session_id = crate::state::SessionId::from_raw_unchecked("transitional");
        });
        session.push_message(serde_json::json!({"role": "user", "content": "canonical"}));
        let mut value = serde_json::to_value(&session).unwrap();
        let object = value.as_object_mut().unwrap();
        object.insert("id".to_string(), serde_json::json!("transitional"));
        object.insert(
            "messages".to_string(),
            serde_json::json!([{"role": "user", "content": "stale"}]),
        );
        std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

        assert!(matches!(
            MigrateSessionStateV1.run(&context),
            MigrationOutcome::Applied(_)
        ));

        let migrated: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(migrated.get("id").is_none());
        assert!(migrated.get("messages").is_none());
        assert_eq!(
            migrated["session_state"]["conversation"]["messages"][0]["content"],
            "canonical"
        );
    }

    #[test]
    fn canonical_document_is_byte_stable_and_idempotent() {
        let (_root, context) = context();
        let path = session_path(&context, "canonical");
        let mut state = crate::state::SessionState::default();
        state.identity.session_id = crate::state::SessionId::from_raw_unchecked("canonical");
        let document = crate::state::SessionDocument::from_state(
            "title".to_string(),
            chrono::Utc::now(),
            chrono::Utc::now(),
            "model".to_string(),
            "provider".to_string(),
            state,
        );
        let original = serde_json::to_vec_pretty(&document).unwrap();
        std::fs::write(&path, &original).unwrap();

        assert!(matches!(
            MigrateSessionStateV1.run(&context),
            MigrationOutcome::Skipped
        ));
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert!(matches!(
            MigrateSessionStateV1.run(&context),
            MigrationOutcome::Skipped
        ));
    }

    #[test]
    fn malformed_file_fails_without_changing_original_bytes() {
        let (_root, context) = context();
        let path = session_path(&context, "broken");
        let original = b"{not valid json";
        std::fs::write(&path, original).unwrap();

        let outcome = MigrateSessionStateV1.run(&context);

        assert!(matches!(outcome, MigrationOutcome::Failed(_)));
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[test]
    fn malformed_file_does_not_block_other_session_migrations() {
        let (_root, context) = context();
        let broken_path = session_path(&context, "a-broken");
        let valid_path = session_path(&context, "z-valid");
        std::fs::write(&broken_path, b"{not valid json").unwrap();
        std::fs::write(&valid_path, legacy_fixture("z-valid")).unwrap();

        let outcome = MigrateSessionStateV1.run(&context);

        assert!(matches!(outcome, MigrationOutcome::Failed(_)));
        assert_eq!(std::fs::read(&broken_path).unwrap(), b"{not valid json");
        let migrated: serde_json::Value =
            serde_json::from_slice(&std::fs::read(valid_path).unwrap()).unwrap();
        assert_eq!(migrated["session_state"]["version"], 1);
        assert!(migrated.get("messages").is_none());
    }

    #[test]
    fn future_schema_fails_without_downgrading_file() {
        let (_root, context) = context();
        let path = session_path(&context, "future");
        let mut state = crate::state::SessionState::default();
        state.identity.session_id = crate::state::SessionId::from_raw_unchecked("future");
        let mut envelope = SessionStateV1::wrap(state);
        envelope.version = 999;
        let original = serde_json::to_vec_pretty(&serde_json::json!({
            "title": "future",
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2025-01-01T00:00:00Z",
            "model": "model",
            "provider": "provider",
            "session_state": envelope
        }))
        .unwrap();
        std::fs::write(&path, &original).unwrap();

        assert!(matches!(
            MigrateSessionStateV1.run(&context),
            MigrationOutcome::Failed(_)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }

    #[test]
    fn mismatched_filename_fails_without_moving_session_identity() {
        let (_root, context) = context();
        let path = session_path(&context, "file-name");
        let original = legacy_fixture("different-id");
        std::fs::write(&path, &original).unwrap();

        assert!(matches!(
            MigrateSessionStateV1.run(&context),
            MigrationOutcome::Failed(_)
        ));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        assert!(!session_path(&context, "different-id").exists());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_session_is_refused_without_touching_target() {
        use std::os::unix::fs::symlink;

        let (_root, context) = context();
        let target = context.openclaudia_data.join("outside-session");
        let original = legacy_fixture("linked");
        std::fs::write(&target, &original).unwrap();
        symlink(&target, session_path(&context, "linked")).unwrap();

        assert!(matches!(
            MigrateSessionStateV1.run(&context),
            MigrationOutcome::Failed(_)
        ));
        assert_eq!(std::fs::read_to_string(target).unwrap(), original);
    }
}
