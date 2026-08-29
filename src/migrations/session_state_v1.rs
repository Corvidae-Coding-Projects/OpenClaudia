//! Rewrite interactive chat sessions into the canonical V1 document shape.
//!
//! The complete bounded input set is decoded and validated before any target
//! is published. Each publication is generation-checked, descriptor-relative,
//! atomic, and durable. A later publication failure leaves a typed partial
//! count; startup remains closed and a restart deterministically reconciles the
//! already-current prefix before continuing.

use std::ffi::OsString;
use std::path::PathBuf;

use crate::persistence::{
    CommitState, FileClass, PersistenceError, PersistentStorage, StorageGeneration,
};

use super::{
    Migration, MigrationContext, MigrationFailure, MigrationFailureKind, MigrationOutcome,
    MigrationStore,
};

const MAX_SESSION_FILES: usize = 4_096;
const MAX_SESSION_DIRECTORY_ENTRIES: usize = MAX_SESSION_FILES * 2;
const MAX_SESSION_STORE_BYTES: u64 = 256 * 1_024 * 1_024;

struct PlannedSession {
    target: OsString,
    expected: StorageGeneration,
    desired: Vec<u8>,
    changes_schema: bool,
}

pub struct MigrateSessionStateV1;

impl MigrateSessionStateV1 {
    fn sessions_dir(ctx: &MigrationContext) -> PathBuf {
        ctx.openclaudia_data.join("chat_sessions")
    }

    const fn persistence_failure(
        operation: &'static str,
        error: &PersistenceError,
    ) -> MigrationFailure {
        let kind = match error {
            PersistenceError::TooLarge { .. } => MigrationFailureKind::ResourceLimitExceeded,
            PersistenceError::Conflict { .. } => MigrationFailureKind::ConcurrentChange,
            PersistenceError::InvalidRoot { .. } | PersistenceError::InvalidTarget { .. } => {
                MigrationFailureKind::InvalidPersistentState
            }
            PersistenceError::Io { .. }
            | PersistenceError::Unchanged { .. }
            | PersistenceError::UnsupportedPlatform { .. } => {
                MigrationFailureKind::PublicationFailed
            }
        };
        MigrationFailure::new(kind, MigrationStore::OpenClaudiaData, operation)
    }

    const fn invalid(operation: &'static str) -> MigrationFailure {
        MigrationFailure::new(
            MigrationFailureKind::InvalidPersistentState,
            MigrationStore::OpenClaudiaData,
            operation,
        )
    }

    const fn schema_failure(error: &crate::state::persist::PersistError) -> MigrationFailure {
        let kind = match error {
            crate::state::persist::PersistError::FutureSchema { .. } => {
                MigrationFailureKind::UnsupportedFutureSchema
            }
            crate::state::persist::PersistError::ResourceLimit(_) => {
                MigrationFailureKind::ResourceLimitExceeded
            }
            crate::state::persist::PersistError::Io(_)
            | crate::state::persist::PersistError::Json(_)
            | crate::state::persist::PersistError::UnsupportedOldSchema { .. }
            | crate::state::persist::PersistError::MigrationRequired { .. }
            | crate::state::persist::PersistError::InvalidMigrationContext
            | crate::state::persist::PersistError::InvalidRecord(_)
            | crate::state::persist::PersistError::InconsistentSessionId { .. }
            | crate::state::persist::PersistError::InvalidProviderNativeState(_) => {
                MigrationFailureKind::InvalidPersistentState
            }
        };
        MigrationFailure::new(
            kind,
            MigrationStore::OpenClaudiaData,
            "decode saved session schema",
        )
    }

    fn plan(
        ctx: &MigrationContext,
        storage: &PersistentStorage,
        mut targets: Vec<OsString>,
    ) -> Result<Vec<PlannedSession>, MigrationFailure> {
        targets.sort();
        if targets.len() > MAX_SESSION_FILES {
            return Err(MigrationFailure::new(
                MigrationFailureKind::ResourceLimitExceeded,
                MigrationStore::OpenClaudiaData,
                "bound saved session count",
            ));
        }
        let directory = Self::sessions_dir(ctx);
        let mut total_bytes = 0_u64;
        let mut plans = Vec::with_capacity(targets.len());
        for target in targets {
            let observed = storage
                .read(PathBuf::from(&target), FileClass::Session)
                .map_err(|error| Self::persistence_failure("read saved session", &error))?;
            let raw = observed
                .expose_bytes(|bytes| bytes.map(<[u8]>::to_vec))
                .ok_or_else(|| Self::invalid("reconcile missing saved session"))?;
            let text = std::str::from_utf8(&raw)
                .map_err(|_| Self::invalid("decode saved session UTF-8"))?;
            let (document, canonical) =
                crate::state::persist::decode_document_for_migration(text, &ctx.workspace_root)
                    .map_err(|error| Self::schema_failure(&error))?;
            let path = directory.join(&target);
            crate::state::validate_session_file(
                &path,
                document.session_state.state.identity.session_id.as_str(),
            )
            .map_err(|_| Self::invalid("validate saved session identity"))?;
            let desired = if canonical {
                raw
            } else {
                serde_json::to_vec_pretty(&document)
                    .map_err(|_| Self::invalid("encode canonical saved session"))?
            };
            let desired_text = std::str::from_utf8(&desired)
                .map_err(|_| Self::invalid("verify canonical saved session UTF-8"))?;
            let (_, verified_current) = crate::state::persist::decode_document_for_migration(
                desired_text,
                &ctx.workspace_root,
            )
            .map_err(|error| Self::schema_failure(&error))?;
            if !verified_current {
                return Err(Self::invalid("verify canonical saved session schema"));
            }
            total_bytes = total_bytes
                .checked_add(u64::try_from(desired.len()).unwrap_or(u64::MAX))
                .filter(|total| *total <= MAX_SESSION_STORE_BYTES)
                .ok_or_else(|| {
                    MigrationFailure::new(
                        MigrationFailureKind::ResourceLimitExceeded,
                        MigrationStore::OpenClaudiaData,
                        "bound saved session bytes",
                    )
                })?;
            plans.push(PlannedSession {
                target,
                expected: observed.generation(),
                desired,
                changes_schema: !canonical,
            });
        }
        Ok(plans)
    }

    fn open_store(ctx: &MigrationContext) -> Result<Option<PersistentStorage>, MigrationFailure> {
        let directory = Self::sessions_dir(ctx);
        match std::fs::symlink_metadata(&directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                return Err(Self::invalid("validate saved session store directory"));
            }
            Ok(_) => {}
            Err(error) => {
                return Err(MigrationFailure::from_io(
                    MigrationFailureKind::InvalidPersistentState,
                    MigrationStore::OpenClaudiaData,
                    "inspect saved session store",
                    &error,
                ));
            }
        }
        PersistentStorage::open(&directory)
            .map(Some)
            .map_err(|error| Self::persistence_failure("open saved session store", &error))
    }

    fn targets(directory: &std::path::Path) -> Result<Vec<OsString>, MigrationFailure> {
        let entries = std::fs::read_dir(directory).map_err(|error| {
            let kind = if error.kind() == std::io::ErrorKind::NotFound {
                MigrationFailureKind::ConcurrentChange
            } else {
                MigrationFailureKind::InvalidPersistentState
            };
            MigrationFailure::from_io(
                kind,
                MigrationStore::OpenClaudiaData,
                "enumerate saved session store",
                &error,
            )
        })?;
        let mut targets = Vec::new();
        for (index, entry) in entries.enumerate() {
            if index == MAX_SESSION_DIRECTORY_ENTRIES {
                return Err(MigrationFailure::new(
                    MigrationFailureKind::ResourceLimitExceeded,
                    MigrationStore::OpenClaudiaData,
                    "bound saved session directory entries",
                ));
            }
            let target = entry
                .map_err(|error| {
                    MigrationFailure::from_io(
                        MigrationFailureKind::InvalidPersistentState,
                        MigrationStore::OpenClaudiaData,
                        "read saved session directory entry",
                        &error,
                    )
                })?
                .file_name();
            if PathBuf::from(&target)
                .extension()
                .is_some_and(|extension| extension == "json")
            {
                if targets.len() == MAX_SESSION_FILES {
                    return Err(MigrationFailure::new(
                        MigrationFailureKind::ResourceLimitExceeded,
                        MigrationStore::OpenClaudiaData,
                        "bound saved session count",
                    ));
                }
                targets.push(target);
            }
        }
        Ok(targets)
    }

    fn publish(storage: &PersistentStorage, plans: Vec<PlannedSession>) -> MigrationOutcome {
        let mut changed_artifacts = 0usize;
        for plan in plans {
            let receipt = match storage.commit(
                PathBuf::from(&plan.target),
                FileClass::Session,
                plan.expected,
                &plan.desired,
            ) {
                Ok(receipt) => receipt,
                Err(error) => {
                    return MigrationOutcome::Failed(
                        Self::persistence_failure("publish canonical saved session", &error)
                            .with_committed_artifacts(changed_artifacts),
                    );
                }
            };
            if plan.changes_schema {
                changed_artifacts += 1;
            }
            if receipt.state() == CommitState::PublishedDurabilityUncertain {
                return MigrationOutcome::Failed(
                    MigrationFailure::new(
                        MigrationFailureKind::DurabilityUncertain,
                        MigrationStore::OpenClaudiaData,
                        "synchronize canonical saved session",
                    )
                    .with_committed_artifacts(changed_artifacts),
                );
            }
            let verified = match storage.read(PathBuf::from(&plan.target), FileClass::Session) {
                Ok(verified) => verified,
                Err(error) => {
                    return MigrationOutcome::Failed(
                        Self::persistence_failure("verify published saved session", &error)
                            .with_committed_artifacts(changed_artifacts),
                    );
                }
            };
            let bytes_match = verified
                .expose_bytes(|bytes| bytes.is_some_and(|bytes| bytes == plan.desired.as_slice()));
            if verified.generation() != receipt.generation() || !bytes_match {
                return MigrationOutcome::Failed(
                    MigrationFailure::new(
                        MigrationFailureKind::ConcurrentChange,
                        MigrationStore::OpenClaudiaData,
                        "verify published saved session generation",
                    )
                    .with_committed_artifacts(changed_artifacts),
                );
            }
        }
        if changed_artifacts == 0 {
            MigrationOutcome::Current
        } else {
            MigrationOutcome::Applied { changed_artifacts }
        }
    }
}

impl Migration for MigrateSessionStateV1 {
    fn id(&self) -> &'static str {
        "m001-session-state-v1"
    }

    fn description(&self) -> &'static str {
        "Rewrite saved interactive sessions into canonical state V1"
    }

    fn store(&self) -> MigrationStore {
        MigrationStore::OpenClaudiaData
    }

    fn run(&self, ctx: &MigrationContext) -> MigrationOutcome {
        let directory = Self::sessions_dir(ctx);
        let storage = match Self::open_store(ctx) {
            Ok(Some(storage)) => storage,
            Ok(None) => return MigrationOutcome::Current,
            Err(failure) => return MigrationOutcome::Failed(failure),
        };
        let targets = match Self::targets(&directory) {
            Ok(targets) => targets,
            Err(failure) => return MigrationOutcome::Failed(failure),
        };
        let plans = match Self::plan(ctx, &storage, targets) {
            Ok(plans) => plans,
            Err(failure) => return MigrationOutcome::Failed(failure),
        };
        Self::publish(&storage, plans)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{AgentMode, Session, SessionStateV1};

    fn context() -> (tempfile::TempDir, MigrationContext) {
        let root = tempfile::tempdir().unwrap();
        let workspace = root.path().join("workspace");
        std::fs::create_dir_all(&workspace).unwrap();
        let context = MigrationContext::with_paths_and_workspace(
            root.path().join("claude"),
            root.path().join("openclaudia"),
            workspace,
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
    fn legacy_tui_shape_retains_content_and_strips_path_authority() {
        let (_root, context) = context();
        let path = session_path(&context, "legacy-session");
        std::fs::write(&path, legacy_fixture("legacy-session")).unwrap();

        let outcome = MigrateSessionStateV1.run(&context);
        assert!(matches!(
            outcome,
            MigrationOutcome::Applied {
                changed_artifacts: 1
            }
        ));

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
        assert!(state
            .identity
            .additional_directories_for_claude_md
            .is_empty());
        assert_eq!(state.identity.cwd, context.workspace_root);
        assert_eq!(state.identity.original_cwd, state.identity.cwd);
        assert_eq!(state.identity.project_root, state.identity.cwd);
        assert_eq!(state.identity.session_project_dir, state.identity.cwd);
        assert_eq!(state.transcript.transcript_cwd, state.identity.cwd);
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
            MigrationOutcome::Applied {
                changed_artifacts: 1
            }
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
        let mut state = crate::state::SessionState::new(context.workspace_root.clone());
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
            MigrationOutcome::Current
        ));
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert!(matches!(
            MigrateSessionStateV1.run(&context),
            MigrationOutcome::Current
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
    fn malformed_file_blocks_all_session_publication_during_preflight() {
        let (_root, context) = context();
        let broken_path = session_path(&context, "a-broken");
        let valid_path = session_path(&context, "z-valid");
        std::fs::write(&broken_path, b"{not valid json").unwrap();
        std::fs::write(&valid_path, legacy_fixture("z-valid")).unwrap();

        let outcome = MigrateSessionStateV1.run(&context);

        assert!(matches!(outcome, MigrationOutcome::Failed(_)));
        assert_eq!(std::fs::read(&broken_path).unwrap(), b"{not valid json");
        let still_legacy: serde_json::Value =
            serde_json::from_slice(&std::fs::read(valid_path).unwrap()).unwrap();
        assert!(still_legacy.get("session_state").is_none());
        assert!(still_legacy.get("messages").is_some());
    }

    #[test]
    fn version_zero_preserves_causal_state_and_strips_live_authority() {
        let (_root, context) = context();
        let path = session_path(&context, "legacy-v0");
        let mut state = crate::state::SessionState::new(PathBuf::from("/untrusted/source"));
        state.identity.session_id = crate::state::SessionId::from_raw_unchecked("legacy-v0");
        state
            .identity
            .additional_directories_for_claude_md
            .push(PathBuf::from("/untrusted/additional"));
        state.modes.coordinator = true;
        state.budgets.thinking_budget_override = Some(u32::MAX);
        state.transcript.watermark = 1;
        state
            .conversation
            .messages
            .push(serde_json::json!({"role": "user", "content": "retained"}));
        let document = crate::state::SessionDocument::from_state(
            "legacy-v0".to_string(),
            chrono::Utc::now(),
            chrono::Utc::now(),
            "model".to_string(),
            "provider".to_string(),
            state,
        );
        let mut value = serde_json::to_value(document).unwrap();
        value["session_state"]["version"] = serde_json::json!(0);
        value["session_state"]["permissions"] = serde_json::json!({
            "bypass_mode": true,
            "trust_accepted": true,
            "persistence_disabled": false
        });
        std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

        assert!(matches!(
            MigrateSessionStateV1.run(&context),
            MigrationOutcome::Applied {
                changed_artifacts: 1
            }
        ));

        let migrated: crate::state::Session =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        let state = migrated.state_snapshot();
        assert_eq!(state.identity.cwd, PathBuf::from("/untrusted/source"));
        assert_eq!(state.identity.original_cwd, state.identity.cwd);
        assert_eq!(state.identity.project_root, state.identity.cwd);
        assert_eq!(state.identity.session_project_dir, state.identity.cwd);
        assert!(state
            .identity
            .additional_directories_for_claude_md
            .is_empty());
        assert!(state.identity.active_workspace.is_none());
        assert!(state.modes.coordinator);
        assert_eq!(state.budgets.thinking_budget_override, Some(u32::MAX));
        assert!(!state.permissions.bypass_mode);
        assert!(!state.permissions.trust_accepted);
        assert_eq!(state.transcript.watermark, 1);
        assert_eq!(state.transcript.transcript_cwd, state.identity.cwd);
        assert_eq!(state.conversation.messages[0]["content"], "retained");
    }

    #[test]
    fn future_schema_fails_without_downgrading_file() {
        let (_root, context) = context();
        let path = session_path(&context, "future");
        let mut state = crate::state::SessionState::new(context.workspace_root.clone());
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

        let MigrationOutcome::Failed(failure) = MigrateSessionStateV1.run(&context) else {
            panic!("future session schema must fail closed");
        };
        assert_eq!(
            failure.kind(),
            MigrationFailureKind::UnsupportedFutureSchema
        );
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
