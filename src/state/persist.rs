//! On-disk serialization shape for [`super::SessionState`].
//!
//! The ratatui TUI and legacy line REPL historically wrote divergent shapes.
//! Both now serialize through [`SessionDocument`], which stores picker
//! metadata next to one required [`SessionStateV1`] payload. Legacy top-level
//! fields remain read-only input handled by the migration decoder; new writes
//! never duplicate identity or conversation state.
//!
//! Schema numbers are an exact contract. Version zero is accepted only by the
//! bounded migration decoder with an explicit trusted workspace; version one
//! is the only directly loadable shape, and future versions fail closed.

use serde::{Deserialize, Deserializer, Serialize};

use std::path::{Path, PathBuf};

use super::{AgentMode, SessionId, SessionState};

const MAX_SESSION_DOCUMENT_BYTES: usize = 16 * 1_024 * 1_024;
const MAX_SESSION_JSON_NODES: usize = 200_000;
const MAX_SESSION_JSON_DEPTH: usize = 64;
const MAX_SESSION_MESSAGES: usize = 50_000;
const MAX_SESSION_UNDO_ENTRIES: usize = 10_000;
const MAX_SESSION_ADDITIONAL_DIRECTORIES: usize = 256;
const MAX_SESSION_IDE_FILES: usize = 4_096;
const MAX_SESSION_IDE_DIAGNOSTICS: usize = 20_000;
const MAX_SESSION_METADATA_BYTES: usize = 16 * 1_024;

const DOCUMENT_KEYS: &[&str] = &[
    "title",
    "created_at",
    "updated_at",
    "model",
    "provider",
    "session_state",
    // Known transitional duplicates are accepted only as migration input.
    "id",
    "mode",
    "behavior_mode",
    "messages",
    "undo_stack",
    "plan_mode",
    "approved_plan",
    "working_dirs",
];

const STATE_KEYS: &[&str] = &[
    "version",
    "identity",
    "conversation",
    "ui",
    "modes",
    // Historical payloads may contain this process-local category. Serde
    // deliberately discards it and canonical migration removes the field.
    "permissions",
    "budgets",
    "ide",
    "transcript",
];

const IDENTITY_KEYS: &[&str] = &[
    "session_id",
    "parent_session_id",
    "original_cwd",
    "cwd",
    "project_root",
    "session_project_dir",
    "additional_directories_for_claude_md",
    "active_workspace",
];
const CONVERSATION_KEYS: &[&str] = &[
    "messages",
    "provider_native_state",
    "undo_stack",
    "approved_plan",
    "plan_mode",
    "behavior_mode",
    "behavior_scope_targets",
];
const UI_KEYS: &[&str] = &["plan_mode", "lsp_recommendation_shown_this_session"];
const UI_PLAN_MODE_KEYS: &[&str] = &[
    "has_exited",
    "needs_exit_attachment",
    "needs_auto_exit_attachment",
];
const MODES_KEYS: &[&str] = &["agent_mode", "coordinator"];
const BUDGET_KEYS: &[&str] = &[
    "effort_level",
    "thinking_budget_override",
    "estimated_tokens",
];
const IDE_KEYS: &[&str] = &["active_file", "recent_files", "selection", "diagnostics"];
const IDE_SELECTION_KEYS: &[&str] = &["file_path", "line_start", "line_count", "text"];
const IDE_DIAGNOSTIC_KEYS: &[&str] = &["line", "severity", "message", "source"];
const TRANSCRIPT_KEYS: &[&str] = &["watermark", "transcript_cwd"];
const PERMISSION_KEYS: &[&str] = &["bypass_mode", "trust_accepted", "persistence_disabled"];
const BEHAVIOR_MODE_KEYS: &[&str] = &["agency", "quality", "scope", "modifiers"];
const BEHAVIOR_SCOPE_KEYS: &[&str] = &["explicit", "targets"];
const BEHAVIOR_SCOPE_TARGET_KEYS: &[&str] = &["kind", "value"];
const PLAN_MODE_KEYS: &[&str] = &[
    "active",
    "plan_file",
    "plan_realpath",
    "allowed_prompts",
    "previous_mode",
];
const ALLOWED_PROMPT_KEYS: &[&str] = &["tool", "prompt"];

/// Canonical session document shared by every interactive frontend.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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

#[derive(Serialize)]
struct CanonicalSessionDocument<'document> {
    title: &'document str,
    created_at: &'document chrono::DateTime<chrono::Utc>,
    updated_at: &'document chrono::DateTime<chrono::Utc>,
    model: &'document str,
    provider: &'document str,
    session_state: &'document SessionStateV1,
}

impl Serialize for SessionDocument {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::Error as _;

        validate_document(self).map_err(S::Error::custom)?;
        CanonicalSessionDocument {
            title: &self.title,
            created_at: &self.created_at,
            updated_at: &self.updated_at,
            model: &self.model,
            provider: &self.provider,
            session_state: &self.session_state,
        }
        .serialize(serializer)
    }
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
    /// a newer binary, [`PersistError::MigrationRequired`] for an old schema,
    /// or [`PersistError::InconsistentSessionId`] when a transitional file
    /// carries conflicting identities.
    pub fn into_state(self) -> Result<SessionState, PersistError> {
        match SessionStateV1::classify(self.session_state.version)? {
            SessionSchema::Current => {}
            SessionSchema::Legacy => {
                return Err(PersistError::MigrationRequired {
                    found: self.session_state.version,
                    minimum: SessionStateV1::MIN_SUPPORTED_VERSION,
                    current: SessionStateV1::CURRENT_VERSION,
                });
            }
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
        validate_document_metadata(
            &self.title,
            &self.created_at,
            &self.updated_at,
            &self.model,
            &self.provider,
        )?;
        validate_state(&state)?;
        Ok(state)
    }
}

/// Pre-V1 top-level session layout. Read-only: new files are never emitted in
/// this shape. Defaults cover both the old TUI and line-REPL variants.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
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
    fn upgrade(self, workspace_root: &Path) -> Result<SessionDocument, PersistError> {
        let mut state = SessionState::new(workspace_root.to_path_buf());
        state.identity.session_id = SessionId::from_raw_unchecked(self.id);
        state.conversation.messages = self.messages;
        state.conversation.undo_stack = self.undo_stack;
        state.conversation.approved_plan = self.approved_plan;
        state.conversation.plan_mode = self.plan_mode;
        state.conversation.behavior_mode = self.behavior_mode;
        state.modes.agent_mode = self.mode;
        // `working_dirs` selected prompt inputs in the originating process.
        // It is parsed for exact compatibility but never imported as live
        // filesystem authority. The trusted workspace is supplied by the
        // startup host instead of being inferred from persisted paths.
        let _ = self.working_dirs;
        strip_imported_authority(&mut state, workspace_root);
        let document = SessionDocument::from_state(
            self.title,
            self.created_at,
            self.updated_at,
            self.model,
            self.provider,
            state,
        );
        validate_document(&document)?;
        Ok(document)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionSchema {
    Legacy,
    Current,
}

fn validate_known_object_keys(
    value: &serde_json::Value,
    allowed: &[&str],
    operation: &'static str,
) -> Result<(), PersistError> {
    let object = value
        .as_object()
        .ok_or(PersistError::InvalidRecord(operation))?;
    if object.keys().all(|key| allowed.contains(&key.as_str())) {
        Ok(())
    } else {
        Err(PersistError::InvalidRecord(operation))
    }
}

fn validate_child_object_keys(
    parent: &serde_json::Value,
    child: &str,
    allowed: &[&str],
) -> Result<(), PersistError> {
    if let Some(value) = parent.get(child).filter(|value| !value.is_null()) {
        validate_known_object_keys(value, allowed, "unknown nested session-state field")?;
    }
    Ok(())
}

fn validate_state_shape(value: &serde_json::Value) -> Result<(), PersistError> {
    validate_known_object_keys(value, STATE_KEYS, "unknown session-state field")?;
    validate_child_object_keys(value, "identity", IDENTITY_KEYS)?;
    validate_child_object_keys(value, "conversation", CONVERSATION_KEYS)?;
    validate_child_object_keys(value, "ui", UI_KEYS)?;
    validate_child_object_keys(value, "modes", MODES_KEYS)?;
    validate_child_object_keys(value, "permissions", PERMISSION_KEYS)?;
    validate_child_object_keys(value, "budgets", BUDGET_KEYS)?;
    validate_child_object_keys(value, "ide", IDE_KEYS)?;
    validate_child_object_keys(value, "transcript", TRANSCRIPT_KEYS)?;

    if let Some(conversation) = value.get("conversation") {
        validate_child_object_keys(conversation, "behavior_mode", BEHAVIOR_MODE_KEYS)?;
        validate_child_object_keys(conversation, "behavior_scope_targets", BEHAVIOR_SCOPE_KEYS)?;
        validate_child_object_keys(conversation, "plan_mode", PLAN_MODE_KEYS)?;
        if let Some(targets) = conversation
            .get("behavior_scope_targets")
            .and_then(|scope| scope.get("targets"))
            .and_then(serde_json::Value::as_array)
        {
            for target in targets {
                validate_known_object_keys(
                    target,
                    BEHAVIOR_SCOPE_TARGET_KEYS,
                    "unknown behavior-scope target field",
                )?;
            }
        }
        if let Some(prompts) = conversation
            .get("plan_mode")
            .and_then(|plan| plan.get("allowed_prompts"))
            .and_then(serde_json::Value::as_array)
        {
            for prompt in prompts {
                validate_known_object_keys(
                    prompt,
                    ALLOWED_PROMPT_KEYS,
                    "unknown plan-mode prompt field",
                )?;
            }
        }
    }
    if let Some(ui) = value.get("ui") {
        validate_child_object_keys(ui, "plan_mode", UI_PLAN_MODE_KEYS)?;
    }
    if let Some(ide) = value.get("ide") {
        validate_child_object_keys(ide, "selection", IDE_SELECTION_KEYS)?;
        if let Some(diagnostics) = ide
            .get("diagnostics")
            .and_then(serde_json::Value::as_object)
        {
            for file_diagnostics in diagnostics.values() {
                if let Some(file_diagnostics) = file_diagnostics.as_array() {
                    for diagnostic in file_diagnostics {
                        validate_known_object_keys(
                            diagnostic,
                            IDE_DIAGNOSTIC_KEYS,
                            "unknown IDE diagnostic field",
                        )?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_json_bounds(value: &serde_json::Value) -> Result<(), PersistError> {
    let mut nodes = 0_usize;
    let mut pending = vec![(value, 0_usize)];
    while let Some((node, depth)) = pending.pop() {
        if depth > MAX_SESSION_JSON_DEPTH {
            return Err(PersistError::ResourceLimit(
                "session JSON nesting exceeds the supported limit",
            ));
        }
        nodes = nodes.checked_add(1).ok_or(PersistError::ResourceLimit(
            "session JSON node count overflowed",
        ))?;
        if nodes > MAX_SESSION_JSON_NODES {
            return Err(PersistError::ResourceLimit(
                "session JSON node count exceeds the supported limit",
            ));
        }
        match node {
            serde_json::Value::Array(items) => {
                if nodes.saturating_add(items.len()) > MAX_SESSION_JSON_NODES {
                    return Err(PersistError::ResourceLimit(
                        "session JSON node count exceeds the supported limit",
                    ));
                }
                pending.extend(items.iter().map(|item| (item, depth + 1)));
            }
            serde_json::Value::Object(fields) => {
                if nodes.saturating_add(fields.len()) > MAX_SESSION_JSON_NODES {
                    return Err(PersistError::ResourceLimit(
                        "session JSON node count exceeds the supported limit",
                    ));
                }
                pending.extend(fields.values().map(|item| (item, depth + 1)));
            }
            serde_json::Value::Null
            | serde_json::Value::Bool(_)
            | serde_json::Value::Number(_)
            | serde_json::Value::String(_) => {}
        }
    }
    Ok(())
}

fn strip_imported_authority(state: &mut SessionState, workspace_root: &Path) {
    // Preserve causal/session data, including the project identity needed to
    // resume the session from its original workspace. The frontend derives a
    // fresh run and requires that project identity to match the host-selected
    // launch project before any path becomes authority. Only fields that can
    // directly carry live authority are discarded here.
    state.identity.additional_directories_for_claude_md.clear();
    state.identity.active_workspace = None;
    state.conversation.plan_mode = None;
    state.conversation.behavior_scope_targets = crate::modes::BehaviorScopeTargets::default();
    state.permissions = super::PermissionsState::default();
    if state.identity.original_cwd.as_os_str().is_empty()
        || state.identity.cwd.as_os_str().is_empty()
        || state.identity.project_root.as_os_str().is_empty()
        || state.identity.session_project_dir.as_os_str().is_empty()
        || state.transcript.transcript_cwd.as_os_str().is_empty()
    {
        state.identity.original_cwd = workspace_root.to_path_buf();
        state.identity.cwd = workspace_root.to_path_buf();
        state.identity.project_root = workspace_root.to_path_buf();
        state.identity.session_project_dir = workspace_root.to_path_buf();
        state.transcript.transcript_cwd = workspace_root.to_path_buf();
        state.transcript.watermark = 0;
    }
}

#[derive(Debug, Clone, Copy)]
enum MetadataKind {
    Title,
    ProviderIdentity,
}

fn validate_metadata_text(value: &str, kind: MetadataKind) -> Result<(), PersistError> {
    if value.len() > MAX_SESSION_METADATA_BYTES
        || (matches!(kind, MetadataKind::ProviderIdentity) && value.trim().is_empty())
        || value.chars().any(|character| {
            character == '\0'
                || (matches!(kind, MetadataKind::ProviderIdentity)
                    && (character == '\n' || character == '\r'))
                || (character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
        })
    {
        Err(PersistError::InvalidRecord(
            "session metadata is empty, excessive, or contains control characters",
        ))
    } else {
        Ok(())
    }
}

fn validate_document_metadata(
    title: &str,
    created_at: &chrono::DateTime<chrono::Utc>,
    updated_at: &chrono::DateTime<chrono::Utc>,
    model: &str,
    provider: &str,
) -> Result<(), PersistError> {
    validate_metadata_text(title, MetadataKind::Title)?;
    validate_metadata_text(model, MetadataKind::ProviderIdentity)?;
    validate_metadata_text(provider, MetadataKind::ProviderIdentity)?;
    if updated_at < created_at {
        return Err(PersistError::InvalidRecord(
            "session update timestamp precedes creation timestamp",
        ));
    }
    Ok(())
}

fn validate_state(state: &SessionState) -> Result<(), PersistError> {
    crate::state::validate_session_id(state.identity.session_id.as_str())
        .map_err(PersistError::InvalidRecord)?;
    if let Some(parent) = &state.identity.parent_session_id {
        crate::state::validate_session_id(parent.as_str()).map_err(PersistError::InvalidRecord)?;
    }
    for path in [
        &state.identity.original_cwd,
        &state.identity.cwd,
        &state.identity.project_root,
        &state.identity.session_project_dir,
        &state.transcript.transcript_cwd,
    ] {
        if !path.is_absolute() {
            return Err(PersistError::InvalidRecord(
                "session identity contains a non-absolute path",
            ));
        }
    }
    if state.identity.additional_directories_for_claude_md.len()
        > MAX_SESSION_ADDITIONAL_DIRECTORIES
    {
        return Err(PersistError::ResourceLimit(
            "session additional-directory set exceeds the supported item limit",
        ));
    }
    if state
        .identity
        .additional_directories_for_claude_md
        .iter()
        .any(|path| !path.is_absolute())
    {
        return Err(PersistError::InvalidRecord(
            "session additional-directory set contains a non-absolute path",
        ));
    }
    if let Some(workspace) = &state.identity.active_workspace {
        workspace
            .validate()
            .map_err(|_| PersistError::InvalidRecord("invalid isolated-workspace descriptor"))?;
    }
    if state.conversation.messages.len() > MAX_SESSION_MESSAGES
        || state.conversation.undo_stack.len() > MAX_SESSION_UNDO_ENTRIES
    {
        return Err(PersistError::ResourceLimit(
            "session conversation exceeds the supported item limit",
        ));
    }
    if state.transcript.watermark > state.conversation.messages.len() {
        return Err(PersistError::InvalidRecord(
            "session transcript watermark exceeds conversation length",
        ));
    }
    let diagnostic_count = state
        .ide
        .diagnostics
        .values()
        .try_fold(0_usize, |count, diagnostics| {
            count.checked_add(diagnostics.len())
        })
        .ok_or(PersistError::ResourceLimit(
            "session IDE diagnostic count overflowed",
        ))?;
    if state.ide.recent_files.len() > MAX_SESSION_IDE_FILES
        || state.ide.diagnostics.len() > MAX_SESSION_IDE_FILES
        || diagnostic_count > MAX_SESSION_IDE_DIAGNOSTICS
    {
        return Err(PersistError::ResourceLimit(
            "session IDE state exceeds the supported item limit",
        ));
    }
    Ok(())
}

fn validate_document(document: &SessionDocument) -> Result<(), PersistError> {
    match SessionStateV1::classify(document.session_state.version)? {
        SessionSchema::Current => {}
        SessionSchema::Legacy => {
            return Err(PersistError::MigrationRequired {
                found: document.session_state.version,
                minimum: SessionStateV1::MIN_SUPPORTED_VERSION,
                current: SessionStateV1::CURRENT_VERSION,
            });
        }
    }
    validate_document_metadata(
        &document.title,
        &document.created_at,
        &document.updated_at,
        &document.model,
        &document.provider,
    )?;
    validate_state(&document.session_state.state)?;
    if let Some(native) = &document
        .session_state
        .state
        .conversation
        .provider_native_state
    {
        native
            .validate_identity(&document.provider, &document.model)
            .map_err(|error| PersistError::InvalidProviderNativeState(error.to_string()))?;
    }
    Ok(())
}

/// Decode a canonical document for ordinary session loading.
///
/// Legacy shapes are deliberately rejected here. They may be upgraded only by
/// [`decode_document_for_migration`], which is called by the fail-closed
/// startup migration with an explicit trusted workspace.
pub(crate) fn decode_document_value(
    value: serde_json::Value,
    workspace_root: &Path,
) -> Result<SessionDocument, PersistError> {
    decode_document_value_with_policy(value, workspace_root, false)
}

fn decode_document_value_with_policy(
    value: serde_json::Value,
    workspace_root: &Path,
    allow_legacy_migration: bool,
) -> Result<SessionDocument, PersistError> {
    if allow_legacy_migration && !workspace_root.is_absolute() {
        return Err(PersistError::InvalidMigrationContext);
    }
    validate_json_bounds(&value)?;
    if value.get("session_state").is_some() {
        let state_value = value
            .get("session_state")
            .ok_or(PersistError::InvalidRecord("missing session state"))?;
        let raw_version = state_value
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .ok_or(PersistError::InvalidRecord(
                "session schema version is missing or invalid",
            ))?;
        let version = u32::try_from(raw_version).map_err(|_| PersistError::FutureSchema {
            found: u32::MAX,
            supported: SessionStateV1::CURRENT_VERSION,
        })?;
        let schema = SessionStateV1::classify(version)?;
        if matches!(schema, SessionSchema::Legacy) && !allow_legacy_migration {
            return Err(PersistError::MigrationRequired {
                found: version,
                minimum: SessionStateV1::MIN_SUPPORTED_VERSION,
                current: SessionStateV1::CURRENT_VERSION,
            });
        }
        validate_known_object_keys(&value, DOCUMENT_KEYS, "unknown session document field")?;
        validate_state_shape(state_value)?;
        let mut document_value = value;
        if let Some(object) = document_value.as_object_mut() {
            for duplicate in [
                "mode",
                "behavior_mode",
                "messages",
                "undo_stack",
                "plan_mode",
                "approved_plan",
                "working_dirs",
            ] {
                object.remove(duplicate);
            }
        }
        let document: SessionDocument = serde_json::from_value(document_value)?;
        return match schema {
            SessionSchema::Current => {
                // Validate transitional duplicated identities before a caller
                // can use the canonical session id in a path.
                let state = document.clone().into_state()?;
                let mut canonical = document;
                canonical.compatibility_id = None;
                canonical.session_state = SessionStateV1::wrap(state);
                Ok(canonical)
            }
            SessionSchema::Legacy => {
                let SessionDocument {
                    title,
                    created_at,
                    updated_at,
                    model,
                    provider,
                    session_state,
                    compatibility_id,
                } = document;
                let mut state = session_state.into_state();
                if let Some(legacy) = compatibility_id {
                    if state.identity.session_id.as_str() != legacy {
                        return Err(PersistError::InconsistentSessionId {
                            legacy,
                            canonical: state.identity.session_id.to_string(),
                        });
                    }
                }
                strip_imported_authority(&mut state, workspace_root);
                let canonical = SessionDocument::from_state(
                    title, created_at, updated_at, model, provider, state,
                );
                validate_document(&canonical)?;
                Ok(canonical)
            }
        };
    }
    if !allow_legacy_migration {
        return Err(PersistError::MigrationRequired {
            found: SessionStateV1::MIN_SUPPORTED_VERSION,
            minimum: SessionStateV1::MIN_SUPPORTED_VERSION,
            current: SessionStateV1::CURRENT_VERSION,
        });
    }
    let legacy: LegacySessionDocument = serde_json::from_value(value)?;
    legacy.upgrade(workspace_root)
}

/// Decode a session document and report whether it already used the canonical
/// non-duplicated V1 layout.
///
/// # Errors
///
/// Returns [`PersistError::Json`] for malformed or structurally invalid JSON,
/// [`PersistError::FutureSchema`] for a newer state version, or
/// [`PersistError::InconsistentSessionId`] for conflicting transitional ids.
/// Resource and semantic bounds are checked before a migrated document can be
/// published.
pub fn decode_document_for_migration(
    raw: &str,
    workspace_root: &Path,
) -> Result<(SessionDocument, bool), PersistError> {
    if raw.len() > MAX_SESSION_DOCUMENT_BYTES {
        return Err(PersistError::ResourceLimit(
            "session document exceeds the supported byte limit",
        ));
    }
    let value: serde_json::Value = serde_json::from_str(raw)?;
    let canonical = value
        .get("session_state")
        .and_then(|state| state.get("version"))
        .and_then(serde_json::Value::as_u64)
        == Some(u64::from(SessionStateV1::CURRENT_VERSION))
        && value
            .get("session_state")
            .is_some_and(|state| state.get("permissions").is_none())
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
    Ok((
        decode_document_value_with_policy(value, workspace_root, true)?,
        canonical,
    ))
}

/// Schema version 1 — matches [`super::SessionState`] field-for-field.
/// Shipping the version tag from day one gives future migrations a
/// sentinel to dispatch on (see crosslink #506 migrations framework).
#[derive(Debug, Clone, Serialize)]
pub struct SessionStateV1 {
    /// Schema version number. Always `1` for this type — a future
    /// `SessionStateV2` would have `version: 2` and its own struct.
    pub version: u32,
    /// The actual payload.
    #[serde(flatten)]
    pub state: SessionState,
}

#[derive(Deserialize)]
struct RawSessionStateV1 {
    version: u32,
    #[serde(flatten)]
    state: SessionState,
}

impl<'de> Deserialize<'de> for SessionStateV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        use serde::de::Error as _;

        let value = serde_json::Value::deserialize(deserializer)?;
        validate_json_bounds(&value).map_err(D::Error::custom)?;
        validate_state_shape(&value).map_err(D::Error::custom)?;
        let raw_version = value
            .get("version")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| D::Error::custom("session schema version is missing or invalid"))?;
        let version = u32::try_from(raw_version)
            .map_err(|_| D::Error::custom("session schema version is newer than supported"))?;
        Self::classify(version).map_err(D::Error::custom)?;
        let raw: RawSessionStateV1 = serde_json::from_value(value).map_err(D::Error::custom)?;
        Ok(Self {
            version: raw.version,
            state: raw.state,
        })
    }
}

impl SessionStateV1 {
    /// Oldest schema with an implemented deterministic migration.
    pub const MIN_SUPPORTED_VERSION: u32 = 0;
    /// The value of `version` this type corresponds to. Callers
    /// that read on-disk files compare the decoded `version` field
    /// against this before deserializing the rest — a mismatch
    /// triggers the migration path.
    pub const CURRENT_VERSION: u32 = 1;

    const fn classify(version: u32) -> Result<SessionSchema, PersistError> {
        if version == Self::CURRENT_VERSION {
            Ok(SessionSchema::Current)
        } else if version == Self::MIN_SUPPORTED_VERSION {
            Ok(SessionSchema::Legacy)
        } else {
            Err(PersistError::FutureSchema {
                found: version,
                supported: Self::CURRENT_VERSION,
            })
        }
    }

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
    #[error("schema version {found} predates the minimum supported version ({minimum})")]
    UnsupportedOldSchema { found: u32, minimum: u32 },
    #[error("schema version {found} requires migration (supported range {minimum}..={current})")]
    MigrationRequired {
        found: u32,
        minimum: u32,
        current: u32,
    },
    #[error("session migration requires an absolute trusted workspace root")]
    InvalidMigrationContext,
    #[error("invalid session record: {0}")]
    InvalidRecord(&'static str),
    #[error("session resource limit exceeded: {0}")]
    ResourceLimit(&'static str),
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
    validate_state(state)?;
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
/// Returns `PersistError::Json` on malformed JSON,
/// `PersistError::MigrationRequired` for a pre-V1 state that lacks a trusted
/// workspace context, or `PersistError::FutureSchema` when the on-disk version
/// is newer than this binary understands.
pub fn decode(raw: &str) -> Result<SessionState, PersistError> {
    if raw.len() > MAX_SESSION_DOCUMENT_BYTES {
        return Err(PersistError::ResourceLimit(
            "session state exceeds the supported byte limit",
        ));
    }
    let value: serde_json::Value = serde_json::from_str(raw)?;
    validate_json_bounds(&value)?;
    validate_state_shape(&value)?;
    let raw_version = value
        .get("version")
        .map_or(Some(0), serde_json::Value::as_u64)
        .ok_or(PersistError::InvalidRecord(
            "session schema version is invalid",
        ))?;
    let version = u32::try_from(raw_version).map_err(|_| PersistError::FutureSchema {
        found: u32::MAX,
        supported: SessionStateV1::CURRENT_VERSION,
    })?;
    match SessionStateV1::classify(version)? {
        SessionSchema::Current => {}
        SessionSchema::Legacy => {
            return Err(PersistError::MigrationRequired {
                found: version,
                minimum: SessionStateV1::MIN_SUPPORTED_VERSION,
                current: SessionStateV1::CURRENT_VERSION,
            });
        }
    }
    let v1: SessionStateV1 = serde_json::from_value(value)?;
    let state = v1.into_state();
    validate_state(&state)?;
    Ok(state)
}

#[cfg(test)]
#[derive(Deserialize)]
struct VersionPeek {
    #[serde(default = "default_version")]
    version: u32,
}

#[cfg(test)]
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
        let mut state = SessionState::new(PathBuf::from("/tmp/versioned"));
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
        assert!(matches!(
            decode(&payload),
            Err(PersistError::MigrationRequired {
                found: 0,
                minimum: 0,
                current: 1
            })
        ));
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
    fn legacy_session_document_migrates_content_without_path_authority() {
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

        let (document, canonical) =
            decode_document_for_migration(&encoded, Path::new("/tmp/current")).unwrap();
        assert!(!canonical);
        let restored = document.into_state().unwrap();

        assert_eq!(restored.identity.session_id.as_str(), "legacy-session-id");
        assert_eq!(restored.identity.cwd, PathBuf::from("/tmp/current"));
        assert_eq!(restored.modes.agent_mode, AgentMode::Extend);
        assert_eq!(restored.conversation.messages.len(), 1);
        assert!(restored
            .identity
            .additional_directories_for_claude_md
            .is_empty());
        assert_eq!(
            restored.identity.original_cwd,
            PathBuf::from("/tmp/current")
        );
        assert_eq!(
            restored.identity.project_root,
            PathBuf::from("/tmp/current")
        );
        assert_eq!(
            restored.identity.session_project_dir,
            PathBuf::from("/tmp/current")
        );
        assert_eq!(
            restored.transcript.transcript_cwd,
            PathBuf::from("/tmp/current")
        );
    }

    #[test]
    fn ordinary_document_decode_routes_legacy_through_startup_migration() {
        let legacy = serde_json::json!({
            "id": "legacy-session-id",
            "title": "legacy",
            "created_at": "2025-01-01T00:00:00Z",
            "updated_at": "2025-01-01T00:00:00Z",
            "model": "model",
            "provider": "provider"
        });

        assert!(matches!(
            decode_document_value(legacy, Path::new("/ambient/workspace")),
            Err(PersistError::MigrationRequired {
                found: 0,
                minimum: 0,
                current: 1
            })
        ));
    }

    #[test]
    fn current_document_rejects_unknown_schema_fields() {
        let state = SessionState::new(PathBuf::from("/tmp/current"));
        let document = SessionDocument::from_state(
            "title".to_string(),
            chrono::Utc::now(),
            chrono::Utc::now(),
            "model".to_string(),
            "provider".to_string(),
            state,
        );
        let mut value = serde_json::to_value(document).unwrap();
        value["session_state"]["unknown_future_field"] = serde_json::json!(true);

        assert!(matches!(
            decode_document_value(value, Path::new("/tmp/current")),
            Err(PersistError::InvalidRecord("unknown session-state field"))
        ));

        let state = SessionState::new(PathBuf::from("/tmp/current"));
        let document = SessionDocument::from_state(
            "title".to_string(),
            chrono::Utc::now(),
            chrono::Utc::now(),
            "model".to_string(),
            "provider".to_string(),
            state,
        );
        let mut value = serde_json::to_value(document).unwrap();
        value["session_state"]["identity"]["unknown_future_field"] = serde_json::json!(true);
        assert!(matches!(
            decode_document_value(value, Path::new("/tmp/current")),
            Err(PersistError::InvalidRecord(
                "unknown nested session-state field"
            ))
        ));
    }

    #[test]
    fn legacy_versioned_document_preserves_project_identity_but_strips_live_authority() {
        let mut state = SessionState::new(PathBuf::from("/untrusted"));
        state.identity.session_id = SessionId::from_raw_unchecked("legacy-v0");
        state
            .identity
            .additional_directories_for_claude_md
            .push(PathBuf::from("/untrusted/additional"));
        state.modes.coordinator = true;
        let document = SessionDocument::from_state(
            "legacy".to_string(),
            chrono::Utc::now(),
            chrono::Utc::now(),
            "model".to_string(),
            "provider".to_string(),
            state,
        );
        let mut value = serde_json::to_value(document).unwrap();
        value["session_state"]["version"] = serde_json::json!(0);
        let encoded = serde_json::to_string(&value).unwrap();
        let (migrated, canonical) =
            decode_document_for_migration(&encoded, Path::new("/trusted/workspace")).unwrap();
        assert!(!canonical);
        let migrated = migrated.into_state().unwrap();

        assert_eq!(migrated.identity.cwd, PathBuf::from("/untrusted"));
        assert!(migrated
            .identity
            .additional_directories_for_claude_md
            .is_empty());
        assert!(migrated.modes.coordinator);
        assert!(migrated.identity.active_workspace.is_none());
        assert_eq!(migrated.transcript.watermark, 0);
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
