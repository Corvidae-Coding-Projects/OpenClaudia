//! User-owned session events that are never part of provider conversation state.
//!
//! Private notes and side-question attempts persist with the owning session,
//! but are deliberately outside portable messages, provider continuation,
//! compaction, exports, titles, undo/redo, and memory projections.

use std::collections::HashSet;
use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use crate::runtime::{CallId, ContentDigest, RunId};

use super::causal::CausalEventRef;
use super::CausalStateError;

const LOCAL_EVENT_SCHEMA_VERSION: u16 = 1;
const MAX_PRIVATE_NOTES: usize = 1_024;
const MAX_NEW_PRIVATE_NOTE_BYTES: usize = 64 * 1_024;
const MAX_RETAINED_PRIVATE_NOTE_BYTES: usize = MAX_NEW_PRIVATE_NOTE_BYTES;
const MAX_PRIVATE_NOTE_TOTAL_BYTES: usize = 8 * 1_024 * 1_024;
const MAX_NOTE_PROJECTIONS: usize = 32;
const MAX_SIDE_QUESTIONS: usize = 256;
const MAX_SIDE_QUESTION_BYTES: usize = 16 * 1_024;
pub const MAX_SIDE_QUESTION_RESULT_BYTES: usize = 256 * 1_024;
const MAX_SIDE_QUESTION_FAILURE_BYTES: usize = 8 * 1_024;
const MAX_SIDE_QUESTION_TOTAL_BYTES: usize = 32 * 1_024 * 1_024;

macro_rules! local_uuid_id {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(formatter)
            }
        }
    };
}

local_uuid_id!(PrivateEventId, "Identity of one user-owned private event.");
local_uuid_id!(
    PrivateProjectionConsentId,
    "Identity of one explicit user projection decision."
);
local_uuid_id!(
    SideQuestionAttemptId,
    "Identity of one bounded side-question attempt."
);
local_uuid_id!(
    SideQuestionResultId,
    "Identity of one terminal side-question result."
);

/// Actor that owns and controls a private event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateEventOwner {
    User,
}

/// Sensitivity applied to private local session content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalEventSensitivity {
    UserPrivate,
}

/// Retention contract for local user-owned events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalEventRetention {
    /// Persist with the session until the user deletes the event or the
    /// session itself is deleted under the session-store policy.
    SessionUntilDeleted,
}

/// Authority of an explicitly projected private note.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateProjectionAuthority {
    UserEvidence,
}

/// One explicit, note-bound user decision permitting a provider projection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserNoteProjectionConsent {
    id: PrivateProjectionConsentId,
    note_id: PrivateEventId,
    granted_at: DateTime<Utc>,
}

impl UserNoteProjectionConsent {
    /// Create an explicit one-use projection decision for exactly one note.
    #[must_use]
    pub fn explicit_for(note_id: PrivateEventId) -> Self {
        Self {
            id: PrivateProjectionConsentId::new(),
            note_id,
            granted_at: Utc::now(),
        }
    }
}

/// Durable receipt for an intentional private-note projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateNoteProjectionReceipt {
    pub consent_id: PrivateProjectionConsentId,
    pub note_id: PrivateEventId,
    pub granted_at: DateTime<Utc>,
    pub projected_at: DateTime<Utc>,
    pub parent_event: CausalEventRef,
    pub content_digest: ContentDigest,
    pub authority: PrivateProjectionAuthority,
}

/// Tombstone proving that retained private bytes were removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateNoteDeletionReceipt {
    pub deleted_at: DateTime<Utc>,
    pub deleted_content_digest: ContentDigest,
}

/// A user-owned note retained outside all model-visible state.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrivateNoteEvent {
    schema_version: u16,
    id: PrivateEventId,
    owner: PrivateEventOwner,
    sensitivity: LocalEventSensitivity,
    retention: LocalEventRetention,
    created_at: DateTime<Utc>,
    content: Option<String>,
    content_digest: ContentDigest,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    projections: Vec<PrivateNoteProjectionReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    deletion: Option<PrivateNoteDeletionReceipt>,
}

impl fmt::Debug for PrivateNoteEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrivateNoteEvent")
            .field("schema_version", &self.schema_version)
            .field("id", &self.id)
            .field("owner", &self.owner)
            .field("sensitivity", &self.sensitivity)
            .field("retention", &self.retention)
            .field("created_at", &self.created_at)
            .field(
                "content",
                &self
                    .content
                    .as_ref()
                    .map(|text| format!("<redacted:{} bytes>", text.len())),
            )
            .field("content_digest", &self.content_digest)
            .field("projection_count", &self.projections.len())
            .field("deletion", &self.deletion)
            .finish()
    }
}

impl PrivateNoteEvent {
    fn new(content: String, created_at: DateTime<Utc>) -> Result<Self, LocalEventError> {
        validate_new_private_note(&content)?;
        Ok(Self::new_retained(content, created_at))
    }

    fn migrated(content: String, created_at: DateTime<Utc>) -> Result<Self, LocalEventError> {
        validate_retained_private_note(&content)?;
        Ok(Self::new_retained(content, created_at))
    }

    fn new_retained(content: String, created_at: DateTime<Utc>) -> Self {
        let content_digest = ContentDigest::sha256(content.as_bytes());
        Self {
            schema_version: LOCAL_EVENT_SCHEMA_VERSION,
            id: PrivateEventId::new(),
            owner: PrivateEventOwner::User,
            sensitivity: LocalEventSensitivity::UserPrivate,
            retention: LocalEventRetention::SessionUntilDeleted,
            created_at,
            content: Some(content),
            content_digest,
            projections: Vec::new(),
            deletion: None,
        }
    }

    #[must_use]
    pub const fn id(&self) -> PrivateEventId {
        self.id
    }

    #[must_use]
    pub const fn owner(&self) -> PrivateEventOwner {
        self.owner
    }

    #[must_use]
    pub const fn sensitivity(&self) -> LocalEventSensitivity {
        self.sensitivity
    }

    #[must_use]
    pub const fn retention(&self) -> LocalEventRetention {
        self.retention
    }

    #[must_use]
    pub fn content(&self) -> Option<&str> {
        self.content.as_deref()
    }

    #[must_use]
    pub const fn deletion(&self) -> Option<&PrivateNoteDeletionReceipt> {
        self.deletion.as_ref()
    }

    #[must_use]
    pub fn projections(&self) -> &[PrivateNoteProjectionReceipt] {
        &self.projections
    }

    #[allow(clippy::needless_pass_by_value)] // A consent receipt is intentionally single-use.
    fn project(
        &mut self,
        consent: UserNoteProjectionConsent,
        parent_event: CausalEventRef,
    ) -> Result<PrivateNoteProjection, LocalEventError> {
        if consent.note_id != self.id {
            return Err(LocalEventError::ConsentMismatch);
        }
        let note_content = self
            .content
            .as_ref()
            .ok_or(LocalEventError::PrivateNoteDeleted)?;
        if self.projections.len() >= MAX_NOTE_PROJECTIONS {
            return Err(LocalEventError::ProjectionLimit);
        }
        let receipt = PrivateNoteProjectionReceipt {
            consent_id: consent.id,
            note_id: self.id,
            granted_at: consent.granted_at,
            projected_at: Utc::now(),
            parent_event,
            content_digest: self.content_digest,
            authority: PrivateProjectionAuthority::UserEvidence,
        };
        self.projections.push(receipt.clone());
        Ok(PrivateNoteProjection {
            message: serde_json::json!({
                "role": "user",
                "content": note_content,
                "metadata": {
                    "openclaudia_context_source": "private_note_user_evidence",
                    "private_note_id": self.id.to_string(),
                    "projection_consent_id": consent.id.to_string(),
                    "authority": "user_evidence"
                }
            }),
            receipt,
        })
    }

    fn delete(&mut self) -> Result<PrivateNoteDeletionReceipt, LocalEventError> {
        if let Some(receipt) = &self.deletion {
            return Ok(receipt.clone());
        }
        let _content = self
            .content
            .take()
            .ok_or(LocalEventError::PrivateNoteDeleted)?;
        let receipt = PrivateNoteDeletionReceipt {
            deleted_at: Utc::now(),
            deleted_content_digest: self.content_digest,
        };
        self.deletion = Some(receipt.clone());
        Ok(receipt)
    }

    fn validate(&self) -> Result<(), LocalEventError> {
        if self.schema_version != LOCAL_EVENT_SCHEMA_VERSION
            || self.owner != PrivateEventOwner::User
            || self.sensitivity != LocalEventSensitivity::UserPrivate
            || self.retention != LocalEventRetention::SessionUntilDeleted
            || self.projections.len() > MAX_NOTE_PROJECTIONS
        {
            return Err(LocalEventError::InvalidRecord);
        }
        match (&self.content, &self.deletion) {
            (Some(content), None)
                if content.len() <= MAX_RETAINED_PRIVATE_NOTE_BYTES
                    && !content.trim().is_empty()
                    && ContentDigest::sha256(content.as_bytes()) == self.content_digest => {}
            (None, Some(deletion)) if deletion.deleted_content_digest == self.content_digest => {}
            _ => return Err(LocalEventError::InvalidRecord),
        }
        for receipt in &self.projections {
            let identity_mismatch = receipt.note_id != self.id;
            let digest_mismatch = receipt.content_digest != self.content_digest;
            let authority_mismatch = receipt.authority != PrivateProjectionAuthority::UserEvidence;
            if identity_mismatch
                || digest_mismatch
                || authority_mismatch
                || receipt.parent_event.validate().is_err()
            {
                return Err(LocalEventError::InvalidRecord);
            }
        }
        Ok(())
    }
}

/// Provider message and receipt produced only after explicit consent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateNoteProjection {
    pub message: Value,
    pub receipt: PrivateNoteProjectionReceipt,
}

/// Stable class of a side-question failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SideQuestionFailureCode {
    Admission,
    Persistence,
    RequestBuild,
    Policy,
    Provider,
    UnexpectedToolContinuation,
    ResultTooLarge,
}

/// Reference attached to a successful side-question result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SideQuestionResultRef {
    pub result_id: SideQuestionResultId,
    pub attempt_id: SideQuestionAttemptId,
    pub parent_event: CausalEventRef,
    pub content_digest: ContentDigest,
}

/// Explicit lifecycle of one bounded child attempt.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum SideQuestionOutcome {
    PendingAdmission,
    Running,
    Succeeded {
        reference: SideQuestionResultRef,
        content: String,
        completed_at: DateTime<Utc>,
    },
    Failed {
        code: SideQuestionFailureCode,
        detail: String,
        completed_at: DateTime<Utc>,
    },
    TimedOut {
        timeout_millis: u64,
        completed_at: DateTime<Utc>,
    },
    Cancelled {
        reason: String,
        completed_at: DateTime<Utc>,
    },
}

impl fmt::Debug for SideQuestionOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PendingAdmission => formatter.write_str("PendingAdmission"),
            Self::Running => formatter.write_str("Running"),
            Self::Succeeded {
                reference,
                content,
                completed_at,
            } => formatter
                .debug_struct("Succeeded")
                .field("reference", reference)
                .field("content", &format!("<redacted:{} bytes>", content.len()))
                .field("completed_at", completed_at)
                .finish(),
            Self::Failed {
                code,
                detail,
                completed_at,
            } => formatter
                .debug_struct("Failed")
                .field("code", code)
                .field("detail", &format!("<redacted:{} bytes>", detail.len()))
                .field("completed_at", completed_at)
                .finish(),
            Self::TimedOut {
                timeout_millis,
                completed_at,
            } => formatter
                .debug_struct("TimedOut")
                .field("timeout_millis", timeout_millis)
                .field("completed_at", completed_at)
                .finish(),
            Self::Cancelled {
                reason,
                completed_at,
            } => formatter
                .debug_struct("Cancelled")
                .field("reason", &format!("<redacted:{} bytes>", reason.len()))
                .field("completed_at", completed_at)
                .finish(),
        }
    }
}

/// One side question bound to an immutable parent causal event and child run.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SideQuestionAttempt {
    schema_version: u16,
    attempt_id: SideQuestionAttemptId,
    call_id: CallId,
    parent_event: CausalEventRef,
    parent_run: RunId,
    child_run: Option<RunId>,
    parent_snapshot_digest: ContentDigest,
    parent_message_count: usize,
    provider: String,
    model: String,
    sensitivity: LocalEventSensitivity,
    retention: LocalEventRetention,
    created_at: DateTime<Utc>,
    question: String,
    question_digest: ContentDigest,
    outcome: SideQuestionOutcome,
}

impl fmt::Debug for SideQuestionAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SideQuestionAttempt")
            .field("schema_version", &self.schema_version)
            .field("attempt_id", &self.attempt_id)
            .field("call_id", &self.call_id)
            .field("parent_event", &self.parent_event)
            .field("parent_run", &self.parent_run)
            .field("child_run", &self.child_run)
            .field("parent_snapshot_digest", &self.parent_snapshot_digest)
            .field("parent_message_count", &self.parent_message_count)
            .field("provider", &self.provider)
            .field("model", &self.model)
            .field("sensitivity", &self.sensitivity)
            .field("retention", &self.retention)
            .field("created_at", &self.created_at)
            .field(
                "question",
                &format!("<redacted:{} bytes>", self.question.len()),
            )
            .field("question_digest", &self.question_digest)
            .field("outcome", &self.outcome)
            .finish()
    }
}

impl SideQuestionAttempt {
    #[must_use]
    pub const fn attempt_id(&self) -> SideQuestionAttemptId {
        self.attempt_id
    }

    #[must_use]
    pub const fn call_id(&self) -> CallId {
        self.call_id
    }

    #[must_use]
    pub const fn parent_event(&self) -> &CausalEventRef {
        &self.parent_event
    }

    #[must_use]
    pub const fn child_run(&self) -> Option<RunId> {
        self.child_run
    }

    #[must_use]
    pub const fn outcome(&self) -> &SideQuestionOutcome {
        &self.outcome
    }

    fn validate(&self) -> Result<(), LocalEventError> {
        self.parent_event
            .validate()
            .map_err(|_| LocalEventError::InvalidRecord)?;
        if self.schema_version != LOCAL_EVENT_SCHEMA_VERSION
            || self.sensitivity != LocalEventSensitivity::UserPrivate
            || self.retention != LocalEventRetention::SessionUntilDeleted
            || self.question.trim().is_empty()
            || self.question.len() > MAX_SIDE_QUESTION_BYTES
            || ContentDigest::sha256(self.question.as_bytes()) != self.question_digest
            || self.provider.trim().is_empty()
            || self.model.trim().is_empty()
        {
            return Err(LocalEventError::InvalidRecord);
        }
        match &self.outcome {
            SideQuestionOutcome::PendingAdmission => {
                if self.child_run.is_some() {
                    return Err(LocalEventError::InvalidRecord);
                }
            }
            SideQuestionOutcome::Running | SideQuestionOutcome::TimedOut { .. } => {
                if self.child_run.is_none() {
                    return Err(LocalEventError::InvalidRecord);
                }
            }
            SideQuestionOutcome::Succeeded {
                reference,
                content,
                completed_at: _,
            } => {
                if self.child_run.is_none()
                    || content.len() > MAX_SIDE_QUESTION_RESULT_BYTES
                    || reference.attempt_id != self.attempt_id
                    || reference.parent_event != self.parent_event
                    || reference.parent_event.validate().is_err()
                    || reference.content_digest != ContentDigest::sha256(content.as_bytes())
                {
                    return Err(LocalEventError::InvalidRecord);
                }
            }
            SideQuestionOutcome::Failed { detail, .. } => {
                if detail.is_empty() || detail.len() > MAX_SIDE_QUESTION_FAILURE_BYTES {
                    return Err(LocalEventError::InvalidRecord);
                }
            }
            SideQuestionOutcome::Cancelled { reason, .. } => {
                if reason.is_empty() || reason.len() > MAX_SIDE_QUESTION_FAILURE_BYTES {
                    return Err(LocalEventError::InvalidRecord);
                }
            }
        }
        Ok(())
    }
}

/// Immutable parent material returned to the side-question executor.
#[derive(Clone)]
pub struct SideQuestionLaunch {
    pub attempt_id: SideQuestionAttemptId,
    pub call_id: CallId,
    pub parent_event: CausalEventRef,
    pub parent_snapshot_digest: ContentDigest,
    pub messages: Vec<Value>,
    pub question: String,
}

impl fmt::Debug for SideQuestionLaunch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SideQuestionLaunch")
            .field("attempt_id", &self.attempt_id)
            .field("call_id", &self.call_id)
            .field("parent_event", &self.parent_event)
            .field("parent_snapshot_digest", &self.parent_snapshot_digest)
            .field("message_count", &self.messages.len())
            .field(
                "question",
                &format!("<redacted:{} bytes>", self.question.len()),
            )
            .finish()
    }
}

/// Persisted local-only state owned by one session.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionLocalState {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    private_notes: Vec<PrivateNoteEvent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    side_questions: Vec<SideQuestionAttempt>,
}

impl fmt::Debug for SessionLocalState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionLocalState")
            .field("private_notes", &self.private_notes)
            .field("side_questions", &self.side_questions)
            .finish()
    }
}

impl SessionLocalState {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.private_notes.is_empty() && self.side_questions.is_empty()
    }

    #[must_use]
    pub fn private_notes(&self) -> &[PrivateNoteEvent] {
        &self.private_notes
    }

    #[must_use]
    pub fn side_questions(&self) -> &[SideQuestionAttempt] {
        &self.side_questions
    }

    pub(crate) fn add_private_note(
        &mut self,
        content: String,
        created_at: DateTime<Utc>,
    ) -> Result<PrivateEventId, LocalEventError> {
        if self.private_notes.len() >= MAX_PRIVATE_NOTES {
            return Err(LocalEventError::PrivateNoteLimit);
        }
        let note = PrivateNoteEvent::new(content, created_at)?;
        if self
            .private_note_content_bytes()
            .saturating_add(note.content.as_ref().map_or(0, String::len))
            > MAX_PRIVATE_NOTE_TOTAL_BYTES
        {
            return Err(LocalEventError::PrivateNoteLimit);
        }
        let id = note.id;
        self.private_notes.push(note);
        Ok(id)
    }

    fn add_migrated_private_note(
        &mut self,
        content: String,
        created_at: DateTime<Utc>,
    ) -> Result<PrivateEventId, LocalEventError> {
        validate_retained_private_note(&content)?;
        if self.private_notes.len() >= MAX_PRIVATE_NOTES {
            return Err(LocalEventError::PrivateNoteLimit);
        }
        if self
            .private_note_content_bytes()
            .saturating_add(content.len())
            > MAX_PRIVATE_NOTE_TOTAL_BYTES
        {
            return Err(LocalEventError::PrivateNoteLimit);
        }
        let note = PrivateNoteEvent::migrated(content, created_at)?;
        let id = note.id;
        self.private_notes.push(note);
        Ok(id)
    }

    pub(crate) fn project_private_note(
        &mut self,
        note_id: PrivateEventId,
        consent: UserNoteProjectionConsent,
        parent_event: CausalEventRef,
    ) -> Result<PrivateNoteProjection, LocalEventError> {
        self.private_notes
            .iter_mut()
            .find(|note| note.id == note_id)
            .ok_or(LocalEventError::PrivateNoteNotFound)?
            .project(consent, parent_event)
    }

    pub(crate) fn delete_private_note(
        &mut self,
        note_id: PrivateEventId,
    ) -> Result<PrivateNoteDeletionReceipt, LocalEventError> {
        self.private_notes
            .iter_mut()
            .find(|note| note.id == note_id)
            .ok_or(LocalEventError::PrivateNoteNotFound)?
            .delete()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn start_side_question(
        &mut self,
        call_id: CallId,
        parent_event: CausalEventRef,
        parent_run: RunId,
        parent_snapshot_digest: ContentDigest,
        parent_message_count: usize,
        provider: String,
        model: String,
        question: String,
    ) -> Result<SideQuestionAttemptId, LocalEventError> {
        validate_side_question(&question)?;
        if self.side_questions.len() >= MAX_SIDE_QUESTIONS {
            return Err(LocalEventError::SideQuestionLimit);
        }
        if self
            .side_question_content_bytes()
            .saturating_add(question.len())
            > MAX_SIDE_QUESTION_TOTAL_BYTES
        {
            return Err(LocalEventError::SideQuestionLimit);
        }
        let attempt_id = SideQuestionAttemptId::new();
        self.side_questions.push(SideQuestionAttempt {
            schema_version: LOCAL_EVENT_SCHEMA_VERSION,
            attempt_id,
            call_id,
            parent_event,
            parent_run,
            child_run: None,
            parent_snapshot_digest,
            parent_message_count,
            provider,
            model,
            sensitivity: LocalEventSensitivity::UserPrivate,
            retention: LocalEventRetention::SessionUntilDeleted,
            created_at: Utc::now(),
            question_digest: ContentDigest::sha256(question.as_bytes()),
            question,
            outcome: SideQuestionOutcome::PendingAdmission,
        });
        Ok(attempt_id)
    }

    pub(crate) fn bind_side_question_child(
        &mut self,
        attempt_id: SideQuestionAttemptId,
        child_run: RunId,
    ) -> Result<(), LocalEventError> {
        let attempt = self.side_question_mut(attempt_id)?;
        if !matches!(attempt.outcome, SideQuestionOutcome::PendingAdmission) {
            return Err(LocalEventError::SideQuestionTerminal);
        }
        attempt.child_run = Some(child_run);
        attempt.outcome = SideQuestionOutcome::Running;
        Ok(())
    }

    pub(crate) fn succeed_side_question(
        &mut self,
        attempt_id: SideQuestionAttemptId,
        content: String,
    ) -> Result<SideQuestionResultRef, LocalEventError> {
        if content.len() > MAX_SIDE_QUESTION_RESULT_BYTES {
            return Err(LocalEventError::SideQuestionResultTooLarge);
        }
        if self
            .side_question_content_bytes()
            .saturating_add(content.len())
            > MAX_SIDE_QUESTION_TOTAL_BYTES
        {
            return Err(LocalEventError::SideQuestionResultTooLarge);
        }
        let attempt = self.side_question_mut(attempt_id)?;
        if !matches!(attempt.outcome, SideQuestionOutcome::Running) {
            return Err(LocalEventError::SideQuestionTerminal);
        }
        let reference = SideQuestionResultRef {
            result_id: SideQuestionResultId::new(),
            attempt_id,
            parent_event: attempt.parent_event.clone(),
            content_digest: ContentDigest::sha256(content.as_bytes()),
        };
        attempt.outcome = SideQuestionOutcome::Succeeded {
            reference: reference.clone(),
            content,
            completed_at: Utc::now(),
        };
        Ok(reference)
    }

    pub(crate) fn fail_side_question(
        &mut self,
        attempt_id: SideQuestionAttemptId,
        code: SideQuestionFailureCode,
        detail: String,
    ) -> Result<(), LocalEventError> {
        validate_failure_detail(&detail)?;
        let attempt = self.side_question_mut(attempt_id)?;
        ensure_open_attempt(&attempt.outcome)?;
        attempt.outcome = SideQuestionOutcome::Failed {
            code,
            detail,
            completed_at: Utc::now(),
        };
        Ok(())
    }

    pub(crate) fn timeout_side_question(
        &mut self,
        attempt_id: SideQuestionAttemptId,
        timeout_millis: u64,
    ) -> Result<(), LocalEventError> {
        let attempt = self.side_question_mut(attempt_id)?;
        if !matches!(attempt.outcome, SideQuestionOutcome::Running) {
            return Err(LocalEventError::SideQuestionTerminal);
        }
        attempt.outcome = SideQuestionOutcome::TimedOut {
            timeout_millis,
            completed_at: Utc::now(),
        };
        Ok(())
    }

    pub(crate) fn cancel_side_question(
        &mut self,
        attempt_id: SideQuestionAttemptId,
        reason: String,
    ) -> Result<(), LocalEventError> {
        validate_failure_detail(&reason)?;
        let attempt = self.side_question_mut(attempt_id)?;
        ensure_open_attempt(&attempt.outcome)?;
        attempt.outcome = SideQuestionOutcome::Cancelled {
            reason,
            completed_at: Utc::now(),
        };
        Ok(())
    }

    fn side_question_mut(
        &mut self,
        attempt_id: SideQuestionAttemptId,
    ) -> Result<&mut SideQuestionAttempt, LocalEventError> {
        self.side_questions
            .iter_mut()
            .find(|attempt| attempt.attempt_id == attempt_id)
            .ok_or(LocalEventError::SideQuestionNotFound)
    }

    fn private_note_content_bytes(&self) -> usize {
        self.private_notes
            .iter()
            .filter_map(|note| note.content.as_ref())
            .fold(0_usize, |total, content| {
                total.saturating_add(content.len())
            })
    }

    fn side_question_content_bytes(&self) -> usize {
        self.side_questions.iter().fold(0_usize, |total, attempt| {
            let outcome_bytes = match &attempt.outcome {
                SideQuestionOutcome::Succeeded { content, .. } => content.len(),
                SideQuestionOutcome::Failed { detail, .. } => detail.len(),
                SideQuestionOutcome::Cancelled { reason, .. } => reason.len(),
                SideQuestionOutcome::PendingAdmission
                | SideQuestionOutcome::Running
                | SideQuestionOutcome::TimedOut { .. } => 0,
            };
            total
                .saturating_add(attempt.question.len())
                .saturating_add(outcome_bytes)
        })
    }

    pub(crate) fn validate(&self) -> Result<(), LocalEventError> {
        if self.private_notes.len() > MAX_PRIVATE_NOTES
            || self.side_questions.len() > MAX_SIDE_QUESTIONS
        {
            return Err(LocalEventError::InvalidRecord);
        }
        let mut note_ids = HashSet::with_capacity(self.private_notes.len());
        for note in &self.private_notes {
            note.validate()?;
            if !note_ids.insert(note.id) {
                return Err(LocalEventError::InvalidRecord);
            }
        }
        if self.private_note_content_bytes() > MAX_PRIVATE_NOTE_TOTAL_BYTES {
            return Err(LocalEventError::InvalidRecord);
        }
        let mut attempt_ids = HashSet::with_capacity(self.side_questions.len());
        let mut call_ids = HashSet::with_capacity(self.side_questions.len());
        for attempt in &self.side_questions {
            attempt.validate()?;
            if !attempt_ids.insert(attempt.attempt_id) || !call_ids.insert(attempt.call_id) {
                return Err(LocalEventError::InvalidRecord);
            }
        }
        if self.side_question_content_bytes() > MAX_SIDE_QUESTION_TOTAL_BYTES {
            return Err(LocalEventError::InvalidRecord);
        }
        Ok(())
    }
}

/// Failure to create, project, delete, or finalize a local session event.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LocalEventError {
    #[error("private note must not be empty")]
    PrivateNoteEmpty,
    #[error("private note exceeds its retained byte limit")]
    PrivateNoteTooLarge,
    #[error("private note retention limit reached")]
    PrivateNoteLimit,
    #[error("private note was not found")]
    PrivateNoteNotFound,
    #[error("private note was deleted")]
    PrivateNoteDeleted,
    #[error("projection consent belongs to another private note")]
    ConsentMismatch,
    #[error("private note projection receipt limit reached")]
    ProjectionLimit,
    #[error("side question must not be empty")]
    SideQuestionEmpty,
    #[error("side question exceeds its byte limit")]
    SideQuestionTooLarge,
    #[error("side-question retention limit reached")]
    SideQuestionLimit,
    #[error("side-question attempt was not found")]
    SideQuestionNotFound,
    #[error("side-question attempt already has a terminal outcome")]
    SideQuestionTerminal,
    #[error("side-question result exceeds its byte limit")]
    SideQuestionResultTooLarge,
    #[error("local failure detail is empty or exceeds its byte limit")]
    InvalidFailureDetail,
    #[error("local session event record is malformed")]
    InvalidRecord,
    #[error("local session event serialization failed: {0}")]
    Serialization(String),
}

/// Failure to bind a local event to canonical session causality.
#[derive(Debug, Error)]
pub enum LocalEventStateError {
    #[error(transparent)]
    Local(#[from] LocalEventError),
    #[error(transparent)]
    Causal(#[from] CausalStateError),
}

fn validate_new_private_note(content: &str) -> Result<(), LocalEventError> {
    if content.trim().is_empty() {
        Err(LocalEventError::PrivateNoteEmpty)
    } else if content.len() > MAX_NEW_PRIVATE_NOTE_BYTES {
        Err(LocalEventError::PrivateNoteTooLarge)
    } else {
        Ok(())
    }
}

fn validate_retained_private_note(content: &str) -> Result<(), LocalEventError> {
    if content.trim().is_empty() {
        Err(LocalEventError::PrivateNoteEmpty)
    } else if content.len() > MAX_RETAINED_PRIVATE_NOTE_BYTES {
        Err(LocalEventError::PrivateNoteTooLarge)
    } else {
        Ok(())
    }
}

fn validate_side_question(question: &str) -> Result<(), LocalEventError> {
    if question.trim().is_empty() {
        Err(LocalEventError::SideQuestionEmpty)
    } else if question.len() > MAX_SIDE_QUESTION_BYTES {
        Err(LocalEventError::SideQuestionTooLarge)
    } else {
        Ok(())
    }
}

const fn validate_failure_detail(detail: &str) -> Result<(), LocalEventError> {
    if detail.is_empty() || detail.len() > MAX_SIDE_QUESTION_FAILURE_BYTES {
        Err(LocalEventError::InvalidFailureDetail)
    } else {
        Ok(())
    }
}

const fn ensure_open_attempt(outcome: &SideQuestionOutcome) -> Result<(), LocalEventError> {
    if matches!(
        outcome,
        SideQuestionOutcome::PendingAdmission | SideQuestionOutcome::Running
    ) {
        Ok(())
    } else {
        Err(LocalEventError::SideQuestionTerminal)
    }
}

pub fn legacy_private_note_text(message: &Value) -> Option<String> {
    let is_note = message
        .pointer("/metadata/type")
        .and_then(Value::as_str)
        .is_some_and(|kind| matches!(kind, "note" | "private_note"));
    if !is_note {
        return None;
    }
    let raw = match message.get("content") {
        Some(Value::String(content)) => content.clone(),
        Some(content) => serde_json::to_string(content).ok()?,
        None => String::new(),
    };
    let content = raw
        .strip_prefix("[Note: ")
        .and_then(|content| content.strip_suffix(']'))
        .unwrap_or(&raw)
        .to_string();
    Some(content)
}

/// Move legacy note-shaped messages into the local lane and redact undo copies.
pub fn migrate_legacy_private_notes(
    messages: &mut Vec<Value>,
    undo_stack: &mut [(Value, Value)],
    local: &mut SessionLocalState,
    created_at: DateTime<Utc>,
) -> Result<usize, LocalEventError> {
    let mut proposed_messages = messages.clone();
    let mut proposed_undo_stack = undo_stack.to_vec();
    let mut proposed_local = local.clone();
    let migrated = migrate_legacy_private_notes_in_place(
        &mut proposed_messages,
        &mut proposed_undo_stack,
        &mut proposed_local,
        created_at,
    )?;
    *messages = proposed_messages;
    undo_stack.clone_from_slice(&proposed_undo_stack);
    *local = proposed_local;
    Ok(migrated)
}

fn migrate_legacy_private_notes_in_place(
    messages: &mut Vec<Value>,
    undo_stack: &mut [(Value, Value)],
    local: &mut SessionLocalState,
    created_at: DateTime<Utc>,
) -> Result<usize, LocalEventError> {
    let mut migrated = 0_usize;
    let prior = std::mem::take(messages);
    messages.reserve(prior.len());
    for message in prior {
        if let Some(content) = legacy_private_note_text(&message) {
            let _id = local.add_migrated_private_note(content, created_at)?;
            migrated = migrated.saturating_add(1);
        } else {
            messages.push(message);
        }
    }
    for (user, assistant) in undo_stack {
        migrated = migrated.saturating_add(migrate_undo_note(user, local, created_at)?);
        migrated = migrated.saturating_add(migrate_undo_note(assistant, local, created_at)?);
    }
    Ok(migrated)
}

fn migrate_undo_note(
    message: &mut Value,
    local: &mut SessionLocalState,
    created_at: DateTime<Utc>,
) -> Result<usize, LocalEventError> {
    let Some(content) = legacy_private_note_text(message) else {
        return Ok(0);
    };
    let id = local.add_migrated_private_note(content, created_at)?;
    *message = serde_json::json!({
        "role": "system",
        "content": "[Private note migrated to the local event store]",
        "metadata": {
            "type": "private_note_tombstone",
            "private_note_id": id.to_string()
        }
    });
    Ok(1)
}

pub fn digest_messages(messages: &[Value]) -> Result<ContentDigest, LocalEventError> {
    serde_json::to_vec(messages)
        .map(ContentDigest::sha256)
        .map_err(|error| LocalEventError::Serialization(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_note_debug_never_contains_content() {
        let note =
            PrivateNoteEvent::new("seed-private-value".to_string(), Utc::now()).expect("note");
        let rendered = format!("{note:?}");
        assert!(!rendered.contains("seed-private-value"));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn deleting_a_note_removes_bytes_and_keeps_digest_tombstone() {
        let mut local = SessionLocalState::default();
        let id = local
            .add_private_note("delete me".to_string(), Utc::now())
            .expect("note");
        let receipt = local.delete_private_note(id).expect("delete");
        let note = &local.private_notes()[0];
        assert!(note.content().is_none());
        assert_eq!(receipt.deleted_content_digest, note.content_digest);
        assert!(local.validate().is_ok());
    }

    #[test]
    fn legacy_note_is_removed_from_messages_and_preserved_locally() {
        let mut messages = vec![
            serde_json::json!({
                "role": "system",
                "content": "[Note: seed-private-value]",
                "metadata": {"type": "note"}
            }),
            serde_json::json!({"role": "user", "content": "visible"}),
        ];
        let mut undo = Vec::new();
        let mut local = SessionLocalState::default();
        assert_eq!(
            migrate_legacy_private_notes(&mut messages, &mut undo, &mut local, Utc::now())
                .expect("migration"),
            1
        );
        assert_eq!(
            messages,
            vec![serde_json::json!({"role": "user", "content": "visible"})]
        );
        assert_eq!(
            local.private_notes()[0].content(),
            Some("seed-private-value")
        );
    }

    #[test]
    fn failed_legacy_note_migration_leaves_every_lane_unchanged() {
        let original_messages = vec![
            serde_json::json!({
                "role": "system",
                "content": "[Note: ]",
                "metadata": {"type": "note"}
            }),
            serde_json::json!({"role": "user", "content": "visible"}),
        ];
        let original_undo = vec![(
            serde_json::json!({"role": "user", "content": "undo user"}),
            serde_json::json!({"role": "assistant", "content": "undo assistant"}),
        )];
        let mut messages = original_messages.clone();
        let mut undo = original_undo.clone();
        let mut local = SessionLocalState::default();

        assert_eq!(
            migrate_legacy_private_notes(&mut messages, &mut undo, &mut local, Utc::now()),
            Err(LocalEventError::PrivateNoteEmpty)
        );
        assert_eq!(messages, original_messages);
        assert_eq!(undo, original_undo);
        assert!(local.is_empty());
    }
}
