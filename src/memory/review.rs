//! Host-authorized technical-lesson review transitions.
//!
//! Review is a causal metadata transition, not a confidence upgrade and never
//! an instruction grant. The canonical executor supplies an opaque consumed
//! one-use host approval; this module binds its redacted audit projection to
//! one exact lesson head and publishes the lesson, audit, and any linked source
//! projection in one SQLite transaction.

use anyhow::{Context as _, Result};
use rusqlite::{params, Connection, TransactionBehavior};
use serde::{Deserialize, Serialize};

use super::{
    technical_lesson_kind_name, ApplyRevisionOutcome, LessonReviewState, LogicalMemoryId,
    MemoryAttribution, MemoryDb, MemoryDigest, MemoryProvenance, MemoryRecordScope, MemoryRevision,
    MemoryRevisionState, MemorySourceEvidence, MemorySourceKind, TechnicalLesson,
    TechnicalLessonStoreError, WorkspaceMemoryId, TECHNICAL_LESSON_TAG,
};
use crate::permissions::HostApprovalEvidence;

/// Schema of the immutable receipt-audit payload stored in the causal graph.
pub const TECHNICAL_MEMORY_REVIEW_AUDIT_SCHEMA_VERSION: u32 = 1;
/// Exact tag identifying host-review audit roots; these are not lessons and do
/// not enter model retrieval.
pub const TECHNICAL_MEMORY_REVIEW_AUDIT_TAG: &str = "openclaudia:technical-memory-review-audit:v1";

const MAX_REVIEW_AUDIT_BYTES: usize = 16 * 1_024;
const REVIEW_SOURCE_PREFIX: &str = "host-review-receipt:";

/// Host-controlled review operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TechnicalLessonReviewAction {
    Review,
    Revoke,
}

impl TechnicalLessonReviewAction {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Review => "review",
            Self::Revoke => "revoke",
        }
    }

    const fn result_status(self) -> TechnicalLessonReviewStatus {
        match self {
            Self::Review => TechnicalLessonReviewStatus::Reviewed,
            Self::Revoke => TechnicalLessonReviewStatus::Revoked,
        }
    }
}

/// Truthful review mutation outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TechnicalLessonReviewStatus {
    Reviewed,
    Revoked,
    AlreadyReviewed,
    AlreadyCandidate,
    Idempotent,
}

/// Bounded result returned by the canonical review tool. Lesson prose is
/// intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TechnicalLessonReviewResult {
    pub status: TechnicalLessonReviewStatus,
    pub logical_id: LogicalMemoryId,
    pub previous_record_digest: MemoryDigest,
    pub record_digest: MemoryDigest,
    pub audit_record_digest: Option<MemoryDigest>,
    pub review: LessonReviewState,
    pub effectively_host_reviewed: bool,
}

pub struct TechnicalLessonReviewRequest<'a> {
    pub logical_id: LogicalMemoryId,
    pub expected_record_digest: MemoryDigest,
    pub action: TechnicalLessonReviewAction,
    pub approval: &'a HostApprovalEvidence,
    pub reviewed_at_unix_seconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TechnicalLessonReviewAudit {
    schema_version: u32,
    action: TechnicalLessonReviewAction,
    workspace_id: WorkspaceMemoryId,
    logical_id: LogicalMemoryId,
    expected_record_digest: MemoryDigest,
    resulting_record_digest: MemoryDigest,
    reviewed_at_unix_seconds: i64,
    authorization: HostApprovalEvidence,
}

#[derive(Clone, Copy)]
struct ReviewMutation<'a> {
    current: &'a MemoryRevision,
    lesson: &'a TechnicalLesson,
    workspace_id: &'a WorkspaceMemoryId,
    approval: &'a HostApprovalEvidence,
    action: TechnicalLessonReviewAction,
    reviewed_at_unix_seconds: i64,
}

impl MemoryDb {
    pub(super) fn validate_all_host_review_audits_on(
        conn: &Connection,
        workspace_id: &WorkspaceMemoryId,
    ) -> Result<()> {
        let mut statement = conn.prepare(
            r"SELECT revision.logical_id, revision.version,
                     revision.parent_digest, revision.record_digest,
                     revision.content_digest, revision.content,
                     revision.tags_json, revision.provenance_json,
                     revision.record_state,
                     revision.additional_parent_digests_json
                FROM memory_revisions revision
               WHERE EXISTS (
                   SELECT 1 FROM json_each(revision.tags_json) AS tag
                    WHERE tag.value = ?1
               )
               ORDER BY revision.record_digest",
        )?;
        let mut rows = statement.query(params![TECHNICAL_MEMORY_REVIEW_AUDIT_TAG])?;
        while let Some(row) = rows.next()? {
            let audit_revision = Self::revision_from_row(row)?;
            audit_revision.validate()?;
            anyhow::ensure!(
                audit_revision.version == super::MemoryVersion::INITIAL
                    && audit_revision.parent_digest.is_none()
                    && audit_revision.state == MemoryRevisionState::Active
                    && audit_revision.tags == [TECHNICAL_MEMORY_REVIEW_AUDIT_TAG.to_string()]
                    && audit_revision.provenance.workspace_id.as_deref()
                        == Some(workspace_id.as_str())
                    && audit_revision.provenance.scope == MemoryRecordScope::UserPrivate,
                "host-review audit root is invalid"
            );
            let audit = TechnicalLessonReviewAudit::decode(&audit_revision.content)?;
            anyhow::ensure!(
                audit.workspace_id == *workspace_id,
                "host-review audit belongs to a different workspace"
            );
            let reviewed_revision =
                Self::load_revision_by_digest(conn, &audit.resulting_record_digest)?
                    .context("host-review audit result revision is unavailable")?;
            let lesson = Self::validate_technical_lesson_revision(
                &reviewed_revision,
                workspace_id,
                MemoryRecordScope::UserPrivate,
            )?;
            audit.validate_for_revision(
                &reviewed_revision,
                &lesson,
                workspace_id,
                &audit_revision,
            )?;
        }
        Ok(())
    }

    /// Review or revoke one exact technical-lesson head using authority that
    /// the canonical permission executor already consumed.
    pub(crate) fn transition_technical_lesson_review(
        &self,
        request: &TechnicalLessonReviewRequest<'_>,
    ) -> Result<TechnicalLessonReviewResult> {
        let workspace_id = self
            .workspace_id
            .clone()
            .context("technical lessons require a workspace-bound store")?;
        let workspace_digest = self
            .approval_workspace_digest
            .as_deref()
            .ok_or(TechnicalLessonStoreError::ReviewApprovalInvalid)?;
        if request.approval.workspace_digest != workspace_digest {
            return Err(TechnicalLessonStoreError::ReviewApprovalInvalid.into());
        }
        let mut conn = self.lock_conn()?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .context("technical lesson review: failed to begin transaction")?;
        let result = Self::transition_technical_lesson_review_on(&tx, &workspace_id, request)?;
        tx.commit()
            .context("technical lesson review: committing review and audit")?;
        drop(conn);
        Ok(result)
    }

    fn transition_technical_lesson_review_on(
        conn: &Connection,
        workspace_id: &WorkspaceMemoryId,
        request: &TechnicalLessonReviewRequest<'_>,
    ) -> Result<TechnicalLessonReviewResult> {
        validate_approval_for_review(
            request.approval,
            request.action,
            request.logical_id,
            &request.expected_record_digest,
        )?;
        let heads = Self::head_digests(conn, request.logical_id)?;
        if heads.len() > 1 {
            return Err(TechnicalLessonStoreError::UnresolvedConflict.into());
        }
        let current = heads
            .first()
            .map(|digest| {
                Self::load_revision_by_digest(conn, digest)?
                    .context("technical lesson review head is missing")
            })
            .transpose()?
            .context("technical lesson is unavailable")?;
        if current.record_digest != request.expected_record_digest {
            return Self::existing_review_replay_on(conn, workspace_id, &current, request)?
                .context(TechnicalLessonStoreError::StaleRevision);
        }
        anyhow::ensure!(
            current.state == MemoryRevisionState::Active,
            "technical lesson is deleted"
        );
        let lesson = Self::validate_technical_lesson_revision(
            &current,
            workspace_id,
            MemoryRecordScope::UserPrivate,
        )?;
        Self::validate_host_review_audit_on(conn, &current, workspace_id)?;

        match (&lesson.review, request.action) {
            (LessonReviewState::HostReviewed { .. }, TechnicalLessonReviewAction::Review) => {
                return Ok(noop_result(
                    TechnicalLessonReviewStatus::AlreadyReviewed,
                    &current,
                    &lesson,
                    request.reviewed_at_unix_seconds,
                ));
            }
            (LessonReviewState::Candidate, TechnicalLessonReviewAction::Revoke) => {
                return Ok(noop_result(
                    TechnicalLessonReviewStatus::AlreadyCandidate,
                    &current,
                    &lesson,
                    request.reviewed_at_unix_seconds,
                ));
            }
            _ => {}
        }

        if request.action == TechnicalLessonReviewAction::Review
            && (lesson.is_expired_at(request.reviewed_at_unix_seconds)
                || lesson.is_due_for_review_at(request.reviewed_at_unix_seconds))
        {
            return Err(TechnicalLessonStoreError::ReviewIneligible.into());
        }
        let mutation = ReviewMutation {
            current: &current,
            lesson: &lesson,
            workspace_id,
            approval: request.approval,
            action: request.action,
            reviewed_at_unix_seconds: request.reviewed_at_unix_seconds,
        };
        Self::publish_review_mutation_on(conn, mutation)
    }

    fn publish_review_mutation_on(
        conn: &Connection,
        mutation: ReviewMutation<'_>,
    ) -> Result<TechnicalLessonReviewResult> {
        let ReviewMutation {
            current,
            lesson,
            workspace_id,
            approval,
            action,
            reviewed_at_unix_seconds,
        } = mutation;
        let receipt_logical_id = review_audit_logical_id(workspace_id, &approval.receipt_id);
        if !Self::head_digests(conn, receipt_logical_id)?.is_empty() {
            return Err(TechnicalLessonStoreError::ReviewReceiptReuse.into());
        }
        let source_member = Self::prepare_source_member_review_on(conn, workspace_id, current)?;
        let next_lesson = match action {
            TechnicalLessonReviewAction::Review => lesson.host_reviewed(
                current.record_digest.clone(),
                approval.receipt_id.clone(),
                reviewed_at_unix_seconds,
            )?,
            TechnicalLessonReviewAction::Revoke => {
                lesson.review_revoked(current.record_digest.clone())?
            }
        };
        let source_digest = review_authorization_digest(
            approval,
            action,
            current.logical_id,
            &current.record_digest,
        )?;
        let provenance = review_provenance(
            Self::store_id_on(conn)?,
            workspace_id,
            approval,
            action,
            source_digest,
        );
        Self::validate_technical_lesson_provenance(
            &provenance,
            workspace_id,
            MemoryRecordScope::UserPrivate,
        )?;
        let revision = current.successor(
            next_lesson.encode()?,
            vec![
                TECHNICAL_LESSON_TAG.to_string(),
                format!(
                    "technical-kind:{}",
                    technical_lesson_kind_name(next_lesson.kind)
                ),
            ],
            provenance.clone(),
        )?;
        let audit = TechnicalLessonReviewAudit {
            schema_version: TECHNICAL_MEMORY_REVIEW_AUDIT_SCHEMA_VERSION,
            action,
            workspace_id: workspace_id.clone(),
            logical_id: current.logical_id,
            expected_record_digest: current.record_digest.clone(),
            resulting_record_digest: revision.record_digest.clone(),
            reviewed_at_unix_seconds,
            authorization: approval.clone(),
        };
        audit.validate()?;
        let audit_revision = MemoryRevision::new_with_logical_id(
            receipt_logical_id,
            audit.encode()?,
            vec![TECHNICAL_MEMORY_REVIEW_AUDIT_TAG.to_string()],
            provenance,
        );

        let outcome =
            Self::apply_linear_revision_in_transaction(conn, &revision, &current.record_digest)?;
        if !matches!(
            outcome,
            ApplyRevisionOutcome::Advanced | ApplyRevisionOutcome::Idempotent
        ) {
            return Err(TechnicalLessonStoreError::ConcurrentMutation.into());
        }
        Self::apply_root_revision_in_transaction(conn, &audit_revision)?;
        Self::validate_host_review_audit_on(conn, &revision, workspace_id)?;
        if let Some(source_member) = source_member {
            Self::publish_source_member_review_on(
                conn,
                workspace_id,
                source_member,
                &revision,
                approval.actor_id.clone(),
            )?;
        }
        Ok(TechnicalLessonReviewResult {
            status: action.result_status(),
            logical_id: revision.logical_id,
            previous_record_digest: current.record_digest.clone(),
            record_digest: revision.record_digest,
            audit_record_digest: Some(audit_revision.record_digest),
            review: next_lesson.review.clone(),
            effectively_host_reviewed: next_lesson
                .is_effectively_host_reviewed_at(reviewed_at_unix_seconds),
        })
    }

    fn existing_review_replay_on(
        conn: &Connection,
        workspace_id: &WorkspaceMemoryId,
        current: &MemoryRevision,
        request: &TechnicalLessonReviewRequest<'_>,
    ) -> Result<Option<TechnicalLessonReviewResult>> {
        let expected_source = review_source_id(&request.approval.receipt_id);
        if current.state != MemoryRevisionState::Active
            || current.parent_digest.as_ref() != Some(&request.expected_record_digest)
            || current.provenance.source_id != expected_source
        {
            return Ok(None);
        }
        let lesson = Self::validate_technical_lesson_revision(
            current,
            workspace_id,
            MemoryRecordScope::UserPrivate,
        )?;
        Self::validate_host_review_audit_on(conn, current, workspace_id)?;
        let audit_revision =
            Self::load_review_audit_revision_on(conn, workspace_id, &request.approval.receipt_id)?;
        let audit = TechnicalLessonReviewAudit::decode(&audit_revision.content)?;
        if audit.action != request.action {
            return Err(TechnicalLessonStoreError::IdempotencyCollision.into());
        }
        if audit.authorization != *request.approval {
            return Err(TechnicalLessonStoreError::IdempotencyCollision.into());
        }
        if audit.expected_record_digest != request.expected_record_digest {
            return Err(TechnicalLessonStoreError::IdempotencyCollision.into());
        }
        Ok(Some(TechnicalLessonReviewResult {
            status: TechnicalLessonReviewStatus::Idempotent,
            logical_id: current.logical_id,
            previous_record_digest: request.expected_record_digest.clone(),
            record_digest: current.record_digest.clone(),
            audit_record_digest: Some(audit_revision.record_digest),
            review: lesson.review.clone(),
            effectively_host_reviewed: lesson
                .is_effectively_host_reviewed_at(request.reviewed_at_unix_seconds),
        }))
    }

    pub(super) fn validate_host_review_audit_on(
        conn: &Connection,
        revision: &MemoryRevision,
        workspace_id: &WorkspaceMemoryId,
    ) -> Result<()> {
        if revision.state != MemoryRevisionState::Active {
            return Ok(());
        }
        let lesson = TechnicalLesson::decode(&revision.content)?;
        let receipt_from_review = match &lesson.review {
            LessonReviewState::Candidate => None,
            LessonReviewState::HostReviewed { receipt_id, .. } => Some(receipt_id.as_str()),
        };
        let receipt_from_source = revision
            .provenance
            .source_id
            .strip_prefix(REVIEW_SOURCE_PREFIX);
        let Some(receipt_id) = receipt_from_review.or(receipt_from_source) else {
            return Ok(());
        };
        if receipt_from_review.is_some_and(|review| review != receipt_id)
            || receipt_from_source.is_some_and(|source| source != receipt_id)
        {
            return Err(TechnicalLessonStoreError::ReviewAuditInvalid.into());
        }
        let audit_revision = Self::load_review_audit_revision_on(conn, workspace_id, receipt_id)
            .map_err(|_| TechnicalLessonStoreError::ReviewAuditInvalid)?;
        let audit = TechnicalLessonReviewAudit::decode(&audit_revision.content)
            .map_err(|_| TechnicalLessonStoreError::ReviewAuditInvalid)?;
        audit
            .validate_for_revision(revision, &lesson, workspace_id, &audit_revision)
            .map_err(|_| TechnicalLessonStoreError::ReviewAuditInvalid.into())
    }

    /// Require this exact lesson revision to be a host-review transition, not
    /// merely a candidate revision for which no audit is required.
    pub(super) fn validate_host_review_transition_on(
        conn: &Connection,
        revision: &MemoryRevision,
        workspace_id: &WorkspaceMemoryId,
    ) -> Result<()> {
        if revision.provenance.source_kind != MemorySourceKind::Explicit
            || revision
                .provenance
                .source_id
                .strip_prefix(REVIEW_SOURCE_PREFIX)
                .is_none()
        {
            return Err(TechnicalLessonStoreError::ReviewAuditInvalid.into());
        }
        Self::validate_host_review_audit_on(conn, revision, workspace_id)
    }

    fn load_review_audit_revision_on(
        conn: &Connection,
        workspace_id: &WorkspaceMemoryId,
        receipt_id: &str,
    ) -> Result<MemoryRevision> {
        let logical_id = review_audit_logical_id(workspace_id, receipt_id);
        let heads = Self::head_digests(conn, logical_id)?;
        anyhow::ensure!(heads.len() == 1, "host-review receipt audit is unavailable");
        Self::load_revision_by_digest(conn, &heads[0])?
            .context("host-review receipt audit head is missing")
    }
}

impl TechnicalLessonReviewAudit {
    fn encode(&self) -> Result<String> {
        self.validate()?;
        let encoded = serde_json::to_string(self)?;
        anyhow::ensure!(
            encoded.len() <= MAX_REVIEW_AUDIT_BYTES,
            "host-review audit exceeds its byte budget"
        );
        Ok(encoded)
    }

    pub(super) fn decode(encoded: &str) -> Result<Self> {
        anyhow::ensure!(
            encoded.len() <= MAX_REVIEW_AUDIT_BYTES,
            "host-review audit exceeds its byte budget"
        );
        let audit: Self = serde_json::from_str(encoded)?;
        audit.validate()?;
        Ok(audit)
    }

    fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.schema_version == TECHNICAL_MEMORY_REVIEW_AUDIT_SCHEMA_VERSION
                && self.reviewed_at_unix_seconds >= 0,
            "host-review audit schema or timestamp is invalid"
        );
        validate_approval_for_review(
            &self.authorization,
            self.action,
            self.logical_id,
            &self.expected_record_digest,
        )?;
        anyhow::ensure!(
            self.authorization.receipt_id.parse::<uuid::Uuid>().is_ok(),
            "host-review receipt identity is invalid"
        );
        Ok(())
    }

    fn validate_for_revision(
        &self,
        revision: &MemoryRevision,
        lesson: &TechnicalLesson,
        workspace_id: &WorkspaceMemoryId,
        audit_revision: &MemoryRevision,
    ) -> Result<()> {
        self.validate()?;
        anyhow::ensure!(
            &self.workspace_id == workspace_id
                && self.logical_id == revision.logical_id
                && self.resulting_record_digest == revision.record_digest
                && revision.parent_digest.as_ref() == Some(&self.expected_record_digest)
                && review_source_id(&self.authorization.receipt_id)
                    == revision.provenance.source_id
                && revision.provenance.source_kind == MemorySourceKind::Explicit
                && revision.provenance.author_id == self.authorization.actor_id
                && revision.provenance.source_digest
                    == review_authorization_digest(
                        &self.authorization,
                        self.action,
                        self.logical_id,
                        &self.expected_record_digest,
                    )?
                && audit_revision.logical_id
                    == review_audit_logical_id(workspace_id, &self.authorization.receipt_id)
                && audit_revision.version == super::MemoryVersion::INITIAL
                && audit_revision.parent_digest.is_none()
                && audit_revision.state == MemoryRevisionState::Active
                && audit_revision.tags == [TECHNICAL_MEMORY_REVIEW_AUDIT_TAG.to_string()]
                && audit_revision.provenance == revision.provenance,
            "host-review audit does not match the causal revision"
        );
        match (self.action, &lesson.review) {
            (
                TechnicalLessonReviewAction::Review,
                LessonReviewState::HostReviewed {
                    receipt_id,
                    reviewed_at_unix_seconds,
                },
            ) => anyhow::ensure!(
                receipt_id == &self.authorization.receipt_id
                    && *reviewed_at_unix_seconds == self.reviewed_at_unix_seconds,
                "reviewed lesson does not match its host-review audit"
            ),
            (TechnicalLessonReviewAction::Revoke, LessonReviewState::Candidate) => {}
            _ => anyhow::bail!("lesson review state does not match its host-review audit"),
        }
        Ok(())
    }
}

fn noop_result(
    status: TechnicalLessonReviewStatus,
    current: &MemoryRevision,
    lesson: &TechnicalLesson,
    now_unix_seconds: i64,
) -> TechnicalLessonReviewResult {
    TechnicalLessonReviewResult {
        status,
        logical_id: current.logical_id,
        previous_record_digest: current.record_digest.clone(),
        record_digest: current.record_digest.clone(),
        audit_record_digest: None,
        review: lesson.review.clone(),
        effectively_host_reviewed: lesson.is_effectively_host_reviewed_at(now_unix_seconds),
    }
}

fn review_source_id(receipt_id: &str) -> String {
    format!("{REVIEW_SOURCE_PREFIX}{receipt_id}")
}

fn review_audit_logical_id(workspace_id: &WorkspaceMemoryId, receipt_id: &str) -> LogicalMemoryId {
    LogicalMemoryId::for_technical_source(
        workspace_id.as_str(),
        &format!("technical-review-audit:{receipt_id}"),
    )
}

fn review_authorization_digest(
    approval: &HostApprovalEvidence,
    action: TechnicalLessonReviewAction,
    logical_id: LogicalMemoryId,
    expected_record_digest: &MemoryDigest,
) -> Result<MemoryDigest> {
    let encoded = serde_json::to_vec(approval)?;
    Ok(MemoryDigest::for_fields(
        b"openclaudia.memory.host-review-authorization.v1",
        &[
            &encoded,
            action.as_str().as_bytes(),
            logical_id.to_string().as_bytes(),
            expected_record_digest.as_str().as_bytes(),
        ],
    ))
}

fn review_provenance(
    store_id: super::MemoryStoreId,
    workspace_id: &WorkspaceMemoryId,
    approval: &HostApprovalEvidence,
    action: TechnicalLessonReviewAction,
    source_digest: MemoryDigest,
) -> MemoryProvenance {
    MemoryProvenance::new(
        MemorySourceEvidence::new(
            MemorySourceKind::Explicit,
            review_source_id(&approval.receipt_id),
            format!(
                "host-review-v1:{}:policy-{}:capability-{}",
                action.as_str(),
                approval.host_policy_generation,
                approval.capability_generation
            ),
            source_digest,
        ),
        MemoryAttribution::new(
            approval.actor_id.clone(),
            Some(store_id),
            Some(workspace_id.to_string()),
        ),
        MemoryRecordScope::UserPrivate,
    )
}

fn validate_approval_for_review(
    approval: &HostApprovalEvidence,
    action: TechnicalLessonReviewAction,
    logical_id: LogicalMemoryId,
    expected_record_digest: &MemoryDigest,
) -> Result<()> {
    let arguments = serde_json::json!({
        "action": action.as_str(),
        "logical_id": logical_id.to_string(),
        "expected_record_digest": expected_record_digest.to_string(),
    });
    let valid = approval.schema_version == crate::permissions::APPROVAL_RECEIPT_SCHEMA_VERSION
        && approval.grant_kind == "one_use"
        && matches!(
            approval.provenance.as_str(),
            "interactive_user" | "acp_client" | "host_administrator"
        )
        && approval.binds_exact_call(
            "MemoryReview",
            "external_mutation",
            None,
            &logical_id.to_string(),
            &arguments,
        )
        && approval.workspace_generation > 0
        && approval.capability_generation > 0
        && approval.host_policy_generation > 0
        && approval.receipt_id.parse::<uuid::Uuid>().is_ok()
        && is_sha256_digest(&approval.scope_digest)
        && is_sha256_digest(&approval.evidence_digest)
        && is_sha256_digest(&approval.actor_id)
        && is_sha256_digest(&approval.workspace_digest)
        && is_sha256_digest(&approval.run_id_digest)
        && approval
            .session_id_digest
            .as_deref()
            .is_none_or(is_sha256_digest)
        && is_sha256_digest(&approval.target_digest)
        && is_sha256_digest(&approval.arguments_digest)
        && is_sha256_digest(&approval.tool_call_id_digest);
    if !valid {
        return Err(TechnicalLessonStoreError::ReviewApprovalInvalid.into());
    }
    Ok(())
}

fn is_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Arc;

    use serde_json::json;

    use super::*;
    use crate::memory::{
        LessonApplicability, LessonCitation, LessonCitationKind, LessonRetention,
        TechnicalLessonConfidence, TechnicalLessonDraft, TechnicalLessonKind,
        TechnicalLessonRecord, TechnicalLessonSensitivity,
    };
    use crate::permissions::{ApprovalProvenance, PermissionManager};
    use crate::state::SessionId;
    use crate::tools::{
        FunctionCall, ToolCall, ToolRunContext, WorkspaceAccess, HOST_SAFETY_POLICY_GENERATION,
    };

    struct Fixture {
        _host: tempfile::TempDir,
        _workspace: tempfile::TempDir,
        db: MemoryDb,
        run: Arc<ToolRunContext>,
    }

    fn fixture() -> Fixture {
        let host = tempfile::tempdir().expect("host home");
        let workspace = tempfile::tempdir().expect("workspace");
        let run = ToolRunContext::builder(SessionId::new(), workspace.path())
            .working_directory(workspace.path())
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::new())
            .workspace_access(WorkspaceAccess::ReadWrite)
            .process(false)
            .network(false)
            .secrets(false)
            .provider("memory-review-test")
            .build()
            .expect("run context");
        let db = MemoryDb::open_for_workspace(host.path(), workspace.path()).expect("memory db");
        Fixture {
            _host: host,
            _workspace: workspace,
            db,
            run,
        }
    }

    fn draft(label: &str, retention: LessonRetention) -> TechnicalLessonDraft {
        TechnicalLessonDraft {
            title: format!("Review invariant {label}"),
            kind: TechnicalLessonKind::Security,
            observation: "A consumed host receipt must bind the exact lesson transition."
                .to_string(),
            guidance: "Recompute the canonical target and arguments before mutation.".to_string(),
            applicability: LessonApplicability {
                paths: vec!["src/memory/review.rs".to_string()],
                symbols: vec!["MemoryDb::transition_technical_lesson_review".to_string()],
                ..LessonApplicability::default()
            },
            citations: vec![LessonCitation {
                kind: LessonCitationKind::Test,
                locator: "src/memory/review.rs".to_string(),
                source_version: format!("test:{label}"),
                digest: MemoryDigest::for_fields(b"review-test-citation-v1", &[label.as_bytes()]),
                line_start: Some(1),
                line_end: Some(1),
            }],
            confidence: TechnicalLessonConfidence::VerifiedByTest,
            sensitivity: TechnicalLessonSensitivity::Internal,
            retention,
        }
    }

    fn save_candidate(
        fixture: &Fixture,
        label: &str,
        retention: LessonRetention,
    ) -> TechnicalLessonRecord {
        fixture
            .db
            .save_technical_lesson_candidate(
                &draft(label, retention),
                MemorySourceEvidence::new(
                    MemorySourceKind::ToolOutcome,
                    format!("review-test:{label}"),
                    "test-generation".to_string(),
                    MemoryDigest::for_fields(b"review-test-source-v1", &[label.as_bytes()]),
                ),
                "test-agent".to_string(),
                10,
            )
            .expect("candidate")
    }

    fn review_call(
        action: TechnicalLessonReviewAction,
        logical_id: LogicalMemoryId,
        expected_record_digest: &MemoryDigest,
    ) -> ToolCall {
        ToolCall {
            id: uuid::Uuid::new_v4().to_string(),
            call_type: "function".to_string(),
            function: FunctionCall {
                name: "memory_review".to_string(),
                arguments: serde_json::to_string(&json!({
                    "action": action.as_str(),
                    "logical_id": logical_id,
                    "expected_record_digest": expected_record_digest,
                }))
                .expect("review arguments"),
            },
        }
    }

    fn approval(
        fixture: &Fixture,
        action: TechnicalLessonReviewAction,
        record: &TechnicalLessonRecord,
    ) -> HostApprovalEvidence {
        let call = review_call(action, record.logical_id, &record.record_digest);
        let manager = PermissionManager::unrestricted_for_run(&fixture.run);
        let permit = manager
            .approve_tool_call_once(
                &call,
                Some(fixture.run.session_id()),
                ApprovalProvenance::InteractiveUser,
            )
            .expect("one-use host approval");
        manager
            .consume_execution_permit(&permit, &call, Some(fixture.run.session_id()))
            .expect("consume approval")
            .host_approval_evidence(&fixture.run, HOST_SAFETY_POLICY_GENERATION)
            .expect("host evidence")
    }

    fn transition(
        fixture: &Fixture,
        record: &TechnicalLessonRecord,
        action: TechnicalLessonReviewAction,
        approval: &HostApprovalEvidence,
        now: i64,
    ) -> Result<TechnicalLessonReviewResult> {
        fixture
            .db
            .transition_technical_lesson_review(&TechnicalLessonReviewRequest {
                logical_id: record.logical_id,
                expected_record_digest: record.record_digest.clone(),
                action,
                approval,
                reviewed_at_unix_seconds: now,
            })
    }

    #[test]
    fn review_and_revoke_are_causal_without_confidence_upgrade() {
        let fixture = fixture();
        let candidate = save_candidate(&fixture, "causal", LessonRetention::Indefinite);
        let original_confidence = candidate.lesson.confidence;
        let original_capture = candidate.lesson.captured_at_unix_seconds;

        let review_approval = approval(&fixture, TechnicalLessonReviewAction::Review, &candidate);
        let reviewed = transition(
            &fixture,
            &candidate,
            TechnicalLessonReviewAction::Review,
            &review_approval,
            20,
        )
        .expect("review");
        assert_eq!(reviewed.status, TechnicalLessonReviewStatus::Reviewed);
        assert!(reviewed.effectively_host_reviewed);
        assert!(reviewed.audit_record_digest.is_some());

        let reviewed_record = fixture
            .db
            .query_technical_lessons(None, 20, 20)
            .expect("reviewed query")
            .records
            .pop()
            .expect("reviewed record");
        assert_eq!(reviewed_record.lesson.confidence, original_confidence);
        assert_eq!(
            reviewed_record.lesson.captured_at_unix_seconds,
            original_capture
        );
        assert!(reviewed_record.effectively_host_reviewed);

        let revoke_approval = approval(
            &fixture,
            TechnicalLessonReviewAction::Revoke,
            &reviewed_record,
        );
        let revoked = transition(
            &fixture,
            &reviewed_record,
            TechnicalLessonReviewAction::Revoke,
            &revoke_approval,
            30,
        )
        .expect("revoke");
        assert_eq!(revoked.status, TechnicalLessonReviewStatus::Revoked);
        assert_eq!(revoked.review, LessonReviewState::Candidate);
        assert!(!revoked.effectively_host_reviewed);
    }

    #[test]
    fn exact_authorized_replay_is_idempotent() {
        let fixture = fixture();
        let candidate = save_candidate(&fixture, "replay", LessonRetention::Indefinite);
        let evidence = approval(&fixture, TechnicalLessonReviewAction::Review, &candidate);
        let first = transition(
            &fixture,
            &candidate,
            TechnicalLessonReviewAction::Review,
            &evidence,
            20,
        )
        .expect("first review");
        let replay = transition(
            &fixture,
            &candidate,
            TechnicalLessonReviewAction::Review,
            &evidence,
            20,
        )
        .expect("review replay");
        assert_eq!(replay.status, TechnicalLessonReviewStatus::Idempotent);
        assert_eq!(replay.record_digest, first.record_digest);
        assert_eq!(replay.audit_record_digest, first.audit_record_digest);
    }

    #[test]
    fn exact_evidence_rejects_action_target_and_revision_substitution() {
        let fixture = fixture();
        let first = save_candidate(&fixture, "first", LessonRetention::Indefinite);
        let second = save_candidate(&fixture, "second", LessonRetention::Indefinite);
        let evidence = approval(&fixture, TechnicalLessonReviewAction::Review, &first);

        assert!(transition(
            &fixture,
            &first,
            TechnicalLessonReviewAction::Revoke,
            &evidence,
            20,
        )
        .is_err());
        assert!(transition(
            &fixture,
            &second,
            TechnicalLessonReviewAction::Review,
            &evidence,
            20,
        )
        .is_err());
        let wrong_revision = TechnicalLessonRecord {
            record_digest: second.record_digest,
            ..first
        };
        assert!(transition(
            &fixture,
            &wrong_revision,
            TechnicalLessonReviewAction::Review,
            &evidence,
            20,
        )
        .is_err());
        let records = fixture
            .db
            .query_technical_lessons(None, 20, 20)
            .expect("unchanged candidates")
            .records;
        assert_eq!(records.len(), 2);
        assert!(records
            .iter()
            .all(|record| record.lesson.review == LessonReviewState::Candidate));
    }

    #[test]
    fn due_and_expired_candidates_cannot_be_reviewed() {
        for (label, retention) in [
            ("due", LessonRetention::ReviewAfter { unix_seconds: 20 }),
            ("expired", LessonRetention::ExpireAfter { unix_seconds: 20 }),
        ] {
            let fixture = fixture();
            let candidate = save_candidate(&fixture, label, retention);
            let evidence = approval(&fixture, TechnicalLessonReviewAction::Review, &candidate);
            let error = transition(
                &fixture,
                &candidate,
                TechnicalLessonReviewAction::Review,
                &evidence,
                20,
            )
            .expect_err("retention gate");
            assert_eq!(
                error.downcast_ref::<TechnicalLessonStoreError>(),
                Some(&TechnicalLessonStoreError::ReviewIneligible)
            );
        }
    }

    #[test]
    fn preexisting_receipt_audit_rolls_back_lesson_mutation() {
        let fixture = fixture();
        let candidate = save_candidate(&fixture, "collision", LessonRetention::Indefinite);
        let evidence = approval(&fixture, TechnicalLessonReviewAction::Review, &candidate);
        let workspace_id = fixture.db.workspace_id().expect("workspace");
        let collision = MemoryRevision::new_with_logical_id(
            review_audit_logical_id(workspace_id, &evidence.receipt_id),
            "reserved receipt collision".to_string(),
            vec![TECHNICAL_MEMORY_REVIEW_AUDIT_TAG.to_string()],
            MemoryProvenance::new(
                MemorySourceEvidence::new(
                    MemorySourceKind::Explicit,
                    "test:receipt-collision".to_string(),
                    "test-generation".to_string(),
                    MemoryDigest::for_fields(b"review-collision-v1", &[b"collision"]),
                ),
                MemoryAttribution::new(
                    "test-host".to_string(),
                    Some(fixture.db.store_id().expect("store")),
                    Some(workspace_id.to_string()),
                ),
                MemoryRecordScope::UserPrivate,
            ),
        );
        {
            let conn = fixture.db.lock_conn().expect("memory connection");
            MemoryDb::apply_root_revision_in_transaction(&conn, &collision)
                .expect("simulate preexisting corrupt collision");
        }

        let error = transition(
            &fixture,
            &candidate,
            TechnicalLessonReviewAction::Review,
            &evidence,
            20,
        )
        .expect_err("receipt reuse");
        assert_eq!(
            error.downcast_ref::<TechnicalLessonStoreError>(),
            Some(&TechnicalLessonStoreError::ReviewReceiptReuse)
        );
        let unchanged = fixture
            .db
            .revision_heads(candidate.logical_id)
            .expect("candidate head");
        assert_eq!(unchanged.len(), 1);
        assert_eq!(unchanged[0].record_digest, candidate.record_digest);
    }

    #[test]
    fn generic_revision_api_cannot_inject_review_authority_or_audit_roots() {
        let fixture = fixture();
        let candidate = save_candidate(&fixture, "generic-injection", LessonRetention::Indefinite);
        let evidence = approval(&fixture, TechnicalLessonReviewAction::Review, &candidate);
        let workspace_id = fixture.db.workspace_id().expect("workspace");
        let reviewed_lesson = candidate
            .lesson
            .host_reviewed(
                candidate.record_digest.clone(),
                evidence.receipt_id.clone(),
                20,
            )
            .expect("reviewed lesson");
        let source_digest = review_authorization_digest(
            &evidence,
            TechnicalLessonReviewAction::Review,
            candidate.logical_id,
            &candidate.record_digest,
        )
        .expect("authorization digest");
        let provenance = review_provenance(
            fixture.db.store_id().expect("store"),
            workspace_id,
            &evidence,
            TechnicalLessonReviewAction::Review,
            source_digest,
        );
        let current = fixture
            .db
            .revision_heads(candidate.logical_id)
            .expect("candidate head")
            .pop()
            .expect("candidate revision");
        let forged_review = current
            .successor(
                reviewed_lesson.encode().expect("review content"),
                vec![
                    TECHNICAL_LESSON_TAG.to_string(),
                    format!(
                        "technical-kind:{}",
                        technical_lesson_kind_name(reviewed_lesson.kind)
                    ),
                ],
                provenance.clone(),
            )
            .expect("forged review revision");
        let review_error = fixture
            .db
            .apply_revision(&forged_review)
            .expect_err("generic review injection must fail");
        assert!(review_error
            .to_string()
            .contains("authenticated review transaction"));

        let forged_audit = MemoryRevision::new_with_logical_id(
            review_audit_logical_id(workspace_id, &evidence.receipt_id),
            "{}".to_string(),
            vec![TECHNICAL_MEMORY_REVIEW_AUDIT_TAG.to_string()],
            provenance,
        );
        let audit_error = fixture
            .db
            .apply_revision(&forged_audit)
            .expect_err("generic audit injection must fail");
        assert!(audit_error
            .to_string()
            .contains("authenticated review transaction"));
        assert_eq!(
            fixture
                .db
                .revision_heads(candidate.logical_id)
                .expect("unchanged candidate")
                .pop()
                .expect("candidate head")
                .record_digest,
            candidate.record_digest
        );
    }

    #[test]
    fn tampered_authorization_projection_fails_before_mutation() {
        let fixture = fixture();
        let candidate = save_candidate(&fixture, "evidence-tamper", LessonRetention::Indefinite);
        let evidence = approval(&fixture, TechnicalLessonReviewAction::Review, &candidate);

        let mut changed_run = evidence.clone();
        changed_run.run_id_digest =
            MemoryDigest::for_fields(b"changed-run-v1", &[b"other"]).to_string();
        let changed_run_error = transition(
            &fixture,
            &candidate,
            TechnicalLessonReviewAction::Review,
            &changed_run,
            20,
        )
        .expect_err("changed run evidence must fail");
        assert_eq!(
            changed_run_error.downcast_ref::<TechnicalLessonStoreError>(),
            Some(&TechnicalLessonStoreError::ReviewApprovalInvalid)
        );

        let mut changed_policy = evidence;
        changed_policy.host_policy_generation += 1;
        let changed_policy_error = transition(
            &fixture,
            &candidate,
            TechnicalLessonReviewAction::Review,
            &changed_policy,
            20,
        )
        .expect_err("changed policy evidence must fail");
        assert_eq!(
            changed_policy_error.downcast_ref::<TechnicalLessonStoreError>(),
            Some(&TechnicalLessonStoreError::ReviewApprovalInvalid)
        );
        assert_eq!(
            fixture
                .db
                .revision_heads(candidate.logical_id)
                .expect("unchanged candidate")
                .pop()
                .expect("candidate head")
                .record_digest,
            candidate.record_digest
        );
    }

    #[test]
    fn reopening_fails_closed_when_review_audit_is_tampered() {
        let fixture = fixture();
        let candidate = save_candidate(&fixture, "tamper", LessonRetention::Indefinite);
        let evidence = approval(&fixture, TechnicalLessonReviewAction::Review, &candidate);
        transition(
            &fixture,
            &candidate,
            TechnicalLessonReviewAction::Review,
            &evidence,
            20,
        )
        .expect("review");
        let path = fixture.db.path().to_path_buf();
        drop(fixture.db);
        let conn = rusqlite::Connection::open(&path).expect("raw database");
        let changed = conn
            .execute(
                "UPDATE memory_revisions SET content = '{}' WHERE tags_json = ?1",
                [
                    serde_json::to_string(&vec![TECHNICAL_MEMORY_REVIEW_AUDIT_TAG])
                        .expect("audit tag"),
                ],
            )
            .expect("tamper audit");
        assert_eq!(changed, 1);
        drop(conn);
        assert!(MemoryDb::open(&path).is_err());
    }

    #[test]
    fn reopening_fails_closed_when_review_audit_head_is_missing() {
        let fixture = fixture();
        let candidate = save_candidate(&fixture, "missing-audit", LessonRetention::Indefinite);
        let evidence = approval(&fixture, TechnicalLessonReviewAction::Review, &candidate);
        transition(
            &fixture,
            &candidate,
            TechnicalLessonReviewAction::Review,
            &evidence,
            20,
        )
        .expect("review");
        let workspace_id = fixture.db.workspace_id().expect("workspace").clone();
        let audit_logical_id = review_audit_logical_id(&workspace_id, &evidence.receipt_id);
        let path = fixture.db.path().to_path_buf();
        drop(fixture.db);
        let conn = rusqlite::Connection::open(&path).expect("raw database");
        let removed = conn
            .execute(
                "DELETE FROM memory_heads WHERE logical_id = ?1",
                [audit_logical_id.to_string()],
            )
            .expect("remove audit head");
        assert_eq!(removed, 1);
        drop(conn);
        assert!(MemoryDb::open(&path).is_err());
    }
}
