//! Strict, codebase-specific technical-lesson records.
//!
//! A technical lesson is not a transcript, scratchpad, prompt fragment, or
//! user-profile blob.  It is a bounded claim about one exact workspace, with
//! applicability metadata and at least one digest-bound citation.  Persisted
//! values are always decoded through [`TechnicalLesson::decode`] and remain
//! untrusted reference evidence when returned to a model.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};

use super::{LogicalMemoryId, MemoryDigest, MemoryRecordScope, MemorySourceEvidence};

/// Exact schema understood by this build.
pub const TECHNICAL_LESSON_SCHEMA_VERSION: u32 = 1;
/// Exact archival tag used to distinguish typed lessons from legacy prose.
pub const TECHNICAL_LESSON_TAG: &str = "openclaudia:technical-lesson:v1";

pub const MAX_LESSON_TITLE_BYTES: usize = 160;
pub const MAX_LESSON_OBSERVATION_BYTES: usize = 2_048;
pub const MAX_LESSON_GUIDANCE_BYTES: usize = 2_048;
pub const MAX_LESSON_CORRECTION_BYTES: usize = 512;
pub const MAX_LESSON_LOCATOR_BYTES: usize = 1_024;
pub const MAX_LESSON_VERSION_BYTES: usize = 160;
pub const MAX_LESSON_APPLICABILITY_ITEMS: usize = 32;
pub const MAX_LESSON_CITATIONS: usize = 32;
pub const MAX_LESSON_ITEM_BYTES: usize = 256;
pub const MAX_TECHNICAL_LESSON_BYTES: usize = 32 * 1_024;
pub const MAX_TECHNICAL_LESSONS_PER_STORE: usize = 4_096;
/// Maximum JSON bytes returned by one technical-memory query envelope.
pub const MAX_TECHNICAL_QUERY_RESULT_BYTES: usize = 64 * 1_024;

/// Stable host-derived identity for one canonical workspace root.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WorkspaceMemoryId(String);

impl WorkspaceMemoryId {
    /// Derive a stable identifier without exposing the host path.
    #[must_use]
    pub fn for_canonical_root(root: &std::path::Path) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"openclaudia.workspace-memory.v1\0");
        hasher.update(root.as_os_str().as_encoded_bytes());
        let digest: [u8; 32] = hasher.finalize().into();
        let mut encoded = String::with_capacity(64);
        for byte in digest {
            use fmt::Write as _;
            let _ = write!(encoded, "{byte:02x}");
        }
        Self(format!("workspace-sha256:{encoded}"))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Filesystem-safe digest component without the type prefix.
    ///
    /// # Panics
    ///
    /// Panics only if this type's private constructor invariant is violated;
    /// every constructor and deserializer installs the fixed prefix.
    #[must_use]
    pub fn path_component(&self) -> &str {
        self.0
            .strip_prefix("workspace-sha256:")
            .expect("WorkspaceMemoryId is constructed with its fixed prefix")
    }
}

impl fmt::Display for WorkspaceMemoryId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl FromStr for WorkspaceMemoryId {
    type Err = TechnicalLessonError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let Some(hex) = value.strip_prefix("workspace-sha256:") else {
            return Err(TechnicalLessonError::InvalidWorkspaceId);
        };
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(TechnicalLessonError::InvalidWorkspaceId);
        }
        Ok(Self(value.to_string()))
    }
}

impl Serialize for WorkspaceMemoryId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for WorkspaceMemoryId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Technical category of the lesson.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TechnicalLessonKind {
    Architecture,
    Build,
    Compatibility,
    Configuration,
    Debugging,
    Dependency,
    Operational,
    Performance,
    Security,
    Testing,
    Tooling,
}

/// Strength of the cited observation. This is evidence classification, not
/// instruction authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TechnicalLessonConfidence {
    ObservedOnce,
    Reproduced,
    VerifiedByTest,
}

/// Data handling classification for the lesson payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TechnicalLessonSensitivity {
    Internal,
    Confidential,
}

/// Kind of exact artifact or receipt cited by a lesson.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LessonCitationKind {
    BuildReceipt,
    CommandReceipt,
    Commit,
    Configuration,
    Documentation,
    Issue,
    SourceFile,
    Test,
    ToolResult,
}

/// One digest-bound source observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LessonCitation {
    pub kind: LessonCitationKind,
    pub locator: String,
    pub source_version: String,
    pub digest: MemoryDigest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_start: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_end: Option<u32>,
}

/// Exact codebase surfaces to which a lesson applies.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LessonApplicability {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub symbols: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub environments: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

/// Retention policy carried by the record rather than inferred from age.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "policy", rename_all = "snake_case", deny_unknown_fields)]
pub enum LessonRetention {
    Indefinite,
    ReviewAfter { unix_seconds: i64 },
    ExpireAfter { unix_seconds: i64 },
}

/// Explicit review/consent state. Model tool calls create candidates only;
/// callers cannot self-assert host review in tool arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum LessonReviewState {
    Candidate,
    HostReviewed {
        receipt_id: String,
        reviewed_at_unix_seconds: i64,
    },
}

/// Causal correction metadata for a successor lesson.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LessonCorrection {
    pub corrected_record_digest: MemoryDigest,
    pub reason: String,
}

/// Model-facing capture input. Host-derived identity, review state, source
/// actor, capture time, and correction metadata are deliberately absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TechnicalLessonDraft {
    pub title: String,
    pub kind: TechnicalLessonKind,
    pub observation: String,
    pub guidance: String,
    pub applicability: LessonApplicability,
    pub citations: Vec<LessonCitation>,
    pub confidence: TechnicalLessonConfidence,
    pub sensitivity: TechnicalLessonSensitivity,
    pub retention: LessonRetention,
}

/// One compare-and-swap correction request. Grouping the causal identity,
/// replacement evidence, and host attribution prevents callers from omitting
/// part of the mutation contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TechnicalLessonCorrectionRequest {
    pub logical_id: LogicalMemoryId,
    pub expected_record_digest: MemoryDigest,
    pub replacement: TechnicalLessonDraft,
    pub correction_reason: String,
    pub source: MemorySourceEvidence,
    pub author_id: String,
    pub captured_at_unix_seconds: i64,
}

/// Strict persisted lesson envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TechnicalLesson {
    pub schema_version: u32,
    pub workspace_id: WorkspaceMemoryId,
    pub title: String,
    pub kind: TechnicalLessonKind,
    pub observation: String,
    pub guidance: String,
    pub applicability: LessonApplicability,
    pub citations: Vec<LessonCitation>,
    pub confidence: TechnicalLessonConfidence,
    pub sensitivity: TechnicalLessonSensitivity,
    pub retention: LessonRetention,
    pub review: LessonReviewState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correction: Option<LessonCorrection>,
    pub captured_at_unix_seconds: i64,
}

impl TechnicalLesson {
    /// Bind a validated draft to host-derived workspace and consent metadata.
    ///
    /// # Errors
    ///
    /// Returns an error when any lesson field, citation, applicability item,
    /// timestamp, or retention policy violates the current strict schema.
    pub fn from_candidate(
        workspace_id: WorkspaceMemoryId,
        mut draft: TechnicalLessonDraft,
        captured_at_unix_seconds: i64,
    ) -> Result<Self, TechnicalLessonError> {
        canonicalize_applicability(&mut draft.applicability);
        canonicalize_citations(&mut draft.citations);
        let lesson = Self {
            schema_version: TECHNICAL_LESSON_SCHEMA_VERSION,
            workspace_id,
            title: draft.title,
            kind: draft.kind,
            observation: draft.observation,
            guidance: draft.guidance,
            applicability: draft.applicability,
            citations: draft.citations,
            confidence: draft.confidence,
            sensitivity: draft.sensitivity,
            retention: draft.retention,
            review: LessonReviewState::Candidate,
            correction: None,
            captured_at_unix_seconds,
        };
        lesson.validate()?;
        Ok(lesson)
    }

    /// Create a successor payload while retaining exact workspace identity.
    ///
    /// # Errors
    ///
    /// Returns an error when the replacement or correction metadata violates
    /// the current strict lesson schema.
    pub fn corrected(
        &self,
        mut replacement: TechnicalLessonDraft,
        corrected_record_digest: MemoryDigest,
        reason: String,
        captured_at_unix_seconds: i64,
    ) -> Result<Self, TechnicalLessonError> {
        canonicalize_applicability(&mut replacement.applicability);
        canonicalize_citations(&mut replacement.citations);
        let lesson = Self {
            schema_version: TECHNICAL_LESSON_SCHEMA_VERSION,
            workspace_id: self.workspace_id.clone(),
            title: replacement.title,
            kind: replacement.kind,
            observation: replacement.observation,
            guidance: replacement.guidance,
            applicability: replacement.applicability,
            citations: replacement.citations,
            confidence: replacement.confidence,
            sensitivity: replacement.sensitivity,
            retention: replacement.retention,
            review: LessonReviewState::Candidate,
            correction: Some(LessonCorrection {
                corrected_record_digest,
                reason,
            }),
            captured_at_unix_seconds,
        };
        lesson.validate()?;
        Ok(lesson)
    }

    /// Recreate an active lesson after an exact causal tombstone.
    ///
    /// Source refresh uses this only when the stable manifest identity is
    /// reintroduced after an explicit prune. The new payload remains a
    /// candidate and names the tombstone as its exact predecessor.
    ///
    /// # Errors
    ///
    /// Returns an error when the replacement, reason, timestamp, or
    /// workspace-bound lesson violates the strict lesson schema.
    pub fn restored(
        workspace_id: WorkspaceMemoryId,
        mut replacement: TechnicalLessonDraft,
        tombstone_digest: MemoryDigest,
        reason: String,
        captured_at_unix_seconds: i64,
    ) -> Result<Self, TechnicalLessonError> {
        canonicalize_applicability(&mut replacement.applicability);
        canonicalize_citations(&mut replacement.citations);
        let lesson = Self {
            schema_version: TECHNICAL_LESSON_SCHEMA_VERSION,
            workspace_id,
            title: replacement.title,
            kind: replacement.kind,
            observation: replacement.observation,
            guidance: replacement.guidance,
            applicability: replacement.applicability,
            citations: replacement.citations,
            confidence: replacement.confidence,
            sensitivity: replacement.sensitivity,
            retention: replacement.retention,
            review: LessonReviewState::Candidate,
            correction: Some(LessonCorrection {
                corrected_record_digest: tombstone_digest,
                reason,
            }),
            captured_at_unix_seconds,
        };
        lesson.validate()?;
        Ok(lesson)
    }

    /// Create a causal successor that marks this exact evidence revision as
    /// host reviewed. Content, confidence, applicability, and capture time are
    /// preserved; review changes authority metadata only.
    ///
    /// # Errors
    ///
    /// Returns an error when the receipt/timestamp or resulting lesson is
    /// invalid.
    pub fn host_reviewed(
        &self,
        reviewed_record_digest: MemoryDigest,
        receipt_id: String,
        reviewed_at_unix_seconds: i64,
    ) -> Result<Self, TechnicalLessonError> {
        let mut reviewed = self.clone();
        reviewed.review = LessonReviewState::HostReviewed {
            receipt_id,
            reviewed_at_unix_seconds,
        };
        reviewed.correction = Some(LessonCorrection {
            corrected_record_digest: reviewed_record_digest,
            reason: "host reviewed this exact technical-lesson revision".to_string(),
        });
        reviewed.validate()?;
        Ok(reviewed)
    }

    /// Create a candidate successor that revokes host review without changing
    /// the technical claim or pretending it was freshly captured.
    ///
    /// # Errors
    ///
    /// Returns an error when the resulting causal metadata is invalid.
    pub fn review_revoked(
        &self,
        reviewed_record_digest: MemoryDigest,
    ) -> Result<Self, TechnicalLessonError> {
        let mut revoked = self.clone();
        revoked.review = LessonReviewState::Candidate;
        revoked.correction = Some(LessonCorrection {
            corrected_record_digest: reviewed_record_digest,
            reason: "host review was explicitly revoked".to_string(),
        });
        revoked.validate()?;
        Ok(revoked)
    }

    /// Project the host-bound record back to its canonical source draft.
    #[must_use]
    pub fn draft(&self) -> TechnicalLessonDraft {
        TechnicalLessonDraft {
            title: self.title.clone(),
            kind: self.kind,
            observation: self.observation.clone(),
            guidance: self.guidance.clone(),
            applicability: self.applicability.clone(),
            citations: self.citations.clone(),
            confidence: self.confidence,
            sensitivity: self.sensitivity,
            retention: self.retention.clone(),
        }
    }

    /// Encode the canonical struct field order used as revision content.
    ///
    /// # Errors
    ///
    /// Returns an error when the lesson is invalid or exceeds the record budget.
    pub fn encode(&self) -> Result<String, TechnicalLessonError> {
        self.validate()?;
        let encoded =
            serde_json::to_string(self).map_err(|_| TechnicalLessonError::InvalidEncoding)?;
        if encoded.len() > MAX_TECHNICAL_LESSON_BYTES {
            return Err(TechnicalLessonError::RecordTooLarge);
        }
        Ok(encoded)
    }

    /// Strictly decode and revalidate one persisted typed lesson.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid JSON, unknown fields, unsupported versions,
    /// non-canonical collections, or any bounded-field violation.
    pub fn decode(encoded: &str) -> Result<Self, TechnicalLessonError> {
        if encoded.len() > MAX_TECHNICAL_LESSON_BYTES {
            return Err(TechnicalLessonError::RecordTooLarge);
        }
        let lesson: Self =
            serde_json::from_str(encoded).map_err(|_| TechnicalLessonError::InvalidEncoding)?;
        lesson.validate()?;
        Ok(lesson)
    }

    /// Validate all bounds, canonical ordering, timestamps, and line ranges.
    ///
    /// # Errors
    ///
    /// Returns the exact schema violation found in this lesson.
    pub fn validate(&self) -> Result<(), TechnicalLessonError> {
        if self.schema_version != TECHNICAL_LESSON_SCHEMA_VERSION {
            return Err(TechnicalLessonError::UnsupportedSchema);
        }
        validate_single_line_text(&self.title, MAX_LESSON_TITLE_BYTES, "title")?;
        validate_text(
            &self.observation,
            MAX_LESSON_OBSERVATION_BYTES,
            "observation",
        )?;
        validate_text(&self.guidance, MAX_LESSON_GUIDANCE_BYTES, "guidance")?;
        if self.captured_at_unix_seconds < 0 {
            return Err(TechnicalLessonError::InvalidTimestamp);
        }
        validate_retention(&self.retention, self.captured_at_unix_seconds)?;
        validate_review(&self.review, self.captured_at_unix_seconds)?;
        if let Some(correction) = &self.correction {
            validate_single_line_text(
                &correction.reason,
                MAX_LESSON_CORRECTION_BYTES,
                "correction reason",
            )?;
        }
        validate_applicability(&self.applicability)?;
        if self.citations.is_empty() || self.citations.len() > MAX_LESSON_CITATIONS {
            return Err(TechnicalLessonError::InvalidCitationCount);
        }
        if !is_canonical_citations(&self.citations) {
            return Err(TechnicalLessonError::NonCanonicalCollection);
        }
        for citation in &self.citations {
            validate_single_line_text(
                &citation.locator,
                MAX_LESSON_LOCATOR_BYTES,
                "citation locator",
            )?;
            validate_single_line_text(
                &citation.source_version,
                MAX_LESSON_VERSION_BYTES,
                "citation source version",
            )?;
            match (citation.line_start, citation.line_end) {
                (None, None) => {}
                (Some(start), Some(end)) if start > 0 && end >= start => {}
                _ => return Err(TechnicalLessonError::InvalidLineRange),
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn is_expired_at(&self, now_unix_seconds: i64) -> bool {
        matches!(
            self.retention,
            LessonRetention::ExpireAfter { unix_seconds } if unix_seconds <= now_unix_seconds
        )
    }

    #[must_use]
    pub const fn is_due_for_review_at(&self, now_unix_seconds: i64) -> bool {
        matches!(
            self.retention,
            LessonRetention::ReviewAfter { unix_seconds } if unix_seconds <= now_unix_seconds
        )
    }

    /// Whether host review is currently effective after retention gates.
    #[must_use]
    pub const fn is_effectively_host_reviewed_at(&self, now_unix_seconds: i64) -> bool {
        matches!(self.review, LessonReviewState::HostReviewed { .. })
            && !self.is_expired_at(now_unix_seconds)
            && !self.is_due_for_review_at(now_unix_seconds)
    }

    /// Search projection. It contains technical fields only, never provenance
    /// wrappers or arbitrary surrounding transcript text.
    #[must_use]
    pub fn search_projection(&self) -> String {
        let mut fields = vec![
            self.title.as_str(),
            self.observation.as_str(),
            self.guidance.as_str(),
        ];
        fields.extend(self.applicability.paths.iter().map(String::as_str));
        fields.extend(self.applicability.symbols.iter().map(String::as_str));
        fields.extend(self.applicability.components.iter().map(String::as_str));
        fields.extend(self.applicability.environments.iter().map(String::as_str));
        fields.extend(self.applicability.tags.iter().map(String::as_str));
        fields.join("\n")
    }
}

/// One typed lesson returned with its immutable record identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TechnicalLessonRecord {
    pub logical_id: super::LogicalMemoryId,
    pub version: super::MemoryVersion,
    pub record_digest: MemoryDigest,
    pub scope: MemoryRecordScope,
    /// Host-bound source, actor, store, workspace, and generation metadata.
    /// It describes provenance only and grants no instruction authority.
    pub provenance: super::MemoryProvenance,
    pub conflicted: bool,
    pub due_for_review: bool,
    /// False for candidates and whenever expiry/review-after policy makes a
    /// prior review stale.
    pub effectively_host_reviewed: bool,
    pub lesson: TechnicalLesson,
}

/// Truthful bounded retrieval state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TechnicalLessonQueryStatus {
    Complete,
    NoHit,
    Partial,
    Stale,
}

/// Bounded typed retrieval envelope returned by the canonical tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TechnicalLessonQueryResult {
    pub schema_version: u32,
    pub workspace_id: WorkspaceMemoryId,
    pub authority: &'static str,
    pub status: TechnicalLessonQueryStatus,
    pub query: Option<String>,
    pub retrieval: super::TechnicalRetrievalTrace,
    pub records: Vec<TechnicalLessonRecord>,
    pub omitted_expired: usize,
    pub omitted_conflicted: usize,
    /// True when bounded scan or output work omitted otherwise eligible rows.
    pub truncated_by_budget: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TechnicalLessonError {
    #[error("invalid workspace memory identity")]
    InvalidWorkspaceId,
    #[error("unsupported technical lesson schema")]
    UnsupportedSchema,
    #[error("technical lesson encoding is invalid")]
    InvalidEncoding,
    #[error("technical lesson exceeds its byte budget")]
    RecordTooLarge,
    #[error("technical lesson {field} is empty, oversized, or contains disallowed controls")]
    InvalidText { field: &'static str },
    #[error("technical lesson requires one bounded applicability surface")]
    MissingApplicability,
    #[error("technical lesson applicability exceeds its item budget")]
    ApplicabilityTooLarge,
    #[error("technical lesson citation count is invalid")]
    InvalidCitationCount,
    #[error("technical lesson citation line range is invalid")]
    InvalidLineRange,
    #[error("technical lesson timestamp is invalid")]
    InvalidTimestamp,
    #[error("technical lesson collection is not canonical")]
    NonCanonicalCollection,
}

/// Concurrency failures surfaced by technical-lesson mutations. Keeping these
/// typed lets the tool boundary return `Conflict` without parsing error prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TechnicalLessonStoreError {
    #[error("technical lesson invocation was reused with different evidence")]
    IdempotencyCollision,
    #[error("technical lesson has unresolved causal conflicts")]
    UnresolvedConflict,
    #[error("technical lesson changed since the expected revision")]
    StaleRevision,
    #[error("technical lesson mutation did not become the sole causal head")]
    ConcurrentMutation,
    #[error("host approval receipt was already used for another memory transition")]
    ReviewReceiptReuse,
    #[error("technical lesson is expired or already due for review")]
    ReviewIneligible,
    #[error("technical lesson host-review audit is missing or inconsistent")]
    ReviewAuditInvalid,
    #[error("host approval is not bound to this technical-memory workspace")]
    ReviewApprovalInvalid,
}

fn validate_text(
    value: &str,
    max_bytes: usize,
    field: &'static str,
) -> Result<(), TechnicalLessonError> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed != value
        || value.len() > max_bytes
        || value
            .chars()
            .any(|ch| ch.is_control() && ch != '\n' && ch != '\t')
    {
        return Err(TechnicalLessonError::InvalidText { field });
    }
    Ok(())
}

fn validate_single_line_text(
    value: &str,
    max_bytes: usize,
    field: &'static str,
) -> Result<(), TechnicalLessonError> {
    validate_text(value, max_bytes, field)?;
    if value.contains(['\n', '\r', '\t']) {
        return Err(TechnicalLessonError::InvalidText { field });
    }
    Ok(())
}

const fn validate_retention(
    retention: &LessonRetention,
    captured_at: i64,
) -> Result<(), TechnicalLessonError> {
    let timestamp = match retention {
        LessonRetention::Indefinite => return Ok(()),
        LessonRetention::ReviewAfter { unix_seconds }
        | LessonRetention::ExpireAfter { unix_seconds } => *unix_seconds,
    };
    if timestamp <= captured_at {
        return Err(TechnicalLessonError::InvalidTimestamp);
    }
    Ok(())
}

fn validate_review(
    review: &LessonReviewState,
    captured_at: i64,
) -> Result<(), TechnicalLessonError> {
    if let LessonReviewState::HostReviewed {
        receipt_id,
        reviewed_at_unix_seconds,
    } = review
    {
        validate_single_line_text(receipt_id, MAX_LESSON_ITEM_BYTES, "review receipt")?;
        if uuid::Uuid::parse_str(receipt_id).is_err() {
            return Err(TechnicalLessonError::InvalidText {
                field: "review receipt",
            });
        }
        if *reviewed_at_unix_seconds < captured_at {
            return Err(TechnicalLessonError::InvalidTimestamp);
        }
    }
    Ok(())
}

fn validate_applicability(applicability: &LessonApplicability) -> Result<(), TechnicalLessonError> {
    let collections = [
        &applicability.paths,
        &applicability.symbols,
        &applicability.components,
        &applicability.environments,
        &applicability.tags,
    ];
    let count = collections.iter().map(|items| items.len()).sum::<usize>();
    if count == 0 {
        return Err(TechnicalLessonError::MissingApplicability);
    }
    if count > MAX_LESSON_APPLICABILITY_ITEMS {
        return Err(TechnicalLessonError::ApplicabilityTooLarge);
    }
    for items in collections {
        if !is_sorted_unique(items) {
            return Err(TechnicalLessonError::NonCanonicalCollection);
        }
        for item in items {
            validate_single_line_text(item, MAX_LESSON_ITEM_BYTES, "applicability item")?;
        }
    }
    for path in &applicability.paths {
        let parsed = std::path::Path::new(path);
        if parsed.is_absolute()
            || parsed
                .components()
                .any(|component| !matches!(component, std::path::Component::Normal(_)))
        {
            return Err(TechnicalLessonError::InvalidText {
                field: "applicability path",
            });
        }
    }
    Ok(())
}

fn canonicalize_applicability(applicability: &mut LessonApplicability) {
    for items in [
        &mut applicability.paths,
        &mut applicability.symbols,
        &mut applicability.components,
        &mut applicability.environments,
        &mut applicability.tags,
    ] {
        items.sort();
        items.dedup();
    }
}

fn canonicalize_citations(citations: &mut Vec<LessonCitation>) {
    citations.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.locator.cmp(&right.locator))
            .then_with(|| left.source_version.cmp(&right.source_version))
            .then_with(|| left.digest.cmp(&right.digest))
            .then_with(|| left.line_start.cmp(&right.line_start))
            .then_with(|| left.line_end.cmp(&right.line_end))
    });
    citations.dedup();
}

fn is_sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn is_canonical_citations(citations: &[LessonCitation]) -> bool {
    citations.windows(2).all(|pair| {
        (
            pair[0].kind,
            &pair[0].locator,
            &pair[0].source_version,
            &pair[0].digest,
            pair[0].line_start,
            pair[0].line_end,
        ) < (
            pair[1].kind,
            &pair[1].locator,
            &pair[1].source_version,
            &pair[1].digest,
            pair[1].line_start,
            pair[1].line_end,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn citation() -> LessonCitation {
        LessonCitation {
            kind: LessonCitationKind::SourceFile,
            locator: "src/memory.rs".to_string(),
            source_version: "git:abc123".to_string(),
            digest: MemoryDigest::for_fields(b"lesson-test", &[b"source"]),
            line_start: Some(10),
            line_end: Some(20),
        }
    }

    fn draft() -> TechnicalLessonDraft {
        TechnicalLessonDraft {
            title: "SQLite migrations must preflight future versions".to_string(),
            kind: TechnicalLessonKind::Compatibility,
            observation: "The store previously treated every newer schema as current.".to_string(),
            guidance: "Read the exact schema marker before opening the writer transaction."
                .to_string(),
            applicability: LessonApplicability {
                paths: vec!["src/memory.rs".to_string()],
                symbols: vec!["MemoryDb::open".to_string()],
                ..LessonApplicability::default()
            },
            citations: vec![citation()],
            confidence: TechnicalLessonConfidence::VerifiedByTest,
            sensitivity: TechnicalLessonSensitivity::Internal,
            retention: LessonRetention::Indefinite,
        }
    }

    #[test]
    fn candidate_round_trip_is_strict_and_workspace_bound() {
        let workspace = WorkspaceMemoryId::for_canonical_root(std::path::Path::new("/repo"));
        let lesson = TechnicalLesson::from_candidate(workspace.clone(), draft(), 100).unwrap();
        let encoded = lesson.encode().unwrap();
        assert_eq!(TechnicalLesson::decode(&encoded).unwrap(), lesson);
        assert_eq!(lesson.workspace_id, workspace);
        assert_eq!(lesson.review, LessonReviewState::Candidate);
        assert!(!encoded.contains("system_prompt"));
    }

    #[test]
    fn unknown_fields_future_schema_and_missing_evidence_fail_closed() {
        let workspace = WorkspaceMemoryId::for_canonical_root(std::path::Path::new("/repo"));
        let lesson = TechnicalLesson::from_candidate(workspace.clone(), draft(), 100).unwrap();
        let mut value = serde_json::to_value(&lesson).unwrap();
        value["unknown"] = serde_json::json!(true);
        assert_eq!(
            TechnicalLesson::decode(&serde_json::to_string(&value).unwrap()),
            Err(TechnicalLessonError::InvalidEncoding)
        );

        let mut future = serde_json::to_value(lesson).unwrap();
        future["schema_version"] = serde_json::json!(TECHNICAL_LESSON_SCHEMA_VERSION + 1);
        assert_eq!(
            TechnicalLesson::decode(&serde_json::to_string(&future).unwrap()),
            Err(TechnicalLessonError::UnsupportedSchema)
        );

        let mut missing_evidence = draft();
        missing_evidence.citations.clear();
        assert_eq!(
            TechnicalLesson::from_candidate(workspace, missing_evidence, 100),
            Err(TechnicalLessonError::InvalidCitationCount)
        );
    }

    #[test]
    fn workspace_and_citation_digests_require_canonical_lowercase_encoding() {
        let workspace = WorkspaceMemoryId::for_canonical_root(std::path::Path::new("/repo"));
        let lesson = TechnicalLesson::from_candidate(workspace, draft(), 100).unwrap();
        let mut uppercase_workspace = serde_json::to_value(&lesson).unwrap();
        let workspace_hex = lesson
            .workspace_id
            .as_str()
            .strip_prefix("workspace-sha256:")
            .unwrap();
        uppercase_workspace["workspace_id"] = serde_json::json!(format!(
            "workspace-sha256:{}",
            workspace_hex.to_ascii_uppercase()
        ));
        assert_eq!(
            TechnicalLesson::decode(&serde_json::to_string(&uppercase_workspace).unwrap()),
            Err(TechnicalLessonError::InvalidEncoding)
        );

        let mut uppercase_digest = serde_json::to_value(lesson).unwrap();
        let encoded_digest = uppercase_digest["citations"][0]["digest"].as_str().unwrap();
        let digest_hex = encoded_digest.strip_prefix("sha256:").unwrap();
        uppercase_digest["citations"][0]["digest"] =
            serde_json::json!(format!("sha256:{}", digest_hex.to_ascii_uppercase()));
        assert_eq!(
            TechnicalLesson::decode(&serde_json::to_string(&uppercase_digest).unwrap()),
            Err(TechnicalLessonError::InvalidEncoding)
        );
    }

    #[test]
    fn correction_is_causal_metadata_not_an_in_place_overwrite() {
        let workspace = WorkspaceMemoryId::for_canonical_root(std::path::Path::new("/repo"));
        let lesson = TechnicalLesson::from_candidate(workspace, draft(), 100).unwrap();
        let parent = MemoryDigest::for_fields(b"lesson-parent", &[b"parent"]);
        let corrected = lesson
            .corrected(
                draft(),
                parent.clone(),
                "New test evidence".to_string(),
                200,
            )
            .unwrap();
        assert_eq!(
            corrected.correction,
            Some(LessonCorrection {
                corrected_record_digest: parent,
                reason: "New test evidence".to_string(),
            })
        );
    }
}
