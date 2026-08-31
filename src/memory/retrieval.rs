//! Bounded retrieval policy for typed, codebase-specific technical lessons.
//!
//! Retrieval is invoked explicitly by the memory tools. It ranks existing
//! typed evidence but cannot create authority, alter review state, or project
//! stored content into ambient prompts.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{TechnicalLesson, TechnicalLessonRecord};

/// Version of the task-context and retrieval-trace contract.
pub const TECHNICAL_RETRIEVAL_SCHEMA_VERSION: u32 = 1;
/// Maximum items accepted in any one task-context collection.
pub const MAX_RETRIEVAL_CONTEXT_ITEMS: usize = 16;
/// Maximum total items accepted across one task context.
pub const MAX_RETRIEVAL_CONTEXT_TOTAL_ITEMS: usize = 64;
/// Maximum UTF-8 bytes in one task-context item.
pub const MAX_RETRIEVAL_CONTEXT_ITEM_BYTES: usize = 256;
/// Maximum normalized query terms considered by a retrieval policy.
pub const MAX_RETRIEVAL_QUERY_TERMS: usize = 32;
/// Maximum records decoded and considered by one runtime retrieval call.
pub const MAX_RETRIEVAL_CANDIDATES_SCANNED: usize = 512;

const TASK_CONTEXT_MATCH_SCORE: u32 = 24;
const TASK_STAGE_MATCH_SCORE: u32 = 12;
const QUERY_TITLE_MATCH_SCORE: u32 = 12;
const QUERY_OBSERVATION_MATCH_SCORE: u32 = 7;
const QUERY_GUIDANCE_MATCH_SCORE: u32 = 6;
const QUERY_APPLICABILITY_MATCH_SCORE: u32 = 10;
const EXACT_QUERY_PHRASE_SCORE: u32 = 16;
const STALE_SCORE_PENALTY: u32 = 12;
const MIN_TASK_CONDITIONED_SCORE: u32 = 12;
const DIVERSITY_OVERLAP_PENALTY: u32 = 8;

/// Semantic stage supplied explicitly by the caller making a memory tool call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TechnicalRetrievalStage {
    Analyze,
    Reproduce,
    Edit,
    Verify,
    Operate,
}

impl TechnicalRetrievalStage {
    const fn matching_tags(self) -> &'static [&'static str] {
        match self {
            Self::Analyze => &["analyze", "analysis", "architecture", "design"],
            Self::Reproduce => &["reproduce", "debug", "debugging", "diagnose"],
            Self::Edit => &["edit", "implement", "implementation", "refactor"],
            Self::Verify => &["verify", "verification", "test", "testing"],
            Self::Operate => &["operate", "operational", "deploy", "runtime"],
        }
    }
}

/// Explicit task surfaces used to rank technical lessons for one tool call.
///
/// These fields are supplied by the caller and are not inferred from a
/// transcript, hidden reasoning, or ambient prompt state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TechnicalRetrievalContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<TechnicalRetrievalStage>,
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

/// One explicit typed retrieval request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TechnicalLessonRetrievalRequest {
    pub query: Option<String>,
    pub context: Option<TechnicalRetrievalContext>,
    pub limit: usize,
}

impl TechnicalRetrievalContext {
    /// Validate, normalize, sort, and deduplicate task surfaces.
    ///
    /// # Errors
    ///
    /// Returns an error when any collection or item exceeds its bound, an item
    /// is empty or contains a control character, or no task signal is present.
    pub fn canonicalize(mut self) -> Result<Self, TechnicalRetrievalError> {
        canonicalize_items(&mut self.paths, "paths")?;
        canonicalize_items(&mut self.symbols, "symbols")?;
        canonicalize_items(&mut self.components, "components")?;
        canonicalize_items(&mut self.environments, "environments")?;
        canonicalize_items(&mut self.tags, "tags")?;
        let total = self.paths.len()
            + self.symbols.len()
            + self.components.len()
            + self.environments.len()
            + self.tags.len();
        if total > MAX_RETRIEVAL_CONTEXT_TOTAL_ITEMS {
            return Err(TechnicalRetrievalError::ContextTooLarge);
        }
        if total == 0 && self.stage.is_none() {
            return Err(TechnicalRetrievalError::EmptyContext);
        }
        Ok(self)
    }

    #[must_use]
    pub const fn item_count(&self) -> usize {
        self.paths.len()
            + self.symbols.len()
            + self.components.len()
            + self.environments.len()
            + self.tags.len()
    }
}

/// Stable policy identifiers used by runtime traces and evaluation artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TechnicalRetrievalPolicyId {
    NoMemory,
    LexicalV1,
    FieldWeightedSparseV1,
    TaskConditionedSparseV1,
    TaskConditionedFreshnessV1,
    TaskConditionedThresholdV1,
    TaskConditionedDiverseV1,
}

impl TechnicalRetrievalPolicyId {
    #[must_use]
    pub const fn minimum_score(self) -> u32 {
        match self {
            Self::NoMemory => u32::MAX,
            Self::LexicalV1
            | Self::FieldWeightedSparseV1
            | Self::TaskConditionedSparseV1
            | Self::TaskConditionedFreshnessV1 => 1,
            Self::TaskConditionedThresholdV1 | Self::TaskConditionedDiverseV1 => {
                MIN_TASK_CONDITIONED_SCORE
            }
        }
    }

    const fn uses_task_context(self) -> bool {
        !matches!(
            self,
            Self::NoMemory | Self::LexicalV1 | Self::FieldWeightedSparseV1
        )
    }

    const fn uses_freshness(self) -> bool {
        matches!(
            self,
            Self::TaskConditionedFreshnessV1
                | Self::TaskConditionedThresholdV1
                | Self::TaskConditionedDiverseV1
        )
    }

    const fn uses_diversity(self) -> bool {
        matches!(self, Self::TaskConditionedDiverseV1)
    }

    const fn requires_task_context_match(self) -> bool {
        matches!(
            self,
            Self::TaskConditionedThresholdV1 | Self::TaskConditionedDiverseV1
        )
    }
}

/// Availability of an optional semantic retrieval backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TechnicalSemanticBackendStatus {
    NotConfigured,
    RejectedByPrivacyPolicy,
    Unavailable,
    Available,
}

/// Provenance of the policy selected for this retrieval call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TechnicalRetrievalPolicyStatus {
    /// No task context was supplied, so the compatibility lexical policy ran.
    CompatibilityBaseline,
    /// The exact bundled evaluation and independent review approved this policy.
    EvidenceApproved,
    /// Task context was supplied, but artifact validation failed closed.
    EvidenceRejectedFallback,
}

/// Observable ranking metadata returned with every retrieval result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TechnicalRetrievalTrace {
    pub schema_version: u32,
    pub policy: TechnicalRetrievalPolicyId,
    pub policy_status: TechnicalRetrievalPolicyStatus,
    pub semantic_backend: TechnicalSemanticBackendStatus,
    pub context: Option<TechnicalRetrievalContext>,
    pub candidates_scanned: usize,
    pub candidates_matched: usize,
    pub minimum_score: u32,
    pub stale_records_returned: usize,
}

impl TechnicalRetrievalTrace {
    #[must_use]
    pub(crate) const fn new(
        policy: TechnicalRetrievalPolicyId,
        policy_status: TechnicalRetrievalPolicyStatus,
        semantic_backend: TechnicalSemanticBackendStatus,
        context: Option<TechnicalRetrievalContext>,
    ) -> Self {
        Self {
            schema_version: TECHNICAL_RETRIEVAL_SCHEMA_VERSION,
            policy,
            policy_status,
            semantic_backend,
            context,
            candidates_scanned: 0,
            candidates_matched: 0,
            minimum_score: policy.minimum_score(),
            stale_records_returned: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TechnicalRetrievalError {
    #[error("technical retrieval context is empty")]
    EmptyContext,
    #[error("technical retrieval context exceeds its aggregate item budget")]
    ContextTooLarge,
    #[error("technical retrieval context field {field} exceeds its item budget")]
    TooManyContextItems { field: &'static str },
    #[error("technical retrieval context field {field} contains an invalid item")]
    InvalidContextItem { field: &'static str },
}

#[derive(Debug)]
pub struct RankedTechnicalLesson {
    pub score: u32,
    pub record: TechnicalLessonRecord,
    diversity_keys: BTreeSet<String>,
}

/// Rank already validated records without changing their evidence metadata.
pub fn rank_technical_lessons(
    records: Vec<TechnicalLessonRecord>,
    query: Option<&str>,
    query_terms: &[String],
    context: Option<&TechnicalRetrievalContext>,
    policy: TechnicalRetrievalPolicyId,
) -> Vec<RankedTechnicalLesson> {
    let minimum_score = policy.minimum_score();
    let mut ranked = records
        .into_iter()
        .filter_map(|record| {
            let score = score_lesson(
                &record.lesson,
                record.due_for_review,
                query,
                query_terms,
                context,
                policy,
            );
            (score >= minimum_score).then(|| RankedTechnicalLesson {
                score,
                diversity_keys: lesson_diversity_keys(&record.lesson),
                record,
            })
        })
        .collect::<Vec<_>>();
    ranked.sort_by(compare_ranked_lessons);
    if policy.uses_diversity() {
        diversify_ranked_lessons(ranked)
    } else {
        ranked
    }
}

fn score_lesson(
    lesson: &TechnicalLesson,
    due_for_review: bool,
    query: Option<&str>,
    query_terms: &[String],
    context: Option<&TechnicalRetrievalContext>,
    policy: TechnicalRetrievalPolicyId,
) -> u32 {
    if policy == TechnicalRetrievalPolicyId::NoMemory {
        return 0;
    }
    if policy == TechnicalRetrievalPolicyId::LexicalV1 {
        return lexical_baseline_score(lesson, query_terms);
    }

    let title = normalized_terms(&lesson.title);
    let observation = normalized_terms(&lesson.observation);
    let guidance = normalized_terms(&lesson.guidance);
    let applicability = applicability_terms(lesson);
    let query_terms = query_terms
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut score = weighted_overlap(&query_terms, &title, QUERY_TITLE_MATCH_SCORE)
        + weighted_overlap(&query_terms, &observation, QUERY_OBSERVATION_MATCH_SCORE)
        + weighted_overlap(&query_terms, &guidance, QUERY_GUIDANCE_MATCH_SCORE)
        + weighted_overlap(
            &query_terms,
            &applicability,
            QUERY_APPLICABILITY_MATCH_SCORE,
        );
    if let Some(query) = query {
        let query = query.to_lowercase();
        if lesson.title.to_lowercase().contains(&query)
            || lesson.observation.to_lowercase().contains(&query)
            || lesson.guidance.to_lowercase().contains(&query)
        {
            score = score.saturating_add(EXACT_QUERY_PHRASE_SCORE);
        }
    }
    if policy.uses_task_context() {
        if let Some(context) = context {
            let task_score = context_score(lesson, context);
            if policy.requires_task_context_match() && task_score.explicit_surfaces == 0 {
                return 0;
            }
            score = score
                .saturating_add(task_score.explicit_surfaces)
                .saturating_add(task_score.stage);
        }
    }
    if policy.uses_freshness() && due_for_review {
        score = score.saturating_sub(STALE_SCORE_PENALTY);
    }
    score
}

fn lexical_baseline_score(lesson: &TechnicalLesson, query_terms: &[String]) -> u32 {
    if query_terms.is_empty() {
        return 1;
    }
    let projection = lesson.search_projection().to_lowercase();
    u32::try_from(
        query_terms
            .iter()
            .filter(|term| projection.contains(term.as_str()))
            .count(),
    )
    .unwrap_or(u32::MAX)
}

struct TaskContextScore {
    explicit_surfaces: u32,
    stage: u32,
}

fn context_score(
    lesson: &TechnicalLesson,
    context: &TechnicalRetrievalContext,
) -> TaskContextScore {
    let fields = [
        (&context.paths, &lesson.applicability.paths),
        (&context.symbols, &lesson.applicability.symbols),
        (&context.components, &lesson.applicability.components),
        (&context.environments, &lesson.applicability.environments),
        (&context.tags, &lesson.applicability.tags),
    ];
    let explicit_surfaces = fields.into_iter().fold(0_u32, |score, (wanted, actual)| {
        score.saturating_add(
            u32::try_from(case_insensitive_overlap(wanted, actual))
                .unwrap_or(u32::MAX)
                .saturating_mul(TASK_CONTEXT_MATCH_SCORE),
        )
    });
    let stage = context.stage.map_or(0, |stage| {
        let tags = lesson
            .applicability
            .tags
            .iter()
            .chain(&lesson.applicability.components)
            .flat_map(|value| normalized_terms(value))
            .collect::<BTreeSet<_>>();
        u32::from(stage.matching_tags().iter().any(|tag| tags.contains(*tag)))
            * TASK_STAGE_MATCH_SCORE
    });
    TaskContextScore {
        explicit_surfaces,
        stage,
    }
}

fn compare_ranked_lessons(
    left: &RankedTechnicalLesson,
    right: &RankedTechnicalLesson,
) -> std::cmp::Ordering {
    right
        .score
        .cmp(&left.score)
        .then_with(|| {
            right
                .record
                .lesson
                .captured_at_unix_seconds
                .cmp(&left.record.lesson.captured_at_unix_seconds)
        })
        .then_with(|| right.record.version.cmp(&left.record.version))
        .then_with(|| left.record.logical_id.cmp(&right.record.logical_id))
        .then_with(|| {
            memory_scope_rank(left.record.scope).cmp(&memory_scope_rank(right.record.scope))
        })
}

const fn memory_scope_rank(scope: super::MemoryRecordScope) -> u8 {
    match scope {
        super::MemoryRecordScope::UserPrivate => 0,
        super::MemoryRecordScope::TeamShared => 1,
        super::MemoryRecordScope::ProjectEvidence => 2,
    }
}

fn diversify_ranked_lessons(mut pending: Vec<RankedTechnicalLesson>) -> Vec<RankedTechnicalLesson> {
    let mut selected = Vec::with_capacity(pending.len());
    let mut selected_key_counts = BTreeMap::<String, u32>::new();
    while !pending.is_empty() {
        let mut best_index = 0;
        for candidate_index in 1..pending.len() {
            if compare_diverse_candidates(
                &pending[candidate_index],
                &pending[best_index],
                &selected_key_counts,
            )
            .is_lt()
            {
                best_index = candidate_index;
            }
        }
        let next = pending.remove(best_index);
        for key in &next.diversity_keys {
            let count = selected_key_counts.entry(key.clone()).or_default();
            *count = count.saturating_add(1);
        }
        selected.push(next);
    }
    selected
}

fn compare_diverse_candidates(
    left: &RankedTechnicalLesson,
    right: &RankedTechnicalLesson,
    selected_key_counts: &BTreeMap<String, u32>,
) -> std::cmp::Ordering {
    diversity_adjusted_score(right, selected_key_counts)
        .cmp(&diversity_adjusted_score(left, selected_key_counts))
        .then_with(|| compare_ranked_lessons(left, right))
}

fn diversity_adjusted_score(
    candidate: &RankedTechnicalLesson,
    selected_key_counts: &BTreeMap<String, u32>,
) -> u32 {
    let overlap = candidate
        .diversity_keys
        .iter()
        .map(|key| selected_key_counts.get(key).copied().unwrap_or_default())
        .sum::<u32>();
    candidate
        .score
        .saturating_sub(overlap.saturating_mul(DIVERSITY_OVERLAP_PENALTY))
}

fn lesson_diversity_keys(lesson: &TechnicalLesson) -> BTreeSet<String> {
    lesson
        .applicability
        .components
        .iter()
        .chain(&lesson.applicability.tags)
        .map(|value| value.to_lowercase())
        .collect()
}

fn applicability_terms(lesson: &TechnicalLesson) -> BTreeSet<String> {
    lesson
        .applicability
        .paths
        .iter()
        .chain(&lesson.applicability.symbols)
        .chain(&lesson.applicability.components)
        .chain(&lesson.applicability.environments)
        .chain(&lesson.applicability.tags)
        .flat_map(|value| normalized_terms(value))
        .collect()
}

fn normalized_terms(value: &str) -> BTreeSet<String> {
    value
        .split(|character: char| !character.is_alphanumeric())
        .filter(|term| !term.is_empty())
        .map(str::to_lowercase)
        .collect()
}

fn weighted_overlap(wanted: &BTreeSet<&str>, actual: &BTreeSet<String>, weight: u32) -> u32 {
    u32::try_from(wanted.iter().filter(|term| actual.contains(**term)).count())
        .unwrap_or(u32::MAX)
        .saturating_mul(weight)
}

fn case_insensitive_overlap(wanted: &[String], actual: &[String]) -> usize {
    let actual = actual
        .iter()
        .map(|value| value.to_lowercase())
        .collect::<BTreeSet<_>>();
    wanted
        .iter()
        .filter(|value| actual.contains(&value.to_lowercase()))
        .count()
}

fn canonicalize_items(
    items: &mut Vec<String>,
    field: &'static str,
) -> Result<(), TechnicalRetrievalError> {
    if items.len() > MAX_RETRIEVAL_CONTEXT_ITEMS {
        return Err(TechnicalRetrievalError::TooManyContextItems { field });
    }
    for item in &mut *items {
        *item = item.trim().to_lowercase();
        if item.is_empty()
            || item.len() > MAX_RETRIEVAL_CONTEXT_ITEM_BYTES
            || item.chars().any(char::is_control)
        {
            return Err(TechnicalRetrievalError::InvalidContextItem { field });
        }
    }
    items.sort_unstable();
    items.dedup();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_is_canonical_and_bounded() {
        let context = TechnicalRetrievalContext {
            stage: Some(TechnicalRetrievalStage::Verify),
            paths: vec![" src/memory.rs ".to_string(), "SRC/MEMORY.RS".to_string()],
            tags: vec!["testing".to_string()],
            ..TechnicalRetrievalContext::default()
        }
        .canonicalize()
        .expect("valid context");
        assert_eq!(context.paths, ["src/memory.rs"]);
        assert_eq!(context.item_count(), 2);

        assert_eq!(
            TechnicalRetrievalContext::default().canonicalize(),
            Err(TechnicalRetrievalError::EmptyContext)
        );
    }
}
