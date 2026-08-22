//! Adversarial S-105 evidence and promotion tests.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path, PathBuf};

use openclaudia::memory::{
    build_technical_retrieval_evaluation, LessonCitationKind, MemoryDigest,
    TechnicalRetrievalCorpus, TechnicalRetrievalEvaluation, TechnicalRetrievalEvidenceBundle,
    TechnicalRetrievalEvidenceCode, TechnicalRetrievalPolicyId,
};
use openclaudia::runtime::ContentDigest;
use serde_json::{json, Value};

const TUNING: &str = include_str!("../capabilities/technical-memory-retrieval-tuning.json");
const HELD_OUT: &str = include_str!("../capabilities/technical-memory-retrieval-heldout.json");
const EVALUATION: &str = include_str!("../capabilities/technical-memory-retrieval-evaluation.json");

fn approved_review(evaluation: &str, reviewer_id: &str) -> String {
    approved_review_for(TUNING, HELD_OUT, evaluation, reviewer_id)
}

fn approved_review_for(
    tuning: &str,
    held_out: &str,
    evaluation: &str,
    reviewer_id: &str,
) -> String {
    serde_json::to_string_pretty(&json!({
        "schema_version": 1,
        "review_id": "s105-independent-review-fixture",
        "reviewer_id": reviewer_id,
        "reviewer_model_id": "independent-review-fixture-v1",
        "reviewer_config_digest": ContentDigest::sha256(b"s105 independent review fixture"),
        "evaluation_generator_id": "s105-evaluation-runner",
        "tuning_corpus_digest": ContentDigest::sha256(tuning),
        "held_out_corpus_digest": ContentDigest::sha256(held_out),
        "evaluation_digest": ContentDigest::sha256(evaluation),
        "verdict": "approved",
        "reviewed_dimensions": [
            "split_isolation",
            "baseline_coverage",
            "adversarial_states",
            "runtime_parity",
            "privacy_and_cost",
            "artifact_and_resource_bounds"
        ],
        "limitations": [
            "This approval exists only inside an adversarial validator test and is not the bundled release review."
        ]
    }))
    .expect("review fixture")
}

fn evaluation_value() -> Value {
    serde_json::from_str(EVALUATION).expect("evaluation artifact")
}

fn encoded(value: &Value) -> String {
    serde_json::to_string_pretty(value).expect("JSON artifact")
}

fn repository_file(locator: &str) -> PathBuf {
    let relative = Path::new(locator);
    assert!(!relative.is_absolute(), "citation path must be relative");
    assert!(
        relative
            .components()
            .all(|component| matches!(component, Component::Normal(_))),
        "citation path must not traverse or use prefixes: {locator}"
    );
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .expect("repository root");
    let candidate = root
        .join(relative)
        .canonicalize()
        .unwrap_or_else(|error| panic!("citation path {locator} is unavailable: {error}"));
    assert!(
        candidate.starts_with(&root) && candidate.is_file(),
        "citation path {locator} must resolve to a repository file"
    );
    candidate
}

fn repository_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn checked_in_corpora_bind_real_repository_sources() {
    let mut expected_receipts = BTreeSet::new();
    for source in [TUNING, HELD_OUT] {
        let corpus: TechnicalRetrievalCorpus =
            serde_json::from_str(source).expect("retrieval corpus");
        for lesson in corpus.lessons {
            for path in &lesson.draft.applicability.paths {
                repository_file(path);
            }
            for citation in &lesson.draft.citations {
                assert!(
                    matches!(
                        citation.kind,
                        LessonCitationKind::Configuration
                            | LessonCitationKind::Documentation
                            | LessonCitationKind::SourceFile
                            | LessonCitationKind::Test
                    ),
                    "checked-in evaluation citation must be file-verifiable"
                );
                assert!(
                    citation.source_version.starts_with("git:")
                        || citation.source_version == "worktree:s105",
                    "citation source version must identify its repository generation"
                );
                if let Some(revision) = citation.source_version.strip_prefix("git:") {
                    assert_eq!(
                        revision, corpus.repository_revision_id,
                        "citation generation must match the corpus baseline revision"
                    );
                }
                let bytes = fs::read(repository_file(&citation.locator))
                    .expect("read cited repository file");
                assert_eq!(
                    citation.digest,
                    MemoryDigest::sha256(&bytes),
                    "citation digest drifted for {}",
                    citation.locator
                );
                expected_receipts.insert((
                    citation.kind,
                    citation.locator.clone(),
                    citation.source_version.clone(),
                    citation.digest.clone(),
                ));
            }
        }
    }

    let evaluation: TechnicalRetrievalEvaluation =
        serde_json::from_str(EVALUATION).expect("retrieval evaluation");
    let observed_receipts = evaluation
        .citation_verification_receipts
        .iter()
        .map(|receipt| {
            let bytes = fs::read(repository_file(&receipt.locator))
                .expect("read receipt-bound repository file");
            assert_eq!(
                receipt.byte_len,
                u64::try_from(bytes.len()).expect("repository file length")
            );
            assert_eq!(receipt.observed_digest, MemoryDigest::sha256(&bytes));
            assert_eq!(receipt.expected_digest, receipt.observed_digest);
            (
                receipt.kind,
                receipt.locator.clone(),
                receipt.source_version.clone(),
                receipt.expected_digest.clone(),
            )
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(observed_receipts, expected_receipts);
}

#[test]
fn exact_independent_approval_promotes_only_the_measured_policy() {
    let mut relabelled: Value = serde_json::from_str(TUNING).expect("tuning corpus value");
    relabelled["corpus_id"] = json!("openclaudia-technical-memory-relabel-v1");
    relabelled["split"] = json!("held_out");
    let relabelled = encoded(&relabelled);
    let review = approved_review_for(
        TUNING,
        &relabelled,
        EVALUATION,
        "independent-fixture-reviewer",
    );
    let bundle =
        TechnicalRetrievalEvidenceBundle::from_sources(TUNING, &relabelled, EVALUATION, &review);
    let error = bundle.expect_err("held-out relabel must fail");
    assert_eq!(
        error.code,
        TechnicalRetrievalEvidenceCode::SplitContamination
    );

    let review = approved_review(EVALUATION, "independent-fixture-reviewer");
    let bundle =
        TechnicalRetrievalEvidenceBundle::from_sources(TUNING, HELD_OUT, EVALUATION, &review)
            .expect("independently approved evidence");
    assert_eq!(
        bundle.selected_policy(),
        TechnicalRetrievalPolicyId::TaskConditionedDiverseV1
    );
    assert_eq!(bundle.evaluation().trial_count, 3);
}

#[test]
fn self_review_and_digest_mismatch_fail_closed() {
    let self_review = approved_review(EVALUATION, "s105-evaluation-runner");
    let error =
        TechnicalRetrievalEvidenceBundle::from_sources(TUNING, HELD_OUT, EVALUATION, &self_review)
            .expect_err("self review must fail");
    assert_eq!(error.code, TechnicalRetrievalEvidenceCode::SelfReview);

    let mut same_model: Value =
        serde_json::from_str(&approved_review(EVALUATION, "different-reviewer-id"))
            .expect("review value");
    same_model["reviewer_model_id"] = json!("openclaudia-deterministic-retrieval-evaluator-v1");
    let error = TechnicalRetrievalEvidenceBundle::from_sources(
        TUNING,
        HELD_OUT,
        EVALUATION,
        &encoded(&same_model),
    )
    .expect_err("the evaluator model must not review itself under another ID");
    assert_eq!(error.code, TechnicalRetrievalEvidenceCode::SelfReview);

    let mut review: Value =
        serde_json::from_str(&approved_review(EVALUATION, "independent-fixture-reviewer"))
            .expect("review value");
    review["evaluation_digest"] = json!(ContentDigest::sha256(b"different evaluation"));
    let error = TechnicalRetrievalEvidenceBundle::from_sources(
        TUNING,
        HELD_OUT,
        EVALUATION,
        &encoded(&review),
    )
    .expect_err("digest mismatch must fail");
    assert_eq!(error.code, TechnicalRetrievalEvidenceCode::DigestMismatch);

    let mut reordered: Value =
        serde_json::from_str(&approved_review(EVALUATION, "independent-fixture-reviewer"))
            .expect("review value");
    reordered["reviewed_dimensions"]
        .as_array_mut()
        .expect("review dimensions")
        .reverse();
    let error = TechnicalRetrievalEvidenceBundle::from_sources(
        TUNING,
        HELD_OUT,
        EVALUATION,
        &encoded(&reordered),
    )
    .expect_err("non-canonical review dimensions must fail");
    assert_eq!(error.code, TechnicalRetrievalEvidenceCode::IncompleteReview);
}

#[test]
fn missing_baseline_under_trial_and_forged_metrics_fail_closed() {
    let mut evaluation = evaluation_value();
    evaluation["tuning_reports"]
        .as_array_mut()
        .expect("tuning reports")
        .remove(0);
    let evaluation = encoded(&evaluation);
    let review = approved_review(&evaluation, "independent-fixture-reviewer");
    let error =
        TechnicalRetrievalEvidenceBundle::from_sources(TUNING, HELD_OUT, &evaluation, &review)
            .expect_err("missing baseline must fail");
    assert_eq!(error.code, TechnicalRetrievalEvidenceCode::MissingBaseline);

    let mut evaluation = evaluation_value();
    evaluation["trial_count"] = json!(2);
    let evaluation = encoded(&evaluation);
    let review = approved_review(&evaluation, "independent-fixture-reviewer");
    let error =
        TechnicalRetrievalEvidenceBundle::from_sources(TUNING, HELD_OUT, &evaluation, &review)
            .expect_err("under-trial evidence must fail");
    assert_eq!(error.code, TechnicalRetrievalEvidenceCode::UnderTrial);

    let mut evaluation = evaluation_value();
    evaluation["held_out_reports"][5]["metrics"]["recall_numerator"] = json!(2);
    let evaluation = encoded(&evaluation);
    let review = approved_review(&evaluation, "independent-fixture-reviewer");
    let error =
        TechnicalRetrievalEvidenceBundle::from_sources(TUNING, HELD_OUT, &evaluation, &review)
            .expect_err("forged metrics must fail");
    assert_eq!(error.code, TechnicalRetrievalEvidenceCode::MetricsMismatch);
}

#[test]
fn tied_ablation_and_unbound_evaluator_config_fail_closed() {
    let mut tuning: Value = serde_json::from_str(TUNING).expect("tuning corpus value");
    let mut held_out: Value = serde_json::from_str(HELD_OUT).expect("held-out corpus value");
    for corpus in [&mut tuning, &mut held_out] {
        corpus["cases"]
            .as_array_mut()
            .expect("corpus cases")
            .retain(|case| {
                !case["id"].as_str().is_some_and(|id| {
                    id.contains("freshness-ablation") || id.contains("diversity-ablation")
                })
            });
    }
    let tuning = encoded(&tuning);
    let held_out = encoded(&held_out);
    let evaluation = build_technical_retrieval_evaluation(
        &tuning,
        &held_out,
        repository_root(),
        3,
        TechnicalRetrievalPolicyId::TaskConditionedDiverseV1,
        "s105-evaluation-runner",
        "openclaudia-deterministic-retrieval-evaluator-v1",
    )
    .expect("unpromoted ablation evaluation can be measured");
    let evaluation = serde_json::to_string_pretty(&evaluation).expect("evaluation JSON");
    let review = approved_review_for(
        &tuning,
        &held_out,
        &evaluation,
        "independent-fixture-reviewer",
    );
    let error =
        TechnicalRetrievalEvidenceBundle::from_sources(&tuning, &held_out, &evaluation, &review)
            .expect_err("a tied retained mechanism must not be promoted");
    assert_eq!(
        error.code,
        TechnicalRetrievalEvidenceCode::PromotionNotImproved
    );

    let mut tuning: Value = serde_json::from_str(TUNING).expect("tuning corpus value");
    let mut held_out: Value = serde_json::from_str(HELD_OUT).expect("held-out corpus value");
    for corpus in [&mut tuning, &mut held_out] {
        corpus["cases"]
            .as_array_mut()
            .expect("corpus cases")
            .retain(|case| {
                !case["id"]
                    .as_str()
                    .is_some_and(|id| id.contains("field-weight-ablation"))
            });
    }
    let tuning = encoded(&tuning);
    let held_out = encoded(&held_out);
    let evaluation = build_technical_retrieval_evaluation(
        &tuning,
        &held_out,
        repository_root(),
        3,
        TechnicalRetrievalPolicyId::TaskConditionedDiverseV1,
        "s105-evaluation-runner",
        "openclaudia-deterministic-retrieval-evaluator-v1",
    )
    .expect("field ablation can be measured without promotion");
    let evaluation = serde_json::to_string_pretty(&evaluation).expect("evaluation JSON");
    let review = approved_review_for(
        &tuning,
        &held_out,
        &evaluation,
        "independent-fixture-reviewer",
    );
    let error =
        TechnicalRetrievalEvidenceBundle::from_sources(&tuning, &held_out, &evaluation, &review)
            .expect_err("field weighting without controlled benefit must not be promoted");
    assert_eq!(
        error.code,
        TechnicalRetrievalEvidenceCode::PromotionNotImproved
    );

    let mut evaluation = evaluation_value();
    evaluation["evaluator_config_digest"] =
        json!(ContentDigest::sha256(b"unbound evaluator configuration"));
    let evaluation = encoded(&evaluation);
    let review = approved_review(&evaluation, "independent-fixture-reviewer");
    let error =
        TechnicalRetrievalEvidenceBundle::from_sources(TUNING, HELD_OUT, &evaluation, &review)
            .expect_err("an unbound evaluator configuration must fail");
    assert_eq!(error.code, TechnicalRetrievalEvidenceCode::DigestMismatch);
}

#[test]
fn remote_semantic_claim_unknown_fields_and_oversized_artifacts_fail_closed() {
    let mut evaluation = evaluation_value();
    evaluation["mechanisms"][1]["status"] = json!("evaluated");
    let evaluation = encoded(&evaluation);
    let review = approved_review(&evaluation, "independent-fixture-reviewer");
    let error =
        TechnicalRetrievalEvidenceBundle::from_sources(TUNING, HELD_OUT, &evaluation, &review)
            .expect_err("unmeasured semantic claim must fail");
    assert_eq!(
        error.code,
        TechnicalRetrievalEvidenceCode::UnmeasuredMechanism
    );

    let mut evaluation = evaluation_value();
    evaluation["ambient_prompt"] = json!("hidden authority");
    let evaluation = encoded(&evaluation);
    let review = approved_review(&evaluation, "independent-fixture-reviewer");
    let error =
        TechnicalRetrievalEvidenceBundle::from_sources(TUNING, HELD_OUT, &evaluation, &review)
            .expect_err("unknown field must fail");
    assert_eq!(error.code, TechnicalRetrievalEvidenceCode::ParseFailed);

    let oversized = " ".repeat(262_145);
    let review = approved_review(EVALUATION, "independent-fixture-reviewer");
    let error =
        TechnicalRetrievalEvidenceBundle::from_sources(&oversized, HELD_OUT, EVALUATION, &review)
            .expect_err("oversized corpus must fail before parsing");
    assert_eq!(error.code, TechnicalRetrievalEvidenceCode::ArtifactTooLarge);
}

#[test]
fn corpus_queries_cannot_exceed_or_diverge_from_runtime_normalization() {
    for invalid_query in [
        (0..33)
            .map(|index| format!("term-{index}"))
            .collect::<Vec<_>>()
            .join(" "),
        " leading-space".to_string(),
    ] {
        let mut tuning: Value = serde_json::from_str(TUNING).expect("tuning corpus value");
        tuning["cases"][0]["query"] = json!(invalid_query);
        let error = build_technical_retrieval_evaluation(
            &encoded(&tuning),
            HELD_OUT,
            repository_root(),
            3,
            TechnicalRetrievalPolicyId::TaskConditionedDiverseV1,
            "s105-evaluation-runner",
            "openclaudia-deterministic-retrieval-evaluator-v1",
        )
        .expect_err("runtime-incompatible corpus query must fail");
        assert_eq!(error.code, TechnicalRetrievalEvidenceCode::InvalidBounds);
    }
}

#[test]
fn corpus_cannot_self_assert_freshness_or_expiry() {
    let mut tuning: Value = serde_json::from_str(TUNING).expect("tuning corpus value");
    let lesson = tuning["lessons"]
        .as_array_mut()
        .expect("lessons")
        .iter_mut()
        .find(|lesson| lesson["id"] == "tune-freshness-current")
        .expect("current fixture");
    lesson["due_for_review"] = json!(true);
    let error = build_technical_retrieval_evaluation(
        &encoded(&tuning),
        HELD_OUT,
        repository_root(),
        3,
        TechnicalRetrievalPolicyId::TaskConditionedDiverseV1,
        "s105-evaluation-runner",
        "openclaudia-deterministic-retrieval-evaluator-v1",
    )
    .expect_err("freshness label must be derived from retention");
    assert_eq!(error.code, TechnicalRetrievalEvidenceCode::InvalidReference);

    let mut held_out: Value = serde_json::from_str(HELD_OUT).expect("held-out corpus value");
    let lesson = held_out["lessons"]
        .as_array_mut()
        .expect("lessons")
        .iter_mut()
        .find(|lesson| lesson["id"] == "held-expired-membership")
        .expect("expired fixture");
    lesson["state"] = json!("available");
    let error = build_technical_retrieval_evaluation(
        TUNING,
        &encoded(&held_out),
        repository_root(),
        3,
        TechnicalRetrievalPolicyId::TaskConditionedDiverseV1,
        "s105-evaluation-runner",
        "openclaudia-deterministic-retrieval-evaluator-v1",
    )
    .expect_err("expiry label must be derived from retention");
    assert_eq!(error.code, TechnicalRetrievalEvidenceCode::InvalidReference);

    let mut tuning: Value = serde_json::from_str(TUNING).expect("tuning corpus value");
    tuning["lessons"][0]["scope"] = json!("project_evidence");
    let error = build_technical_retrieval_evaluation(
        &encoded(&tuning),
        HELD_OUT,
        repository_root(),
        3,
        TechnicalRetrievalPolicyId::TaskConditionedDiverseV1,
        "s105-evaluation-runner",
        "openclaudia-deterministic-retrieval-evaluator-v1",
    )
    .expect_err("corpus cannot bypass the production store authority scope");
    assert_eq!(error.code, TechnicalRetrievalEvidenceCode::InvalidBounds);
}

#[test]
fn citation_bytes_and_complete_receipt_set_are_mandatory() {
    let mut tuning: Value = serde_json::from_str(TUNING).expect("tuning corpus value");
    tuning["lessons"][0]["draft"]["citations"][0]["digest"] =
        json!("sha256:0000000000000000000000000000000000000000000000000000000000000000");
    let error = build_technical_retrieval_evaluation(
        &encoded(&tuning),
        HELD_OUT,
        repository_root(),
        3,
        TechnicalRetrievalPolicyId::TaskConditionedDiverseV1,
        "s105-evaluation-runner",
        "openclaudia-deterministic-retrieval-evaluator-v1",
    )
    .expect_err("a fabricated citation digest must fail final-environment verification");
    assert_eq!(error.code, TechnicalRetrievalEvidenceCode::DigestMismatch);

    let mut tuning: Value = serde_json::from_str(TUNING).expect("tuning corpus value");
    tuning["lessons"][0]["draft"]["citations"][0]["source_version"] =
        json!("git:0000000000000000000000000000000000000000");
    let error = build_technical_retrieval_evaluation(
        &encoded(&tuning),
        HELD_OUT,
        repository_root(),
        3,
        TechnicalRetrievalPolicyId::TaskConditionedDiverseV1,
        "s105-evaluation-runner",
        "openclaudia-deterministic-retrieval-evaluator-v1",
    )
    .expect_err("a false citation generation must fail final-environment verification");
    assert_eq!(error.code, TechnicalRetrievalEvidenceCode::InvalidReference);

    let mut evaluation = evaluation_value();
    evaluation["citation_verification_receipts"]
        .as_array_mut()
        .expect("citation receipts")
        .pop()
        .expect("at least one citation receipt");
    let evaluation = encoded(&evaluation);
    let review = approved_review(&evaluation, "independent-fixture-reviewer");
    let error =
        TechnicalRetrievalEvidenceBundle::from_sources(TUNING, HELD_OUT, &evaluation, &review)
            .expect_err("missing citation verification coverage must fail");
    assert_eq!(
        error.code,
        TechnicalRetrievalEvidenceCode::NonCanonicalCollection
    );
}
