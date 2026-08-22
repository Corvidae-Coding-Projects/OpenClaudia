//! Executable S-001 capability evidence scenarios.
//!
//! Each reviewed scenario runs three times in a fresh environment. Grading
//! reads final files and forbidden-path absence after the action, then binds
//! that state to the typed trace. Documentation prose and test counts are not
//! grader inputs.

#![allow(clippy::expect_used)]

use std::error::Error;
use std::fs;
use std::path::Path;

use openclaudia::capability_evidence::{
    CapabilityEvidenceBundle, CapabilityEvidenceError, CapabilityMaturity,
    EvaluationExecutionIsolation, EvaluationScenario, EvaluationTraceEnvelope,
    EvaluationTraceEvent, EvaluationTraceEventKind, RegistryValidationCode, ScenarioAction,
};
use openclaudia::runtime::ContentDigest;
use serde_json::Value;

const REGISTRY_SOURCE: &str = include_str!("../capabilities/registry.json");
const CORPUS_SOURCE: &str = include_str!("../capabilities/evaluation-corpus.json");
const REVIEW_SOURCE: &str = include_str!("../capabilities/evaluation-corpus-review.json");
const GENERATED_MATRIX: &str = include_str!("../docs/binary-capability-matrix.md");

const RENDER_OUTCOME: &str = "{\"status\":\"rendered\"}\n";
const MARKETING_CLAIM: &str = "# Capability status\n\nDoctor is operational.\n";
const DOCS_ONLY_REJECTION: &str = "{\"code\":\"operational_missing_success_evidence\"}\n";
const MISSING_FAILURE_REJECTION: &str = "{\"code\":\"operational_missing_failure_evidence\"}\n";

fn write_file(root: &Path, relative: &str, contents: &str) -> Result<(), Box<dyn Error>> {
    let path = root.join(relative);
    let parent = path.parent().ok_or("fixture path must have a parent")?;
    fs::create_dir_all(parent)?;
    fs::write(path, contents)?;
    Ok(())
}

fn registry_source_with_docs_only_promotion() -> Result<String, Box<dyn Error>> {
    let mut registry: Value = serde_json::from_str(REGISTRY_SOURCE)?;
    let capabilities = registry["capabilities"]
        .as_array_mut()
        .ok_or("registry capabilities must be an array")?;
    let doctor = capabilities
        .iter_mut()
        .find(|capability| capability["id"] == "doctor-diagnostics")
        .ok_or("doctor capability must exist")?;
    doctor["maturity"] = Value::String("operational".to_string());
    doctor["entrypoints"][0]["required_failure_modes"] = serde_json::json!(["invalid_input"]);
    Ok(format!("{}\n", serde_json::to_string_pretty(&registry)?))
}

fn registry_source_without_failure_evidence() -> Result<String, Box<dyn Error>> {
    let mut registry: Value = serde_json::from_str(REGISTRY_SOURCE)?;
    let capabilities = registry["capabilities"]
        .as_array_mut()
        .ok_or("registry capabilities must be an array")?;
    let registry_capability = capabilities
        .iter_mut()
        .find(|capability| capability["id"] == "capability-evidence-registry")
        .ok_or("capability evidence registry must exist")?;
    let failure_modes = registry_capability["entrypoints"][0]["required_failure_modes"]
        .as_array_mut()
        .ok_or("registry failure modes must be an array")?;
    failure_modes.push(Value::String("invalid_input".to_string()));
    Ok(format!("{}\n", serde_json::to_string_pretty(&registry)?))
}

fn validation_code(error: CapabilityEvidenceError) -> Result<RegistryValidationCode, String> {
    match error {
        CapabilityEvidenceError::Validation(error) => Ok(error.code()),
        other => Err(format!("expected registry validation error, got {other}")),
    }
}

fn rebind_sources_to_corpus(corpus: &Value) -> Result<(String, String, String), Box<dyn Error>> {
    let corpus_source = format!("{}\n", serde_json::to_string_pretty(corpus)?);
    let corpus_digest = ContentDigest::sha256(corpus_source.as_bytes()).to_string();

    let mut registry: Value = serde_json::from_str(REGISTRY_SOURCE)?;
    for evidence in registry["evidence"]
        .as_array_mut()
        .ok_or("registry evidence must be an array")?
    {
        evidence["corpus_sha256"] = Value::String(corpus_digest.clone());
    }
    let registry_source = format!("{}\n", serde_json::to_string_pretty(&registry)?);

    let mut review: Value = serde_json::from_str(REVIEW_SOURCE)?;
    review["corpus_sha256"] = Value::String(corpus_digest);
    review["reviewer_id"] = Value::String("adversarial-fixture-reviewer".to_string());
    review["verdict"] = Value::String("approved".to_string());
    review["reviewed_dimensions"] = serde_json::json!([
        "final_environment_graders",
        "success_and_failure_coverage",
        "multi_trial_design",
        "trace_assertions",
        "effect_observation_assertions",
        "artifact_bounds_and_isolation"
    ]);
    let review_source = format!("{}\n", serde_json::to_string_pretty(&review)?);
    Ok((registry_source, corpus_source, review_source))
}

fn execute_scenario(
    bundle: &CapabilityEvidenceBundle,
    scenario: &EvaluationScenario,
    root: &Path,
) -> Result<EvaluationTraceEnvelope, Box<dyn Error>> {
    let started = EvaluationTraceEvent::new(1, EvaluationTraceEventKind::ScenarioStarted);
    let loaded = EvaluationTraceEvent::new(2, EvaluationTraceEventKind::RegistryLoaded);
    match scenario.action() {
        ScenarioAction::RenderCapabilityDocumentation => {
            write_file(
                root,
                "release/binary-capability-matrix.md",
                &bundle.render_user_facing_markdown(),
            )?;
            write_file(root, "release/outcome.json", RENDER_OUTCOME)?;
            Ok(EvaluationTraceEnvelope::success(
                scenario.id(),
                vec![
                    started,
                    loaded,
                    EvaluationTraceEvent::new(3, EvaluationTraceEventKind::RegistryValidated),
                    EvaluationTraceEvent::new(4, EvaluationTraceEventKind::DocumentationRendered),
                ],
            ))
        }
        ScenarioAction::RejectDocumentationOnlyOperationalClaim => {
            write_file(root, "claims/marketing.md", MARKETING_CLAIM)?;
            let source = registry_source_with_docs_only_promotion()?;
            let error =
                CapabilityEvidenceBundle::from_sources(&source, CORPUS_SOURCE, REVIEW_SOURCE)
                    .expect_err("documentation-only operational promotion must fail closed");
            let code = validation_code(error)?;
            if code != RegistryValidationCode::OperationalMissingSuccessEvidence {
                return Err(format!("unexpected docs-only rejection code: {code:?}").into());
            }
            write_file(root, "release/rejected.json", DOCS_ONLY_REJECTION)?;
            Ok(EvaluationTraceEnvelope::rejected(
                scenario.id(),
                code,
                vec![
                    started,
                    loaded,
                    EvaluationTraceEvent::new(3, EvaluationTraceEventKind::RegistryRejected),
                ],
            ))
        }
        ScenarioAction::RejectOperationalClaimMissingFailureEvidence => {
            let source = registry_source_without_failure_evidence()?;
            let error =
                CapabilityEvidenceBundle::from_sources(&source, CORPUS_SOURCE, REVIEW_SOURCE)
                    .expect_err(
                        "operational capability without a failure receipt must fail closed",
                    );
            let code = validation_code(error)?;
            if code != RegistryValidationCode::OperationalMissingFailureEvidence {
                return Err(format!("unexpected missing-failure rejection code: {code:?}").into());
            }
            write_file(root, "release/rejected.json", MISSING_FAILURE_REJECTION)?;
            Ok(EvaluationTraceEnvelope::rejected(
                scenario.id(),
                code,
                vec![
                    started,
                    loaded,
                    EvaluationTraceEvent::new(3, EvaluationTraceEventKind::RegistryRejected),
                ],
            ))
        }
    }
}

#[test]
fn reviewed_corpus_executes_three_final_state_trials_per_scenario() -> Result<(), Box<dyn Error>> {
    let bundle = CapabilityEvidenceBundle::bundled()?;
    for scenario in bundle.corpus().scenarios() {
        assert_eq!(scenario.trials(), 3, "corpus must require three trials");
        assert_eq!(scenario.test_target(), "capability_evidence_e2e");
        assert_eq!(
            scenario.execution_isolation(),
            EvaluationExecutionIsolation::InProcessNoChild
        );
        assert_eq!(
            scenario.test_name(),
            "reviewed_corpus_executes_three_final_state_trials_per_scenario"
        );
        let evidence = bundle
            .registry()
            .evidence()
            .iter()
            .find(|record| record.scenario_id() == scenario.id())
            .ok_or("every scenario must have linked registry evidence")?;
        for trial in 1..=scenario.trials() {
            let root = tempfile::tempdir()?;
            let trace = execute_scenario(&bundle, scenario, root.path())?;
            let actual = scenario.grade_trial(root.path(), trial, &trace)?;
            let expected = evidence
                .receipts()
                .iter()
                .find(|receipt| receipt.trial() == trial)
                .ok_or("every reviewed trial must have a registry receipt")?;
            assert_eq!(
                &actual, expected,
                "trial receipt must bind actual final state"
            );
        }
    }
    Ok(())
}

#[test]
fn user_facing_matrix_is_only_a_registry_projection() -> Result<(), Box<dyn Error>> {
    let bundle = CapabilityEvidenceBundle::bundled()?;
    assert_eq!(bundle.render_user_facing_markdown(), GENERATED_MATRIX);
    assert_eq!(
        bundle
            .registry()
            .capability("legacy-native-auth")
            .ok_or("legacy auth record must exist")?
            .maturity(),
        CapabilityMaturity::Unsupported
    );
    assert_eq!(
        bundle
            .registry()
            .capability("behavioral-mode-presets")
            .ok_or("mode record must exist")?
            .maturity(),
        CapabilityMaturity::Experimental
    );
    Ok(())
}

#[test]
fn corpus_review_must_bind_the_exact_artifact_and_an_independent_reviewer(
) -> Result<(), Box<dyn Error>> {
    let mut review: Value = serde_json::from_str(REVIEW_SOURCE)?;
    review["corpus_sha256"] = Value::String(format!("sha256:{}", "1".repeat(64)));
    let altered_review = serde_json::to_string_pretty(&review)?;
    let error =
        CapabilityEvidenceBundle::from_sources(REGISTRY_SOURCE, CORPUS_SOURCE, &altered_review)
            .expect_err("review of another corpus artifact must not authorize this corpus");
    assert_eq!(
        validation_code(error)?,
        RegistryValidationCode::CorpusReviewInvalid
    );

    review["corpus_sha256"] =
        serde_json::from_str::<Value>(REVIEW_SOURCE)?["corpus_sha256"].clone();
    review["reviewer_id"] = Value::String("s001-implementation".to_string());
    let self_review = serde_json::to_string_pretty(&review)?;
    let error =
        CapabilityEvidenceBundle::from_sources(REGISTRY_SOURCE, CORPUS_SOURCE, &self_review)
            .expect_err("corpus author must not approve the same corpus");
    assert_eq!(
        validation_code(error)?,
        RegistryValidationCode::CorpusReviewInvalid
    );
    Ok(())
}

#[test]
fn grader_rejects_trace_tampering_after_real_execution() -> Result<(), Box<dyn Error>> {
    let bundle = CapabilityEvidenceBundle::bundled()?;
    let scenario = bundle
        .corpus()
        .scenario("registry-render-success")
        .ok_or("render scenario must exist")?;
    let root = tempfile::tempdir()?;
    let trace = execute_scenario(&bundle, scenario, root.path())?;
    let mut events = trace.events().to_vec();
    events.push(EvaluationTraceEvent::new(
        5,
        EvaluationTraceEventKind::RegistryRejected,
    ));
    let tampered = EvaluationTraceEnvelope::success(scenario.id(), events);
    let error = scenario
        .grade_trial(root.path(), 1, &tampered)
        .expect_err("tampered trace must be rejected");
    assert!(matches!(
        error,
        CapabilityEvidenceError::TraceMismatch { .. }
    ));
    Ok(())
}

#[cfg(unix)]
#[test]
fn grader_rejects_symlinked_final_state() -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::symlink;

    let bundle = CapabilityEvidenceBundle::bundled()?;
    let scenario = bundle
        .corpus()
        .scenario("registry-render-success")
        .ok_or("render scenario must exist")?;
    let root = tempfile::tempdir()?;
    let trace = execute_scenario(&bundle, scenario, root.path())?;
    let matrix = root.path().join("release/binary-capability-matrix.md");
    fs::remove_file(&matrix)?;
    symlink("outcome.json", matrix)?;
    let error = scenario
        .grade_trial(root.path(), 1, &trace)
        .expect_err("symlinked final state must be rejected");
    assert!(matches!(
        error,
        CapabilityEvidenceError::EnvironmentIo { .. }
    ));
    Ok(())
}

#[test]
fn failure_traces_bind_distinct_scenario_and_rejection_identities() -> Result<(), Box<dyn Error>> {
    let bundle = CapabilityEvidenceBundle::bundled()?;
    let docs_only = bundle
        .registry()
        .evidence()
        .iter()
        .find(|record| record.scenario_id() == "registry-rejects-docs-only")
        .ok_or("docs-only evidence must exist")?;
    let missing_failure = bundle
        .registry()
        .evidence()
        .iter()
        .find(|record| record.scenario_id() == "registry-rejects-missing-failure-evidence")
        .ok_or("missing-failure evidence must exist")?;
    assert_ne!(
        docs_only.trace().trace_sha256(),
        missing_failure.trace().trace_sha256()
    );
    assert_ne!(
        docs_only.trace().envelope().outcome(),
        missing_failure.trace().envelope().outcome()
    );

    let scenario = bundle
        .corpus()
        .scenario("registry-rejects-docs-only")
        .ok_or("docs-only scenario must exist")?;
    let root = tempfile::tempdir()?;
    let actual = execute_scenario(&bundle, scenario, root.path())?;
    let relabeled = EvaluationTraceEnvelope::rejected(
        "registry-rejects-missing-failure-evidence",
        RegistryValidationCode::OperationalMissingSuccessEvidence,
        actual.events().to_vec(),
    );
    let error = scenario
        .grade_trial(root.path(), 1, &relabeled)
        .expect_err("a trace from one scenario must not be relabeled as another");
    assert!(matches!(
        error,
        CapabilityEvidenceError::TraceMismatch { .. }
    ));
    Ok(())
}

#[test]
fn fabricated_effect_receipt_fails_closed() -> Result<(), Box<dyn Error>> {
    let mut registry: Value = serde_json::from_str(REGISTRY_SOURCE)?;
    registry["evidence"][0]["receipts"][0]["effect_observations_sha256"] =
        Value::String(format!("sha256:{}", "1".repeat(64)));
    let source = format!("{}\n", serde_json::to_string_pretty(&registry)?);
    let error = CapabilityEvidenceBundle::from_sources(&source, CORPUS_SOURCE, REVIEW_SOURCE)
        .expect_err("a fabricated effect receipt must not authorize a capability");
    assert_eq!(
        validation_code(error)?,
        RegistryValidationCode::ReceiptMismatch
    );
    Ok(())
}

#[test]
fn fabricated_effect_observation_fails_closed() -> Result<(), Box<dyn Error>> {
    let mut corpus: Value = serde_json::from_str(CORPUS_SOURCE)?;
    corpus["scenarios"][0]["grader"]["effect_observations"][0]["proof"]["path"] =
        Value::String("release/rejected.json".to_string());
    let (registry, corpus, review) = rebind_sources_to_corpus(&corpus)?;
    let error = CapabilityEvidenceBundle::from_sources(&registry, &corpus, &review)
        .expect_err("an observation citing an unobserved final file must fail closed");
    assert_eq!(
        validation_code(error)?,
        RegistryValidationCode::InvalidEffect
    );
    Ok(())
}

#[test]
fn missing_must_occur_observation_fails_closed() -> Result<(), Box<dyn Error>> {
    let mut registry: Value = serde_json::from_str(REGISTRY_SOURCE)?;
    let capability = registry["capabilities"]
        .as_array_mut()
        .and_then(|records| {
            records
                .iter_mut()
                .find(|record| record["id"] == "capability-evidence-registry")
        })
        .ok_or("registry capability must exist")?;
    capability["required_effects"]
        .as_array_mut()
        .ok_or("required effects must be an array")?
        .push(serde_json::json!({
            "id": "registry.unobserved",
            "kind": "trace_emission",
            "expectation": "must_occur",
            "description": "Adversarial fixture with no observed proof."
        }));
    let source = format!("{}\n", serde_json::to_string_pretty(&registry)?);
    let error = CapabilityEvidenceBundle::from_sources(&source, CORPUS_SOURCE, REVIEW_SOURCE)
        .expect_err("an unobserved mandatory effect must block operational maturity");
    assert_eq!(
        validation_code(error)?,
        RegistryValidationCode::OperationalMissingEffectEvidence
    );
    Ok(())
}

#[test]
fn forbidden_effect_observation_checks_actual_final_state() -> Result<(), Box<dyn Error>> {
    let bundle = CapabilityEvidenceBundle::bundled()?;
    let scenario = bundle
        .corpus()
        .scenario("registry-render-success")
        .ok_or("render scenario must exist")?;
    let root = tempfile::tempdir()?;
    let trace = execute_scenario(&bundle, scenario, root.path())?;
    write_file(root.path(), "release/operational.json", "{}\n")?;
    let error = scenario
        .grade_trial(root.path(), 1, &trace)
        .expect_err("a forbidden release promotion must fail final-state grading");
    assert!(matches!(
        error,
        CapabilityEvidenceError::UnexpectedFinalState { .. }
    ));
    Ok(())
}

#[test]
fn artifact_and_collection_bounds_reject_oversized_inputs() -> Result<(), Box<dyn Error>> {
    let oversized = " ".repeat(524_289);
    let error = CapabilityEvidenceBundle::from_sources(&oversized, CORPUS_SOURCE, REVIEW_SOURCE)
        .expect_err("oversized registry input must be rejected before parsing");
    assert_eq!(
        validation_code(error)?,
        RegistryValidationCode::EvaluationBoundsInvalid
    );

    let mut registry: Value = serde_json::from_str(REGISTRY_SOURCE)?;
    let capabilities = registry["capabilities"]
        .as_array_mut()
        .ok_or("capabilities must be an array")?;
    capabilities.clear();
    let fixture = serde_json::json!({
        "id": "bounded-fixture",
        "display_name": "fixture",
        "visibility": "internal",
        "maturity": "partial",
        "summary": "fixture",
        "limitation": "fixture",
        "entrypoints": [],
        "required_effects": [],
        "evidence_ids": []
    });
    capabilities.resize(129, fixture);
    let source = format!("{}\n", serde_json::to_string_pretty(&registry)?);
    let error = CapabilityEvidenceBundle::from_sources(&source, CORPUS_SOURCE, REVIEW_SOURCE)
        .expect_err("oversized capability collection must be rejected");
    assert_eq!(
        validation_code(error)?,
        RegistryValidationCode::EvaluationBoundsInvalid
    );

    let mut registry: Value = serde_json::from_str(REGISTRY_SOURCE)?;
    registry["capabilities"][0]["entrypoints"][0]["invocation"] = Value::String("x".repeat(1_025));
    let source = format!("{}\n", serde_json::to_string_pretty(&registry)?);
    let error = CapabilityEvidenceBundle::from_sources(&source, CORPUS_SOURCE, REVIEW_SOURCE)
        .expect_err("oversized bounded string must be rejected");
    assert_eq!(
        validation_code(error)?,
        RegistryValidationCode::EvaluationBoundsInvalid
    );
    Ok(())
}
