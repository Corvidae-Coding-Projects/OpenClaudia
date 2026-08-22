//! Deterministic final-environment evaluation for S-055 automatic learning.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]

mod support;

use std::collections::HashSet;
use std::sync::Arc;

use openclaudia::auto_learn::{observe_tool_result, retire_run, LearningCaptureStatus};
use openclaudia::config::AppConfig;
use openclaudia::memory::{MemoryDb, TechnicalLessonRecord};
use openclaudia::permissions::PermissionManager;
use openclaudia::services::tool_executor::{ToolExecutor, ToolExecutorRequest};
use openclaudia::tools::{
    FunctionCall, ToolCall, ToolFailureCode, ToolHandlerResult, ToolResult, ToolRetryability,
    ToolRunContext,
};
use serde::Deserialize;
use serde_json::{json, Value};

const CORPUS_SOURCE: &str =
    include_str!("../capabilities/automatic-learning-evaluation-corpus.json");
const MAX_CORPUS_BYTES: usize = 64 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    schema_version: u32,
    #[serde(rename = "corpus_id")]
    id: String,
    budgets: Budgets,
    scenarios: Vec<Scenario>,
    expected_metrics: Metrics,
    limitations: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Budgets {
    #[serde(rename = "max_scenarios")]
    scenarios: usize,
    #[serde(rename = "max_events_per_scenario")]
    events_per_scenario: usize,
    #[serde(rename = "max_arguments_bytes")]
    arguments_bytes: usize,
    #[serde(rename = "max_forbidden_fragments_per_scenario")]
    forbidden_fragments_per_scenario: usize,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Classification {
    Benefit,
    Negative,
    CausalCorrection,
    UserCorrection,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenario {
    id: String,
    classification: Classification,
    #[serde(default)]
    frontends: Vec<String>,
    events: Vec<Event>,
    #[serde(default)]
    retrieval_query: Option<String>,
    #[serde(default)]
    user_correction: Option<UserCorrection>,
    forbidden_memory_fragments: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    call_id: String,
    tool: String,
    arguments: Value,
    outcome: EventOutcome,
    content: String,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EventOutcome {
    Success,
    Error,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UserCorrection {
    reason: String,
    observation: String,
    guidance: String,
}

#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Metrics {
    downstream_benefit_successes: u32,
    downstream_benefit_cases: u32,
    false_learning_candidates: u32,
    false_learning_cases: u32,
    harmful_memory_records: u32,
    stored_records_inspected: u32,
    causal_correction_successes: u32,
    causal_correction_cases: u32,
    user_correction_successes: u32,
    user_correction_cases: u32,
}

struct Fixture {
    _host: tempfile::TempDir,
    _workspace: tempfile::TempDir,
    db: MemoryDb,
    run: Arc<ToolRunContext>,
    config: AppConfig,
    session_id: String,
}

impl Fixture {
    fn new(session: &str) -> Self {
        let host = tempfile::tempdir().expect("host home");
        let workspace = tempfile::tempdir().expect("workspace");
        std::fs::create_dir_all(workspace.path().join("src")).expect("source directory");
        let db =
            MemoryDb::open_for_workspace(host.path(), workspace.path()).expect("workspace memory");
        let run = support::test_run_context(workspace.path());
        let config = serde_yaml::from_str(
            r"
proxy:
  port: 8080
  host: 127.0.0.1
  target: local
providers:
  local:
    base_url: http://localhost:1234/v1
memory:
  automatic_learning_enabled: true
",
        )
        .expect("evaluation config");
        Self {
            _host: host,
            _workspace: workspace,
            db,
            run,
            config,
            session_id: session.to_string(),
        }
    }

    fn lessons(&self) -> Vec<TechnicalLessonRecord> {
        self.db
            .query_technical_lessons(None, 20, chrono::Utc::now().timestamp())
            .expect("technical lessons")
            .records
    }

    fn execute(&self, id: &str, tool: &str, arguments: &Value) -> ToolResult {
        let manager = PermissionManager::unrestricted_for_run(&self.run);
        let call = call(id, tool, arguments);
        ToolExecutor::execute(ToolExecutorRequest {
            run_context: &self.run,
            tool_call: &call,
            memory_db: Some(&self.db),
            app_config: Some(&self.config),
            task_mgr: None,
            permission_mgr: &manager,
            authorization: None,
            session_id: Some(&self.session_id),
            policy_enforcer: None,
        })
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        retire_run(&self.run);
    }
}

fn call(id: &str, tool: &str, arguments: &Value) -> ToolCall {
    ToolCall {
        id: id.to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: tool.to_string(),
            arguments: serde_json::to_string(&arguments).expect("arguments"),
        },
    }
}

fn result(event: &Event) -> ToolResult {
    let call = call(&event.call_id, &event.tool, &event.arguments);
    match event.outcome {
        EventOutcome::Success => ToolResult::bind(
            &call,
            &event.tool,
            ToolHandlerResult::success_text(event.content.clone()),
        ),
        EventOutcome::Error => ToolResult::failure(
            &call,
            ToolFailureCode::External,
            event.content.clone(),
            ToolRetryability::Safe,
        ),
    }
}

fn validate_corpus(corpus: &Corpus) {
    assert_eq!(corpus.schema_version, 1);
    assert_eq!(corpus.id, "openclaudia-automatic-learning-evaluation-v1");
    assert!(!corpus.limitations.is_empty());
    assert!(!corpus.scenarios.is_empty());
    assert!(corpus.scenarios.len() <= corpus.budgets.scenarios);
    let mut ids = HashSet::new();
    for scenario in &corpus.scenarios {
        assert!(!scenario.id.is_empty());
        assert!(
            ids.insert(&scenario.id),
            "duplicate scenario {}",
            scenario.id
        );
        assert!(!scenario.events.is_empty());
        assert!(scenario.events.len() <= corpus.budgets.events_per_scenario);
        assert!(
            scenario.forbidden_memory_fragments.len()
                <= corpus.budgets.forbidden_fragments_per_scenario
        );
        let mut calls = HashSet::new();
        for event in &scenario.events {
            assert!(event.arguments.is_object());
            assert!(
                serde_json::to_vec(&event.arguments)
                    .expect("argument encoding")
                    .len()
                    <= corpus.budgets.arguments_bytes
            );
            assert!(calls.insert(&event.call_id));
        }
        match scenario.classification {
            Classification::Benefit => assert!(scenario.retrieval_query.is_some()),
            Classification::UserCorrection => {
                assert!(scenario.user_correction.is_some());
                assert_eq!(scenario.frontends, ["cli", "tui", "acp", "subagent"]);
            }
            Classification::Negative | Classification::CausalCorrection => {}
        }
    }
}

fn run_events(fixture: &Fixture, scenario: &Scenario) -> Vec<LearningCaptureStatus> {
    scenario
        .events
        .iter()
        .filter_map(|event| {
            observe_tool_result(&fixture.run, &fixture.db, None, &result(event))
                .map(|receipt| receipt.status)
        })
        .collect()
}

fn count_harmful(records: &[TechnicalLessonRecord], forbidden: &[String]) -> u32 {
    records
        .iter()
        .filter(|record| {
            let encoded = serde_json::to_string(record)
                .expect("record encoding")
                .to_ascii_lowercase();
            forbidden
                .iter()
                .any(|fragment| encoded.contains(&fragment.to_ascii_lowercase()))
        })
        .count()
        .try_into()
        .expect("bounded harmful count")
}

fn retrieve_candidate(fixture: &Fixture, query: &str, logical_id: &str) -> bool {
    let result = fixture.execute(
        "downstream-memory-search",
        "memory_search",
        &json!({"query": query, "limit": 5}),
    );
    if result.is_error() {
        return false;
    }
    result
        .structured()
        .and_then(|value| value["records"].as_array())
        .is_some_and(|records| {
            records.iter().any(|record| {
                record["logical_id"].as_str() == Some(logical_id)
                    && record["lesson"]["citations"]
                        .as_array()
                        .is_some_and(|citations| citations.len() >= 3)
            })
        })
}

fn apply_user_correction(
    fixture: &Fixture,
    record: &TechnicalLessonRecord,
    correction: &UserCorrection,
) -> bool {
    let lesson = &record.lesson;
    let result = fixture.execute(
        "explicit-user-correction",
        "memory_update",
        &json!({
            "logical_id": record.logical_id,
            "expected_record_digest": record.record_digest,
            "correction_reason": correction.reason,
            "replacement": {
                "title": lesson.title,
                "kind": lesson.kind,
                "observation": correction.observation,
                "guidance": correction.guidance,
                "applicability": lesson.applicability,
                "citations": lesson.citations,
                "confidence": lesson.confidence,
                "sensitivity": lesson.sensitivity,
                "retention": lesson.retention
            }
        }),
    );
    !result.is_error()
        && result
            .structured()
            .is_some_and(|value| value["record"]["version"] == 2)
        && fixture.lessons().first().is_some_and(|current| {
            current.lesson.observation == correction.observation
                && current.lesson.guidance == correction.guidance
        })
}

#[test]
fn bundled_corpus_measures_benefit_false_learning_harm_and_correction() {
    assert!(CORPUS_SOURCE.len() <= MAX_CORPUS_BYTES);
    let corpus: Corpus = serde_json::from_str(CORPUS_SOURCE).expect("strict evaluation corpus");
    validate_corpus(&corpus);
    let mut metrics = Metrics::default();

    for scenario in &corpus.scenarios {
        let frontends = if scenario.frontends.is_empty() {
            vec!["canonical"]
        } else {
            scenario.frontends.iter().map(String::as_str).collect()
        };
        for frontend in frontends {
            let fixture = Fixture::new(&format!("s055-eval-{frontend}-{}", scenario.id));
            let statuses = run_events(&fixture, scenario);
            let records = fixture.lessons();
            metrics.harmful_memory_records = metrics.harmful_memory_records.saturating_add(
                count_harmful(&records, &scenario.forbidden_memory_fragments),
            );
            metrics.stored_records_inspected = metrics
                .stored_records_inspected
                .saturating_add(records.len().try_into().expect("bounded records"));

            match scenario.classification {
                Classification::Benefit => {
                    metrics.downstream_benefit_cases += 1;
                    let candidate = records.first().expect("benefit candidate");
                    if retrieve_candidate(
                        &fixture,
                        scenario.retrieval_query.as_deref().expect("query"),
                        &candidate.logical_id.to_string(),
                    ) {
                        metrics.downstream_benefit_successes += 1;
                    }
                }
                Classification::Negative => {
                    metrics.false_learning_cases += 1;
                    metrics.false_learning_candidates = metrics
                        .false_learning_candidates
                        .saturating_add(records.len().try_into().expect("bounded records"));
                }
                Classification::CausalCorrection => {
                    metrics.causal_correction_cases += 1;
                    if records.first().is_some_and(|record| {
                        record.version.get() == 2
                            && record.lesson.observation.contains("contradicts")
                            && statuses.iter().any(|status| {
                                matches!(
                                    status,
                                    LearningCaptureStatus::ContradictionStored { version: 2, .. }
                                )
                            })
                    }) {
                        metrics.causal_correction_successes += 1;
                    }
                }
                Classification::UserCorrection => {
                    metrics.user_correction_cases += 1;
                    let candidate = records.first().expect("user-correctable candidate");
                    if apply_user_correction(
                        &fixture,
                        candidate,
                        scenario.user_correction.as_ref().expect("correction"),
                    ) {
                        metrics.user_correction_successes += 1;
                    }
                }
            }
        }
    }

    assert_eq!(metrics, corpus.expected_metrics);
}
