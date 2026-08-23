//! Typed model-side skill selection at the real run trust boundary.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]

use openclaudia::skills::{SkillCapabilityPolicy, SkillRunAccess};
use openclaudia::tools::skill::execute_skill;
use openclaudia::tools::{ToolFailureCode, ToolOutcome, ToolRunContext, WorkspaceAccess};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

fn run(root: &Path, trust_project: bool) -> Arc<ToolRunContext> {
    let mut builder = ToolRunContext::builder(openclaudia::state::SessionId::new(), root)
        .read_only_roots(Vec::new())
        .read_write_roots(Vec::new())
        .environment_grants(HashMap::new())
        .workspace_access(WorkspaceAccess::ReadWrite)
        .process(false)
        .network(false)
        .secrets(false)
        .provider("skill-selection-test");
    if trust_project {
        let policy = SkillCapabilityPolicy::project(
            vec!["Bash(git status *)".to_string()],
            true,
            true,
            true,
        )
        .expect("bounded test policy");
        builder = builder.skill_access(
            SkillRunAccess::host_granted_project(root, policy).expect("canonical test root"),
        );
    }
    builder.build().expect("skill test run")
}

fn args(name: Value) -> HashMap<String, Value> {
    HashMap::from([("name".to_string(), name)])
}

fn assert_failure(result: &openclaudia::tools::ToolHandlerResult, code: ToolFailureCode) {
    let ToolOutcome::Error { failure } = &result.outcome else {
        panic!("expected typed failure, got {:?}", result.outcome);
    };
    assert_eq!(failure.code, code);
    assert!(!failure.message.is_empty());
}

fn write_skill(root: &Path, body: &str) {
    let directory = root.join(".openclaudia/skills/review");
    std::fs::create_dir_all(&directory).expect("skill directory");
    std::fs::write(
        directory.join("SKILL.md"),
        format!(
            "---\nname: review\ndescription: Review code\nallowed_tools:\n  - Bash(git status *)\nmodel: gpt-5.6\neffort: high\n---\n{body}\n"
        ),
    )
    .expect("skill fixture");
}

#[test]
fn invalid_name_arguments_are_typed_and_bounded() {
    let root = tempfile::tempdir().expect("root");
    let run = run(root.path(), false);
    for arguments in [HashMap::new(), args(json!(42)), args(json!("   "))] {
        let result = execute_skill(&run, &arguments);
        assert_failure(&result, ToolFailureCode::InvalidArguments);
        assert!(result.content().len() < 500);
    }
}

#[test]
fn repository_skill_is_inert_without_host_trust() {
    let root = tempfile::tempdir().expect("root");
    write_skill(root.path(), "UNTRUSTED_PROJECT_BODY");
    let run = run(root.path(), false);

    let result = execute_skill(&run, &args(json!("review")));

    assert_failure(&result, ToolFailureCode::Unavailable);
    assert!(!result.content().contains("UNTRUSTED_PROJECT_BODY"));
}

#[test]
fn trusted_model_selection_is_structured_reference_without_runtime_grants() {
    let root = tempfile::tempdir().expect("root");
    write_skill(root.path(), "REVIEW_THE_REAL_DIFF");
    let run = run(root.path(), true);

    let result = execute_skill(&run, &args(json!("  review  ")));

    assert!(!matches!(result.outcome, ToolOutcome::Error { .. }));
    assert!(result.content().contains("REVIEW_THE_REAL_DIFF"));
    assert!(!result.content().contains("<skill"));
    let ToolOutcome::Success { content } = &result.outcome else {
        panic!("expected complete skill selection");
    };
    let structured = content.structured.as_ref().expect("typed selection");
    assert_eq!(structured["schema"], "openclaudia.skill_selection.v1");
    assert_eq!(structured["name"], "review");
    assert_eq!(structured["trigger"], "model_selection");
    assert_eq!(
        structured["requested_allowed_tools"],
        json!(["Bash(git status *)"])
    );
    assert_eq!(structured["effective_allowed_tools"], json!([]));
    assert!(structured["effective_model"].is_null());
    assert!(structured["effective_effort"].is_null());
    assert_eq!(structured["hooks_active"], false);
    assert_eq!(structured["provenance"]["source"], "project");
    assert!(structured["provenance"]["content_digest"]
        .as_str()
        .is_some_and(|digest| digest.starts_with("sha256:")));
}

#[test]
fn content_digest_cache_observes_an_in_place_edit_in_the_same_run() {
    let root = tempfile::tempdir().expect("root");
    write_skill(root.path(), "FIRST_BODY");
    let run = run(root.path(), true);
    let arguments = args(json!("review"));

    let first = execute_skill(&run, &arguments);
    let first_structured = match &first.outcome {
        ToolOutcome::Success { content } => content.structured.as_ref().expect("first selection"),
        ToolOutcome::Error { failure } => panic!("first selection failed: {failure:?}"),
        ToolOutcome::Partial { .. } => panic!("skill selection cannot be partial"),
    };
    let first_digest = first_structured["provenance"]["content_digest"]
        .as_str()
        .expect("first digest")
        .to_string();

    write_skill(root.path(), "SECOND_BODY");
    let second = execute_skill(&run, &arguments);
    let second_structured = match &second.outcome {
        ToolOutcome::Success { content } => content.structured.as_ref().expect("second selection"),
        ToolOutcome::Error { failure } => panic!("second selection failed: {failure:?}"),
        ToolOutcome::Partial { .. } => panic!("skill selection cannot be partial"),
    };

    assert!(second.content().contains("SECOND_BODY"));
    assert!(!second.content().contains("FIRST_BODY"));
    assert_ne!(
        first_digest,
        second_structured["provenance"]["content_digest"]
            .as_str()
            .expect("second digest")
    );
}
