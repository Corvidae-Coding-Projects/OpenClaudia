//! End-to-end trust, capability, freshness, containment, and provider tests
//! for scoped skill packages.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]

use openclaudia::skills::{
    activate_skill_for_run, activate_user_invocable_skill_for_run, load_skills_for_run,
    revoke_project_skills_at, trust_project_skills_at, SkillActivationTrigger,
    SkillCapabilityPolicy, SkillRunAccess,
};
use openclaudia::tools::{ToolRunContext, WorkspaceAccess};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

mod support;

fn write_skill(root: &Path, package: &str, frontmatter: &str, body: &str) {
    let directory = root.join(".openclaudia/skills").join(package);
    std::fs::create_dir_all(&directory).expect("skill package directory");
    std::fs::write(
        directory.join("SKILL.md"),
        format!("---\n{frontmatter}\n---\n{body}\n"),
    )
    .expect("skill package");
}

fn run_with_access(root: &Path, access: SkillRunAccess) -> Arc<ToolRunContext> {
    ToolRunContext::builder(openclaudia::state::SessionId::new(), root)
        .working_directory(root)
        .read_only_roots(Vec::new())
        .read_write_roots(Vec::new())
        .environment_grants(HashMap::new())
        .skill_access(access)
        .workspace_access(WorkspaceAccess::ReadWrite)
        .process(false)
        .network(false)
        .secrets(false)
        .provider("skill-capability-test")
        .build()
        .expect("skill run")
}

fn project_policy(
    allowed_tools: Vec<String>,
    allow_model: bool,
    allow_effort: bool,
    allow_hooks: bool,
) -> SkillCapabilityPolicy {
    SkillCapabilityPolicy::project(allowed_tools, allow_model, allow_effort, allow_hooks)
        .expect("bounded project skill policy")
}

#[test]
fn project_policy_rejects_unbounded_effect_tool_grants() {
    for specification in ["Bash", "Bash(*)", "Write(**)", "Edit", "WebFetch"] {
        let error =
            SkillCapabilityPolicy::project(vec![specification.to_string()], false, false, false)
                .expect_err("unbounded effect grant must be rejected");
        assert!(error.to_string().contains("unbounded"));
    }
    assert!(SkillCapabilityPolicy::project(
        vec!["Bash(git status *)".to_string()],
        false,
        false,
        false,
    )
    .is_ok());
}

#[test]
fn trust_store_revocation_makes_project_skills_inert_in_the_same_run() {
    let project = tempfile::tempdir().expect("project");
    let host = tempfile::tempdir().expect("host state");
    let store = host.path().join("project-skill-trust.json");
    write_skill(
        project.path(),
        "review",
        "name: review\ndescription: review this project",
        "TRUSTED_REVIEW_BODY",
    );
    let policy = project_policy(Vec::new(), false, false, false);
    trust_project_skills_at(project.path(), &store, policy).expect("trust project skills");
    let access = SkillRunAccess::capture_project_from_trust_store(project.path(), &store)
        .expect("capture trust receipt");
    let run = run_with_access(project.path(), access);

    assert_eq!(load_skills_for_run(&run).len(), 1);
    assert!(activate_user_invocable_skill_for_run(&run, "review").is_ok());

    revoke_project_skills_at(project.path(), &store).expect("revoke project skills");

    assert!(load_skills_for_run(&run).is_empty());
    assert!(activate_user_invocable_skill_for_run(&run, "review").is_err());
}

#[test]
fn explicit_activation_intersects_effects_with_the_host_policy() {
    let project = tempfile::tempdir().expect("project");
    write_skill(
        project.path(),
        "review",
        r"name: review
description: review this project
allowed_tools:
  - read_file
  - write_file
model: gpt-5.6
effort: high
hooks:
  pre_tool_use:
    - matcher: read_file
      hooks:
        - type: command
          command: echo scoped
          shell: false
          timeout: 5",
        "CAPABILITY_INTERSECTION_BODY",
    );
    let policy = project_policy(vec!["read_file".to_string()], true, false, true);
    let access = SkillRunAccess::host_granted_project(project.path(), policy)
        .expect("host-granted project skills");
    let run = run_with_access(project.path(), access);

    let explicit =
        activate_user_invocable_skill_for_run(&run, "review").expect("explicit skill activation");
    assert_eq!(
        explicit.allowed_tools(),
        Some(["read_file".to_string()].as_slice())
    );
    assert_eq!(explicit.model(), Some("gpt-5.6"));
    assert_eq!(explicit.effort(), None);
    assert_eq!(
        explicit.hooks().map(|hooks| hooks.pre_tool_use.len()),
        Some(1)
    );

    let model_selected =
        activate_skill_for_run(&run, "review", SkillActivationTrigger::ModelSelection)
            .expect("model skill selection");
    assert!(model_selected.allowed_tools().is_none());
    assert!(model_selected.model().is_none());
    assert!(model_selected.effort().is_none());
    assert!(model_selected.hooks().is_none());
}

#[test]
fn conditional_skill_body_appears_only_after_a_real_matching_file_read() {
    let project = tempfile::tempdir().expect("project");
    std::fs::create_dir_all(project.path().join("src")).expect("source directory");
    std::fs::write(
        project.path().join("src/lib.rs"),
        "pub const MARKER: bool = true;\n",
    )
    .expect("source file");
    write_skill(
        project.path(),
        "rust-review",
        "name: rust-review\ndescription: review Rust\npaths: [\"src/**/*.rs\"]",
        "CONDITIONAL_RUST_SKILL_BODY",
    );
    let access = SkillRunAccess::host_granted_project(
        project.path(),
        project_policy(Vec::new(), false, false, false),
    )
    .expect("host-granted project skills");
    let run = run_with_access(project.path(), access);

    let before = openclaudia::prompt::build_prompt_context_for_run(
        &openclaudia::modes::BehaviorMode::default(),
        &run,
    );
    assert!(before
        .reference_context()
        .contains("Available skill metadata"));
    assert!(!before
        .reference_context()
        .contains("CONDITIONAL_RUST_SKILL_BODY"));

    let arguments = HashMap::from([("path".to_string(), json!("src/lib.rs"))]);
    let result = support::dispatch_tool_result_for_run(&run, "read_file", &arguments);
    assert!(
        !result.is_error(),
        "the production read path must record the touched file"
    );

    let after = openclaudia::prompt::build_prompt_context_for_run(
        &openclaudia::modes::BehaviorMode::default(),
        &run,
    );
    assert!(after
        .reference_context()
        .contains("CONDITIONAL_RUST_SKILL_BODY"));
    assert!(!after
        .stable_prefix()
        .contains("CONDITIONAL_RUST_SKILL_BODY"));
    assert!(!after
        .dynamic_suffix()
        .contains("CONDITIONAL_RUST_SKILL_BODY"));
}

#[test]
fn same_layer_duplicate_names_are_rejected_deterministically() {
    let project = tempfile::tempdir().expect("project");
    write_skill(
        project.path(),
        "first",
        "name: duplicate\ndescription: first",
        "FIRST_DUPLICATE_BODY",
    );
    write_skill(
        project.path(),
        "second",
        "name: duplicate\ndescription: second",
        "SECOND_DUPLICATE_BODY",
    );
    let access = SkillRunAccess::host_granted_project(
        project.path(),
        project_policy(Vec::new(), false, false, false),
    )
    .expect("host-granted project skills");
    let run = run_with_access(project.path(), access);

    assert!(load_skills_for_run(&run).is_empty());
}

#[cfg(unix)]
#[test]
fn symlinked_skill_files_cannot_escape_the_catalog_root() {
    use std::os::unix::fs::symlink;

    let project = tempfile::tempdir().expect("project");
    let outside = tempfile::tempdir().expect("outside");
    let outside_skill = outside.path().join("outside.md");
    std::fs::write(
        &outside_skill,
        "---\nname: escaped\ndescription: escaped\n---\nESCAPED_BODY\n",
    )
    .expect("outside skill");
    let skill_root = project.path().join(".openclaudia/skills");
    std::fs::create_dir_all(&skill_root).expect("skill root");
    symlink(&outside_skill, skill_root.join("escaped.md")).expect("skill symlink");
    let access = SkillRunAccess::host_granted_project(
        project.path(),
        project_policy(Vec::new(), false, false, false),
    )
    .expect("host-granted project skills");
    let run = run_with_access(project.path(), access);

    assert!(load_skills_for_run(&run).is_empty());
}

#[cfg(unix)]
#[test]
fn symlinked_project_skill_root_cannot_escape_the_trusted_workspace() {
    use std::os::unix::fs::symlink;

    let project = tempfile::tempdir().expect("project");
    let outside = tempfile::tempdir().expect("outside");
    std::fs::write(
        outside.path().join("escaped.md"),
        "---\nname: escaped\ndescription: escaped\n---\nESCAPED_ROOT_BODY\n",
    )
    .expect("outside skill");
    std::fs::create_dir_all(project.path().join(".openclaudia")).expect("project config root");
    symlink(outside.path(), project.path().join(".openclaudia/skills"))
        .expect("skill-root symlink");
    let access = SkillRunAccess::host_granted_project(
        project.path(),
        project_policy(Vec::new(), false, false, false),
    )
    .expect("host-granted project skills");
    let run = run_with_access(project.path(), access);

    assert!(load_skills_for_run(&run).is_empty());
}

#[test]
fn parent_workspace_grant_does_not_authorize_a_nested_workspace() {
    let parent = tempfile::tempdir().expect("parent workspace");
    let nested = parent.path().join("nested");
    std::fs::create_dir_all(&nested).expect("nested workspace");
    write_skill(
        &nested,
        "nested",
        "name: nested\ndescription: nested",
        "NESTED_BODY",
    );
    let parent_access = SkillRunAccess::host_granted_project(
        parent.path(),
        project_policy(Vec::new(), false, false, false),
    )
    .expect("parent grant");
    let nested_run = run_with_access(&nested, parent_access);

    assert!(load_skills_for_run(&nested_run).is_empty());
}

#[test]
fn selected_skill_reference_survives_supported_provider_adapters_without_system_authority() {
    let project = tempfile::tempdir().expect("project");
    write_skill(
        project.path(),
        "provider-review",
        "name: provider-review\ndescription: provider review",
        "PROVIDER_SKILL_REFERENCE_BODY",
    );
    let access = SkillRunAccess::host_granted_project(
        project.path(),
        project_policy(Vec::new(), false, false, false),
    )
    .expect("host-granted project skills");
    let run = run_with_access(project.path(), access);
    let activation = activate_user_invocable_skill_for_run(&run, "provider-review")
        .expect("provider skill activation");
    let context = openclaudia::prompt::build_prompt_context_with_items_for_run(
        &openclaudia::modes::BehaviorMode::default(),
        &run,
        vec![activation.context_item("provider.skill.explicit")],
        openclaudia::context::ContextBudget::default(),
    );
    let messages = context.prepare_chat_messages(&[openclaudia::proxy::ChatMessage {
        role: "user".to_string(),
        content: openclaudia::proxy::MessageContent::Text("Use the selected skill".to_string()),
        name: None,
        tool_calls: None,
        tool_call_id: None,
        extra: HashMap::new(),
    }]);

    for (provider, model) in [
        ("openai", "gpt-5.6"),
        ("anthropic", "claude-sonnet-4-6"),
        ("google", "gemini-3.5-flash"),
        ("ollama", "llama3.2"),
    ] {
        let adapter = openclaudia::providers::get_adapter(provider).expect("provider adapter");
        let request = openclaudia::proxy::ChatCompletionRequest {
            model: model.to_string(),
            messages: messages.clone(),
            temperature: None,
            max_tokens: Some(512),
            stream: Some(false),
            tools: None,
            tool_choice: None,
            extra: HashMap::new(),
        };
        let body = adapter
            .transform_request_with_thinking(
                &request,
                &openclaudia::config::ThinkingConfig::default(),
            )
            .unwrap_or_else(|error| panic!("{provider} request transform failed: {error}"));
        let rendered = body.to_string();
        assert!(
            rendered.contains("PROVIDER_SKILL_REFERENCE_BODY"),
            "{provider} dropped the selected skill reference"
        );
        assert!(!rendered.contains("<skill"));
        assert_system_projection_excludes_marker(provider, &body);
    }
}

fn assert_system_projection_excludes_marker(provider: &str, body: &Value) {
    let marker = "PROVIDER_SKILL_REFERENCE_BODY";
    for key in ["system", "systemInstruction", "system_instruction"] {
        assert!(
            !body
                .get(key)
                .is_some_and(|value| value.to_string().contains(marker)),
            "{provider} promoted the skill reference through {key}"
        );
    }
    if let Some(messages) = body.get("messages").and_then(Value::as_array) {
        for message in messages {
            if message.get("role").and_then(Value::as_str) == Some("system") {
                assert!(
                    !message.to_string().contains(marker),
                    "{provider} promoted the skill reference into a system message"
                );
            }
        }
    }
}
