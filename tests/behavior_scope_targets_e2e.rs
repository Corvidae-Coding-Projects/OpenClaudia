use std::collections::HashMap;
use std::sync::Arc;

use openclaudia::modes::{BehaviorMode, BehaviorScopeTargets, Preset, RuntimeMode, Scope};
use openclaudia::state::SessionId;
use openclaudia::tools::{ToolRunContext, WorkspaceAccess};
use serde_json::json;

fn scoped_run(
    root: &std::path::Path,
    mode: BehaviorMode,
    targets: BehaviorScopeTargets,
) -> Result<Arc<ToolRunContext>, String> {
    ToolRunContext::builder(SessionId::new(), root)
        .working_directory(root)
        .read_only_roots(Vec::new())
        .read_write_roots(Vec::new())
        .environment_grants(HashMap::new())
        .mcp_environment_grants(HashMap::new())
        .executable_search_path("")
        .workspace_access(WorkspaceAccess::ReadWrite)
        .process(false)
        .network(false)
        .secrets(false)
        .runtime_mode(RuntimeMode::Behavioral(mode))
        .behavior_scope_targets(targets)
        .build()
}

#[test]
fn narrow_activation_requires_explicit_targets() {
    let root = tempfile::tempdir().expect("workspace");
    let error = scoped_run(
        root.path(),
        BehaviorMode::from_preset(Preset::Safe),
        BehaviorScopeTargets::workspace_root(),
    )
    .expect_err("implicit workspace approval must not activate narrow mode");

    assert!(
        error.contains("narrow behavioral scope requires"),
        "{error}"
    );
}

#[test]
fn narrow_scope_allows_the_approved_path_and_denies_escape() {
    let root = tempfile::tempdir().expect("workspace");
    std::fs::create_dir_all(root.path().join("src")).expect("src");
    std::fs::write(
        root.path().join("src/target.rs"),
        "pub const TARGET: u8 = 1;\n",
    )
    .expect("target");
    std::fs::write(
        root.path().join("src/other.rs"),
        "pub const OTHER: u8 = 2;\n",
    )
    .expect("other");
    let targets = BehaviorScopeTargets::from_user_values(
        root.path(),
        root.path(),
        &["src/target.rs".to_string()],
    )
    .expect("explicit target");
    let run = scoped_run(
        root.path(),
        BehaviorMode::from_preset(Preset::Safe),
        targets,
    )
    .expect("narrow run");

    assert!(run
        .admit_runtime_mode_tool(
            "write_file",
            &json!({"path": "src/target.rs", "content": "changed"}),
        )
        .is_ok());
    let error = run
        .admit_runtime_mode_tool(
            "write_file",
            &json!({"path": "src/other.rs", "content": "changed"}),
        )
        .expect_err("unapproved sibling must be denied");
    assert!(error.contains("denies tool 'write_file'"), "{error}");
}

#[test]
fn adjacent_scope_allows_one_directory_neighborhood_only() {
    let root = tempfile::tempdir().expect("workspace");
    std::fs::create_dir_all(root.path().join("src/feature")).expect("feature");
    std::fs::create_dir_all(root.path().join("src/other")).expect("other");
    std::fs::write(root.path().join("src/feature/main.rs"), "").expect("target");
    let targets = BehaviorScopeTargets::from_user_values(
        root.path(),
        root.path(),
        &["src/feature/main.rs".to_string()],
    )
    .expect("explicit target");
    let mut mode = BehaviorMode::from_preset(Preset::Extend);
    mode.scope = Scope::Adjacent;
    let run = scoped_run(root.path(), mode, targets).expect("adjacent run");

    assert!(run
        .admit_runtime_mode_tool(
            "write_file",
            &json!({"path": "src/feature/helper.rs", "content": ""}),
        )
        .is_ok());
    assert!(run
        .admit_runtime_mode_tool(
            "write_file",
            &json!({"path": "src/other/escape.rs", "content": ""}),
        )
        .is_err());
}

#[test]
fn non_path_effects_require_an_exact_tool_target() {
    let root = tempfile::tempdir().expect("workspace");
    let without_bash = BehaviorScopeTargets::from_user_values(
        root.path(),
        root.path(),
        &["src/lib.rs".to_string()],
    )
    .expect("path target");
    let mode = BehaviorMode::from_preset(Preset::Safe);
    let denied = scoped_run(root.path(), mode.clone(), without_bash).expect("narrow run");
    assert!(denied
        .admit_runtime_mode_tool("bash", &json!({"command": "cargo check"}))
        .is_err());

    let with_bash = BehaviorScopeTargets::from_user_values(
        root.path(),
        root.path(),
        &["src/lib.rs".to_string(), "tool:bash".to_string()],
    )
    .expect("path and tool targets");
    let allowed = scoped_run(root.path(), mode, with_bash).expect("narrow run");
    assert!(allowed
        .admit_runtime_mode_tool("bash", &json!({"command": "cargo check"}))
        .is_ok());
}

#[test]
fn default_adjacent_scope_preserves_existing_run_capabilities() {
    let root = tempfile::tempdir().expect("workspace");
    let run = scoped_run(
        root.path(),
        BehaviorMode::from_preset(Preset::Extend),
        BehaviorScopeTargets::workspace_root(),
    )
    .expect("default adjacent run");

    assert!(run
        .admit_runtime_mode_tool("enter_plan_mode", &json!({}))
        .is_ok());
    assert!(run
        .admit_runtime_mode_tool(
            "read_file",
            &json!({"path": run.private_temp_root().join("owned.txt")}),
        )
        .is_ok());
}

#[test]
fn target_set_and_mode_transition_share_one_generation() {
    let root = tempfile::tempdir().expect("workspace");
    std::fs::create_dir_all(root.path().join("src")).expect("src");
    let run = scoped_run(
        root.path(),
        BehaviorMode::from_preset(Preset::Extend),
        BehaviorScopeTargets::workspace_root(),
    )
    .expect("default adjacent run");
    let before = run.runtime_mode();

    let error = run
        .transition_runtime_mode(RuntimeMode::Behavioral(BehaviorMode::from_preset(
            Preset::Safe,
        )))
        .expect_err("narrow transition cannot reuse implicit targets");
    assert!(
        error.contains("narrow behavioral scope requires"),
        "{error}"
    );
    assert_eq!(
        run.runtime_mode(),
        before,
        "failed transition must be atomic"
    );

    let explicit =
        BehaviorScopeTargets::from_user_values(root.path(), root.path(), &["src".to_string()])
            .expect("explicit target");
    let after = run
        .transition_runtime_mode_scoped(
            RuntimeMode::Behavioral(BehaviorMode::from_preset(Preset::Safe)),
            explicit.clone(),
        )
        .expect("scoped transition");
    assert_eq!(after.generation, before.generation + 1);
    assert_eq!(after.scope_targets, explicit);

    let child = run
        .derive_frontend_session(SessionId::new(), root.path(), root.path(), "local")
        .expect("derived frontend run");
    assert_eq!(child.runtime_mode().scope_targets, after.scope_targets);
    assert!(child
        .admit_runtime_mode_tool("write_file", &json!({"path": "outside.rs", "content": ""}),)
        .is_err());
}

#[test]
fn scope_targets_round_trip_with_session_state() {
    let root = tempfile::tempdir().expect("workspace");
    let targets = BehaviorScopeTargets::from_user_values(
        root.path(),
        root.path(),
        &["src/lib.rs".to_string(), "tool:bash".to_string()],
    )
    .expect("targets");
    let mut state = openclaudia::state::SessionState::new(root.path().to_path_buf());
    state.conversation.behavior_scope_targets = targets.clone();

    let encoded = serde_json::to_string(&state).expect("serialize");
    let decoded: openclaudia::state::SessionState =
        serde_json::from_str(&encoded).expect("deserialize");
    assert_eq!(decoded.conversation.behavior_scope_targets, targets);
}
