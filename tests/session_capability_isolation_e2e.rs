//! Adversarial S-019 coverage for explicit run capabilities.
//!
//! These tests exercise the public dispatch boundary. They intentionally use
//! distinct roots and run generations, never process CWD or thread-local
//! identity, so a passing result proves the capability object—not test
//! serialization—provides isolation.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::unwrap_used)]

use openclaudia::permissions::PermissionManager;
use openclaudia::runtime::CancellationReason;
use openclaudia::tools::{
    execute_tool, execute_tool_full, execute_tool_without_context, retire_run, FunctionCall,
    ToolFailureCode, ToolOutcome, ToolResource, ToolRunContext, WorkspaceAccess,
};
use openclaudia::tools::{ToolCall, ToolResult};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Arc, Barrier};

#[allow(clippy::needless_pass_by_value)] // Test call sites construct one-shot JSON payloads inline.
fn call(name: &str, arguments: Value) -> ToolCall {
    ToolCall {
        id: format!("s019-{name}"),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: name.to_string(),
            arguments: arguments.to_string(),
        },
    }
}

fn assert_failure_code(result: &ToolResult, expected: ToolFailureCode) {
    let ToolOutcome::Error { failure } = result.outcome() else {
        panic!("expected typed failure {expected:?}, got {result:?}");
    };
    assert_eq!(failure.code, expected, "unexpected failure: {failure:?}");
}

fn run(
    root: &std::path::Path,
    owner: &str,
    environment_grants: HashMap<String, String>,
) -> Arc<ToolRunContext> {
    ToolRunContext::builder(openclaudia::state::SessionId::new(), root)
        .read_only_roots(Vec::new())
        .read_write_roots(Vec::new())
        .process_owner(owner)
        .environment_grants(environment_grants)
        .workspace_access(WorkspaceAccess::ReadWrite)
        .process(true)
        .network(false)
        .secrets(false)
        .provider("s019-adversarial")
        .build()
        .expect("explicit adversarial run")
}

fn shell_id(result: &ToolResult) -> String {
    result
        .content()
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("Background shell started with ID: "))
        .expect("background result must expose shell id")
        .to_string()
}

fn environment_probe_command() -> String {
    let first = "S019_ENV_A";
    let second = "S019_ENV_B";
    format!("printf '%s|%s' \"${{{first}:-missing}}\" \"${{{second}:-missing}}\"")
}

struct BackgroundShellGuard {
    run: Arc<ToolRunContext>,
    shell_id: Option<String>,
}

impl BackgroundShellGuard {
    fn new(run: &Arc<ToolRunContext>, result: &ToolResult) -> Self {
        Self {
            run: Arc::clone(run),
            shell_id: Some(shell_id(result)),
        }
    }

    fn id(&self) -> &str {
        self.shell_id.as_deref().expect("live shell guard")
    }

    fn kill(&mut self) -> ToolResult {
        let shell_id = self.id().to_string();
        let result = execute_tool(
            &self.run,
            &call("kill_shell", json!({"shell_id": shell_id})),
        );
        if !result.is_error() {
            self.shell_id = None;
        }
        result
    }
}

impl Drop for BackgroundShellGuard {
    fn drop(&mut self) {
        if let Some(shell_id) = self.shell_id.take() {
            let _ = execute_tool(
                &self.run,
                &call("kill_shell", json!({"shell_id": shell_id})),
            );
        }
    }
}

#[test]
fn missing_run_fails_closed_without_reading_or_writing_cwd() {
    let fixture = tempfile::tempdir_in(".").expect("cwd fixture");
    let secret = fixture.path().join("secret.txt");
    let target = fixture.path().join("must-not-exist.txt");
    std::fs::write(&secret, "S019-CWD-SECRET").expect("secret fixture");

    let read = execute_tool_without_context(&call("read_file", json!({"path": secret})));
    assert_failure_code(&read, ToolFailureCode::Unavailable);
    assert!(!read.content().contains("S019-CWD-SECRET"));

    let write = execute_tool_without_context(&call(
        "write_file",
        json!({"path": target, "content": "ambient write"}),
    ));
    assert_failure_code(&write, ToolFailureCode::Unavailable);
    assert!(
        !target.exists(),
        "unbound dispatch must not mutate process CWD"
    );
}

#[test]
fn absent_resource_grants_return_typed_unavailable_results() {
    let root = tempfile::tempdir().expect("workspace");
    let read_only = ToolRunContext::builder(openclaudia::state::SessionId::new(), root.path())
        .read_only_roots(Vec::new())
        .read_write_roots(Vec::new())
        .workspace_access(WorkspaceAccess::ReadOnly)
        .process(false)
        .network(false)
        .secrets(false)
        .environment_grants(HashMap::new())
        .provider("s019-resource-denial")
        .build()
        .expect("restricted run");

    let write_target = root.path().join("denied.txt");
    let write = execute_tool(
        &read_only,
        &call(
            "write_file",
            json!({"path": write_target, "content": "denied"}),
        ),
    );
    assert_failure_code(&write, ToolFailureCode::Unavailable);
    assert!(!write_target.exists());

    let process = execute_tool(
        &read_only,
        &call("bash", json!({"command": "printf denied"})),
    );
    assert_failure_code(&process, ToolFailureCode::Unavailable);

    let pdf = execute_tool(
        &read_only,
        &call("read_file", json!({"path": "unopened.pdf"})),
    );
    assert_failure_code(&pdf, ToolFailureCode::Unavailable);
    assert!(
        pdf.content().contains("Process"),
        "PDF parsing must fail at typed process preflight before binary or file lookup: {pdf:?}"
    );

    let mcp = execute_tool(&read_only, &call("list_mcp_resources", json!({})));
    assert_failure_code(&mcp, ToolFailureCode::Unavailable);
    assert!(
        mcp.content().contains("Process"),
        "MCP I/O must fail at capability preflight before manager lookup: {mcp:?}"
    );

    let network = execute_tool(
        &read_only,
        &call("web_fetch", json!({"url": "https://example.com/"})),
    );
    assert_failure_code(&network, ToolFailureCode::Unavailable);

    let subagent = execute_tool_full(
        &read_only,
        &call(
            "task",
            json!({
                "description": "must not start",
                "prompt": "must not reach a provider",
                "subagent_type": "explore"
            }),
        ),
        None,
        None,
        &PermissionManager::unrestricted_for_run(&read_only),
    );
    assert_failure_code(&subagent, ToolFailureCode::Unavailable);
    assert!(
        subagent.content().contains("Network"),
        "task must fail at capability preflight before configuration or provider dispatch: {subagent:?}"
    );

    assert!(matches!(
        read_only.require(ToolResource::Secrets),
        Err(openclaudia::tools::ToolCapabilityError::Unavailable {
            resource: ToolResource::Secrets,
            ..
        })
    ));
}

#[test]
fn library_backed_crosslink_help_needs_no_process_but_store_access_needs_write() {
    let root = tempfile::tempdir().expect("crosslink capability workspace");
    let read_only = ToolRunContext::builder(openclaudia::state::SessionId::new(), root.path())
        .read_only_roots(Vec::new())
        .read_write_roots(Vec::new())
        .workspace_access(WorkspaceAccess::ReadOnly)
        .process(false)
        .network(false)
        .secrets(false)
        .environment_grants(HashMap::new())
        .provider("s019-crosslink-resource-classification")
        .build()
        .expect("read-only run");

    let help = execute_tool(&read_only, &call("crosslink", json!({"operation": "help"})));
    assert!(
        !help.is_error(),
        "static help must not require a process: {help:?}"
    );

    let list = execute_tool(&read_only, &call("crosslink", json!({"operation": "list"})));
    assert_failure_code(&list, ToolFailureCode::Unavailable);
    assert!(
        list.content().contains("WorkspaceWrite"),
        "store-backed operation must fail at typed write preflight: {list:?}"
    );
    assert!(!root.path().join(".crosslink").exists());
}

#[test]
#[cfg(feature = "browser")]
fn browser_only_tools_require_process_before_network_dispatch() {
    let root = tempfile::tempdir().expect("browser capability workspace");
    let network_only = ToolRunContext::builder(openclaudia::state::SessionId::new(), root.path())
        .read_only_roots(Vec::new())
        .read_write_roots(Vec::new())
        .workspace_access(WorkspaceAccess::ReadOnly)
        .process(false)
        .network(true)
        .secrets(false)
        .environment_grants(HashMap::new())
        .provider("s019-browser-process-denial")
        .build()
        .expect("network-only run");

    let direct_fetch = execute_tool(
        &network_only,
        &call("web_fetch", json!({"url": "not-a-url"})),
    );
    assert!(direct_fetch.is_error());
    assert!(
        !direct_fetch.content().contains("Process"),
        "direct web_fetch validation must remain available without browser process authority: {direct_fetch:?}"
    );

    let fetch = execute_tool(
        &network_only,
        &call("web_browser", json!({"url": "https://example.com/"})),
    );
    assert_failure_code(&fetch, ToolFailureCode::Unavailable);
    assert!(
        fetch.content().contains("Process"),
        "browser-only dispatch must fail before egress when process authority is absent: {fetch:?}"
    );
}

#[test]
#[allow(clippy::too_many_lines)] // Keep both symmetric concurrent run scenarios visibly paired.
fn concurrent_roots_and_environment_grants_do_not_cross() {
    let root_a = tempfile::tempdir().expect("workspace A");
    let root_b = tempfile::tempdir().expect("workspace B");
    let secret_a = root_a.path().join("secret.txt");
    let secret_b = root_b.path().join("secret.txt");
    std::fs::write(&secret_a, "SECRET-A").expect("secret A");
    std::fs::write(&secret_b, "SECRET-B").expect("secret B");

    let run_a = run(
        root_a.path(),
        "s019-root-a",
        HashMap::from([("S019_ENV_A".to_string(), "alpha".to_string())]),
    );
    let run_b = run(
        root_b.path(),
        "s019-root-b",
        HashMap::from([("S019_ENV_B".to_string(), "beta".to_string())]),
    );
    let barrier = Arc::new(Barrier::new(2));

    let worker_a = {
        let run = Arc::clone(&run_a);
        let barrier = Arc::clone(&barrier);
        let own_target = root_a.path().join("owned-a.txt");
        let foreign_secret = secret_b;
        let foreign_target = root_b.path().join("cross-a.txt");
        std::thread::spawn(move || {
            barrier.wait();
            let own_write = execute_tool(
                &run,
                &call(
                    "write_file",
                    json!({"path": own_target, "content": "owned by A"}),
                ),
            );
            let cross_read =
                execute_tool(&run, &call("read_file", json!({"path": foreign_secret})));
            let cross_write = execute_tool(
                &run,
                &call(
                    "write_file",
                    json!({"path": foreign_target, "content": "cross A"}),
                ),
            );
            let environment = execute_tool(
                &run,
                &call("bash", json!({"command": environment_probe_command()})),
            );
            (own_write, cross_read, cross_write, environment)
        })
    };

    let worker_b = {
        let run = Arc::clone(&run_b);
        let barrier = Arc::clone(&barrier);
        let own_target = root_b.path().join("owned-b.txt");
        let foreign_secret = secret_a;
        let foreign_target = root_a.path().join("cross-b.txt");
        std::thread::spawn(move || {
            barrier.wait();
            let own_write = execute_tool(
                &run,
                &call(
                    "write_file",
                    json!({"path": own_target, "content": "owned by B"}),
                ),
            );
            let cross_read =
                execute_tool(&run, &call("read_file", json!({"path": foreign_secret})));
            let cross_write = execute_tool(
                &run,
                &call(
                    "write_file",
                    json!({"path": foreign_target, "content": "cross B"}),
                ),
            );
            let environment = execute_tool(
                &run,
                &call("bash", json!({"command": environment_probe_command()})),
            );
            (own_write, cross_read, cross_write, environment)
        })
    };

    let (own_a, read_b_from_a, write_b_from_a, env_a) = worker_a.join().expect("worker A");
    let (own_b, read_a_from_b, write_a_from_b, env_b) = worker_b.join().expect("worker B");
    assert!(!own_a.is_error(), "A own write failed: {own_a:?}");
    assert!(!own_b.is_error(), "B own write failed: {own_b:?}");
    assert!(read_b_from_a.is_error());
    assert!(read_a_from_b.is_error());
    assert!(write_b_from_a.is_error());
    assert!(write_a_from_b.is_error());
    assert!(!read_b_from_a.content().contains("SECRET-B"));
    assert!(!read_a_from_b.content().contains("SECRET-A"));
    assert!(!root_b.path().join("cross-a.txt").exists());
    assert!(!root_a.path().join("cross-b.txt").exists());

    assert!(!env_a.is_error(), "A environment command failed: {env_a:?}");
    assert!(!env_b.is_error(), "B environment command failed: {env_b:?}");
    assert_eq!(env_a.content(), "alpha|missing");
    assert_eq!(env_b.content(), "missing|beta");
}

#[test]
fn approval_bindings_rotate_with_each_exact_run_generation() {
    let root = tempfile::tempdir().expect("approval workspace");
    let first = run(root.path(), "approval-first", HashMap::new());
    let second = run(root.path(), "approval-second", HashMap::new());

    let first_binding = openclaudia::permissions::ApprovalBinding::for_run(&first);
    let second_binding = openclaudia::permissions::ApprovalBinding::for_run(&second);
    assert_ne!(first.run_id(), second.run_id());
    assert_ne!(first.generation(), second.generation());
    assert_ne!(first_binding, second_binding);
}

#[test]
fn project_skill_lookup_is_bound_to_the_exact_run_root() {
    let root_a = tempfile::tempdir().expect("skill workspace A");
    let root_b = tempfile::tempdir().expect("skill workspace B");
    let name_a = "s019-project-skill-a-2fcb18c9";
    let name_b = "s019-project-skill-b-8d039614";
    let skill_a = root_a.path().join(".openclaudia/skills").join(name_a);
    let skill_b = root_b.path().join(".openclaudia/skills").join(name_b);
    std::fs::create_dir_all(&skill_a).expect("skill A directory");
    std::fs::create_dir_all(&skill_b).expect("skill B directory");
    std::fs::write(
        skill_a.join("SKILL.md"),
        format!("---\nname: {name_a}\ndescription: run A only\n---\nS019-SKILL-BODY-A\n"),
    )
    .expect("skill A fixture");
    std::fs::write(
        skill_b.join("SKILL.md"),
        format!("---\nname: {name_b}\ndescription: run B only\n---\nS019-SKILL-BODY-B\n"),
    )
    .expect("skill B fixture");

    let run_a = run(root_a.path(), "s019-skill-a", HashMap::new());
    let run_b = run(root_b.path(), "s019-skill-b", HashMap::new());
    let own_a = execute_tool(&run_a, &call("skill", json!({"name": name_a})));
    let own_b = execute_tool(&run_b, &call("skill", json!({"name": name_b})));
    let foreign_from_a = execute_tool(&run_a, &call("skill", json!({"name": name_b})));
    let foreign_from_b = execute_tool(&run_b, &call("skill", json!({"name": name_a})));

    assert!(
        !own_a.is_error(),
        "run A could not load its skill: {own_a:?}"
    );
    assert!(
        !own_b.is_error(),
        "run B could not load its skill: {own_b:?}"
    );
    assert!(own_a.content().contains("S019-SKILL-BODY-A"));
    assert!(own_b.content().contains("S019-SKILL-BODY-B"));
    assert!(foreign_from_a.is_error(), "run A loaded B's project skill");
    assert!(foreign_from_b.is_error(), "run B loaded A's project skill");
    assert!(!foreign_from_a.content().contains("S019-SKILL-BODY-B"));
    assert!(!foreign_from_b.content().contains("S019-SKILL-BODY-A"));
}

#[test]
fn prompt_skill_catalog_is_concurrently_bound_to_each_run_root() {
    let root_a = tempfile::tempdir().expect("prompt skill workspace A");
    let root_b = tempfile::tempdir().expect("prompt skill workspace B");
    let name_a = "000-s019-prompt-skill-a-09c65a8d";
    let name_b = "000-s019-prompt-skill-b-ec2aa24f";
    for (root, name, description) in [
        (root_a.path(), name_a, "prompt run A only"),
        (root_b.path(), name_b, "prompt run B only"),
    ] {
        let skill_dir = root.join(".openclaudia/skills").join(name);
        std::fs::create_dir_all(&skill_dir).expect("prompt skill directory");
        std::fs::write(
            skill_dir.join("SKILL.md"),
            format!("---\nname: {name}\ndescription: {description}\n---\nbody\n"),
        )
        .expect("prompt skill fixture");
    }

    let run_a = run(root_a.path(), "s019-prompt-skill-a", HashMap::new());
    let run_b = run(root_b.path(), "s019-prompt-skill-b", HashMap::new());
    let barrier = Arc::new(Barrier::new(2));
    let prompt_a = {
        let run = Arc::clone(&run_a);
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            openclaudia::prompt::build_prompt_context_for_run(
                &openclaudia::modes::BehaviorMode::default(),
                &run,
            )
            .reference_context()
            .to_string()
        })
    };
    let prompt_b = {
        let run = Arc::clone(&run_b);
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            openclaudia::prompt::build_prompt_context_for_run(
                &openclaudia::modes::BehaviorMode::default(),
                &run,
            )
            .reference_context()
            .to_string()
        })
    };

    let reference_a = prompt_a.join().expect("prompt A thread");
    let reference_b = prompt_b.join().expect("prompt B thread");
    assert!(reference_a.contains(name_a));
    assert!(!reference_a.contains(name_b));
    assert!(reference_b.contains(name_b));
    assert!(!reference_b.contains(name_a));

    let compatibility = openclaudia::prompt::build_prompt_context(
        &openclaudia::modes::BehaviorMode::default(),
        root_a.path().to_str(),
    );
    assert!(
        !compatibility.reference_context().contains(name_a),
        "a display-only working-directory string must not authorize project skill discovery"
    );
}

#[cfg(unix)]
#[test]
fn background_processes_are_exact_run_scoped() {
    let root_a = tempfile::tempdir().expect("workspace A");
    let root_b = tempfile::tempdir().expect("workspace B");
    let run_a = run(root_a.path(), "s019-process-a", HashMap::new());
    let run_b = run(root_b.path(), "s019-process-b", HashMap::new());

    let spawned_a = execute_tool(
        &run_a,
        &call(
            "bash",
            json!({"command": "sleep 30", "run_in_background": true}),
        ),
    );
    assert!(!spawned_a.is_error(), "spawn A: {spawned_a:?}");
    let mut shell_a = BackgroundShellGuard::new(&run_a, &spawned_a);

    let spawned_b = execute_tool(
        &run_b,
        &call(
            "bash",
            json!({"command": "sleep 30", "run_in_background": true}),
        ),
    );
    assert!(!spawned_b.is_error(), "spawn B: {spawned_b:?}");
    let mut shell_b = BackgroundShellGuard::new(&run_b, &spawned_b);

    let cross_observe = execute_tool(
        &run_a,
        &call("bash_output", json!({"shell_id": shell_b.id()})),
    );
    let cross_kill = execute_tool(
        &run_a,
        &call("kill_shell", json!({"shell_id": shell_b.id()})),
    );
    assert!(
        cross_observe.is_error(),
        "foreign output leaked: {cross_observe:?}"
    );
    assert!(
        cross_kill.is_error(),
        "foreign kill succeeded: {cross_kill:?}"
    );

    let b_still_running = execute_tool(
        &run_b,
        &call("bash_output", json!({"shell_id": shell_b.id()})),
    );
    assert!(
        !b_still_running.is_error(),
        "B lost its process: {b_still_running:?}"
    );

    let cleanup_a = shell_a.kill();
    let cleanup_b = shell_b.kill();
    assert!(!cleanup_a.is_error(), "cleanup A: {cleanup_a:?}");
    assert!(!cleanup_b.is_error(), "cleanup B: {cleanup_b:?}");
}

#[cfg(unix)]
#[test]
fn retiring_one_run_cancels_only_its_owned_lifecycle_resources() {
    let root_a = tempfile::tempdir().expect("workspace A");
    let root_b = tempfile::tempdir().expect("workspace B");
    let run_a = run(root_a.path(), "s019-retire-a", HashMap::new());
    let run_b = run(root_b.path(), "s019-retire-b", HashMap::new());
    let spawned_a = execute_tool(
        &run_a,
        &call(
            "bash",
            json!({"command": "sleep 30", "run_in_background": true}),
        ),
    );
    let spawned_b = execute_tool(
        &run_b,
        &call(
            "bash",
            json!({"command": "sleep 30", "run_in_background": true}),
        ),
    );
    assert!(!spawned_a.is_error(), "spawn A: {spawned_a:?}");
    assert!(!spawned_b.is_error(), "spawn B: {spawned_b:?}");
    let mut shell_a = BackgroundShellGuard::new(&run_a, &spawned_a);
    let mut shell_b = BackgroundShellGuard::new(&run_b, &spawned_b);

    retire_run(&run_a);
    shell_a.shell_id = None;
    assert!(run_a.runtime().cancellation().is_cancelled());
    assert!(!run_b.runtime().cancellation().is_cancelled());
    let retired_output = execute_tool(
        &run_a,
        &call("bash_output", json!({"shell_id": shell_id(&spawned_a)})),
    );
    assert!(
        retired_output.is_error(),
        "retired run retained its shell: {retired_output:?}"
    );
    let live_output = execute_tool(
        &run_b,
        &call("bash_output", json!({"shell_id": shell_b.id()})),
    );
    assert!(
        !live_output.is_error(),
        "retiring A disturbed B: {live_output:?}"
    );
    let cleanup_b = shell_b.kill();
    assert!(!cleanup_b.is_error(), "cleanup B: {cleanup_b:?}");
}

#[test]
fn cancellation_and_descriptor_bindings_are_run_scoped() {
    let root_a = tempfile::tempdir().expect("workspace A");
    let root_b = tempfile::tempdir().expect("workspace B");
    let run_a = run(root_a.path(), "s019-cancel-a", HashMap::new());
    let run_b = run(root_b.path(), "s019-cancel-b", HashMap::new());
    let cancellation_a = run_a.runtime().cancellation();
    let cancellation_b = run_b.runtime().cancellation();

    assert_ne!(cancellation_a.root_id(), cancellation_b.root_id());
    let receipt = cancellation_a.cancel(CancellationReason::User);
    assert_eq!(receipt.root, run_a.runtime().descriptor().cancellation_root);
    assert!(cancellation_a.is_cancelled());
    assert!(!cancellation_b.is_cancelled());

    assert_eq!(run_a.runtime().descriptor().run_id, run_a.run_id());
    assert_eq!(
        run_a.runtime().descriptor().capabilities.generation,
        run_a.generation()
    );
    assert_eq!(
        run_a.runtime().descriptor().workspace.root(),
        run_a.project_root()
    );
    assert_ne!(
        run_a.runtime().descriptor().capabilities.manifest_digest,
        run_b.runtime().descriptor().capabilities.manifest_digest
    );
}
