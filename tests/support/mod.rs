#![allow(dead_code)]

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::sync::OnceLock;

use openclaudia::permissions::PermissionManager;
use openclaudia::session::TaskManager;
use openclaudia::tools::{
    execute_tool_with_permission_required, execute_tool_with_tasks, FunctionCall, ToolCall,
    ToolResult, ToolRunContext,
};
use serde_json::Value;

pub fn tool_call(name: &str, args: &HashMap<String, Value>) -> ToolCall {
    ToolCall {
        id: format!("test-{name}"),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: name.to_string(),
            arguments: serde_json::to_string(args).expect("JSON values must serialize"),
        },
    }
}

pub fn dispatch_tool(name: &str, args: &HashMap<String, Value>) -> (String, bool) {
    legacy(&dispatch_tool_result(name, args))
}

pub fn dispatch_tool_result(name: &str, args: &HashMap<String, Value>) -> ToolResult {
    let root = std::env::current_dir().expect("test dispatch requires an explicit workspace");
    dispatch_tool_result_in(&root, name, args)
}

pub fn test_run_context(root: &Path) -> Arc<ToolRunContext> {
    ToolRunContext::builder(openclaudia::state::SessionId::new(), root)
        .working_directory(root)
        .read_only_roots(Vec::new())
        .read_write_roots(Vec::new())
        .environment_grants(HashMap::new())
        .workspace_access(openclaudia::tools::WorkspaceAccess::ReadWrite)
        .process(true)
        .network(true)
        .secrets(true)
        .provider("test")
        .ephemeral_background_jobs()
        .build()
        .expect("test workspace must produce a run capability")
}

pub fn shared_run_context() -> &'static Arc<ToolRunContext> {
    static RUN: OnceLock<Arc<ToolRunContext>> = OnceLock::new();
    RUN.get_or_init(|| test_run_context(Path::new(env!("CARGO_MANIFEST_DIR"))))
}

/// Build a run that explicitly snapshots the host process toolchain inputs.
///
/// Most integration tests intentionally use the deterministic default PATH.
/// Sandbox toolchain probes use this variant because production frontends
/// capture host startup grants and must support user-local Cargo installs.
pub fn host_toolchain_run_context(root: &Path) -> Arc<ToolRunContext> {
    ToolRunContext::builder(openclaudia::state::SessionId::new(), root)
        .working_directory(root)
        .read_only_roots(Vec::new())
        .read_write_roots(Vec::new())
        .environment_grants(HashMap::new())
        .executable_search_path(
            std::env::var_os("PATH")
                .unwrap_or_else(|| std::ffi::OsString::from("/usr/local/bin:/usr/bin:/bin")),
        )
        .host_home(dirs::home_dir().and_then(|path| path.canonicalize().ok()))
        .workspace_access(openclaudia::tools::WorkspaceAccess::ReadWrite)
        .process(true)
        .network(false)
        .secrets(false)
        .provider("host-toolchain-test")
        .ephemeral_background_jobs()
        .build()
        .expect("host toolchain test run must produce an explicit capability")
}

pub fn dispatch_tool_result_in(
    root: &Path,
    name: &str,
    args: &HashMap<String, Value>,
) -> ToolResult {
    let permission_manager = PermissionManager::unrestricted();
    let run = test_run_context(root);
    execute_tool_with_permission_required(
        &run,
        &tool_call(name, args),
        None,
        None,
        None,
        &permission_manager,
    )
}

pub fn dispatch_tool_result_for_run(
    run: &Arc<ToolRunContext>,
    name: &str,
    args: &HashMap<String, Value>,
) -> ToolResult {
    let permission_manager = PermissionManager::unrestricted();
    execute_tool_with_permission_required(
        run,
        &tool_call(name, args),
        None,
        None,
        None,
        &permission_manager,
    )
}

/// Enter through the production canonical executor, including catalog
/// admission, policy accounting, permission authorization, and dispatch.
pub fn dispatch_canonical_tool_result_for_run(
    run: &Arc<ToolRunContext>,
    name: &str,
    args: &HashMap<String, Value>,
) -> ToolResult {
    let permission_manager = PermissionManager::unrestricted_for_run(run);
    openclaudia::services::tool_executor::ToolExecutor::execute(
        openclaudia::services::tool_executor::ToolExecutorRequest {
            run_context: run,
            tool_call: &tool_call(name, args),
            memory_db: None,
            app_config: None,
            task_mgr: None,
            permission_mgr: &permission_manager,
            authorization: None,
            session_id: Some(run.session_id()),
            policy_enforcer: None,
        },
    )
}

pub fn dispatch_tool_with_tasks(
    name: &str,
    args: &HashMap<String, Value>,
    task_manager: Option<&mut TaskManager>,
) -> (String, bool) {
    let permission_manager = PermissionManager::unrestricted();
    let root = std::env::current_dir().expect("test dispatch requires an explicit workspace");
    let run = test_run_context(&root);
    legacy(&execute_tool_with_tasks(
        &run,
        &tool_call(name, args),
        None,
        None,
        task_manager,
        &permission_manager,
    ))
}

pub fn legacy(result: &ToolResult) -> (String, bool) {
    (result.content().to_string(), result.is_error())
}
