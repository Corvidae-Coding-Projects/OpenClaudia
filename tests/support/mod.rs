#![allow(dead_code)]

use std::collections::HashMap;

use openclaudia::permissions::PermissionManager;
use openclaudia::session::TaskManager;
use openclaudia::tools::{
    execute_tool_with_permission_required, execute_tool_with_tasks, FunctionCall, ToolCall,
    ToolResult,
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
    let permission_manager = PermissionManager::unrestricted();
    execute_tool_with_permission_required(
        &tool_call(name, args),
        None,
        None,
        None,
        &permission_manager,
    )
}

pub fn dispatch_tool_with_tasks(
    name: &str,
    args: &HashMap<String, Value>,
    task_manager: Option<&mut TaskManager>,
) -> (String, bool) {
    let permission_manager = PermissionManager::unrestricted();
    legacy(&execute_tool_with_tasks(
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
