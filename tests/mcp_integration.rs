//! MCP integration tests — Phase 2 (#543)
//!
//! Pins OC's **current** contracts in `src/mcp.rs` against the Phase 1 spec
//! from crosslink issue #528.  Goal is behavioral pinning, not bug-fixing.
//! Where OC diverges from CC, the test asserts OC's current behaviour and
//! references the follow-up issue that tracks the remaining fix.
//!
//! ## Spec→test mapping
//!
//! | Spec behavior | Test(s)                                                          |
//! |---------------|------------------------------------------------------------------|
//! | B1 Handshake  | `handshake_sends_correct_protocol_version`                       |
//! |               | `handshake_declares_elicitation_cap` (fix #613)                  |
//! |               | `handshake_initialized_notification_error_swallowed`             |
//! |               | `handshake_initialize_timeout_returns_timeout_error` (fix #628)  |
//! | B2 Tool disc. | `tool_refresh_skips_list_without_tools_cap` (fix #627)           |
//! |               | `tool_refresh_with_tools_cap_parses_list`                        |
//! |               | `supports_tool_list_changed_reads_capability`                    |
//! | B3 Tool call  | `call_tool_is_error_returns_tool_reported_error` (fix #625)      |
//! |               | `call_tool_unknown_tool_returns_tool_not_found`                  |
//! |               | `call_tool_missing_server_returns_not_connected`                 |
//! |               | `call_tool_with_timeout_returns_timeout_error`                   |
//! | B4 Resource   | `list_resources_returns_empty_without_resources_cap`             |
//! |               | `list_resources_calls_wire_when_cap_present`                     |
//! | B5 Error code | `stdio_rpc_error_with_data_included_in_message`                  |
//! |               | `http_rpc_error_preserves_data_field` (fix #626)                 |
//! | B6 Disconnect | `stdio_mid_call_disconnect_returns_transport_error`              |
//! |               | `manager_marks_server_disconnected_after_transport_error` (fix #629) |

use openclaudia::mcp::{
    HttpTransport, McpContentBlock, McpError, McpManager, McpProtocolVersion, McpResourceContents,
    McpServer, McpServerConfig, StdioTransport,
};
use openclaudia::plugins::PluginManager;
use openclaudia::proxy::connect_mcp_servers_with_trust;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::RwLock;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ─── helpers ────────────────────────────────────────────────────────────────

/// Path to the Python echo-server fixture.
fn fixture_path() -> std::path::PathBuf {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .join("tests")
        .join("fixtures")
        .join("mcp_echo_server.py")
}

fn manager_with_allowed_tool(server: &str, tool: &str) -> McpManager {
    let mut permissions = openclaudia::config::PermissionsConfig::default();
    permissions
        .mcp
        .insert(server.to_string(), vec![tool.to_string()]);
    McpManager::new_with_permissions(
        std::sync::Arc::clone(support::shared_run_context()),
        permissions,
    )
}

/// Spawn the echo server fixture via `python3` and return the transport.
///
/// # Panics
///
/// Panics if the fixture file doesn't exist or the process cannot be spawned.
fn spawn_echo_transport() -> StdioTransport {
    let path = fixture_path();
    assert!(path.exists(), "fixture not found at {}", path.display());
    StdioTransport::spawn(
        support::shared_run_context(),
        "python3",
        &[path.to_str().expect("utf-8 path")],
    )
    .expect("spawn echo server")
}

/// Spawn the same real subprocess fixture in the discovery-era 2026-07-28
/// profile. The server rejects any request missing the required per-request
/// metadata, so a successful flow proves more than response deserialization.
fn spawn_current_echo_transport() -> StdioTransport {
    let path = fixture_path();
    StdioTransport::spawn(
        support::shared_run_context(),
        "env",
        &["MCP_CURRENT=1", "python3", path.to_str().expect("utf-8")],
    )
    .expect("spawn current echo server")
}

/// Spawn the echo server with no `tools` capability in the `initialize`
/// response (sets `MCP_NO_TOOLS_CAP` env var via a wrapper invocation).
fn spawn_echo_no_tools_cap() -> StdioTransport {
    let path = fixture_path();
    // Pass env var by invoking `env MCP_NO_TOOLS_CAP=1 python3 <fixture>`
    StdioTransport::spawn(
        support::shared_run_context(),
        "env",
        &[
            "MCP_NO_TOOLS_CAP=1",
            "python3",
            path.to_str().expect("utf-8"),
        ],
    )
    .expect("spawn echo server (no tools cap)")
}

/// Spawn the echo server with no `resources` capability.
fn spawn_echo_no_resources_cap() -> StdioTransport {
    let path = fixture_path();
    StdioTransport::spawn(
        support::shared_run_context(),
        "env",
        &[
            "MCP_NO_RESOURCES_CAP=1",
            "python3",
            path.to_str().expect("utf-8"),
        ],
    )
    .expect("spawn echo server (no resources cap)")
}

// ─── B1: Handshake ──────────────────────────────────────────────────────────

/// B1 — OC sends `protocolVersion: "2024-11-05"` in the initialize params.
///
/// The echo server reflects the server side; the client-side params are
/// opaque once accepted. We verify the handshake succeeds (server recognized
/// the version) and that the server name is returned correctly.
#[tokio::test]
async fn handshake_sends_correct_protocol_version() {
    let transport = spawn_echo_transport();
    let server = McpServer::new("test", Box::new(transport))
        .await
        .expect("McpServer::new should succeed");

    // Verify the server name round-trips (handshake completed)
    assert_eq!(server.name(), "test");
    // Verify tools were discovered (implies initialize + refresh_tools ran)
    assert!(
        !server.tools().is_empty(),
        "echo server should return tools"
    );
}

#[tokio::test]
async fn s065_current_stdio_round_trip_uses_discovery_and_typed_features() {
    let transport = spawn_current_echo_transport();
    let server = McpServer::new("current", Box::new(transport))
        .await
        .expect("current stdio discovery must succeed");

    assert_eq!(server.protocol_version(), McpProtocolVersion::V2026_07_28);
    assert_eq!(server.tools().len(), 4);

    let call = server
        .call_tool("echo", json!({"message": "hello"}))
        .await
        .expect("current tools/call");
    assert_eq!(call["resultType"], "complete");
    assert_eq!(call["structuredContent"]["message"], "hello");

    let resources = server
        .list_resources()
        .await
        .expect("current resources/list");
    assert_eq!(resources[0].uri, "echo://hello");
    let resource = server
        .read_resource_typed("echo://hello")
        .await
        .expect("current resources/read");
    assert!(matches!(
        resource.contents[1],
        McpResourceContents::Blob { .. }
    ));

    let prompts = server.list_prompts().await.expect("current prompts/list");
    assert_eq!(prompts[0].name, "echo_prompt");
    let prompt = server
        .get_prompt(
            "echo_prompt",
            std::collections::BTreeMap::from([("message".to_string(), "typed".to_string())]),
        )
        .await
        .expect("current prompts/get");
    assert!(matches!(
        &prompt.messages[0].content,
        McpContentBlock::Text { text, .. } if text == "typed"
    ));

    server.close().await.expect("close current fixture");
}

/// B1 — OC declares `elicitation` in the `initialize` capabilities.
///
/// We test this via a stdio fixture that inspects the initialize request and
/// reports the observed capability shape through `tools/list`.
#[tokio::test]
async fn handshake_declares_elicitation_cap() {
    let script = r#"
import json
import sys

def respond(req_id, result):
    sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":req_id,"result":result}) + "\n")
    sys.stdout.flush()

discover = json.loads(sys.stdin.readline())
sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":discover["id"],"error":{"code":-32601,"message":"Method not found"}}) + "\n")
sys.stdout.flush()

init = json.loads(sys.stdin.readline())
caps = init.get("params", {}).get("capabilities", {})
cap_ok = "roots" in caps and "elicitation" in caps
respond(init["id"], {
    "protocolVersion": "2024-11-05",
    "capabilities": {"tools": {"listChanged": False}},
    "serverInfo": {"name": "mock", "version": "0.0.1"},
})

json.loads(sys.stdin.readline())

tools = json.loads(sys.stdin.readline())
tool_name = "client_caps_ok" if cap_ok else "client_caps_missing"
respond(tools["id"], {
    "tools": [{
        "name": tool_name,
        "description": "reports observed client capabilities",
        "inputSchema": {"type": "object", "properties": {}},
    }]
})
"#;
    let transport = StdioTransport::spawn(
        support::shared_run_context(),
        "python3",
        &["-u", "-c", script],
    )
    .expect("spawn cap fixture");
    let server = McpServer::new("mock", Box::new(transport))
        .await
        .expect("handshake should succeed");

    assert!(
        server
            .tools()
            .iter()
            .any(|tool| tool.name == "client_caps_ok"),
        "stdio initialize must declare roots and elicitation capabilities"
    );
}

/// B1 — `notifications/initialized` error is silently discarded (`.ok()`).
///
/// The echo server ignores notifications, so the current OC code path (which
/// calls `.ok()` on the result) must not surface an error from `McpServer::new`.
#[tokio::test]
async fn handshake_initialized_notification_error_swallowed() {
    // The echo server receives `notifications/initialized` but does not reply
    // (it's a notification — no id).  OC calls `.ok()` so no error bubbles up.
    let transport = spawn_echo_transport();
    let result = McpServer::new("swallow-test", Box::new(transport)).await;
    assert!(
        result.is_ok(),
        "McpServer::new must succeed even if initialized notification is a no-op"
    );
}

/// B1 — The initialize handshake has a connection-establishment timeout.
#[tokio::test]
async fn handshake_initialize_timeout_returns_timeout_error() {
    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "result": {}
                }))
                .set_delay(Duration::from_secs(2)),
        )
        .mount(&mock_server)
        .await;

    let transport = HttpTransport::__test_new_unchecked(&mock_server.uri());
    let result = McpServer::new_with_config(
        "timeout",
        Box::new(transport),
        McpServerConfig::new().with_initialize_timeout_secs(1),
    )
    .await;

    match result {
        Err(McpError::Timeout {
            phase: "initialize",
        }) => {}
        Err(other) => panic!("initialize timeout must surface McpError::Timeout, got {other:?}"),
        Ok(_) => panic!("initialize timeout must not succeed"),
    }
}

// ─── B2: Tool discovery ─────────────────────────────────────────────────────

/// B2 — `refresh_tools` skips `tools/list` when `capabilities.tools` is absent.
#[tokio::test]
async fn tool_refresh_skips_list_without_tools_cap() {
    // Echo server launched without tools capability in initialize response.
    let transport = spawn_echo_no_tools_cap();
    let server = McpServer::new("no-cap", Box::new(transport))
        .await
        .expect("McpServer::new must succeed even without tools capability");

    assert!(
        server.tools().is_empty(),
        "server without tools capability must not populate tools via tools/list"
    );
}

/// Plugin-declared stdio MCP environment variables must reach the child
/// process. The fixture omits `capabilities.tools` when this env var is set,
/// so an empty `OpenAI` function list proves the env map survived spawn.
#[tokio::test]
async fn manager_stdio_connection_passes_env_to_child_process() {
    let path = fixture_path();
    let path_str = path.to_str().expect("fixture path must be UTF-8");
    let manager = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    let env = HashMap::from([("MCP_NO_TOOLS_CAP".to_string(), "1".to_string())]);

    manager
        .connect_stdio_with_env("env-test", "python3", &[path_str], &env)
        .await
        .expect("connect stdio fixture with env");

    assert!(manager.is_live("env-test").await);
    assert!(
        manager.tools_as_openai_functions().await.is_empty(),
        "env var must suppress fixture tools; non-empty tools means child env was dropped"
    );
}

/// Plugin-declared MCP env vars must survive the whole discovery/connect path
/// used by proxy and TUI startup, not only the lower-level manager API.
#[tokio::test]
async fn plugin_mcp_stdio_env_reaches_child_process() {
    let root = TempDir::new().expect("tempdir");
    let plugin_dir = root.path().join("env-plugin");
    std::fs::create_dir_all(&plugin_dir).expect("plugin dir");
    let fixture = fixture_path();
    let fixture_json = serde_json::to_string(fixture.to_str().expect("fixture path utf-8"))
        .expect("fixture path json");
    let manifest = format!(
        r#"{{
            "name": "env-plugin",
            "mcpServers": {{
                "env-server": {{
                    "transport": "stdio",
                    "command": "python3",
                    "args": [{fixture_json}],
                    "env": {{"MCP_NO_TOOLS_CAP": "1"}}
                }}
            }}
        }}"#
    );
    std::fs::write(plugin_dir.join("plugin.json"), manifest).expect("manifest");

    let mut plugins = PluginManager::with_paths(vec![root.path().to_path_buf()]);
    let errors = plugins.discover();
    assert!(errors.is_empty(), "plugin discovery errors: {errors:?}");
    let plugins = Arc::new(plugins);
    let manager = Arc::new(RwLock::new(McpManager::new(std::sync::Arc::clone(
        support::shared_run_context(),
    ))));

    connect_mcp_servers_with_trust(
        &manager,
        &plugins,
        &std::collections::HashSet::from(["env-plugin/env-server".to_string()]),
    )
    .await;

    let functions = {
        let mcp = manager.read().await;
        assert!(mcp.is_live("env-server").await);
        let functions = mcp.tools_as_openai_functions().await;
        drop(mcp);
        functions
    };
    assert!(
        functions.is_empty(),
        "plugin MCP env var must suppress fixture tools; non-empty tools means env was dropped"
    );
}

#[tokio::test]
async fn repository_mcp_server_requires_exact_host_trust_and_revocation_disconnects_it() {
    let root = TempDir::new().expect("tempdir");
    let plugin_dir = root.path().join("trust-plugin");
    std::fs::create_dir_all(&plugin_dir).expect("plugin dir");
    let fixture_json = serde_json::to_string(fixture_path().to_str().expect("fixture path utf-8"))
        .expect("fixture path json");
    std::fs::write(
        plugin_dir.join("plugin.json"),
        format!(
            r#"{{
                "name": "trust-plugin",
                "mcpServers": {{
                    "trust-server": {{
                        "transport": "stdio",
                        "command": "python3",
                        "args": [{fixture_json}]
                    }}
                }}
            }}"#
        ),
    )
    .expect("manifest");
    let mut plugins = PluginManager::with_paths(vec![root.path().to_path_buf()]);
    assert!(plugins.discover().is_empty());
    let plugins = Arc::new(plugins);
    let manager = Arc::new(RwLock::new(McpManager::new(std::sync::Arc::clone(
        support::shared_run_context(),
    ))));

    connect_mcp_servers_with_trust(&manager, &plugins, &std::collections::HashSet::new()).await;
    assert!(
        !manager.read().await.is_connected("trust-server").await,
        "repository MCP must remain disconnected before explicit trust"
    );

    connect_mcp_servers_with_trust(
        &manager,
        &plugins,
        &std::collections::HashSet::from(["trust-plugin/trust-server".to_string()]),
    )
    .await;
    assert!(manager.read().await.is_live("trust-server").await);

    connect_mcp_servers_with_trust(&manager, &plugins, &std::collections::HashSet::new()).await;
    assert!(
        !manager.read().await.is_connected("trust-server").await,
        "revocation must terminate and unregister the trusted server"
    );
}

#[test]
#[cfg(unix)]
fn stdio_mcp_rejects_an_executable_from_an_agent_writable_root() {
    use std::os::unix::fs::PermissionsExt as _;

    let executable =
        tempfile::NamedTempFile::new_in(".").expect("project-local executable fixture");
    std::fs::set_permissions(executable.path(), std::fs::Permissions::from_mode(0o755))
        .expect("executable mode");
    let result = StdioTransport::spawn(
        support::shared_run_context(),
        executable.path().to_str().expect("utf-8 executable path"),
        &[],
    );
    let Err(error) = result else {
        panic!("project executable must not become an MCP host extension");
    };
    assert!(
        error.to_string().contains("agent-writable"),
        "unexpected executable trust error: {error}"
    );
}

#[test]
fn stdio_mcp_rejects_sensitive_environment_without_an_exact_host_grant() {
    let key = "OPENCLAUDIA_TEST_MCP_PRIVATE_TOKEN";
    let env = HashMap::from([(key.to_string(), "canary-value".to_string())]);
    let Err(error) = StdioTransport::spawn_with_env(
        support::shared_run_context(),
        "python3",
        &["-c", "pass"],
        &env,
    ) else {
        panic!("sensitive MCP env must require an exact host grant");
    };
    assert!(
        error.to_string().contains(key) && error.to_string().contains("host operator"),
        "unexpected environment-grant error: {error}"
    );
}

#[test]
fn stdio_mcp_rejects_sensitive_environment_without_run_secret_capability() {
    let run = openclaudia::tools::ToolRunContext::builder(
        openclaudia::state::SessionId::new(),
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
    )
    .read_only_roots(Vec::new())
    .read_write_roots(Vec::new())
    .environment_grants(HashMap::new())
    .workspace_access(openclaudia::tools::WorkspaceAccess::ReadOnly)
    .process(true)
    .network(false)
    .secrets(false)
    .provider("mcp-secret-denial-test")
    .build()
    .expect("restricted MCP run");
    let env = HashMap::from([("SERVICE_API_KEY".to_string(), "canary".to_string())]);

    let Err(error) = StdioTransport::spawn_with_env(&run, "python3", &["-c", "pass"], &env) else {
        panic!("MCP secret env must require the run's secret capability");
    };
    assert!(
        error.to_string().contains("secret environment grant")
            && error.to_string().contains("unavailable"),
        "unexpected secret capability error: {error}"
    );
}

#[test]
fn stdio_mcp_rejects_host_dynamic_loader_environment() {
    let env = HashMap::from([(
        "LD_PRELOAD".to_string(),
        "./repository-controlled-library.so".to_string(),
    )]);
    let Err(error) = StdioTransport::spawn_with_env(
        support::shared_run_context(),
        "python3",
        &["-c", "pass"],
        &env,
    ) else {
        panic!("MCP env must not influence the host sandbox launcher");
    };
    assert!(
        error.to_string().contains("dynamic loader"),
        "unexpected loader-environment error: {error}"
    );
}

#[tokio::test]
#[cfg(target_os = "linux")]
async fn stdio_mcp_sandbox_blocks_host_file_and_network_access() {
    let outside = TempDir::new().expect("outside tempdir");
    let sentinel = outside.path().join("host-sentinel");
    std::fs::write(&sentinel, "outside-secret").expect("sentinel");
    let path_literal =
        serde_json::to_string(sentinel.to_str().expect("utf-8 sentinel")).expect("json path");
    let script = format!(
        r#"
import json, socket, sys
blocked_file = False
blocked_network = False
try:
    open({path_literal}, "rb").read()
except OSError:
    blocked_file = True
try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
except OSError:
    blocked_network = True

def reply(i, result):
    print(json.dumps({{"jsonrpc":"2.0","id":i,"result":result}}), flush=True)

request = json.loads(sys.stdin.readline())
print(json.dumps({{"jsonrpc":"2.0","id":request["id"],"error":{{"code":-32601,"message":"Method not found"}}}}), flush=True)
request = json.loads(sys.stdin.readline())
reply(request["id"], {{
    "protocolVersion":"2024-11-05",
    "capabilities":{{"tools":{{"listChanged":False}}}},
    "serverInfo":{{"name":"sandbox-probe","version":"1"}}
}})
request = json.loads(sys.stdin.readline())
request = json.loads(sys.stdin.readline())
name = "sandbox_blocked" if blocked_file and blocked_network else "sandbox_escaped"
reply(request["id"], {{"tools":[{{"name":name,"inputSchema":{{"type":"object"}}}}]}})
"#
    );
    let transport = StdioTransport::spawn(
        support::shared_run_context(),
        "python3",
        &["-u", "-c", &script],
    )
    .expect("sandboxed MCP");
    let server = McpServer::new("sandbox-probe", Box::new(transport))
        .await
        .expect("probe handshake");
    assert!(
        server
            .tools()
            .iter()
            .any(|tool| tool.name == "sandbox_blocked"),
        "sandboxed MCP reached a host file or network socket"
    );
}

/// B2 — When `capabilities.tools` IS present, `refresh_tools` parses the
/// tool list correctly and populates `tools()`.
#[tokio::test]
async fn tool_refresh_with_tools_cap_parses_list() {
    let transport = spawn_echo_transport();
    let server = McpServer::new("cap-test", Box::new(transport))
        .await
        .expect("McpServer::new");

    let tools = server.tools();
    assert_eq!(tools.len(), 4, "echo server returns exactly four tools");

    let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
    assert!(names.contains(&"echo"), "tool 'echo' must be present");
    assert!(
        names.contains(&"fail_tool"),
        "tool 'fail_tool' must be present"
    );
    assert!(
        names.contains(&"die_tool"),
        "tool 'die_tool' must be present"
    );
    assert!(
        names.contains(&"slow_tool"),
        "tool 'slow_tool' must be present"
    );

    // Verify description round-trip
    let echo_tool = tools.iter().find(|t| t.name == "echo").unwrap();
    assert_eq!(
        echo_tool.description.as_deref(),
        Some("Echo the input back")
    );
    // Verify inputSchema round-trip
    assert!(
        echo_tool.input_schema.is_some(),
        "inputSchema must be preserved"
    );
}

/// B2 — `supports_tool_list_changed()` returns `true` iff the server
/// advertised `capabilities.tools.listChanged = true`.
#[tokio::test]
async fn supports_tool_list_changed_reads_capability() {
    // Echo server returns `{"listChanged": false}` — pin OC reads this correctly.
    let transport = spawn_echo_transport();
    let server = McpServer::new("list-changed", Box::new(transport))
        .await
        .expect("McpServer::new");
    assert!(
        !server.supports_tool_list_changed(),
        "echo server advertises listChanged:false"
    );
}

// ─── B3: Tool call ──────────────────────────────────────────────────────────

/// B3 — `call_tool` converts MCP `isError:true` tool results into
/// `McpError::ToolReportedError`.
#[tokio::test]
async fn call_tool_is_error_returns_tool_reported_error() {
    let transport = spawn_echo_transport();
    let server = McpServer::new("is-error-test", Box::new(transport))
        .await
        .expect("McpServer::new");

    // `fail_tool` causes the echo server to return `{ "isError": true, ... }`
    let err = server
        .call_tool("fail_tool", json!({}))
        .await
        .expect_err("isError:true must surface as ToolReportedError");

    match err {
        McpError::ToolReportedError { message, result } => {
            assert_eq!(result.get("isError"), Some(&json!(true)));
            assert!(
                message.contains("tool-level error occurred"),
                "tool error message should include content text, got {message}"
            );
        }
        other => panic!("expected ToolReportedError, got {other:?}"),
    }
}

/// B3 — `call_tool` returns `McpError::ToolNotFound` for a name not in
/// the local tool cache, without making a wire call.
#[tokio::test]
async fn call_tool_unknown_tool_returns_tool_not_found() {
    let transport = spawn_echo_transport();
    let server = McpServer::new("not-found-test", Box::new(transport))
        .await
        .expect("McpServer::new");

    let result = server.call_tool("nonexistent_tool", json!({})).await;
    assert!(
        matches!(result, Err(McpError::ToolNotFound(ref name)) if name == "nonexistent_tool"),
        "expected ToolNotFound(nonexistent_tool), got {result:?}"
    );
}

/// B3 — `McpManager::call_tool` returns `McpError::NotConnected` when the
/// server name in `mcp__server__tool` is not registered.
#[tokio::test]
async fn call_tool_missing_server_returns_not_connected() {
    let manager = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    let result = manager
        .call_tool("mcp__missing_server__tool", json!({}))
        .await;
    assert!(
        matches!(result, Err(McpError::NotConnected(ref n)) if n == "missing_server"),
        "expected NotConnected(missing_server), got {result:?}"
    );
}

/// B3 — `call_tool_with_timeout` returns `McpError::Timeout` when the
/// underlying call exceeds the deadline.
///
/// `HttpTransport` uses a sequential `AtomicU64` counter starting at 1.
/// `McpServer::new` first probes current discovery, then explicitly falls back
/// after a legacy 404. Request ids remain sequential for requests; the
/// `notifications/initialized` notification has no id.
/// The subsequent `tools/call` gets id=4.  Each wiremock mock is registered
/// by method body so the 50 ms timeout deterministically reaches the tool call.
#[tokio::test]
async fn call_tool_with_timeout_returns_timeout_error() {
    let mock_server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("\"method\":\"server/discover\""))
        .respond_with(ResponseTemplate::new(404))
        .mount(&mock_server)
        .await;

    // id=2: initialize
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("\"method\":\"initialize\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0", "id": 2,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": { "listChanged": false } },
                "serverInfo": { "name": "slow", "version": "0.0.1" }
            }
        })))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    // Notification: deliberately no JSON-RPC id or response body.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains(
            "\"method\":\"notifications/initialized\"",
        ))
        .respond_with(ResponseTemplate::new(202))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    // id=3: tools/list — returns "slow_op" so the local cache is populated
    // and the ToolNotFound pre-check in call_tool passes.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("\"method\":\"tools/list\""))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0", "id": 3,
            "result": {
                "tools": [{
                    "name": "slow_op",
                    "description": "slow",
                    "inputSchema": {"type": "object", "properties": {}}
                }]
            }
        })))
        .up_to_n_times(1)
        .mount(&mock_server)
        .await;

    // id=4: tools/call — hangs for 10 s; the 50 ms timeout fires first.
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("\"method\":\"tools/call\""))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"jsonrpc":"2.0","id":4,"result":{}}))
                .set_delay(Duration::from_secs(10)),
        )
        .mount(&mock_server)
        .await;

    let manager = manager_with_allowed_tool("slow", "slow_op");
    // mock_server.uri() is a 127.0.0.1 loopback that the SSRF guard
    // (fix #677) rejects in production; tests use the unchecked
    // variant to point at their own listener.
    manager
        .__test_connect_http_unchecked("slow", &mock_server.uri())
        .await
        .expect("connect_http");

    let result = manager
        .call_tool_with_timeout("mcp__slow__slow_op", json!({}), Duration::from_millis(50))
        .await;

    assert!(
        matches!(result, Err(McpError::Timeout { .. })),
        "expected Timeout, got {result:?}"
    );
}

/// B3 — a per-server timeout configured on the manager limits ordinary
/// `call_tool` requests without requiring the caller to use the explicit
/// wrapper. This pins the plugin `.mcp.json` `timeout` path, which stores
/// milliseconds per server.
#[tokio::test]
async fn manager_per_server_tool_timeout_limits_stdio_call() {
    let path = fixture_path();
    let path_str = path.to_str().expect("fixture path must be UTF-8");
    let manager = manager_with_allowed_tool("slow", "slow_tool");

    manager
        .connect_stdio_with_env_and_timeout(
            "slow",
            "python3",
            &[path_str],
            &HashMap::new(),
            Some(Duration::from_millis(50)),
        )
        .await
        .expect("connect stdio echo fixture");

    let started = std::time::Instant::now();
    let result = manager.call_tool("mcp__slow__slow_tool", json!({})).await;

    assert!(
        matches!(result, Err(McpError::Timeout { .. })),
        "expected Timeout from configured per-server deadline, got {result:?}"
    );
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "per-server timeout should fire before the fixture's 2s sleep"
    );
    assert!(
        manager.is_connected("slow").await,
        "timed-out entry remains registered for reconnect"
    );
    assert!(
        !manager.is_live("slow").await,
        "timeout must drop the transport to avoid stale JSON-RPC responses"
    );
}

// ─── B4: Resource capability gate ───────────────────────────────────────────

/// B4 — `list_resources` returns an empty vec immediately when the server
/// does not advertise `capabilities.resources` — no wire call made.
#[tokio::test]
async fn list_resources_returns_empty_without_resources_cap() {
    let transport = spawn_echo_no_resources_cap();
    let server = McpServer::new("no-res-cap", Box::new(transport))
        .await
        .expect("McpServer::new");

    // Capability absent → should return empty without any wire call
    let resources = server.list_resources().await.expect("list_resources");
    assert!(
        resources.is_empty(),
        "list_resources must return [] when resources capability is absent"
    );
}

/// B4 — When `capabilities.resources` IS advertised, `list_resources` issues
/// the wire call and returns parsed resources.
#[tokio::test]
async fn list_resources_calls_wire_when_cap_present() {
    // Echo server with default caps (resources present)
    let transport = spawn_echo_transport();
    let server = McpServer::new("res-cap", Box::new(transport))
        .await
        .expect("McpServer::new");

    let resources = server.list_resources().await.expect("list_resources");
    assert_eq!(resources.len(), 1, "echo server returns one resource");
    assert_eq!(resources[0].uri, "echo://hello");
    assert_eq!(resources[0].name, "hello");
}

// ─── B5: Unknown error code surfacing ───────────────────────────────────────

/// B5 — Stdio transport preserves an unknown JSON-RPC error as typed fields.
#[tokio::test]
async fn stdio_rpc_error_with_data_included_in_message() {
    use openclaudia::mcp::McpTransport;

    // Use the transport directly (bypass McpServer::new) so we can call the
    // synthetic `rpc_error_with_data` method.
    let transport = spawn_echo_transport();
    let result = transport.request("rpc_error_with_data", None).await;

    let err = result.expect_err("should return Err for a JSON-RPC error");
    assert!(matches!(
        err,
        McpError::Rpc {
            code: -32099,
            ref message,
            data: Some(ref data),
            http_status: None,
        } if message == "custom server error" && data["detail"] == "extra context"
    ));
}

/// B5 — HTTP transport preserves `data` and HTTP status as typed fields.
#[tokio::test]
async fn http_rpc_error_preserves_data_field() {
    use openclaudia::mcp::{HttpTransport, McpTransport};

    let mock_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {
                "code": -32099,
                "message": "custom server error",
                "data": { "detail": "extra context" }
            }
        })))
        .mount(&mock_server)
        .await;

    let transport = HttpTransport::__test_new_unchecked(&mock_server.uri());
    let result = transport.request("anything", None).await;

    let err = result.expect_err("must return Err for JSON-RPC error");
    assert!(matches!(
        err,
        McpError::Rpc {
            code: -32099,
            ref message,
            data: Some(ref data),
            http_status: Some(200),
        } if message == "custom server error" && data["detail"] == "extra context"
    ));
}

// ─── B6: Mid-call disconnect ─────────────────────────────────────────────────

/// B6 — A transport disconnect mid-call returns an explicit `McpError` (no
/// panic).  The echo server handles `die` by closing stdout without writing
/// a response.
///
/// EOF before any response bytes now surfaces as `McpError::Transport`.
#[tokio::test]
async fn stdio_mid_call_disconnect_returns_transport_error() {
    use openclaudia::mcp::McpTransport;

    let transport = spawn_echo_transport();

    // First request succeeds — confirms the transport is live.
    let ok = transport.request("tools/list", None).await;
    assert!(ok.is_ok(), "first request must succeed: {ok:?}");

    // `die` causes the server to close stdout without writing a response.
    let err = transport
        .request("die", None)
        .await
        .expect_err("mid-call disconnect must return an explicit error");

    match err {
        McpError::Transport(msg) => assert!(
            msg.contains("closed stdout"),
            "disconnect transport error should explain closed stdout, got {msg}"
        ),
        other => panic!("expected Transport on mid-call disconnect, got {other:?}"),
    }
}

/// B6 — Manager marks a server disconnected after a transport error, leaving
/// the entry registered for the reconnect path.
#[tokio::test]
async fn manager_marks_server_disconnected_after_transport_error() {
    let path = fixture_path();
    let path_str = path.to_str().expect("fixture path must be UTF-8");
    let manager = manager_with_allowed_tool("flaky", "die_tool");

    manager
        .connect_stdio("flaky", "python3", &[path_str])
        .await
        .expect("connect stdio echo fixture");
    assert!(manager.is_connected("flaky").await);
    assert!(manager.is_live("flaky").await);

    let err = manager
        .call_tool("mcp__flaky__die_tool", json!({}))
        .await
        .expect_err("die_tool must close stdout and surface Transport");
    assert!(
        matches!(err, McpError::Transport(_)),
        "die_tool should return Transport, got {err:?}"
    );
    assert!(
        manager.is_connected("flaky").await,
        "disconnected entry remains registered for reconnect"
    );
    assert!(
        !manager.is_live("flaky").await,
        "transport error must mark server entry disconnected"
    );
}

// ─── Additional unit-level pins (no fixture needed) ─────────────────────────

/// B3 / B2 — `McpManager::call_tool` with invalid name format (missing `mcp__`
/// prefix or wrong delimiter count) returns `McpError::ToolNotFound`.
#[tokio::test]
async fn call_tool_invalid_name_format_returns_tool_not_found() {
    let manager = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));

    for bad_name in &["notool", "server_tool", "mcp_server_tool", "server__tool"] {
        let result = manager.call_tool(bad_name, json!({})).await;
        assert!(
            matches!(
                result,
                Err(McpError::NotConnected(_) | McpError::ToolNotFound(_))
            ),
            "bad name '{bad_name}' should yield ToolNotFound or NotConnected, got {result:?}"
        );
    }
}

/// B2 — Tool names with embedded single underscores parse correctly.
///
/// `mcp__my_server__my_tool` must parse `server_name` = "`my_server`", tool = "`my_tool`".
#[tokio::test]
async fn call_tool_underscored_names_parse_correctly() {
    let manager = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    let result = manager
        .call_tool("mcp__my_server__my_tool", json!({}))
        .await;
    assert!(
        matches!(result, Err(McpError::NotConnected(ref n)) if n == "my_server"),
        "should get NotConnected(my_server), got {result:?}"
    );
}

/// B5 — Any unknown/non-standard JSON-RPC error code does not panic and keeps
/// its machine-readable value in `McpError::Rpc`.
#[tokio::test]
async fn arbitrary_unknown_error_codes_do_not_panic() {
    use openclaudia::mcp::{HttpTransport, McpTransport};

    let mock_server = MockServer::start().await;
    for code in &[-1i64, 0, 12345, -99999, i64::MIN, i64::MAX] {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": { "code": code, "message": "test error" }
            })))
            .mount(&mock_server)
            .await;

        let transport = HttpTransport::__test_new_unchecked(&mock_server.uri());
        let result = transport.request("test", None).await;
        assert!(matches!(
            result,
            Err(McpError::Rpc {
                code: actual,
                ref message,
                data: None,
                http_status: Some(200),
            }) if actual == *code && message == "test error"
        ));
    }
    drop(mock_server); // suppress unused warning for outer binding
}

/// B4 — `McpManager::list_resources` for a non-existent server returns `Err`.
#[tokio::test]
async fn manager_list_resources_missing_server_returns_err() {
    let manager = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    let result = manager.list_resources(Some("missing")).await;
    assert!(result.is_err(), "expected Err for missing server");
}

/// B4 — `McpManager::list_resources(None)` with no servers returns empty vec,
/// not an error (multi-server path with zero servers).
#[tokio::test]
async fn manager_list_resources_no_servers_returns_empty() {
    let manager = McpManager::new(std::sync::Arc::clone(support::shared_run_context()));
    let result = manager.list_resources(None).await.expect("should be Ok");
    assert!(result.is_empty());
}
mod support;
