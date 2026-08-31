//! Hostile compiled-fixture coverage for bounded production LSP JSON-RPC.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::unwrap_used)]

use openclaudia::permissions::PermissionManager;
use openclaudia::plugins::manifest::LspServerConfig;
use openclaudia::secrets::EnvironmentGrants;
use openclaudia::services::{
    LspProtocolLimits, LspServerManager, LspServiceError, LspServiceRequest, PluginLspServer,
};
use openclaudia::state::SessionId;
use openclaudia::tools::lsp::{execute_lsp, LspResult};
use openclaudia::tools::{
    execute_tool_full, FunctionCall, ToolCall, ToolOutcome, ToolRunContext, WorkspaceAccess,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

struct SharedFixture {
    binary: PathBuf,
}

struct FixtureRun {
    _root: tempfile::TempDir,
    run: Arc<ToolRunContext>,
    document: PathBuf,
    log: PathBuf,
    manager: LspServerManager,
}

impl FixtureRun {
    fn new(mode: &str, limits: LspProtocolLimits) -> Self {
        let root = tempfile::Builder::new()
            .prefix(&format!("s069-{mode}-"))
            .tempdir_in(".")
            .expect("project-local LSP fixture root");
        let binary_name = if cfg!(windows) {
            "bounded-lsp-server.exe"
        } else {
            "bounded-lsp-server"
        };
        let binary = root.path().join(binary_name);
        std::fs::copy(&shared_fixture().binary, &binary).expect("copy compiled fixture");
        let binary = binary.canonicalize().expect("fixture binary path");
        let document = root.path().join("source.fixture");
        std::fs::write(&document, "initial").expect("fixture document");
        let run = ToolRunContext::builder(SessionId::new(), root.path())
            .working_directory(root.path())
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::new())
            .workspace_access(WorkspaceAccess::ReadWrite)
            .process(true)
            .network(false)
            .secrets(false)
            .provider("bounded-lsp-fixture")
            .build()
            .expect("fixture run capabilities");
        let log = run.private_temp_root().join(format!("{mode}.jsonl"));
        let servers = fixture_servers(&binary, mode, &log);
        run.lsp_service().configure_plugins(servers.clone());
        let manager = LspServerManager::with_limits(Duration::from_secs(60), limits);
        manager.configure_plugins(servers);
        Self {
            _root: root,
            run,
            document,
            log,
            manager,
        }
    }

    fn request(&self, method: &'static str, text: &str) -> LspServiceRequest {
        let document_uri = url::Url::from_file_path(&self.document)
            .expect("document URI")
            .to_string();
        LspServiceRequest {
            language: "fixture".to_string(),
            document_path: self.document.clone(),
            document_uri: document_uri.clone(),
            document_text: text.to_string(),
            method,
            params: json!({
                "textDocument": {"uri": document_uri},
                "position": {"line": 0, "character": 0}
            }),
            continuation_token: None,
        }
    }

    fn execute(&self) -> Result<openclaudia::services::LspServiceResponse, LspServiceError> {
        self.manager
            .execute(&self.run, &self.request("textDocument/hover", "initial"))
    }

    fn tool_call(&self, action: &str) -> (String, bool) {
        execute_lsp(
            &self.run,
            &HashMap::from([
                (
                    "file_path".to_string(),
                    Value::String(self.document.to_string_lossy().into_owned()),
                ),
                ("action".to_string(), Value::String(action.to_string())),
                ("line".to_string(), json!(1)),
                ("character".to_string(), json!(0)),
            ]),
        )
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

#[test]
fn oversized_headers_and_frames_fail_before_unbounded_allocation() {
    let mut header_limits = test_limits();
    header_limits.max_header_bytes = 256;
    let header = FixtureRun::new("oversized-header", header_limits)
        .execute()
        .expect_err("oversized header must fail");
    assert!(header.to_string().contains("header exceeds"), "{header}");

    let mut frame_limits = test_limits();
    frame_limits.max_frame_bytes = 1_024;
    frame_limits.max_turn_bytes = 2_048;
    let frame = FixtureRun::new("oversized-frame", frame_limits)
        .execute()
        .expect_err("oversized frame must fail");
    assert!(
        frame.to_string().contains("frame is 999999 bytes"),
        "{frame}"
    );
}

#[test]
fn drip_fed_response_uses_one_aggregate_deadline() {
    let mut limits = test_limits();
    limits.request_timeout = Duration::from_millis(350);
    let fixture = FixtureRun::new("drip", limits);
    let started = Instant::now();
    let error = fixture.execute().expect_err("drip response must time out");
    assert!(matches!(error, LspServiceError::Deadline(_)), "{error}");
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[test]
fn malformed_jsonrpc_envelopes_are_rejected_not_projected_as_empty_success() {
    for (mode, expected) in [
        ("malformed-json", "invalid response JSON"),
        ("wrong-version", "version 2.0"),
        ("wrong-id", "unexpected JSON-RPC response"),
        ("both-result-error", "exactly one of result or error"),
    ] {
        let error = FixtureRun::new(mode, test_limits())
            .execute()
            .expect_err("malformed envelope must fail");
        assert!(error.to_string().contains(expected), "{mode}: {error}");
    }
}

#[test]
fn server_errors_remain_typed_and_do_not_become_protocol_successes() {
    let error = FixtureRun::new("server-error", test_limits())
        .execute()
        .expect_err("server error must fail");
    assert!(matches!(
        error,
        LspServiceError::Server { code: -32_002, .. }
    ));
}

#[test]
fn reverse_requests_receive_supported_or_explicitly_rejected_responses() {
    let supported = FixtureRun::new("reverse-supported", test_limits());
    supported.execute().expect("supported reverse request");
    let response = reverse_log_response(&supported.log());
    assert_eq!(response["id"], "reverse-1");
    assert_eq!(response["result"], json!([null, null]));

    let unsupported = FixtureRun::new("reverse-unsupported", test_limits());
    unsupported
        .execute()
        .expect("unsupported reverse request is answered, then the turn continues");
    let response = reverse_log_response(&unsupported.log());
    assert_eq!(response["id"], 77);
    assert_eq!(response["error"]["code"], -32601);
}

#[test]
fn diagnostic_notifications_are_typed_versioned_bounded_untrusted_data() {
    let response = FixtureRun::new("diagnostics", test_limits())
        .execute()
        .expect("diagnostic notification");
    assert_eq!(response.diagnostics.len(), 1);
    let publication = &response.diagnostics[0];
    assert_eq!(publication.resource_id, "source.fixture");
    assert_eq!(publication.document_version, Some(1));
    assert_eq!(publication.server_generation, response.server_generation);
    assert!(!publication.stale);
    assert!(publication.untrusted);
    assert_eq!(publication.diagnostics.len(), 1);
    assert_eq!(publication.diagnostics[0].line, 2);
    assert!(publication.diagnostics[0]
        .message
        .contains("fixture diagnostic"));
}

#[test]
fn result_and_message_caps_report_bounded_failures() {
    let mut result_limits = test_limits();
    result_limits.max_result_bytes = 512;
    let error = FixtureRun::new("large-result", result_limits)
        .execute()
        .expect_err("large result must fail");
    assert!(matches!(error, LspServiceError::ResultLimit(_)), "{error}");

    let mut message_limits = test_limits();
    message_limits.max_messages_per_turn = 3;
    let error = FixtureRun::new("message-flood", message_limits)
        .execute()
        .expect_err("message flood must fail");
    assert!(error.to_string().contains("within 3 messages"), "{error}");
}

#[test]
fn blocked_stdin_is_cancelled_by_deadline_and_process_is_reaped() {
    let mut limits = test_limits();
    limits.request_timeout = Duration::from_millis(500);
    limits.shutdown_timeout = Duration::from_millis(250);
    limits.max_queued_bytes = 8 * 1_024;
    limits.max_outbound_message_bytes = 3 * 1_024 * 1_024;
    let fixture = FixtureRun::new("blocked-stdin", limits);
    fixture
        .execute()
        .expect("first request starts the blocked fixture");

    let large_document = "x".repeat(2 * 1_024 * 1_024);
    let started = Instant::now();
    let error = fixture
        .manager
        .execute(
            &fixture.run,
            &fixture.request("textDocument/hover", &large_document),
        )
        .expect_err("blocked stdin must reach the aggregate deadline");
    assert!(matches!(error, LspServiceError::Deadline(_)), "{error}");
    assert!(started.elapsed() < Duration::from_secs(3));
    fixture.manager.shutdown();
    assert!(fixture.manager.is_empty());
}

#[test]
fn unsafe_returned_resources_fail_and_large_valid_lists_are_explicitly_partial() {
    let invalid = FixtureRun::new("invalid-uri", test_limits());
    let (error, is_error) = invalid.tool_call("goToDefinition");
    assert!(is_error);
    assert!(
        error.contains("invalid or unauthorized resource"),
        "{error}"
    );
    assert!(error.contains("/etc/passwd"), "{error}");

    let large = FixtureRun::new("large-list", test_limits());
    let call = ToolCall {
        id: "s069-partial".to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: "lsp".to_string(),
            arguments: json!({
                "file_path": large.document,
                "action": "goToDefinition",
                "line": 1,
                "character": 0
            })
            .to_string(),
        },
    };
    let canonical = execute_tool_full(
        &large.run,
        &call,
        None,
        None,
        &PermissionManager::unrestricted(),
    );
    assert!(matches!(canonical.outcome(), ToolOutcome::Partial { .. }));

    let (output, is_error) = large.tool_call("goToDefinition");
    assert!(!is_error, "{output}");
    let result: LspResult = serde_json::from_str(&output).expect("bounded partial result");
    assert_eq!(result.results.len(), 256);
    assert!(result
        .partial_reasons
        .iter()
        .any(|reason| reason.contains("capped at 256")));
    assert!(result
        .results
        .iter()
        .all(|location| location.resource_id == "source.fixture"));
}

#[test]
fn stderr_capture_remains_bounded_when_the_server_exits() {
    let mut limits = test_limits();
    limits.max_stderr_bytes = 128;
    let error = FixtureRun::new("stderr-exit", limits)
        .execute()
        .expect_err("fixture exits without response");
    assert!(error.to_string().len() < 512, "{error}");
}

fn test_limits() -> LspProtocolLimits {
    LspProtocolLimits {
        request_timeout: Duration::from_secs(2),
        shutdown_timeout: Duration::from_millis(250),
        ..LspProtocolLimits::default()
    }
}

fn fixture_servers(binary: &Path, mode: &str, log: &Path) -> Vec<PluginLspServer> {
    vec![PluginLspServer {
        owner: "bounded-test-fixture".to_string(),
        language: "fixture".to_string(),
        config: LspServerConfig {
            command: binary.to_string_lossy().into_owned(),
            args: vec![mode.to_string(), log.to_string_lossy().into_owned()],
            env: EnvironmentGrants::new(),
            extensions: vec!["fixture".to_string()],
        },
    }]
}

fn reverse_log_response(log: &str) -> Value {
    let body = log
        .lines()
        .find_map(|line| line.strip_prefix("reverse\t"))
        .expect("fixture recorded reverse response");
    serde_json::from_str(body).expect("reverse response JSON")
}

fn shared_fixture() -> &'static SharedFixture {
    static FIXTURE: OnceLock<SharedFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("s069-fixtures");
        std::fs::create_dir_all(&root).expect("compiled fixture root");
        let suffix = if cfg!(windows) { ".exe" } else { "" };
        let output = root.join(format!("bounded-lsp-server-{}{suffix}", std::process::id()));
        let status = Command::new("rustc")
            .arg("--edition=2021")
            .arg(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/bounded_lsp_server.rs"),
            )
            .arg("-o")
            .arg(&output)
            .status()
            .expect("launch rustc for hostile LSP fixture");
        assert!(status.success(), "hostile LSP fixture must build");
        SharedFixture {
            binary: output.canonicalize().expect("compiled fixture path"),
        }
    })
}
