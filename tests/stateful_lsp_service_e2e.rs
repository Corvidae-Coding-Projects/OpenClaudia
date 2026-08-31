//! Compiled protocol-fixture coverage for the production stateful LSP service.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::unwrap_used)]

use openclaudia::plugins::manifest::LspServerConfig;
use openclaudia::secrets::EnvironmentGrants;
use openclaudia::services::{
    LspServerManager, LspServiceError, LspServiceRequest, PluginLspServer,
};
use openclaudia::state::SessionId;
use openclaudia::tools::lsp::{execute_lsp, LspResult};
use openclaudia::tools::{ToolRunContext, WorkspaceAccess};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

struct FixtureRun {
    _root: tempfile::TempDir,
    run: Arc<ToolRunContext>,
    document: PathBuf,
    log: PathBuf,
    binary: PathBuf,
}

impl FixtureRun {
    fn new(name: &str, crash_once: bool) -> Self {
        let root = tempfile::Builder::new()
            .prefix(&format!("s068-{name}-"))
            .tempdir_in(".")
            .expect("project-local LSP fixture root");
        let document = root.path().join("source.fixture");
        std::fs::write(&document, "initial").expect("fixture document");
        let binary = compile_fixture(root.path());
        let run = ToolRunContext::builder(SessionId::new(), root.path())
            .working_directory(root.path())
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::new())
            .workspace_access(WorkspaceAccess::ReadWrite)
            .process(true)
            .network(false)
            .secrets(false)
            .provider("stateful-lsp-fixture")
            .build()
            .expect("fixture run capabilities");
        let log = run.private_temp_root().join(format!("{name}.jsonl"));
        let crash_marker = run.private_temp_root().join(format!("{name}.crashed"));
        let mut args = vec![log.to_string_lossy().into_owned()];
        if crash_once {
            args.push(crash_marker.to_string_lossy().into_owned());
        }
        configure_fixture(&run, &binary, args);
        Self {
            _root: root,
            run,
            document,
            log,
            binary,
        }
    }

    fn call(&self, action: &str, token: Option<&str>) -> (String, bool) {
        let mut args = HashMap::from([
            (
                "file_path".to_string(),
                Value::String(self.document.to_string_lossy().into_owned()),
            ),
            ("action".to_string(), Value::String(action.to_string())),
            ("line".to_string(), json!(1)),
            ("character".to_string(), json!(0)),
        ]);
        if let Some(token) = token {
            args.insert(
                "continuation_token".to_string(),
                Value::String(token.to_string()),
            );
        }
        execute_lsp(&self.run, &args)
    }

    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

#[test]
fn warm_server_owns_document_versions_and_serializes_concurrent_calls() {
    let fixture = Arc::new(FixtureRun::new("versions", false));
    let (first, first_error) = fixture.call("hover", None);
    assert!(!first_error, "{first}");
    let first: LspResult = serde_json::from_str(&first).expect("first result");
    assert_eq!(first.provenance.expect("provenance").document_version, 1);

    std::fs::write(&fixture.document, "changed").expect("change fixture document");
    let workers = (0..4)
        .map(|_| {
            let fixture = Arc::clone(&fixture);
            thread::spawn(move || fixture.call("hover", None))
        })
        .collect::<Vec<_>>();
    for worker in workers {
        let (result, is_error) = worker.join().expect("LSP worker");
        assert!(!is_error, "{result}");
        let result: LspResult = serde_json::from_str(&result).expect("concurrent result");
        assert_eq!(result.provenance.expect("provenance").document_version, 2);
    }

    let log = fixture.log();
    assert_eq!(count(&log, "\"method\":\"initialize\""), 1);
    assert!(log.contains("\"processId\":null"));
    assert_eq!(count(&log, "\"method\":\"textDocument/didOpen\""), 1);
    assert_eq!(count(&log, "\"method\":\"textDocument/didChange\""), 1);
    assert!(log.contains("\"version\":1"));
    assert!(log.contains("\"version\":2"));
}

#[test]
fn call_hierarchy_round_trips_complete_opaque_items_and_rejects_stale_tokens() {
    let fixture = FixtureRun::new("hierarchy", false);
    let (prepared, is_error) = fixture.call("prepareCallHierarchy", None);
    assert!(!is_error, "{prepared}");
    let prepared: LspResult = serde_json::from_str(&prepared).expect("prepare result");
    let continuation = prepared
        .call_hierarchy_items
        .first()
        .expect("complete call hierarchy item");
    assert_eq!(continuation.item["data"]["opaque"]["sequence"], 7);
    assert!(continuation.continuation_token.starts_with("lspct_"));

    let (incoming, is_error) =
        fixture.call("incomingCalls", Some(&continuation.continuation_token));
    assert!(!is_error, "{incoming}");
    let incoming: LspResult = serde_json::from_str(&incoming).expect("incoming result");
    assert_eq!(incoming.results[0].preview.as_deref(), Some("caller"));
    let incoming_continuation = incoming
        .call_hierarchy_items
        .first()
        .expect("incoming caller continuation");
    assert_eq!(incoming_continuation.item["data"]["roundtrip"], "incoming");

    let (outgoing, is_error) =
        fixture.call("outgoingCalls", Some(&continuation.continuation_token));
    assert!(!is_error, "{outgoing}");
    let outgoing: LspResult = serde_json::from_str(&outgoing).expect("outgoing result");
    assert_eq!(outgoing.results[0].preview.as_deref(), Some("callee"));
    let outgoing_continuation = outgoing
        .call_hierarchy_items
        .first()
        .expect("outgoing callee continuation");
    assert_eq!(outgoing_continuation.item["data"]["roundtrip"], "outgoing");

    let (next, is_error) = fixture.call(
        "incomingCalls",
        Some(&incoming_continuation.continuation_token),
    );
    assert!(!is_error, "{next}");

    std::fs::write(&fixture.document, "changed after prepare").expect("change document");
    let (stale, is_error) = fixture.call("incomingCalls", Some(&continuation.continuation_token));
    assert!(is_error);
    assert!(stale.contains("stale"), "{stale}");
}

#[test]
fn crashed_server_restarts_and_rehydrates_the_document() {
    let fixture = FixtureRun::new("restart", true);
    let (first, first_error) = fixture.call("hover", None);
    assert!(
        first_error,
        "first fixture process intentionally exits: {first}"
    );
    let (second, second_error) = fixture.call("hover", None);
    assert!(!second_error, "{second}");
    let second: LspResult = serde_json::from_str(&second).expect("restarted result");
    assert_eq!(second.provenance.expect("provenance").server_generation, 2);

    let log = fixture.log();
    assert_eq!(count(&log, "\"method\":\"initialize\""), 2);
    assert_eq!(count(&log, "\"method\":\"textDocument/didOpen\""), 2);
    assert_eq!(count(&log, "\"version\":1"), 2);
}

#[test]
fn typed_server_error_does_not_discard_a_healthy_generation() {
    let fixture = FixtureRun::new("server-error", false);
    std::fs::write(&fixture.document, "SERVER_ERROR").expect("server-error document");
    let (failed, is_error) = fixture.call("hover", None);
    assert!(is_error);
    assert!(failed.contains("JSON-RPC error -32002"), "{failed}");

    std::fs::write(&fixture.document, "recovered").expect("recovered document");
    let (recovered, is_error) = fixture.call("hover", None);
    assert!(!is_error, "{recovered}");
    let recovered: LspResult = serde_json::from_str(&recovered).expect("recovered result");
    assert_eq!(
        recovered.provenance.expect("provenance").server_generation,
        1
    );
    assert_eq!(count(&fixture.log(), "\"method\":\"initialize\""), 1);
}

#[test]
fn run_cancellation_stops_and_reaps_a_blocked_server() {
    let fixture = Arc::new(FixtureRun::new("cancel", false));
    std::fs::write(&fixture.document, "HANG").expect("hanging document");
    let worker_fixture = Arc::clone(&fixture);
    let worker = thread::spawn(move || worker_fixture.call("hover", None));
    wait_for_log(&fixture.log, "\"method\":\"textDocument/hover\"");
    let _receipt = fixture
        .run
        .runtime()
        .cancellation()
        .cancel(openclaudia::runtime::CancellationReason::User);
    let (result, is_error) = worker.join().expect("cancelled worker");
    assert!(is_error, "{result}");
    fixture.run.lsp_service().shutdown();
    assert!(fixture.run.lsp_service().is_empty());
}

#[test]
fn shutdown_balances_documents_and_reaps_the_server() {
    let fixture = FixtureRun::new("shutdown", false);
    let (result, is_error) = fixture.call("hover", None);
    assert!(!is_error, "{result}");
    fixture.run.lsp_service().shutdown();
    assert!(fixture.run.lsp_service().is_empty());
    let log = fixture.log();
    assert!(log.contains("\"method\":\"textDocument/didClose\""));
    assert!(log.contains("\"method\":\"shutdown\""));
    assert!(log.contains("\"method\":\"exit\""));
}

#[test]
fn config_change_replaces_generation_and_idle_reaping_closes_it() {
    let fixture = FixtureRun::new("config-a", false);
    let (first, is_error) = fixture.call("hover", None);
    assert!(!is_error, "{first}");
    let second_log = fixture.run.private_temp_root().join("config-b.jsonl");
    configure_fixture(
        &fixture.run,
        &fixture.binary,
        vec![second_log.to_string_lossy().into_owned()],
    );
    let (second, is_error) = fixture.call("hover", None);
    assert!(!is_error, "{second}");
    assert!(second_log.exists(), "new config must own the new process");

    let manager = LspServerManager::with_ttl(Duration::ZERO);
    manager.configure_plugins(fixture_servers(
        &fixture.binary,
        vec![second_log.to_string_lossy().into_owned()],
    ));
    let request = service_request(&fixture.document, "initial");
    manager
        .execute(&fixture.run, &request)
        .expect("standalone pooled request");
    assert_eq!(manager.reap_idle(), 1);
    assert!(manager.is_empty());
}

#[test]
fn derived_and_independent_runs_do_not_share_server_state() {
    let fixture = FixtureRun::new("isolation", false);
    let child = fixture
        .run
        .derive_frontend_session(
            SessionId::new(),
            fixture.run.project_root(),
            fixture.run.working_directory(),
            "stateful-lsp-child",
        )
        .expect("derived run");
    assert_eq!(child.lsp_service().plugin_servers().len(), 1);
    assert_ne!(child.run_id(), fixture.run.run_id());
    let child_log = child.private_temp_root().join("isolation-child.jsonl");
    configure_fixture(
        &child,
        &fixture.binary,
        vec![child_log.to_string_lossy().into_owned()],
    );
    let (parent_result, parent_error) = fixture.call("hover", None);
    assert!(!parent_error, "{parent_result}");
    child
        .lsp_service()
        .execute(&child, &service_request(&fixture.document, "initial"))
        .expect("child LSP request");
    assert_eq!(fixture.run.lsp_service().len(), 1);
    assert_eq!(child.lsp_service().len(), 1);
    let parent_log = fixture.log();
    let child_log = std::fs::read_to_string(child_log).expect("child fixture log");
    assert_eq!(count(&parent_log, "\"method\":\"initialize\""), 1);
    assert_eq!(count(&child_log, "\"method\":\"initialize\""), 1);
    assert_eq!(count(&parent_log, "\"method\":\"textDocument/didOpen\""), 1);
    assert_eq!(count(&child_log, "\"method\":\"textDocument/didOpen\""), 1);
}

#[test]
fn plugin_environment_cannot_expand_the_run_authority() {
    let fixture = FixtureRun::new("plugin-env", false);
    fixture
        .run
        .lsp_service()
        .configure_plugins(vec![PluginLspServer {
            owner: "compiled-test-fixture".to_string(),
            language: "fixture".to_string(),
            config: LspServerConfig {
                command: fixture.binary.to_string_lossy().into_owned(),
                args: vec![fixture.log.to_string_lossy().into_owned()],
                env: EnvironmentGrants::try_from(HashMap::from([(
                    "S068_PLUGIN_SECRET".to_string(),
                    "not-granted-to-this-run".to_string(),
                )]))
                .expect("valid protected test environment"),
                extensions: vec!["fixture".to_string()],
            },
        }]);

    let error = fixture
        .run
        .lsp_service()
        .execute(&fixture.run, &service_request(&fixture.document, "initial"))
        .expect_err("plugin environment expansion must fail before spawn");
    assert!(matches!(
        error,
        LspServiceError::InvalidConfiguration { .. }
    ));
    assert!(fixture.run.lsp_service().is_empty());
}

fn configure_fixture(run: &ToolRunContext, binary: &Path, args: Vec<String>) {
    run.lsp_service()
        .configure_plugins(fixture_servers(binary, args));
}

fn fixture_servers(binary: &Path, args: Vec<String>) -> Vec<PluginLspServer> {
    vec![PluginLspServer {
        owner: "compiled-test-fixture".to_string(),
        language: "fixture".to_string(),
        config: LspServerConfig {
            command: binary.to_string_lossy().into_owned(),
            args,
            env: EnvironmentGrants::new(),
            extensions: vec!["fixture".to_string()],
        },
    }]
}

fn service_request(document: &Path, text: &str) -> LspServiceRequest {
    let document_uri = url::Url::from_file_path(document)
        .expect("document URI")
        .to_string();
    LspServiceRequest {
        language: "fixture".to_string(),
        document_path: document.to_path_buf(),
        document_uri: document_uri.clone(),
        document_text: text.to_string(),
        method: "textDocument/hover",
        params: json!({
            "textDocument": {"uri": document_uri},
            "position": {"line": 0, "character": 0}
        }),
        continuation_token: None,
    }
}

fn compile_fixture(root: &Path) -> PathBuf {
    let output = root.join(if cfg!(windows) {
        "stateful-lsp-server.exe"
    } else {
        "stateful-lsp-server"
    });
    let status = Command::new("rustc")
        .arg("--edition=2021")
        .arg(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/stateful_lsp_server.rs"),
        )
        .arg("-o")
        .arg(&output)
        .status()
        .expect("launch rustc for compiled LSP fixture");
    assert!(status.success(), "compiled LSP fixture must build");
    output.canonicalize().expect("compiled fixture path")
}

fn count(haystack: &str, needle: &str) -> usize {
    haystack.match_indices(needle).count()
}

fn wait_for_log(path: &Path, needle: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let log = std::fs::read_to_string(path).unwrap_or_default();
        if log.contains(needle) {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("fixture log never contained {needle}");
}
