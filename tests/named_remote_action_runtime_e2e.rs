//! End-to-end contract tests for S-070 named remote actions.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use openclaudia::permissions::{ApprovalProvenance, PermissionManager};
use openclaudia::runtime::CancellationReason;
use openclaudia::services::tool_executor::{ToolExecutor, ToolExecutorRequest};
use openclaudia::state::SessionId;
use openclaudia::tools::remote_trigger::{
    RemoteActionContract, RemoteActionContractSpec, RemoteActionEffect, RemoteActionIdempotency,
    WebhookRegistry,
};
use openclaudia::tools::{
    get_progressive_tool_definitions, FunctionCall, ToolCall, ToolFailureCode, ToolOutcome,
    ToolRunContext, WorkspaceAccess,
};
use serde_json::{json, Value};
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn contract(
    idempotency: RemoteActionIdempotency,
    max_attempts: u32,
    max_calls_per_run: u32,
    deadline: Duration,
    max_response_bytes: usize,
) -> RemoteActionContract {
    RemoteActionContract::try_from_spec(RemoteActionContractSpec {
        description: "Deliver one typed deployment event".to_string(),
        input_schema: json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {"event": {"type": "string", "minLength": 1}},
            "required": ["event"]
        }),
        output_schema: Some(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {"accepted": {"type": "boolean"}},
            "required": ["accepted"]
        })),
        effect: RemoteActionEffect::ExternalMutation,
        idempotency,
        deadline,
        max_request_bytes: 4096,
        max_response_bytes,
        max_calls_per_run,
        max_in_flight: 1,
        max_attempts,
    })
    .expect("test action contract")
}

fn registry(
    url: &str,
    headers: HashMap<String, String>,
    action_contract: RemoteActionContract,
) -> WebhookRegistry {
    let mut registry = WebhookRegistry::new_allow_plaintext();
    registry
        .register_action(
            "deploy",
            url,
            openclaudia::secrets::SensitiveHeaders::try_from(headers).expect("headers"),
            action_contract,
        )
        .expect("registered action");
    registry
}

fn run_with_registry(
    root: &std::path::Path,
    registry: WebhookRegistry,
    network: bool,
    secrets: bool,
) -> Arc<ToolRunContext> {
    ToolRunContext::builder(SessionId::new(), root)
        .working_directory(root)
        .read_only_roots(Vec::new())
        .read_write_roots(Vec::new())
        .environment_grants(HashMap::new())
        .remote_actions(registry)
        .workspace_access(WorkspaceAccess::ReadOnly)
        .process(false)
        .network(network)
        .secrets(secrets)
        .provider("remote-action-test")
        .build()
        .expect("run")
}

fn call(id: &str, arguments: &Value) -> ToolCall {
    ToolCall {
        id: id.to_string(),
        call_type: "function".to_string(),
        function: FunctionCall {
            name: "remote_trigger".to_string(),
            arguments: arguments.to_string(),
        },
    }
}

async fn execute(run: Arc<ToolRunContext>, call: ToolCall) -> openclaudia::tools::ToolResult {
    tokio::task::spawn_blocking(move || {
        let permissions = PermissionManager::unrestricted_for_run(&run);
        let approval = permissions
            .approve_tool_call_once(
                &call,
                Some(run.session_id()),
                ApprovalProvenance::InteractiveUser,
            )
            .expect("authenticated one-use host approval");
        ToolExecutor::execute(ToolExecutorRequest {
            run_context: &run,
            tool_call: &call,
            memory_db: None,
            app_config: None,
            task_mgr: None,
            permission_mgr: &permissions,
            authorization: Some(approval),
            session_id: Some(run.session_id()),
            policy_enforcer: None,
        })
    })
    .await
    .expect("tool task")
}

async fn execute_without_host_approval(
    run: Arc<ToolRunContext>,
    call: ToolCall,
) -> openclaudia::tools::ToolResult {
    tokio::task::spawn_blocking(move || {
        let permissions = PermissionManager::unrestricted_for_run(&run);
        ToolExecutor::execute(ToolExecutorRequest {
            run_context: &run,
            tool_call: &call,
            memory_db: None,
            app_config: None,
            task_mgr: None,
            permission_mgr: &permissions,
            authorization: None,
            session_id: Some(run.session_id()),
            policy_enforcer: None,
        })
    })
    .await
    .expect("tool task")
}

fn error_code(result: &openclaudia::tools::ToolResult) -> ToolFailureCode {
    match result.outcome() {
        ToolOutcome::Error { failure } => failure.code,
        other => panic!("expected error outcome, got {other:?}"),
    }
}

#[test]
fn catalog_publishes_only_run_available_symbolic_actions() {
    let root = tempfile::tempdir().expect("root");
    let configured = registry(
        "http://127.0.0.1:30001/hook?signed=secret-s070",
        HashMap::from([(
            "Authorization".to_string(),
            "Bearer secret-s070".to_string(),
        )]),
        contract(
            RemoteActionIdempotency::None,
            1,
            2,
            Duration::from_secs(1),
            4096,
        ),
    );
    let available = run_with_registry(root.path(), configured.clone(), true, true);
    let first = get_progressive_tool_definitions(&available, &[], false).expect("catalog");
    available
        .tool_catalog()
        .activate(
            &available,
            &HashMap::from([
                ("query".to_string(), json!("select:remote_trigger")),
                (
                    "catalog_generation".to_string(),
                    json!(first.generation.to_string()),
                ),
            ]),
        )
        .expect("available remote action activation");
    let second = get_progressive_tool_definitions(&available, &[], false).expect("catalog");
    let definition = second
        .definitions
        .iter()
        .find(|definition| {
            definition.pointer("/function/name").and_then(Value::as_str) == Some("remote_trigger")
        })
        .expect("available remote action is published");
    let encoded = definition.to_string();
    assert!(encoded.contains("deploy"));
    assert!(encoded.contains("event"));
    assert!(!encoded.contains("127.0.0.1"));
    assert!(!encoded.contains("secret-s070"));
    assert!(!encoded.to_ascii_lowercase().contains("authorization"));

    let unavailable = run_with_registry(root.path(), configured, true, false);
    let snapshot = get_progressive_tool_definitions(&unavailable, &[], false).expect("catalog");
    assert!(!snapshot
        .active_names
        .iter()
        .any(|name| name == "remote_trigger"));
    let failure = unavailable
        .tool_catalog()
        .activate(
            &unavailable,
            &HashMap::from([
                ("query".to_string(), json!("select:remote_trigger")),
                (
                    "catalog_generation".to_string(),
                    json!(snapshot.generation.to_string()),
                ),
            ]),
        )
        .expect_err("missing secret authority cannot activate remote actions");
    assert_eq!(failure.code, ToolFailureCode::Unavailable);

    let empty = run_with_registry(root.path(), WebhookRegistry::new(), true, true);
    let snapshot = get_progressive_tool_definitions(&empty, &[], false).expect("catalog");
    assert!(!snapshot
        .active_names
        .iter()
        .any(|name| name == "remote_trigger"));
    let failure = empty
        .tool_catalog()
        .activate(
            &empty,
            &HashMap::from([
                ("query".to_string(), json!("select:remote_trigger")),
                (
                    "catalog_generation".to_string(),
                    json!(snapshot.generation.to_string()),
                ),
            ]),
        )
        .expect_err("empty registry cannot activate remote actions");
    assert_eq!(failure.code, ToolFailureCode::Unavailable);
}

#[tokio::test]
async fn fixed_post_happy_path_binds_headers_idempotency_and_typed_receipt() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .and(header("authorization", "Bearer host-secret"))
        .and(body_json(json!({"event": "ship"})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"accepted": true})))
        .expect(1)
        .mount(&server)
        .await;
    let root = tempfile::tempdir().expect("root");
    let run = run_with_registry(
        root.path(),
        registry(
            &format!("{}/hook", server.uri()),
            HashMap::from([(
                "Authorization".to_string(),
                "Bearer host-secret".to_string(),
            )]),
            contract(
                RemoteActionIdempotency::KeyHeader,
                2,
                2,
                Duration::from_secs(2),
                4096,
            ),
        ),
        true,
        true,
    );
    let result = execute(
        run,
        call(
            "call-success",
            &json!({"name": "deploy", "payload": {"event": "ship"}}),
        ),
    )
    .await;
    assert!(matches!(result.outcome(), ToolOutcome::Success { .. }));
    let receipt = result.structured().expect("typed receipt");
    assert_eq!(receipt["delivery"], "confirmed");
    assert_eq!(receipt["attempts"], 1);
    assert_eq!(receipt["response"], json!({"accepted": true}));
    let requests = server.received_requests().await.expect("requests");
    let idempotency = requests[0]
        .headers
        .get("idempotency-key")
        .expect("idempotency header")
        .to_str()
        .expect("ASCII idempotency value");
    assert!(idempotency.starts_with("openclaudia-"));
    server.verify().await;
}

#[tokio::test]
async fn exact_host_approval_is_required_before_dispatch() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let root = tempfile::tempdir().expect("root");
    let run = run_with_registry(
        root.path(),
        registry(
            &format!("{}/hook", server.uri()),
            HashMap::new(),
            contract(
                RemoteActionIdempotency::None,
                1,
                2,
                Duration::from_secs(1),
                4096,
            ),
        ),
        true,
        true,
    );
    let result = execute_without_host_approval(
        run,
        call(
            "missing-approval",
            &json!({"name": "deploy", "payload": {"event": "ship"}}),
        ),
    )
    .await;
    assert_eq!(error_code(&result), ToolFailureCode::PermissionDenied);
    server.verify().await;
}

#[tokio::test]
async fn schema_and_argument_smuggling_fail_before_network_dispatch() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let root = tempfile::tempdir().expect("root");
    let run = run_with_registry(
        root.path(),
        registry(
            &format!("{}/hook", server.uri()),
            HashMap::new(),
            contract(
                RemoteActionIdempotency::None,
                1,
                3,
                Duration::from_secs(1),
                4096,
            ),
        ),
        true,
        true,
    );
    let invalid_payload = execute(
        Arc::clone(&run),
        call(
            "bad-payload",
            &json!({"name": "deploy", "payload": {"url": "http://evil.invalid"}}),
        ),
    )
    .await;
    assert_eq!(
        error_code(&invalid_payload),
        ToolFailureCode::InvalidArguments
    );
    let smuggled_transport = execute(
        run,
        call(
            "bad-envelope",
            &json!({
                "name": "deploy",
                "payload": {"event": "ship"},
                "url": "http://evil.invalid",
                "method": "DELETE",
                "headers": {"Authorization": "attacker"}
            }),
        ),
    )
    .await;
    assert_eq!(
        error_code(&smuggled_transport),
        ToolFailureCode::InvalidArguments
    );
    server.verify().await;
}

#[tokio::test]
async fn redirect_is_not_followed_and_is_reported_as_partial_external_effect() {
    let target = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"accepted": true})))
        .expect(0)
        .mount(&target)
        .await;
    let origin = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(
            ResponseTemplate::new(307).insert_header("location", format!("{}/sink", target.uri())),
        )
        .expect(1)
        .mount(&origin)
        .await;
    let root = tempfile::tempdir().expect("root");
    let run = run_with_registry(
        root.path(),
        registry(
            &format!("{}/hook", origin.uri()),
            HashMap::new(),
            contract(
                RemoteActionIdempotency::None,
                1,
                2,
                Duration::from_secs(2),
                4096,
            ),
        ),
        true,
        true,
    );
    let result = execute(
        run,
        call(
            "call-redirect",
            &json!({"name": "deploy", "payload": {"event": "ship"}}),
        ),
    )
    .await;
    assert!(matches!(result.outcome(), ToolOutcome::Partial { .. }));
    assert_eq!(result.structured().expect("receipt")["status_code"], 307);
    origin.verify().await;
    target.verify().await;
}

#[tokio::test]
async fn retry_is_bounded_and_reuses_one_idempotency_key() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(503).set_body_json(json!({"accepted": false})))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"accepted": true})))
        .mount(&server)
        .await;
    let root = tempfile::tempdir().expect("root");
    let run = run_with_registry(
        root.path(),
        registry(
            &format!("{}/hook", server.uri()),
            HashMap::new(),
            contract(
                RemoteActionIdempotency::KeyHeader,
                2,
                2,
                Duration::from_secs(2),
                4096,
            ),
        ),
        true,
        true,
    );
    let result = execute(
        run,
        call(
            "stable-key",
            &json!({"name": "deploy", "payload": {"event": "ship"}}),
        ),
    )
    .await;
    assert!(matches!(result.outcome(), ToolOutcome::Success { .. }));
    assert_eq!(result.structured().expect("receipt")["attempts"], 2);
    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].headers.get("idempotency-key"),
        requests[1].headers.get("idempotency-key")
    );
}

#[tokio::test]
async fn deadline_and_invalid_result_are_partial_not_false_clean_errors() {
    let slow = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(500))
                .set_body_json(json!({"accepted": true})),
        )
        .mount(&slow)
        .await;
    let root = tempfile::tempdir().expect("root");
    let deadline_run = run_with_registry(
        root.path(),
        registry(
            &format!("{}/hook", slow.uri()),
            HashMap::new(),
            contract(
                RemoteActionIdempotency::None,
                1,
                2,
                Duration::from_millis(100),
                4096,
            ),
        ),
        true,
        true,
    );
    let deadline = execute(
        deadline_run,
        call(
            "deadline",
            &json!({"name": "deploy", "payload": {"event": "ship"}}),
        ),
    )
    .await;
    assert!(matches!(deadline.outcome(), ToolOutcome::Partial { .. }));

    let invalid = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"unexpected": true})))
        .mount(&invalid)
        .await;
    let invalid_run = run_with_registry(
        root.path(),
        registry(
            &format!("{}/hook", invalid.uri()),
            HashMap::new(),
            contract(
                RemoteActionIdempotency::None,
                1,
                2,
                Duration::from_secs(1),
                4096,
            ),
        ),
        true,
        true,
    );
    let invalid_result = execute(
        invalid_run,
        call(
            "invalid-result",
            &json!({"name": "deploy", "payload": {"event": "ship"}}),
        ),
    )
    .await;
    assert!(matches!(
        invalid_result.outcome(),
        ToolOutcome::Partial { .. }
    ));
}

#[tokio::test]
async fn run_cancellation_stops_the_in_flight_request_with_typed_partial_receipt() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_secs(2))
                .set_body_json(json!({"accepted": true})),
        )
        .mount(&server)
        .await;
    let root = tempfile::tempdir().expect("root");
    let run = run_with_registry(
        root.path(),
        registry(
            &format!("{}/hook", server.uri()),
            HashMap::new(),
            contract(
                RemoteActionIdempotency::None,
                1,
                2,
                Duration::from_secs(3),
                4096,
            ),
        ),
        true,
        true,
    );
    let executing = tokio::task::spawn_blocking({
        let run = Arc::clone(&run);
        move || {
            let call = call(
                "cancel",
                &json!({"name": "deploy", "payload": {"event": "ship"}}),
            );
            let permissions = PermissionManager::unrestricted_for_run(&run);
            let approval = permissions
                .approve_tool_call_once(
                    &call,
                    Some(run.session_id()),
                    ApprovalProvenance::InteractiveUser,
                )
                .expect("authenticated one-use host approval");
            ToolExecutor::execute(ToolExecutorRequest {
                run_context: &run,
                tool_call: &call,
                memory_db: None,
                app_config: None,
                task_mgr: None,
                permission_mgr: &permissions,
                authorization: Some(approval),
                session_id: Some(run.session_id()),
                policy_enforcer: None,
            })
        }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let _ = run
        .runtime()
        .cancellation()
        .cancel(CancellationReason::FrontendDisconnected);
    let result = executing.await.expect("tool task");
    assert!(matches!(result.outcome(), ToolOutcome::Partial { .. }));
    let failure = match result.outcome() {
        ToolOutcome::Partial { failures, .. } => &failures[0],
        _ => unreachable!("asserted partial"),
    };
    assert_eq!(failure.code, ToolFailureCode::Cancelled);
}

#[tokio::test]
async fn per_action_in_flight_limit_rejects_a_concurrent_dispatch() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(500))
                .set_body_json(json!({"accepted": true})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let root = tempfile::tempdir().expect("root");
    let run = run_with_registry(
        root.path(),
        registry(
            &format!("{}/hook", server.uri()),
            HashMap::new(),
            contract(
                RemoteActionIdempotency::None,
                1,
                3,
                Duration::from_secs(2),
                4096,
            ),
        ),
        true,
        true,
    );
    let first = tokio::spawn(execute(
        Arc::clone(&run),
        call(
            "concurrent-first",
            &json!({"name": "deploy", "payload": {"event": "first"}}),
        ),
    ));
    for _ in 0..50 {
        if server.received_requests().await.expect("requests").len() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        server
            .received_requests()
            .await
            .expect("first request reached server")
            .len(),
        1,
        "first action must be in flight before testing the concurrency bound"
    );
    let second = execute(
        run,
        call(
            "concurrent-second",
            &json!({"name": "deploy", "payload": {"event": "second"}}),
        ),
    )
    .await;
    assert_eq!(error_code(&second), ToolFailureCode::PolicyDenied);
    let first = first.await.expect("first action task");
    assert!(matches!(first.outcome(), ToolOutcome::Success { .. }));
    server.verify().await;
}

#[tokio::test]
async fn per_run_limit_and_failure_diagnostics_do_not_leak_destination_secrets() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/hook"))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({"accepted": false})))
        .expect(1)
        .mount(&server)
        .await;
    let failing_uri = format!("{}/hook?token=url-secret-s070", server.uri());
    let root = tempfile::tempdir().expect("root");
    let run = run_with_registry(
        root.path(),
        registry(
            &failing_uri,
            HashMap::from([(
                "Authorization".to_string(),
                "Bearer header-secret-s070".to_string(),
            )]),
            contract(
                RemoteActionIdempotency::None,
                1,
                1,
                Duration::from_secs(1),
                4096,
            ),
        ),
        true,
        true,
    );
    let first = execute(
        Arc::clone(&run),
        call(
            "first",
            &json!({"name": "deploy", "payload": {"event": "ship"}}),
        ),
    )
    .await;
    let rendered = format!("{first:?}");
    assert!(!rendered.contains("url-secret-s070"));
    assert!(!rendered.contains("header-secret-s070"));
    let second = execute(
        run,
        call(
            "second",
            &json!({"name": "deploy", "payload": {"event": "ship"}}),
        ),
    )
    .await;
    assert_eq!(error_code(&second), ToolFailureCode::PolicyDenied);
    server.verify().await;
}
