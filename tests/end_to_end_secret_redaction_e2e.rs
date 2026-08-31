//! S-025 acceptance coverage for secret ownership, transport materialization,
//! diagnostic channels, provider failures, and tracing.

#![allow(clippy::expect_used, clippy::missing_panics_doc, clippy::unwrap_used)]

use openclaudia::plugins::manifest::McpServerConfig;
use openclaudia::providers::{AnthropicAdapter, ApiKey, ProviderAdapter};
use openclaudia::secrets::{
    EnvironmentGrants, OAuthToken, SecretString, SensitiveHeaders, MAX_DIAGNOSTIC_BYTES,
};
use openclaudia::tui::events::AppEvent;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const SEEDED: &str = "s025-e2e-secret-7f4f66b9671b";

#[derive(Clone, Default)]
struct TraceWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for TraceWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("trace buffer")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for TraceWriter {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

#[test]
fn typed_config_auth_and_channel_surfaces_never_expose_seeded_secrets() {
    let secret = SecretString::try_from_string(SEEDED.to_string()).expect("secret");
    let token = OAuthToken::try_from_string(SEEDED.to_string()).expect("token");
    let key = ApiKey::try_from_string(SEEDED.to_string()).expect("API key");
    for output in [
        format!("{secret:?}"),
        format!("{secret}"),
        format!("{token:?}"),
        format!("{token}"),
        format!("{key:?}"),
        format!("{key}"),
        serde_json::to_string(&secret).expect("secret serde"),
        serde_json::to_string(&token).expect("token serde"),
        serde_json::to_string(&key).expect("key serde"),
    ] {
        assert!(
            !output.contains(SEEDED),
            "typed auth surface leaked: {output}"
        );
    }

    let config: McpServerConfig = serde_json::from_value(json!({
        "command": "server",
        "env": {"S025_TOKEN": SEEDED},
        "headers": {"X-S025-Secret": SEEDED}
    }))
    .expect("manifest config");
    assert!(config.env.matches_value("S025_TOKEN", SEEDED));
    assert!(config.headers.matches_value("X-S025-Secret", SEEDED));
    let config_debug = format!("{config:?}");
    let config_json = serde_json::to_string(&config).expect("config serde");
    assert!(!config_debug.contains(SEEDED), "{config_debug}");
    assert!(!config_json.contains(SEEDED), "{config_json}");
    assert!(
        serde_json::from_str::<McpServerConfig>(&config_json).is_err(),
        "redacted generic serialization must not silently reload as credentials"
    );

    let (tx, rx) = std::sync::mpsc::channel();
    tx.send(AppEvent::ApiError(
        format!("Authorization: Bearer {SEEDED}").into(),
    ))
    .expect("channel send");
    let AppEvent::ApiError(received) = rx.recv().expect("channel receive") else {
        panic!("expected ApiError");
    };
    assert!(!received.as_str().contains(SEEDED), "{received}");
}

#[tokio::test]
async fn provider_failure_redacts_echoed_header_while_wire_receives_exact_value() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(header("x-s025-secret", SEEDED))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "message": SEEDED,
            "authorization": format!("Bearer {SEEDED}"),
            "nested": {"api_key": SEEDED}
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut headers = SensitiveHeaders::new();
    headers
        .insert_literal("x-s025-secret", SEEDED.to_string())
        .expect("protected header");
    let result = openclaudia::pipeline::run_turn(openclaudia::pipeline::RunTurnParams {
        run_context: Arc::clone(support::shared_run_context()),
        client: &reqwest::Client::new(),
        endpoint: &format!("{}/v1/messages", server.uri()),
        headers: &headers,
        claude_agent_sdk: None,
        codex_agent_sdk: None,
        effort_level: "medium",
        request_body: &json!({"model": "claude-sonnet-4-6", "messages": []}),
        provider: "anthropic",
        model_identity: "claude-sonnet-4-6",
        provider_native_state: None,
        assistant_message_ordinal: 0,
        memory_db: None,
        app_config: None,
        permission_mgr: None,
        transient_allowed_tool_rules: &[],
        hook_engine: None,
        policy_enforcer: None,
        task_mgr: Arc::new(Mutex::new(openclaudia::session::TaskManager::new())),
        session_id: None,
        tx: std::sync::mpsc::channel().0,
    })
    .await;

    let error = result.expect_err("400 must fail");
    assert!(!error.contains(SEEDED), "provider failure leaked: {error}");
    assert!(error.contains("[REDACTED]"), "{error}");
    assert!(error.len() <= MAX_DIAGNOSTIC_BYTES + 64, "{error}");

    let request = headers
        .apply(reqwest::Client::new().get("https://example.com"))
        .expect("header apply")
        .build()
        .expect("request build");
    assert!(request
        .headers()
        .get("x-s025-secret")
        .expect("wire header")
        .is_sensitive());
    assert!(!format!("{:?}", request.headers()).contains(SEEDED));
}

#[tokio::test]
async fn responses_stream_failure_redacts_bare_echoed_request_secret() {
    let server = MockServer::start().await;
    let event = format!(
        "data: {}\n\n",
        json!({
            "type": "response.failed",
            "response": {"error": {"message": format!("provider echoed {SEEDED}")}}
        })
    );
    Mock::given(method("POST"))
        .and(path("/responses"))
        .and(header("authorization", format!("Bearer {SEEDED}")))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(event),
        )
        .expect(1)
        .mount(&server)
        .await;

    let mut headers = SensitiveHeaders::new();
    headers
        .insert_bearer(
            "authorization",
            SecretString::try_from_string(SEEDED.to_string()).expect("secret"),
        )
        .expect("protected header");
    let result = openclaudia::pipeline::run_turn(openclaudia::pipeline::RunTurnParams {
        run_context: Arc::clone(support::shared_run_context()),
        client: &reqwest::Client::new(),
        endpoint: &format!("{}/responses", server.uri()),
        headers: &headers,
        claude_agent_sdk: None,
        codex_agent_sdk: None,
        effort_level: "medium",
        request_body: &json!({"model": "gpt-5", "input": []}),
        provider: "openai",
        model_identity: "gpt-5",
        provider_native_state: None,
        assistant_message_ordinal: 0,
        memory_db: None,
        app_config: None,
        permission_mgr: None,
        transient_allowed_tool_rules: &[],
        hook_engine: None,
        policy_enforcer: None,
        task_mgr: Arc::new(Mutex::new(openclaudia::session::TaskManager::new())),
        session_id: None,
        tx: std::sync::mpsc::channel().0,
    })
    .await;

    let error = result.expect_err("response.failed must fail the turn");
    assert!(!error.contains(SEEDED), "stream failure leaked: {error}");
    assert!(error.contains("[REDACTED]"), "{error}");
}

#[test]
fn malformed_provider_response_trace_and_error_omit_untrusted_payload() {
    let writer = TraceWriter::default();
    let capture = writer.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::WARN)
        .with_writer(writer)
        .finish();
    let result = tracing::subscriber::with_default(subscriber, || {
        AnthropicAdapter::new().transform_response(
            json!({
                "id": "message-id",
                "model": "claude-test",
                "stop_reason": "end_turn",
                "provider_echo": SEEDED
            }),
            false,
        )
    });

    let error = result.expect_err("missing content must fail").to_string();
    let trace =
        String::from_utf8(capture.0.lock().expect("trace buffer").clone()).expect("UTF-8 trace");
    assert!(!error.contains(SEEDED), "provider error leaked: {error}");
    assert!(!trace.contains(SEEDED), "provider trace leaked: {trace}");
    assert!(
        trace.contains("missing required 'content' array"),
        "{trace}"
    );
}

#[cfg(unix)]
#[test]
fn environment_grant_materializes_only_for_child_process() {
    let grants = EnvironmentGrants::try_from(HashMap::from([(
        "S025_CHILD_SECRET".to_string(),
        SEEDED.to_string(),
    )]))
    .expect("environment grants");
    assert!(!format!("{grants:?}").contains(SEEDED));

    let mut command = std::process::Command::new("/bin/sh");
    command
        .env_clear()
        .arg("-c")
        .arg("printf %s \"$S025_CHILD_SECRET\"");
    grants.apply_std(&mut command);
    let output = command.output().expect("child process");
    assert!(output.status.success());
    assert_eq!(output.stdout, SEEDED.as_bytes());
}

mod support;
