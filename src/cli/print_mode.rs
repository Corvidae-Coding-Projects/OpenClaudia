//! One-shot print mode for non-interactive use.
//!
//! This path intentionally does not reuse the legacy REPL loop: it sends one
//! prompt, prints assistant text to stdout, and exits. Request shaping still
//! goes through provider adapters so provider-specific envelopes stay aligned
//! with the proxy and REPL paths.

use eventsource_stream::Eventsource;
use futures::StreamExt;
use openclaudia::providers::ProviderAdapter;
use reqwest::header::CONTENT_TYPE;
use std::io::Write as _;

use crate::{resolve_chat_auth, resolve_model_name, ChatAuth, ChatAuthSelectionMode};

/// Arguments for [`cmd_print`].
pub struct PrintOptions {
    pub model_override: Option<String>,
    pub target_override: Option<String>,
    pub prompt: String,
}

struct PrintSseState {
    anthropic_accumulator: openclaudia::tools::AnthropicToolAccumulator,
    tool_accumulator: openclaudia::tools::ToolCallAccumulator,
    in_thinking_block: bool,
    terminal: openclaudia::pipeline::ChatStreamTerminal,
}

impl PrintSseState {
    fn new(provider: &str) -> Self {
        Self {
            anthropic_accumulator: openclaudia::tools::AnthropicToolAccumulator::new(),
            tool_accumulator: openclaudia::tools::ToolCallAccumulator::new(),
            in_thinking_block: false,
            terminal: openclaudia::pipeline::ChatStreamTerminal::new(provider),
        }
    }
}

fn load_print_config(
    model_override: Option<&str>,
    target_override: Option<&str>,
) -> anyhow::Result<openclaudia::config::AppConfig> {
    let mut config = openclaudia::config::load_config().map_err(|e| {
        if openclaudia::config::config_file_exists() {
            eprintln!("Failed to parse configuration: {e}");
            anyhow::anyhow!("invalid configuration: {e}")
        } else {
            eprintln!("No configuration found. Run 'openclaudia init' first.");
            anyhow::anyhow!("no configuration found")
        }
    })?;

    if let Some(target) = target_override {
        config.proxy.target = target.to_string();
    } else if let Some(model) = model_override {
        let detected = openclaudia::proxy::determine_provider(model, &config);
        if detected != config.proxy.target {
            config.proxy.target = detected;
        }
    }

    Ok(config)
}

fn build_print_request(
    adapter: &dyn ProviderAdapter,
    request: &openclaudia::proxy::ChatCompletionRequest,
    thinking: &openclaudia::config::ThinkingConfig,
    claude_code_token: Option<&openclaudia::secrets::OAuthToken>,
) -> Result<serde_json::Value, String> {
    let mut body = adapter
        .transform_request_with_thinking(request, thinking)
        .map_err(|e| format!("request transform error: {e}"))?;
    if claude_code_token.is_some() {
        openclaudia::claude_credentials::inject_oauth_prefix_only(&mut body);
    }
    Ok(body)
}

fn build_print_chat_request(
    adapter: &dyn ProviderAdapter,
    model: &str,
    prompt: String,
    run: &openclaudia::tools::ToolRunContext,
) -> openclaudia::proxy::ChatCompletionRequest {
    let user_messages = vec![openclaudia::proxy::ChatMessage {
        role: "user".to_string(),
        content: openclaudia::proxy::MessageContent::Text(prompt),
        name: None,
        tool_call_id: None,
        tool_calls: None,
        extra: std::collections::HashMap::new(),
    }];
    let prompt_context = openclaudia::prompt::build_prompt_context_for_run(
        &openclaudia::modes::BehaviorMode::default(),
        run,
    );
    openclaudia::proxy::ChatCompletionRequest {
        model: model.to_string(),
        messages: prompt_context.prepare_chat_messages(&user_messages),
        temperature: None,
        max_tokens: Some(openclaudia::DEFAULT_MAX_TOKENS),
        stream: Some(adapter.name() != "google"),
        tools: None,
        tool_choice: None,
        extra: std::collections::HashMap::new(),
    }
}

fn enforce_print_request_policy(
    config: &openclaudia::config::AppConfig,
    request: &openclaudia::proxy::ChatCompletionRequest,
) -> anyhow::Result<()> {
    let estimated_input = openclaudia::compaction::estimate_request_tokens(request);
    openclaudia::services::policy::ProviderRequestPolicy::new(&config.policy)
        .check(
            openclaudia::services::policy::ProviderRequestPolicyInput::new(
                &request.model,
                estimated_input,
                request.max_tokens,
                0,
            ),
        )
        .map_err(|e| anyhow::anyhow!("Blocked by policy: {e}"))
}

fn resolve_print_endpoint(
    model: &str,
    provider: &openclaudia::config::ProviderConfig,
    adapter: &dyn ProviderAdapter,
    claude_code_token: Option<&openclaudia::secrets::OAuthToken>,
) -> String {
    if claude_code_token.is_some() {
        return openclaudia::claude_credentials::get_oauth_endpoint(model);
    }

    let path = if adapter.name() == "google" {
        adapter.chat_endpoint(model)
    } else {
        adapter
            .stream_endpoint(model)
            .unwrap_or_else(|| adapter.chat_endpoint(model))
    };
    format!(
        "{}{}",
        openclaudia::proxy::normalize_base_url(&provider.base_url),
        path
    )
}

#[cfg(test)]
fn sse_data_from_line(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with(':') {
        return None;
    }
    trimmed.strip_prefix("data:").map(str::trim_start)
}

fn extract_print_sse_text(json: &serde_json::Value, state: &mut PrintSseState) -> Option<String> {
    match openclaudia::pipeline::process_sse_event(
        json,
        state.in_thinking_block,
        &mut state.anthropic_accumulator,
        &mut state.tool_accumulator,
    ) {
        openclaudia::pipeline::SseAction::Text(text) => Some(text),
        openclaudia::pipeline::SseAction::ThinkingStart => {
            state.in_thinking_block = true;
            None
        }
        openclaudia::pipeline::SseAction::ThinkingEnd => {
            state.in_thinking_block = false;
            None
        }
        openclaudia::pipeline::SseAction::Thinking(_)
        | openclaudia::pipeline::SseAction::Reasoning(_)
        | openclaudia::pipeline::SseAction::None => None,
    }
}

#[cfg(test)]
fn extract_print_sse_line(line: &str, state: &mut PrintSseState) -> anyhow::Result<Option<String>> {
    let Some(data) = sse_data_from_line(line) else {
        return Ok(None);
    };
    if data == "[DONE]" {
        state.terminal.observe_done();
        return Ok(None);
    }
    let json = serde_json::from_str::<serde_json::Value>(data)
        .map_err(|e| anyhow::anyhow!("invalid SSE data JSON: {e}"))?;
    state.terminal.observe(&json).map_err(anyhow::Error::msg)?;
    Ok(extract_print_sse_text(&json, state))
}

fn response_is_json(response: &reqwest::Response) -> bool {
    response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|content_type| {
            let lower = content_type.to_ascii_lowercase();
            lower.contains("application/json") || lower.contains("+json")
        })
}

async fn print_json_response(
    response: reqwest::Response,
    adapter: &dyn ProviderAdapter,
) -> anyhow::Result<()> {
    let body = openclaudia::provider_transport::read_json_capped::<serde_json::Value>(
        response,
        openclaudia::provider_transport::MAX_JSON_RESPONSE_BYTES,
    )
    .await?;
    let normalized = adapter
        .transform_response(body.clone(), false)
        .map_err(|error| anyhow::anyhow!("provider response transform failed: {error}"))?;
    let terminal = openclaudia::pipeline::validate_chat_completion_terminal(&normalized)
        .map_err(anyhow::Error::msg)?;
    if terminal != openclaudia::pipeline::ProviderTerminalOutcome::Completed {
        anyhow::bail!("provider requested tools in no-tools print mode");
    }
    let text = adapter.extract_response_text(&body).ok_or_else(|| {
        anyhow::anyhow!("provider response did not contain printable assistant text")
    })?;
    println!("{text}");
    Ok(())
}

async fn print_sse_response(response: reqwest::Response, provider: &str) -> anyhow::Result<()> {
    let mut stream = openclaudia::provider_transport::bounded_byte_stream(
        response,
        openclaudia::provider_transport::MAX_STREAM_RESPONSE_BYTES,
    )
    .eventsource();
    let mut state = PrintSseState::new(provider);
    let mut emitted_text = false;

    while let Some(event) = stream.next().await {
        let event = event.map_err(|err| anyhow::anyhow!("SSE stream error: {err}"))?;
        if event.data == "[DONE]" {
            state.terminal.observe_done();
            break;
        }
        let json = serde_json::from_str::<serde_json::Value>(&event.data)
            .map_err(|err| anyhow::anyhow!("invalid SSE data JSON: {err}"))?;
        state.terminal.observe(&json).map_err(anyhow::Error::msg)?;
        if let Some(text) = extract_print_sse_text(&json, &mut state) {
            emitted_text |= !text.is_empty();
            print!("{text}");
            std::io::stdout().flush()?;
        }
    }

    let tool_call_count = if provider.eq_ignore_ascii_case("anthropic") {
        state
            .anthropic_accumulator
            .finalize_tool_calls_checked()
            .map_err(anyhow::Error::msg)?
            .len()
    } else {
        state
            .tool_accumulator
            .finalize_checked()
            .map_err(anyhow::Error::msg)?
            .len()
    };
    let terminal = state.terminal.finish().map_err(anyhow::Error::msg)?;
    if tool_call_count > 0 {
        anyhow::bail!("provider returned {tool_call_count} tool call(s) to no-tools print mode");
    }
    openclaudia::pipeline::ensure_provider_turn_succeeded(terminal, tool_call_count)
        .map_err(anyhow::Error::msg)?;

    if !emitted_text {
        anyhow::bail!("provider stream did not contain printable assistant text");
    }

    println!();
    Ok(())
}

fn print_message_values(
    request: &openclaudia::proxy::ChatCompletionRequest,
) -> anyhow::Result<Vec<serde_json::Value>> {
    request
        .messages
        .iter()
        .cloned()
        .map(serde_json::to_value)
        .collect::<Result<Vec<_>, _>>()
        .map_err(anyhow::Error::from)
}

async fn print_responses_stream(
    response: reqwest::Response,
    headers: &openclaudia::secrets::SensitiveHeaders,
    provider: &str,
    model: &str,
    assistant_message_ordinal: u64,
) -> anyhow::Result<()> {
    let decoded = openclaudia::pipeline::decode_openai_responses_stream(
        openclaudia::pipeline::OpenAiResponsesStreamParams {
            response,
            headers,
            provider,
            model_identity: model,
            provider_native_state: None,
            assistant_message_ordinal,
        },
        |_| Ok(()),
        |_| Ok(()),
        |_, _| Ok(()),
    )
    .await
    .map_err(anyhow::Error::msg)?;

    if !decoded.tool_calls.is_empty() {
        anyhow::bail!(
            "Responses provider returned {} tool call(s) to no-tools print mode",
            decoded.tool_calls.len()
        );
    }
    openclaudia::pipeline::ensure_provider_turn_succeeded(
        decoded.terminal_outcome,
        decoded.tool_calls.len(),
    )
    .map_err(anyhow::Error::msg)?;
    if decoded.content.is_empty() {
        anyhow::bail!("Responses stream did not contain printable assistant text");
    }
    println!("{}", decoded.content);
    Ok(())
}

struct PreparedPrintTransport {
    request_body: serde_json::Value,
    endpoint: String,
    headers: openclaudia::secrets::SensitiveHeaders,
    wire_api: openclaudia::pipeline::WireApi,
    responses_assistant_ordinal: Option<u64>,
}

struct PreparePrintTransport<'a> {
    config: &'a openclaudia::config::AppConfig,
    provider: &'a openclaudia::config::ProviderConfig,
    adapter: &'a dyn ProviderAdapter,
    model: &'a str,
    chat_request: &'a openclaudia::proxy::ChatCompletionRequest,
    auth: &'a ChatAuth,
}

fn prepare_print_transport(
    p: &PreparePrintTransport<'_>,
) -> anyhow::Result<PreparedPrintTransport> {
    let wire_api = if p.auth.codex_responses_auth.is_some() {
        openclaudia::pipeline::WireApi::OpenAiResponses
    } else {
        openclaudia::pipeline::WireApi::ChatCompletions
    };
    let (request_body, responses_assistant_ordinal) = if wire_api.is_responses() {
        let messages = print_message_values(p.chat_request)?;
        let ordinal = openclaudia::pipeline::next_assistant_message_ordinal(&messages)
            .map_err(anyhow::Error::msg)?;
        (
            openclaudia::pipeline::build_request_for_wire_with_exact_tools_and_state(
                wire_api,
                &p.config.proxy.target,
                p.model,
                &messages,
                p.provider
                    .thinking
                    .reasoning_effort
                    .as_deref()
                    .unwrap_or("medium"),
                None,
                None,
                &[],
                None,
            )
            .map_err(anyhow::Error::msg)?,
            Some(ordinal),
        )
    } else {
        (
            build_print_request(
                p.adapter,
                p.chat_request,
                &p.provider.thinking,
                p.auth.claude_code_token.as_ref(),
            )
            .map_err(anyhow::Error::msg)?,
            None,
        )
    };
    let extra_headers = p.provider.headers.clone();
    let (endpoint, headers) = if let Some(auth) = p.auth.codex_responses_auth.as_ref() {
        let endpoint = openclaudia::pipeline::resolve_endpoint_for_wire(
            wire_api,
            &p.config.proxy.target,
            p.model,
            openclaudia::codex_credentials::CODEX_CHATGPT_BASE_URL,
            None,
        )?;
        let mut headers = auth.headers()?;
        headers.extend(&extra_headers);
        (endpoint, headers)
    } else {
        (
            resolve_print_endpoint(
                p.model,
                p.provider,
                p.adapter,
                p.auth.claude_code_token.as_ref(),
            ),
            openclaudia::pipeline::resolve_headers(
                &p.config.proxy.target,
                p.auth.api_key.as_ref(),
                p.auth.claude_code_token.as_ref(),
                &extra_headers,
            )?,
        )
    };
    Ok(PreparedPrintTransport {
        request_body,
        endpoint,
        headers,
        wire_api,
        responses_assistant_ordinal,
    })
}

/// Run one-shot print mode.
///
/// # Errors
///
/// Returns an error when configuration/auth cannot be resolved, the provider
/// rejects the request, or the response stream cannot be decoded.
pub async fn cmd_print(options: PrintOptions) -> anyhow::Result<()> {
    crate::chdir_to_git_root();

    let config = load_print_config(
        options.model_override.as_deref(),
        options.target_override.as_deref(),
    )?;
    let print_root = std::env::current_dir()
        .map_err(|error| anyhow::anyhow!("could not resolve print-mode project root: {error}"))?;
    let print_run = openclaudia::tools::ToolRunContext::builder(
        openclaudia::state::SessionId::new(),
        &print_root,
    )
    .working_directory(&print_root)
    .read_only_roots(Vec::new())
    .read_write_roots(Vec::new())
    .environment_grants(std::collections::HashMap::new())
    .workspace_access(openclaudia::tools::WorkspaceAccess::ReadOnly)
    .process(false)
    .network(true)
    .secrets(true)
    .provider(config.proxy.target.clone())
    .build()
    .map_err(anyhow::Error::msg)?;
    let provider = config.active_provider().ok_or_else(|| {
        anyhow::anyhow!(
            "no provider configured for target '{}'",
            config.proxy.target
        )
    })?;
    let Some(chat_auth) = resolve_chat_auth(
        &config.proxy.target,
        provider,
        ChatAuthSelectionMode::Automatic,
    )
    .await?
    else {
        anyhow::bail!(
            "could not resolve authentication for target '{}'",
            config.proxy.target
        );
    };
    let model = resolve_model_name(
        options.model_override,
        provider.model.clone(),
        &config.proxy.target,
    )
    .map_err(anyhow::Error::msg)?;
    let adapter = openclaudia::providers::get_adapter(&config.proxy.target)?;
    let chat_request = build_print_chat_request(adapter, &model, options.prompt, &print_run);
    enforce_print_request_policy(&config, &chat_request)?;
    let prepared = prepare_print_transport(&PreparePrintTransport {
        config: &config,
        provider,
        adapter,
        model: &model,
        chat_request: &chat_request,
        auth: &chat_auth,
    })?;
    let PreparedPrintTransport {
        request_body,
        endpoint,
        headers,
        wire_api,
        responses_assistant_ordinal,
    } = prepared;

    let client = openclaudia::provider_transport::shared_client()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let request = headers.apply(client.post(endpoint).json(&request_body))?;

    let response = openclaudia::provider_transport::send(request).await?;
    if !response.status().is_success() {
        let status = response.status();
        let body = openclaudia::secrets::read_bounded_diagnostic_body(response)
            .await
            .unwrap_or_else(|_| zeroize::Zeroizing::new(String::new()));
        let diagnostic = headers.sanitize_diagnostic(&body);
        anyhow::bail!("API error {}: {diagnostic}", status.as_u16());
    }

    if wire_api.is_responses() {
        print_responses_stream(
            response,
            &headers,
            &config.proxy.target,
            &model,
            responses_assistant_ordinal
                .ok_or_else(|| anyhow::anyhow!("Responses request ordinal is missing"))?,
        )
        .await
    } else if response_is_json(&response) {
        print_json_response(response, adapter).await
    } else {
        print_sse_response(response, &config.proxy.target).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, OnceLock};

    fn print_test_run() -> &'static openclaudia::tools::ToolRunContext {
        static RUN: OnceLock<Arc<openclaudia::tools::ToolRunContext>> = OnceLock::new();
        RUN.get_or_init(|| {
            openclaudia::tools::ToolRunContext::builder(
                openclaudia::state::SessionId::new(),
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
            )
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::new())
            .workspace_access(openclaudia::tools::WorkspaceAccess::ReadOnly)
            .process(false)
            .network(true)
            .secrets(true)
            .provider("print-test")
            .build()
            .expect("print test run")
        })
    }

    fn test_config_with_policy(
        policy: openclaudia::services::policy::EnterprisePolicy,
    ) -> openclaudia::config::AppConfig {
        openclaudia::config::AppConfig {
            proxy: openclaudia::config::ProxyConfig::default(),
            providers: HashMap::new(),
            hooks: openclaudia::config::HooksConfig::default(),
            session: openclaudia::config::SessionConfig::default(),
            keybindings: openclaudia::config::KeybindingsConfig::default(),
            vdd: openclaudia::config::VddConfig::default(),
            guardrails: openclaudia::config::GuardrailsConfig::default(),
            permissions: openclaudia::config::PermissionsConfig::default(),
            memory: openclaudia::config::MemoryConfig::default(),
            web_fetch: openclaudia::config::WebFetchConfig::default(),
            policy,
            managed_settings_path: None,
        }
    }

    #[test]
    fn print_sse_extracts_openai_text_delta() {
        let mut state = PrintSseState::new("openai");
        let json = json!({"choices": [{"delta": {"content": "hello"}}]});
        assert_eq!(
            extract_print_sse_text(&json, &mut state),
            Some("hello".to_string())
        );
    }

    #[test]
    fn print_sse_extracts_anthropic_text_delta() {
        let mut state = PrintSseState::new("anthropic");
        let json = json!({
            "type": "content_block_delta",
            "delta": {"type": "text_delta", "text": "world"}
        });
        assert_eq!(
            extract_print_sse_text(&json, &mut state),
            Some("world".to_string())
        );
    }

    #[test]
    fn print_sse_suppresses_thinking_deltas() {
        let mut state = PrintSseState::new("anthropic");
        let start = json!({
            "type": "content_block_start",
            "content_block": {"type": "thinking"}
        });
        let delta = json!({
            "type": "content_block_delta",
            "delta": {"type": "thinking_delta", "thinking": "private"}
        });
        let stop = json!({"type": "content_block_stop"});
        assert_eq!(extract_print_sse_text(&start, &mut state), None);
        assert!(state.in_thinking_block);
        assert_eq!(extract_print_sse_text(&delta, &mut state), None);
        assert_eq!(extract_print_sse_text(&stop, &mut state), None);
        assert!(!state.in_thinking_block);
    }

    #[test]
    fn print_sse_suppresses_openai_reasoning_delta() {
        let mut state = PrintSseState::new("openai");
        let json = json!({"choices": [{"delta": {"reasoning_content": "private"}}]});
        assert_eq!(extract_print_sse_text(&json, &mut state), None);
    }

    #[test]
    fn codex_print_builds_the_shared_no_tools_responses_profile() {
        let adapter = openclaudia::providers::get_adapter("openai").expect("OpenAI adapter");
        let mut config =
            test_config_with_policy(openclaudia::services::policy::EnterprisePolicy::default());
        config.proxy.target = "openai".to_string();
        let provider = openclaudia::config::ProviderConfig {
            api_key: None,
            base_url: "https://api.openai.com/v1".to_string(),
            model: None,
            headers: openclaudia::secrets::SensitiveHeaders::new(),
            thinking: openclaudia::config::ThinkingConfig {
                reasoning_effort: Some("high".to_string()),
                ..openclaudia::config::ThinkingConfig::default()
            },
        };
        let request = build_print_chat_request(
            adapter,
            "gpt-test",
            "inspect the workspace".to_string(),
            print_test_run(),
        );
        let auth = ChatAuth {
            api_key: None,
            claude_code_token: None,
            codex_responses_auth: Some(openclaudia::codex_credentials::CodexResponsesAuth {
                access_token: openclaudia::secrets::OAuthToken::try_from_string(
                    "print-responses-token".to_string(),
                )
                .expect("token"),
                account_id: None,
                is_fedramp_account: false,
                source: openclaudia::codex_credentials::CodexAuthSource::EnvAccessToken,
                mode: openclaudia::codex_credentials::CodexAuthMode::ChatgptAuthTokens,
            }),
        };
        let prepared = prepare_print_transport(&PreparePrintTransport {
            config: &config,
            provider: &provider,
            adapter,
            model: "gpt-test",
            chat_request: &request,
            auth: &auth,
        })
        .expect("Codex print transport");
        let body = prepared.request_body;

        assert_eq!(prepared.responses_assistant_ordinal, Some(1));
        assert_eq!(
            prepared.wire_api,
            openclaudia::pipeline::WireApi::OpenAiResponses
        );
        assert!(prepared.endpoint.ends_with("/responses"));
        assert!(prepared
            .headers
            .matches_value("authorization", "Bearer print-responses-token"));
        assert_eq!(body["store"], false);
        assert_eq!(body["stream"], true);
        assert!(body.get("tools").is_none());
        assert!(body.get("tool_choice").is_none());
        assert!(body.get("parallel_tool_calls").is_none());
        assert!(body.get("messages").is_none());
        assert!(body.get("_openclaudia_responses_history").is_none());
        assert!(body["input"]
            .as_array()
            .expect("Responses input")
            .iter()
            .all(|item| item.get("_openclaudia_message_ordinal").is_none()));
    }

    #[test]
    fn print_sse_line_rejects_malformed_data_json() {
        let mut state = PrintSseState::new("openai");
        let err = extract_print_sse_line("data: {not valid json}", &mut state).unwrap_err();
        assert!(
            err.to_string().contains("invalid SSE data JSON"),
            "malformed SSE data should be a hard print-mode error; got {err}"
        );
    }

    #[test]
    fn print_policy_rejects_unlisted_model_before_request_send() {
        let config = test_config_with_policy(openclaudia::services::policy::EnterprisePolicy {
            model_allowlist: HashSet::from(["allowed-model".to_string()]),
            ..Default::default()
        });
        let request = build_print_chat_request(
            openclaudia::providers::get_adapter("openai").expect("adapter"),
            "blocked-model",
            "hello".to_string(),
            print_test_run(),
        );

        let err = enforce_print_request_policy(&config, &request).unwrap_err();
        assert!(err.to_string().contains("Blocked by policy"));
        assert!(err.to_string().contains("blocked-model"));
    }

    #[test]
    fn print_policy_rejects_request_token_cap_before_request_send() {
        let config = test_config_with_policy(openclaudia::services::policy::EnterprisePolicy {
            max_request_tokens: Some(1),
            ..Default::default()
        });
        let request = build_print_chat_request(
            openclaudia::providers::get_adapter("openai").expect("adapter"),
            "any-model",
            "this prompt is intentionally longer than one estimated token".to_string(),
            print_test_run(),
        );

        let err = enforce_print_request_policy(&config, &request).unwrap_err();
        assert!(err.to_string().contains("Blocked by policy"));
        assert!(err.to_string().contains("request exceeds policy token cap"));
    }

    #[test]
    fn print_request_has_no_tools_and_streams_non_google() {
        let adapter = openclaudia::providers::get_adapter("openai").unwrap();
        let request =
            build_print_chat_request(adapter, "gpt-5.5", "hi".to_string(), print_test_run());
        let body = build_print_request(
            adapter,
            &request,
            &openclaudia::config::ThinkingConfig::default(),
            None,
        )
        .unwrap();
        assert_eq!(body["stream"], true);
        assert!(body.get("tools").is_none());
    }

    #[test]
    fn print_request_applies_openai_reasoning_effort() {
        let adapter = openclaudia::providers::get_adapter("openai").unwrap();
        let thinking = openclaudia::config::ThinkingConfig {
            reasoning_effort: Some("xhigh".to_string()),
            ..Default::default()
        };

        let request =
            build_print_chat_request(adapter, "gpt-5.5", "hi".to_string(), print_test_run());
        let body = build_print_request(adapter, &request, &thinking, None).unwrap();

        assert_eq!(body["reasoning_effort"], "xhigh");
    }

    #[test]
    fn print_request_applies_google_thinking_budget() {
        let adapter = openclaudia::providers::get_adapter("google").unwrap();
        let thinking = openclaudia::config::ThinkingConfig {
            budget_tokens: Some(7777),
            ..openclaudia::config::ThinkingConfig::default()
        };

        let request = build_print_chat_request(
            adapter,
            "gemini-3.5-flash",
            "hi".to_string(),
            print_test_run(),
        );
        let body = build_print_request(adapter, &request, &thinking, None).unwrap();

        assert_eq!(
            body["generationConfig"]["thinkingConfig"]["thinkingBudget"],
            7777
        );
    }

    #[test]
    fn print_endpoint_uses_google_json_endpoint() {
        let adapter = openclaudia::providers::get_adapter("google").unwrap();
        let provider = openclaudia::config::ProviderConfig {
            api_key: None,
            base_url: "https://generativelanguage.googleapis.com".to_string(),
            model: None,
            headers: openclaudia::secrets::SensitiveHeaders::new(),
            thinking: openclaudia::config::ThinkingConfig::default(),
        };
        let endpoint = resolve_print_endpoint("gemini-3.5-flash", &provider, adapter, None);
        assert!(endpoint.ends_with("/v1beta/models/gemini-3.5-flash:generateContent"));
        assert!(!endpoint.contains("streamGenerateContent"));
    }
}
