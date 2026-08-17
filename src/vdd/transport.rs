//! HTTP transport for the VDD loop: adversary + builder request plumbing.

use reqwest::Client;
use serde_json::Value;
use tracing::{debug, info, warn};

use crate::config::{AppConfig, ProviderConfig, VddConfig};
use crate::providers::{get_adapter, ApiKey, ProviderAdapter};
use crate::proxy::ChatCompletionRequest;
use crate::session::TokenUsage;

use crate::vdd::error::VddError;
use crate::vdd::helpers::truncate_output;

/// Runtime authentication material for a provider used by VDD.
///
/// This is deliberately separate from [`VddConfig`]: startup can select
/// account-backed auth for the current session without persisting bearer tokens
/// into `.openclaudia/config.yaml`.
#[derive(Clone, PartialEq, Eq)]
pub enum VddProviderAuth {
    ApiKey(ApiKey),
    ClaudeCodeToken(String),
    CodexResponses(crate::codex_credentials::CodexResponsesAuth),
    None,
}

impl std::fmt::Debug for VddProviderAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiKey(_) => f.write_str("VddProviderAuth::ApiKey(<redacted>)"),
            Self::ClaudeCodeToken(_) => f.write_str("VddProviderAuth::ClaudeCodeToken(<redacted>)"),
            Self::CodexResponses(auth) => f
                .debug_tuple("VddProviderAuth::CodexResponses")
                .field(auth)
                .finish(),
            Self::None => f.write_str("VddProviderAuth::None"),
        }
    }
}

impl VddProviderAuth {
    #[must_use]
    pub const fn api_key(api_key: ApiKey) -> Self {
        Self::ApiKey(api_key)
    }

    #[must_use]
    pub const fn claude_code_token(token: String) -> Self {
        Self::ClaudeCodeToken(token)
    }

    #[must_use]
    pub const fn codex_responses(auth: crate::codex_credentials::CodexResponsesAuth) -> Self {
        Self::CodexResponses(auth)
    }
}

/// Forward a request to a provider and return the raw reqwest response.
///
/// URL composition is entirely delegated to the adapter via `endpoint`
/// (the return value of `ProviderAdapter::chat_endpoint`), so provider-specific
/// path conventions (e.g. Google's `/v1beta/models/{model}:generateContent`)
/// are handled in the adapter, not here.
pub async fn forward_request(
    client: &Client,
    provider: &ProviderConfig,
    endpoint: &str,
    body: &Value,
    headers: Vec<(String, String)>,
) -> Result<reqwest::Response, reqwest::Error> {
    let base_url = provider
        .base_url
        .trim_end_matches('/')
        .trim_end_matches("/v1")
        .trim_end_matches('/');

    // endpoint already encodes the full provider-specific path, including
    // any model name or version segment (e.g. Google's v1beta path). OAuth
    // and Codex-backed flows may provide a fully-qualified endpoint.
    let url = if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        endpoint.to_string()
    } else {
        format!("{base_url}{endpoint}")
    };

    // Validate the constructed URL before sending the request
    if let Err(e) = reqwest::Url::parse(&url) {
        warn!("VDD: Invalid provider URL '{}': {}", url, e);
    }

    debug!("VDD: Sending request to {}", url);

    let mut req = client.post(&url).json(body);
    for (key, value) in headers {
        req = req.header(key.as_str(), value.as_str());
    }
    for (key, value) in &provider.headers {
        req = req.header(key.as_str(), value.as_str());
    }

    req.send().await
}

fn chat_messages_as_values(request: &ChatCompletionRequest) -> Result<Vec<Value>, VddError> {
    request
        .messages
        .iter()
        .map(|message| {
            serde_json::to_value(message)
                .map_err(|e| VddError::AdversaryRequestFailed(format!("message encode: {e}")))
        })
        .collect()
}

fn responses_text_from_json(json: &Value) -> Option<String> {
    if let Some(text) = json.get("output_text").and_then(Value::as_str) {
        return Some(text.to_string());
    }

    let mut out = String::new();
    for item in json.get("output").and_then(Value::as_array)? {
        for part in item
            .get("content")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(text) = part
                .get("text")
                .and_then(Value::as_str)
                .or_else(|| part.get("content").and_then(Value::as_str))
            {
                out.push_str(text);
            }
        }
    }
    (!out.is_empty()).then_some(out)
}

fn responses_usage_from_json(json: &Value) -> TokenUsage {
    let Some(usage) = json.get("usage") else {
        return TokenUsage::default();
    };
    TokenUsage {
        input_tokens: usage
            .get("input_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        output_tokens: usage
            .get("output_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        cache_read_tokens: usage
            .get("input_tokens_details")
            .and_then(|details| details.get("cached_tokens"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
        cache_write_tokens: 0,
    }
}

fn responses_text_from_sse(raw: &str) -> Result<(String, TokenUsage), VddError> {
    let mut text = String::new();
    let mut usage = TokenUsage::default();
    for line in raw.lines() {
        let Some(data) = line.trim_start().strip_prefix("data:") else {
            continue;
        };
        let data = data.trim();
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        let json = serde_json::from_str::<Value>(data).map_err(|e| {
            VddError::AdversaryRequestFailed(format!("responses SSE frame decode: {e}"))
        })?;
        match json.get("type").and_then(Value::as_str).unwrap_or_default() {
            "response.output_text.delta" => {
                if let Some(delta) = json.get("delta").and_then(Value::as_str) {
                    text.push_str(delta);
                }
            }
            "response.completed" => {
                if let Some(response) = json.get("response") {
                    usage.accumulate(&responses_usage_from_json(response));
                    if text.is_empty() {
                        if let Some(final_text) = responses_text_from_json(response) {
                            text = final_text;
                        }
                    }
                }
            }
            "response.failed" | "response.incomplete" => {
                let message = json
                    .get("response")
                    .and_then(|response| response.get("error"))
                    .or_else(|| json.get("error"))
                    .and_then(|error| {
                        error
                            .get("message")
                            .and_then(Value::as_str)
                            .or_else(|| error.as_str())
                    })
                    .unwrap_or("Responses API request failed");
                return Err(VddError::AdversaryRequestFailed(message.to_string()));
            }
            _ => {}
        }
    }
    Ok((text, usage))
}

async fn send_to_codex_responses(
    client: &Client,
    auth: &crate::codex_credentials::CodexResponsesAuth,
    request: &ChatCompletionRequest,
    timeout: std::time::Duration,
    timeout_secs: u64,
) -> Result<(String, TokenUsage), VddError> {
    let messages = chat_messages_as_values(request)?;
    let mut body =
        crate::pipeline::build_openai_responses_request(&request.model, &messages, "medium")
            .map_err(|e| VddError::AdversaryRequestFailed(format!("responses transform: {e}")))?;
    body["stream"] = Value::Bool(false);
    if let Some(obj) = body.as_object_mut() {
        obj.remove("tools");
        obj.remove("tool_choice");
        obj.remove("parallel_tool_calls");
        obj.remove("include");
    }

    let endpoint = format!(
        "{}/responses",
        crate::proxy::normalize_base_url(crate::codex_credentials::CODEX_CHATGPT_BASE_URL)
    );
    let mut req = client.post(endpoint).json(&body);
    for (key, value) in auth.headers() {
        req = req.header(key.as_str(), value.as_str());
    }

    let response = tokio::time::timeout(timeout, req.send())
        .await
        .map_err(|_| VddError::Timeout {
            provider: "openai".to_string(),
            elapsed_secs: timeout_secs,
        })?
        .map_err(|e| VddError::AdversaryRequestFailed(format!("responses request: {e}")))?;
    let status = response.status();

    let raw = tokio::time::timeout(timeout, response.text())
        .await
        .map_err(|_| VddError::Timeout {
            provider: "openai".to_string(),
            elapsed_secs: timeout_secs,
        })?
        .map_err(|e| VddError::AdversaryRequestFailed(format!("responses body: {e}")))?;
    if !status.is_success() {
        return Err(VddError::AdversaryRequestFailed(format!(
            "responses request failed with HTTP {status}: {}",
            truncate_output(&raw, 1000)
        )));
    }

    if raw
        .lines()
        .any(|line| line.trim_start().starts_with("data:"))
    {
        return responses_text_from_sse(&raw);
    }
    let json = serde_json::from_str::<Value>(&raw)
        .map_err(|e| VddError::AdversaryRequestFailed(format!("responses JSON decode: {e}")))?;
    Ok((
        responses_text_from_json(&json).unwrap_or_default(),
        responses_usage_from_json(&json),
    ))
}

fn adversary_headers_and_endpoint(
    config: &VddConfig,
    provider_config: &ProviderConfig,
    adapter: &dyn ProviderAdapter,
    request: &ChatCompletionRequest,
    transformed: &mut Value,
    runtime_auth: Option<&VddProviderAuth>,
) -> Result<(Vec<(String, String)>, String), VddError> {
    match runtime_auth {
        Some(VddProviderAuth::ApiKey(api_key)) => Ok((
            adapter.get_headers(api_key),
            adapter.chat_endpoint(&request.model),
        )),
        Some(VddProviderAuth::ClaudeCodeToken(token)) => {
            if !config.adversary.provider.eq_ignore_ascii_case("anthropic") {
                return Err(VddError::ConfigError(format!(
                    "Claude Code auth can only be used with Anthropic VDD adversary, got '{}'",
                    config.adversary.provider
                )));
            }
            crate::claude_credentials::inject_oauth_prefix_only(transformed);
            Ok((
                crate::claude_credentials::get_oauth_headers(token),
                crate::claude_credentials::get_oauth_endpoint(&request.model),
            ))
        }
        Some(VddProviderAuth::None) => Ok((Vec::new(), adapter.chat_endpoint(&request.model))),
        None => {
            let api_key = config
                .adversary
                .api_key
                .as_ref()
                .or(provider_config.api_key.as_ref())
                .ok_or_else(|| {
                    VddError::ConfigError(format!(
                        "No API key for adversary provider '{}'",
                        config.adversary.provider
                    ))
                })?;
            Ok((
                adapter.get_headers(api_key),
                adapter.chat_endpoint(&request.model),
            ))
        }
        Some(VddProviderAuth::CodexResponses(_)) => unreachable!("handled above"),
    }
}

/// Send a request to the adversary provider. Returns (`response_text`, `token_usage`).
///
/// Per-request timeout — crosslink #496 — wraps both the HTTP send and the
/// body read in `tokio::time::timeout` so a hung adversary cannot block the
/// VDD loop indefinitely. The timeout is configurable via
/// `vdd.adversary.request_timeout_seconds` (default 120 s).
pub async fn send_to_adversary(
    client: &Client,
    config: &VddConfig,
    app_config: &AppConfig,
    request: &ChatCompletionRequest,
    runtime_auth: Option<&VddProviderAuth>,
) -> Result<(String, TokenUsage), VddError> {
    let provider_config = app_config
        .providers
        .get(&config.adversary.provider)
        .ok_or_else(|| {
            VddError::ConfigError(format!(
                "Adversary provider '{}' not configured in providers section",
                config.adversary.provider
            ))
        })?;

    let timeout_secs = config.adversary.request_timeout_seconds;
    let timeout = std::time::Duration::from_secs(timeout_secs);

    if let Some(VddProviderAuth::CodexResponses(auth)) = runtime_auth {
        if !config.adversary.provider.eq_ignore_ascii_case("openai") {
            return Err(VddError::ConfigError(format!(
                "Codex Responses auth can only be used with OpenAI VDD adversary, got '{}'",
                config.adversary.provider
            )));
        }
        return send_to_codex_responses(client, auth, request, timeout, timeout_secs).await;
    }

    // Crosslink #433: a typo in `config.adversary.provider` now surfaces
    // as `ConfigError` instead of being silently mapped to OpenAIAdapter.
    let adapter = get_adapter(&config.adversary.provider)
        .map_err(|e| VddError::ConfigError(e.to_string()))?;
    let mut transformed = adapter
        .transform_request(request)
        .map_err(|e| VddError::AdversaryRequestFailed(e.to_string()))?;

    let (headers, endpoint) = adversary_headers_and_endpoint(
        config,
        provider_config,
        adapter,
        request,
        &mut transformed,
        runtime_auth,
    )?;

    let provider_name = adapter.name().to_string();

    let response = tokio::time::timeout(
        timeout,
        forward_request(client, provider_config, &endpoint, &transformed, headers),
    )
    .await
    .map_err(|_| VddError::Timeout {
        provider: provider_name.clone(),
        elapsed_secs: timeout_secs,
    })?
    .map_err(|e| VddError::AdversaryRequestFailed(e.to_string()))?;

    // Same timeout wraps the body-read to prevent a slow-drip
    // payload from exceeding the total budget.
    let response_json: Value = tokio::time::timeout(timeout, response.json())
        .await
        .map_err(|_| VddError::Timeout {
            provider: provider_name.clone(),
            elapsed_secs: timeout_secs,
        })?
        .map_err(|e| VddError::AdversaryRequestFailed(e.to_string()))?;

    // Crosslink #479: route extraction through the ProviderAdapter trait
    // so provider-specific response shapes (Gemini, Ollama, Anthropic) are
    // handled the same way they are on the main proxy path. The previous
    // free functions silently returned an empty string / zero tokens for
    // any provider whose response shape they did not hardcode.
    let text = adapter
        .extract_response_text(&response_json)
        .unwrap_or_default();
    let tokens = adapter
        .extract_token_usage(&response_json)
        .unwrap_or_default();

    // Always log at INFO level for debugging, truncated
    info!(
        response_length = text.len(),
        "VDD: Received adversary response ({} chars)",
        text.len()
    );

    if config.tracking.log_adversary_responses {
        // Log first 1000 chars to see what we're getting
        info!(
            "VDD: Adversary response preview: {}",
            truncate_output(&text, 1000)
        );
    }

    Ok((text, tokens))
}

/// Send a revision request back to the builder provider.
///
/// Symmetric per-request timeout for the builder (crosslink #496). The
/// builder revision call sits inside the same blocking-loop iteration as
/// the adversary call, so a hung builder would block the loop just as
/// badly. The timeout reuses the adversary's configured value for
/// simplicity — they're the same upper bound on how long any single
/// HTTP round-trip in the loop is allowed to take.
pub async fn send_to_builder(
    client: &Client,
    config: &VddConfig,
    app_config: &AppConfig,
    request: &ChatCompletionRequest,
    provider_name: &str,
    api_key: Option<&ApiKey>,
    runtime_auth: Option<&VddProviderAuth>,
) -> Result<(String, Value, TokenUsage), VddError> {
    let provider_config = app_config.providers.get(provider_name).ok_or_else(|| {
        VddError::BuilderRevisionFailed(format!(
            "Builder provider '{provider_name}' not configured"
        ))
    })?;

    // Crosslink #433: explicit error for an unknown builder provider
    // name, no silent OpenAIAdapter fallback.
    let adapter = get_adapter(provider_name).map_err(|e| VddError::ConfigError(e.to_string()))?;
    let timeout_secs = config.adversary.request_timeout_seconds;
    let timeout = std::time::Duration::from_secs(timeout_secs);

    if let Some(VddProviderAuth::CodexResponses(auth)) = runtime_auth {
        if !provider_name.eq_ignore_ascii_case("openai") {
            return Err(VddError::ConfigError(format!(
                "Codex Responses auth can only be used with OpenAI builder, got '{provider_name}'"
            )));
        }
        let (text, tokens) =
            send_to_codex_responses(client, auth, request, timeout, timeout_secs).await?;
        return Ok((
            text.clone(),
            serde_json::json!({ "output_text": text }),
            tokens,
        ));
    }

    let mut transformed = adapter
        .transform_request(request)
        .map_err(|e| VddError::BuilderRevisionFailed(e.to_string()))?;

    let (headers, endpoint) = match runtime_auth {
        Some(VddProviderAuth::ApiKey(api_key)) => (
            adapter.get_headers(api_key),
            adapter.chat_endpoint(&request.model),
        ),
        Some(VddProviderAuth::ClaudeCodeToken(token)) => {
            if !provider_name.eq_ignore_ascii_case("anthropic") {
                return Err(VddError::ConfigError(format!(
                    "Claude Code auth can only be used with Anthropic builder, got '{provider_name}'"
                )));
            }
            crate::claude_credentials::inject_oauth_prefix_only(&mut transformed);
            (
                crate::claude_credentials::get_oauth_headers(token),
                crate::claude_credentials::get_oauth_endpoint(&request.model),
            )
        }
        Some(VddProviderAuth::None) => (Vec::new(), adapter.chat_endpoint(&request.model)),
        None => (
            api_key.map(|k| adapter.get_headers(k)).unwrap_or_default(),
            adapter.chat_endpoint(&request.model),
        ),
        Some(VddProviderAuth::CodexResponses(_)) => unreachable!("handled above"),
    };

    let pname = provider_name.to_string();

    let response = tokio::time::timeout(
        timeout,
        forward_request(client, provider_config, &endpoint, &transformed, headers),
    )
    .await
    .map_err(|_| VddError::Timeout {
        provider: pname.clone(),
        elapsed_secs: timeout_secs,
    })?
    .map_err(|e| VddError::BuilderRevisionFailed(e.to_string()))?;

    let response_json: Value = tokio::time::timeout(timeout, response.json())
        .await
        .map_err(|_| VddError::Timeout {
            provider: pname,
            elapsed_secs: timeout_secs,
        })?
        .map_err(|e| VddError::BuilderRevisionFailed(e.to_string()))?;

    // Crosslink #479: trait dispatch instead of hardcoded shape matching.
    let text = adapter
        .extract_response_text(&response_json)
        .unwrap_or_default();
    let tokens = adapter
        .extract_token_usage(&response_json)
        .unwrap_or_default();

    Ok((text, response_json, tokens))
}

/// Send a verification request through the builder's provider.
/// Reuses the same HTTP plumbing as `send_to_builder` but with a
/// simpler interface (no revision response needed).
pub async fn send_to_builder_for_verification(
    client: &Client,
    config: &VddConfig,
    app_config: &AppConfig,
    request: &ChatCompletionRequest,
    provider_name: &str,
    api_key: Option<&ApiKey>,
    runtime_auth: Option<&VddProviderAuth>,
) -> Result<(String, TokenUsage), VddError> {
    let provider_config = app_config.providers.get(provider_name).ok_or_else(|| {
        VddError::ConfigError(format!(
            "Builder provider '{provider_name}' not configured — \
             cannot run verification agent"
        ))
    })?;

    // Crosslink #433: explicit error for an unknown verifier provider name.
    let timeout_secs = config.adversary.request_timeout_seconds;
    let timeout = std::time::Duration::from_secs(timeout_secs);

    if let Some(VddProviderAuth::CodexResponses(auth)) = runtime_auth {
        if !provider_name.eq_ignore_ascii_case("openai") {
            return Err(VddError::ConfigError(format!(
                "Codex Responses auth can only be used with OpenAI verifier, got '{provider_name}'"
            )));
        }
        return send_to_codex_responses(client, auth, request, timeout, timeout_secs).await;
    }

    let adapter = get_adapter(provider_name).map_err(|e| VddError::ConfigError(e.to_string()))?;
    let mut transformed = adapter
        .transform_request(request)
        .map_err(|e| VddError::AdversaryRequestFailed(format!("verifier transform: {e}")))?;

    let (headers, endpoint) = match runtime_auth {
        Some(VddProviderAuth::ApiKey(api_key)) => (
            adapter.get_headers(api_key),
            adapter.chat_endpoint(&request.model),
        ),
        Some(VddProviderAuth::ClaudeCodeToken(token)) => {
            if !provider_name.eq_ignore_ascii_case("anthropic") {
                return Err(VddError::ConfigError(format!(
                    "Claude Code auth can only be used with Anthropic verifier, got '{provider_name}'"
                )));
            }
            crate::claude_credentials::inject_oauth_prefix_only(&mut transformed);
            (
                crate::claude_credentials::get_oauth_headers(token),
                crate::claude_credentials::get_oauth_endpoint(&request.model),
            )
        }
        Some(VddProviderAuth::None) => (Vec::new(), adapter.chat_endpoint(&request.model)),
        None => (
            api_key.map(|k| adapter.get_headers(k)).unwrap_or_default(),
            adapter.chat_endpoint(&request.model),
        ),
        Some(VddProviderAuth::CodexResponses(_)) => unreachable!("handled above"),
    };

    let pname = provider_name.to_string();

    let response = tokio::time::timeout(
        timeout,
        forward_request(client, provider_config, &endpoint, &transformed, headers),
    )
    .await
    .map_err(|_| VddError::Timeout {
        provider: pname.clone(),
        elapsed_secs: timeout_secs,
    })?
    .map_err(|e| VddError::AdversaryRequestFailed(format!("verifier request: {e}")))?;

    let response_json: Value = tokio::time::timeout(timeout, response.json())
        .await
        .map_err(|_| VddError::Timeout {
            provider: pname,
            elapsed_secs: timeout_secs,
        })?
        .map_err(|e| VddError::AdversaryRequestFailed(format!("verifier response: {e}")))?;

    // Crosslink #479: trait dispatch instead of hardcoded shape matching.
    let text = adapter
        .extract_response_text(&response_json)
        .unwrap_or_default();
    let tokens = adapter
        .extract_token_usage(&response_json)
        .unwrap_or_default();

    Ok((text, tokens))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        GuardrailsConfig, HooksConfig, KeybindingsConfig, PermissionsConfig, ProviderConfig,
        ProxyConfig, SessionConfig, ThinkingConfig, VddAdversaryConfig, VddConfig,
    };
    use std::collections::HashMap;
    use std::time::Duration;

    fn cfg_with_timeout(secs: u64) -> VddConfig {
        VddConfig {
            enabled: true,
            adversary: VddAdversaryConfig {
                provider: "openai".to_string(),
                model: None,
                api_key: None,
                temperature: 0.3,
                max_tokens: 256,
                request_timeout_seconds: secs,
            },
            ..Default::default()
        }
    }

    fn app_cfg_with_provider(provider: &str, base_url: &str) -> AppConfig {
        let mut providers = HashMap::new();
        providers.insert(
            provider.to_string(),
            ProviderConfig {
                base_url: base_url.to_string(),
                api_key: Some(
                    crate::providers::ApiKey::try_from_string("test-key".to_string()).unwrap(),
                ),
                model: None,
                headers: HashMap::new(),
                thinking: ThinkingConfig::default(),
            },
        );
        AppConfig {
            proxy: ProxyConfig::default(),
            providers,
            hooks: HooksConfig::default(),
            session: SessionConfig::default(),
            keybindings: KeybindingsConfig::default(),
            vdd: VddConfig::default(),
            guardrails: GuardrailsConfig::default(),
            permissions: PermissionsConfig::default(),
            memory: crate::config::MemoryConfig::default(),
            web_fetch: crate::config::WebFetchConfig::default(),
            policy: crate::services::policy::EnterprisePolicy::default(),
            managed_settings_path: None,
        }
    }

    fn dummy_request() -> ChatCompletionRequest {
        ChatCompletionRequest {
            model: "gpt-4".to_string(),
            messages: vec![],
            temperature: None,
            max_tokens: None,
            stream: None,
            tools: None,
            tool_choice: None,
            extra: HashMap::new(),
        }
    }

    // ── Crosslink #496: VDD HTTP timeout ──────────────────────────────────
    //
    // A slow / hung adversary upstream cannot block the VDD loop
    // indefinitely. `send_to_adversary` wraps both the HTTP send and the
    // body-read in `tokio::time::timeout`; on expiry it returns
    // `VddError::Timeout { provider, elapsed_secs }`.

    /// The configured timeout value is propagated from
    /// `VddConfig.adversary.request_timeout_seconds` into the actual
    /// timeout the transport applies. We can't observe the duration
    /// directly, but we can pin that the typed config field is honoured
    /// by checking the timeout's serde default + override semantics.
    #[test]
    fn vdd_timeout_default_is_120_seconds() {
        let cfg = VddConfig::default();
        assert_eq!(cfg.adversary.request_timeout_seconds, 120);
    }

    #[test]
    fn vdd_timeout_override_is_respected_via_config() {
        let cfg = cfg_with_timeout(7);
        assert_eq!(cfg.adversary.request_timeout_seconds, 7);
    }

    /// Hit a reserved-IP "blackhole" address (`192.0.2.1` is TEST-NET-1
    /// per RFC 5737; routed-but-unreachable on every machine that
    /// honours the registry). The connect will hang past the 1 s
    /// timeout. Asserts that we get `VddError::Timeout` (the new
    /// variant) — not `AdversaryRequestFailed`.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn send_to_adversary_surfaces_timeout_variant_on_hang() {
        let cfg = cfg_with_timeout(1);
        // Use a domain that resolves but won't accept connections in 1s.
        // `192.0.2.1` is RFC 5737 test-net, guaranteed unrouted.
        let app_cfg = app_cfg_with_provider("openai", "http://192.0.2.1:81");
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(30))
            .build()
            .unwrap();
        let req = dummy_request();

        // Run the call and advance virtual time past the 1s budget.
        let handle =
            tokio::spawn(
                async move { send_to_adversary(&client, &cfg, &app_cfg, &req, None).await },
            );
        // Drive paused-time forward past the configured timeout.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let result = handle.await.expect("join task");

        match result {
            Err(VddError::Timeout {
                provider,
                elapsed_secs,
            }) => {
                assert_eq!(provider, "openai");
                assert_eq!(elapsed_secs, 1);
            }
            Err(other) => panic!("expected VddError::Timeout, got {other:?}"),
            Ok(_) => panic!("expected timeout, got successful response"),
        }
    }

    /// The `VddError::Timeout` Display includes both the provider name
    /// and the elapsed seconds so the operator can see *which* upstream
    /// is hung and *how long* it has been waiting — required for
    /// triage. The previous code returned a stringly-typed
    /// `AdversaryRequestFailed("...timed out after {n}s")` which forces
    /// callers to substring-match to detect timeouts.
    #[test]
    fn vdd_timeout_error_display_has_provider_and_seconds() {
        let err = VddError::Timeout {
            provider: "google".to_string(),
            elapsed_secs: 42,
        };
        let display = err.to_string();
        assert!(display.contains("google"), "got: {display}");
        assert!(display.contains("42"), "got: {display}");
    }
}
