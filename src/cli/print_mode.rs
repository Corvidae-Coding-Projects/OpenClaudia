//! One-shot print mode for non-interactive use.
//!
//! This frontend submits one no-tools/no-persistence request through the
//! canonical run lifecycle, buffers provisional provider output until its
//! native terminal state is validated, commits the candidate, then performs
//! one checked stdout delivery.

use eventsource_stream::Eventsource;
use futures::StreamExt;
use openclaudia::providers::ProviderAdapter;
use reqwest::header::CONTENT_TYPE;

use crate::{resolve_chat_auth, resolve_model_name, ChatAuth, ChatAuthSelectionMode};

const MAX_PRINT_PROMPT_BYTES: usize = 1024 * 1024;
const MAX_PRINT_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_PRINT_OUTPUT_LINES: usize = 65_536;
const MAX_PRINT_ERROR_BYTES: usize = 4096;
const PRINT_STREAM_IDLE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(openclaudia::proxy::SSE_STREAM_TIMEOUT_SECS);

/// Typed noninteractive failure. Every variant produces a nonzero CLI exit.
#[derive(Debug, thiserror::Error)]
pub enum PrintModeError {
    #[error("print input exceeded the {limit}-byte limit")]
    InputTooLarge { limit: usize },
    #[error("print setup failed: {detail}")]
    Setup { detail: String },
    #[error("print request was blocked by policy: {detail}")]
    Policy { detail: String },
    #[error("print hook lifecycle failed: {detail}")]
    Hook { detail: String },
    #[error("provider refused the print request")]
    Refused,
    #[error("provider output exceeded a bounded print limit: {detail}")]
    Length { detail: String },
    #[error("print request was cancelled: {reason:?}")]
    Cancelled {
        reason: openclaudia::runtime::CancellationReason,
    },
    #[error("provider protocol failed: {detail}")]
    Protocol { detail: String },
    #[error("provider turn ended without a complete printable result: {detail}")]
    Partial { detail: String },
    #[error("provider request failed: {detail}")]
    Provider { detail: String },
    #[error("print finalization failed: {detail}")]
    Finalization { detail: String },
    #[error("stdout closed before committed print output was delivered")]
    BrokenPipe,
    #[error("stdout delivery failed: {detail}")]
    Delivery { detail: String },
    #[error("canonical print runtime failed: {detail}")]
    Runtime { detail: String },
}

impl PrintModeError {
    fn setup(error: impl std::fmt::Display) -> Self {
        Self::Setup {
            detail: bounded_error_detail(&error.to_string()),
        }
    }

    fn policy(error: impl std::fmt::Display) -> Self {
        Self::Policy {
            detail: bounded_error_detail(&error.to_string()),
        }
    }

    fn protocol(error: impl std::fmt::Display) -> Self {
        Self::Protocol {
            detail: bounded_error_detail(&error.to_string()),
        }
    }

    fn partial(error: impl std::fmt::Display) -> Self {
        Self::Partial {
            detail: bounded_error_detail(&error.to_string()),
        }
    }

    fn provider(error: impl std::fmt::Display) -> Self {
        Self::Provider {
            detail: bounded_error_detail(&error.to_string()),
        }
    }

    fn finalization(error: impl std::fmt::Display) -> Self {
        Self::Finalization {
            detail: bounded_error_detail(&error.to_string()),
        }
    }

    fn runtime(error: impl std::fmt::Display) -> Self {
        Self::Runtime {
            detail: bounded_error_detail(&error.to_string()),
        }
    }

    fn run_failure(&self) -> openclaudia::runtime::RunFailure {
        use openclaudia::runtime::RunFailureCode;

        let code = match self {
            Self::Policy { .. } => RunFailureCode::Policy,
            Self::Hook { .. } => RunFailureCode::Hook,
            Self::Protocol { .. } => RunFailureCode::Protocol,
            Self::BrokenPipe | Self::Delivery { .. } => RunFailureCode::Frontend,
            Self::Finalization { .. } | Self::InputTooLarge { .. } | Self::Setup { .. } => {
                RunFailureCode::Invariant
            }
            Self::Runtime { .. } => RunFailureCode::Trace,
            Self::Refused
            | Self::Length { .. }
            | Self::Partial { .. }
            | Self::Provider { .. }
            | Self::Cancelled { .. } => RunFailureCode::Provider,
        };
        openclaudia::runtime::RunFailure {
            code,
            detail: bounded_error_detail(&self.to_string()),
        }
    }

    const fn failure_impact(&self) -> openclaudia::runtime::FailureImpact {
        match self {
            Self::Length { .. } | Self::Partial { .. } => {
                openclaudia::runtime::FailureImpact::Partial
            }
            _ => openclaudia::runtime::FailureImpact::Fatal,
        }
    }
}

fn bounded_error_detail(detail: &str) -> String {
    openclaudia::tui::safety::sanitize_terminal_text(
        detail,
        openclaudia::tui::safety::TextLimits::new(
            MAX_PRINT_ERROR_BYTES,
            MAX_PRINT_ERROR_BYTES,
            64,
            1024,
        ),
    )
    .into_string()
}

/// Arguments for [`cmd_print`].
pub struct PrintOptions {
    pub model_override: Option<String>,
    pub target_override: Option<String>,
    pub prompt: String,
}

struct PrintTurn {
    prompt: String,
    context_items: Vec<openclaudia::context::ContextItem>,
    skill_model: Option<String>,
    skill_effort: Option<String>,
    skill_hooks: Option<openclaudia::config::HooksConfig>,
}

impl PrintTurn {
    const fn plain(prompt: String) -> Self {
        Self {
            prompt,
            context_items: Vec::new(),
            skill_model: None,
            skill_effort: None,
            skill_hooks: None,
        }
    }
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

struct PrintCandidate {
    content: String,
    usage: Option<openclaudia::session::TokenUsage>,
    native_state_digest: Option<openclaudia::runtime::ContentDigest>,
}

fn reported_print_usage(
    usage: openclaudia::session::TokenUsage,
) -> Option<openclaudia::session::TokenUsage> {
    (usage.input_tokens > 0
        || usage.output_tokens > 0
        || usage.cache_read_tokens > 0
        || usage.cache_write_tokens > 0)
        .then_some(usage)
}

impl PrintCandidate {
    fn result_digest(&self) -> openclaudia::runtime::ContentDigest {
        openclaudia::runtime::ContentDigest::sha256(self.content.as_bytes())
    }

    fn committed_state_digest(&self) -> openclaudia::runtime::ContentDigest {
        let mut bound = Vec::with_capacity(self.content.len().saturating_add(80));
        if let Some(digest) = self.native_state_digest {
            bound.extend_from_slice(digest.to_string().as_bytes());
        } else {
            bound.extend_from_slice(b"provider-native-state:none");
        }
        bound.push(0);
        bound.extend_from_slice(self.content.as_bytes());
        openclaudia::runtime::ContentDigest::sha256(bound)
    }
}

struct PrintRuntime {
    kernel: openclaudia::runtime::RuntimeKernel,
    actor: openclaudia::runtime::Actor,
    cancellation: openclaudia::runtime::CancellationHandle,
}

impl PrintRuntime {
    async fn start(run: &openclaudia::tools::ToolRunContext) -> Result<Self, PrintModeError> {
        let actor = run.runtime().descriptor().actor.clone();
        let cancellation = run.runtime().cancellation();
        let kernel = openclaudia::runtime::RuntimeKernel::start_shared(run.runtime())
            .await
            .map_err(PrintModeError::runtime)?;
        Ok(Self {
            kernel,
            actor,
            cancellation,
        })
    }

    async fn begin_call(
        &mut self,
        kind: openclaudia::runtime::CallKind,
    ) -> Result<openclaudia::runtime::CallId, PrintModeError> {
        let call_id = openclaudia::runtime::CallId::new();
        self.kernel
            .begin_call(&self.actor, call_id, kind)
            .await
            .map_err(PrintModeError::runtime)?;
        Ok(call_id)
    }

    async fn finish_call_success(
        &mut self,
        call_id: openclaudia::runtime::CallId,
        result: impl AsRef<[u8]>,
    ) -> Result<(), PrintModeError> {
        self.kernel
            .finish_call(
                &self.actor,
                call_id,
                openclaudia::runtime::CallOutcome::Succeeded {
                    result_digest: openclaudia::runtime::ContentDigest::sha256(result),
                },
            )
            .await
            .map_err(PrintModeError::runtime)?;
        Ok(())
    }

    async fn commit_candidate(&mut self, candidate: &PrintCandidate) -> Result<(), PrintModeError> {
        let base = self.kernel.snapshot().committed_state().clone();
        let generation = base
            .generation
            .get()
            .checked_add(1)
            .and_then(openclaudia::runtime::StateGeneration::new)
            .ok_or_else(|| PrintModeError::runtime("print state generation overflow"))?;
        let proposed = openclaudia::runtime::StateSnapshot {
            generation,
            digest: candidate.committed_state_digest(),
        };
        self.kernel
            .propose_state(
                &self.actor,
                openclaudia::runtime::StateProposal {
                    base,
                    proposed: proposed.clone(),
                },
            )
            .await
            .map_err(PrintModeError::runtime)?;
        self.kernel
            .commit_state(&self.actor, proposed)
            .await
            .map_err(PrintModeError::runtime)?;
        Ok(())
    }

    async fn terminate_call_failure(
        &mut self,
        call_id: openclaudia::runtime::CallId,
        error: PrintModeError,
    ) -> PrintModeError {
        let result = if let PrintModeError::Cancelled { reason } = &error {
            let cancellation_event = self
                .kernel
                .cancel(&self.actor, &self.cancellation, reason.clone())
                .await;
            match cancellation_event {
                Ok(_) => {
                    let receipt = self.cancellation.receipt().ok_or_else(|| {
                        PrintModeError::runtime("cancelled print run produced no receipt")
                    });
                    match receipt {
                        Ok(receipt) => {
                            if let Err(runtime_error) = self
                                .kernel
                                .finish_call(
                                    &self.actor,
                                    call_id,
                                    openclaudia::runtime::CallOutcome::Cancelled {
                                        cancellation: receipt,
                                    },
                                )
                                .await
                            {
                                Err(PrintModeError::runtime(runtime_error))
                            } else {
                                self.kernel
                                    .finish_cancelled(&self.actor, self.cancellation.id())
                                    .await
                                    .map(|_| ())
                                    .map_err(PrintModeError::runtime)
                            }
                        }
                        Err(runtime_error) => Err(runtime_error),
                    }
                }
                Err(runtime_error) => Err(PrintModeError::runtime(runtime_error)),
            }
        } else {
            let failure = error.run_failure();
            let impact = error.failure_impact();
            if let Err(runtime_error) = self
                .kernel
                .finish_call(
                    &self.actor,
                    call_id,
                    openclaudia::runtime::CallOutcome::Failed {
                        failure: failure.clone(),
                        impact,
                    },
                )
                .await
            {
                Err(PrintModeError::runtime(runtime_error))
            } else if impact == openclaudia::runtime::FailureImpact::Partial {
                self.kernel
                    .finish_partially_failed(&self.actor)
                    .await
                    .map(|_| ())
                    .map_err(PrintModeError::runtime)
            } else {
                self.kernel
                    .fail(&self.actor, failure)
                    .await
                    .map(|_| ())
                    .map_err(PrintModeError::runtime)
            }
        };
        result.err().unwrap_or(error)
    }

    async fn terminate_failure(&mut self, error: PrintModeError) -> PrintModeError {
        let failure = error.run_failure();
        self.kernel
            .fail(&self.actor, failure)
            .await
            .err()
            .map_or(error, PrintModeError::runtime)
    }

    async fn succeed(&mut self) -> Result<(), PrintModeError> {
        self.kernel
            .succeed(&self.actor)
            .await
            .map(|_| ())
            .map_err(PrintModeError::runtime)
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
        openclaudia::claude_credentials::inject_oauth_prefix_only(&mut body)
            .map_err(|error| error.to_string())?;
    }
    Ok(body)
}

#[cfg(test)]
fn build_print_chat_request(
    adapter: &dyn ProviderAdapter,
    model: &str,
    prompt: String,
    run: &openclaudia::tools::ToolRunContext,
) -> openclaudia::proxy::ChatCompletionRequest {
    build_print_chat_request_with_items(adapter, model, prompt, run, Vec::new())
}

fn build_print_chat_request_with_items(
    adapter: &dyn ProviderAdapter,
    model: &str,
    prompt: String,
    run: &openclaudia::tools::ToolRunContext,
    context_items: Vec<openclaudia::context::ContextItem>,
) -> openclaudia::proxy::ChatCompletionRequest {
    let user_messages = vec![openclaudia::proxy::ChatMessage {
        role: "user".to_string(),
        content: openclaudia::proxy::MessageContent::Text(prompt),
        name: None,
        tool_call_id: None,
        tool_calls: None,
        extra: std::collections::HashMap::new(),
    }];
    let prompt_context = openclaudia::prompt::build_prompt_context_with_items_for_run(
        &openclaudia::modes::BehaviorMode::default(),
        run,
        context_items,
        openclaudia::context::ContextBudget::default(),
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

fn resolve_print_turn(
    prompt: String,
    run: &openclaudia::tools::ToolRunContext,
) -> anyhow::Result<PrintTurn> {
    let trimmed = prompt.trim();
    let (strict, name, arguments) = if trimmed == "/skill" {
        anyhow::bail!("Usage: openclaudia --print '/skill <name> [arguments]'");
    } else if let Some(rest) = trimmed.strip_prefix("/skill ") {
        let rest = rest.trim_start();
        let (name, arguments) = rest
            .split_once(char::is_whitespace)
            .map_or((rest, ""), |(name, arguments)| (name, arguments.trim()));
        if name.is_empty() {
            anyhow::bail!("Usage: openclaudia --print '/skill <name> [arguments]'");
        }
        (true, name, arguments)
    } else if let Some(rest) = trimmed.strip_prefix('/') {
        let (name, arguments) = rest
            .split_once(char::is_whitespace)
            .map_or((rest, ""), |(name, arguments)| (name, arguments.trim()));
        if name.is_empty() {
            return Ok(PrintTurn::plain(prompt));
        }
        (false, name, arguments)
    } else {
        return Ok(PrintTurn::plain(prompt));
    };

    let activation = match openclaudia::skills::activate_user_invocable_skill_for_run(run, name) {
        Ok(activation) => activation,
        Err(openclaudia::skills::SkillActivationError::Unavailable(_)) if !strict => {
            return Ok(PrintTurn::plain(prompt));
        }
        Err(error) => return Err(anyhow::anyhow!(error)),
    };
    let selected_name = activation.selection().name.clone();
    let user_prompt = if arguments.is_empty() {
        format!("Use the explicitly selected `/{selected_name}` skill reference for this turn.")
    } else {
        format!(
            "Use the explicitly selected `/{selected_name}` skill reference for this turn.\n\nUser arguments:\n{arguments}"
        )
    };
    Ok(PrintTurn {
        prompt: user_prompt,
        context_items: vec![
            activation.context_item(format!("print.skill.explicit.{selected_name}"))
        ],
        skill_model: activation.model().map(str::to_string),
        skill_effort: activation.effort().and_then(normalize_print_skill_effort),
        skill_hooks: activation.hooks().cloned(),
    })
}

fn normalize_print_skill_effort(effort: &str) -> Option<String> {
    match effort.trim().to_ascii_lowercase().as_str() {
        "none" | "minimal" | "low" | "medium" | "high" | "xhigh" => {
            Some(effort.trim().to_ascii_lowercase())
        }
        "max" => Some("xhigh".to_string()),
        _ => None,
    }
}

fn canonical_provider_name(provider: &str) -> &str {
    match provider {
        "gemini" => "google",
        "alibaba" => "qwen",
        "zhipu" | "glm" => "zai",
        "moonshot" => "kimi",
        other => other,
    }
}

fn print_provider_accepts_model(config: &openclaudia::config::AppConfig, model: &str) -> bool {
    if openclaudia::providers::is_openai_compatible_passthrough_target(&config.proxy.target) {
        return true;
    }
    let detected = openclaudia::proxy::determine_provider(model, config);
    canonical_provider_name(&detected) == canonical_provider_name(&config.proxy.target)
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
) -> Result<String, String> {
    if claude_code_token.is_some() {
        return openclaudia::claude_credentials::get_oauth_endpoint(model)
            .map_err(|error| error.to_string());
    }

    let path = if adapter.name() == "google" {
        adapter.chat_endpoint(model)
    } else {
        adapter
            .stream_endpoint(model)
            .unwrap_or_else(|| adapter.chat_endpoint(model))
    };
    Ok(format!(
        "{}{}",
        openclaudia::proxy::normalize_base_url(&provider.base_url),
        path
    ))
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
        openclaudia::pipeline::SseAction::PrivateReasoning(_)
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

fn print_transport_error(
    error: openclaudia::provider_transport::ProviderTransportError,
) -> PrintModeError {
    use openclaudia::provider_transport::ProviderTransportError;

    match error {
        ProviderTransportError::Deadline { .. }
        | ProviderTransportError::Request { timeout: true, .. } => PrintModeError::Cancelled {
            reason: openclaudia::runtime::CancellationReason::Deadline,
        },
        ProviderTransportError::ResponseTooLarge { limit } => PrintModeError::Length {
            detail: format!("provider response exceeded the {limit}-byte transport limit"),
        },
        ProviderTransportError::InvalidJson(detail) => PrintModeError::protocol(detail),
        other => PrintModeError::provider(other),
    }
}

fn provider_terminal_error(detail: impl std::fmt::Display) -> PrintModeError {
    let detail = detail.to_string();
    let normalized = detail.to_ascii_lowercase();
    if normalized.contains("timed out") || normalized.contains("deadline") {
        PrintModeError::Cancelled {
            reason: openclaudia::runtime::CancellationReason::Deadline,
        }
    } else if normalized.contains("output limit")
        || normalized.contains("length_limited")
        || normalized.contains("print output exceeded")
        || normalized.contains("max_tokens")
    {
        PrintModeError::Length {
            detail: bounded_error_detail(&detail),
        }
    } else if normalized.contains("refused")
        || normalized.contains("filtered")
        || normalized.contains("safety_blocked")
    {
        PrintModeError::Refused
    } else if normalized.contains("ended before")
        || normalized.contains("missing terminal")
        || normalized.contains("without a valid terminal")
        || normalized.contains("did not contain printable")
    {
        PrintModeError::partial(detail)
    } else if normalized.contains("api error") || normalized.contains("stream error") {
        PrintModeError::provider(detail)
    } else {
        PrintModeError::protocol(detail)
    }
}

fn require_print_terminal(
    terminal: openclaudia::pipeline::ProviderTerminalOutcome,
    tool_call_count: usize,
) -> Result<(), PrintModeError> {
    use openclaudia::pipeline::ProviderTerminalOutcome;

    match terminal {
        ProviderTerminalOutcome::Completed if tool_call_count == 0 => Ok(()),
        ProviderTerminalOutcome::Completed => Err(PrintModeError::protocol(format!(
            "provider reported completion with {tool_call_count} tool call(s)"
        ))),
        ProviderTerminalOutcome::ToolCalls => Err(PrintModeError::partial(format!(
            "provider requested {tool_call_count} tool continuation(s) in no-tools print mode"
        ))),
        ProviderTerminalOutcome::LengthLimited => Err(PrintModeError::Length {
            detail: "provider stopped at its output limit".to_string(),
        }),
        ProviderTerminalOutcome::Refused | ProviderTerminalOutcome::ContentFiltered => {
            Err(PrintModeError::Refused)
        }
    }
}

fn validate_print_content(content: String) -> Result<String, PrintModeError> {
    if content.len() > MAX_PRINT_OUTPUT_BYTES {
        return Err(PrintModeError::Length {
            detail: format!("assistant text exceeded the {MAX_PRINT_OUTPUT_BYTES}-byte limit"),
        });
    }
    if content.trim().is_empty() {
        return Err(PrintModeError::partial(
            "successful terminal state contained no printable assistant text",
        ));
    }
    Ok(content)
}

fn prepare_print_output(content: &str) -> Result<String, PrintModeError> {
    let rendered = openclaudia::tui::safety::sanitize_terminal_text(
        content,
        openclaudia::tui::safety::TextLimits::new(
            MAX_PRINT_OUTPUT_BYTES,
            MAX_PRINT_OUTPUT_BYTES,
            MAX_PRINT_OUTPUT_LINES,
            MAX_PRINT_OUTPUT_BYTES,
        ),
    );
    if rendered.was_truncated() {
        return Err(PrintModeError::Length {
            detail: format!(
                "terminal-safe output exceeded the {MAX_PRINT_OUTPUT_BYTES}-byte framing limit"
            ),
        });
    }
    Ok(rendered.into_string())
}

fn deliver_print_output(
    writer: &mut impl std::io::Write,
    content: &str,
) -> Result<(), PrintModeError> {
    writer
        .write_all(content.as_bytes())
        .map_err(|error| print_delivery_error(&error))?;
    if !content.ends_with('\n') {
        writer
            .write_all(b"\n")
            .map_err(|error| print_delivery_error(&error))?;
    }
    writer.flush().map_err(|error| print_delivery_error(&error))
}

fn print_delivery_error(error: &std::io::Error) -> PrintModeError {
    if error.kind() == std::io::ErrorKind::BrokenPipe {
        PrintModeError::BrokenPipe
    } else {
        PrintModeError::Delivery {
            detail: bounded_error_detail(&error.to_string()),
        }
    }
}

async fn print_json_response(
    response: reqwest::Response,
    adapter: &dyn ProviderAdapter,
    provider: &str,
    model: &str,
    assistant_message_ordinal: u64,
) -> Result<PrintCandidate, PrintModeError> {
    let body = openclaudia::provider_transport::read_json_capped::<serde_json::Value>(
        response,
        openclaudia::provider_transport::MAX_JSON_RESPONSE_BYTES,
    )
    .await
    .map_err(print_transport_error)?;
    if matches!(
        provider.trim().to_ascii_lowercase().as_str(),
        "google" | "gemini" | "ollama"
    ) {
        let decoded = openclaudia::pipeline::decode_provider_native_json_turn(
            provider,
            model,
            &body,
            None,
            assistant_message_ordinal,
        )
        .map_err(provider_terminal_error)?;
        require_print_terminal(decoded.terminal_outcome, decoded.tool_calls.len())?;
        let content = validate_print_content(decoded.content)?;
        return Ok(PrintCandidate {
            content,
            usage: reported_print_usage(decoded.usage),
            native_state_digest: Some(decoded.provider_native_state.digest()),
        });
    }

    let normalized = adapter
        .transform_response(body.clone(), false)
        .map_err(|error| PrintModeError::protocol(format!("response transform failed: {error}")))?;
    let terminal = openclaudia::pipeline::validate_chat_completion_terminal(&normalized)
        .map_err(provider_terminal_error)?;
    require_print_terminal(terminal, 0)?;
    let text = adapter.extract_response_text(&body).ok_or_else(|| {
        PrintModeError::partial("response did not contain printable assistant text")
    })?;
    Ok(PrintCandidate {
        content: validate_print_content(text)?,
        usage: None,
        native_state_digest: None,
    })
}

async fn print_sse_response(
    response: reqwest::Response,
    provider: &str,
) -> Result<PrintCandidate, PrintModeError> {
    let mut stream = openclaudia::provider_transport::bounded_byte_stream(
        response,
        openclaudia::provider_transport::MAX_STREAM_RESPONSE_BYTES,
    )
    .eventsource();
    let mut state = PrintSseState::new(provider);
    let mut emitted_text = false;
    let mut full_text = String::new();
    let mut response_text_truncated = false;
    let mut usage = openclaudia::session::TokenUsage::default();
    let mut usage_observed = false;

    loop {
        let event = tokio::time::timeout(PRINT_STREAM_IDLE_TIMEOUT, stream.next())
            .await
            .map_err(|_| PrintModeError::Cancelled {
                reason: openclaudia::runtime::CancellationReason::Deadline,
            })?;
        let Some(event) = event else {
            break;
        };
        let event = event.map_err(|error| {
            let detail = bounded_error_detail(&error.to_string());
            if emitted_text {
                return PrintModeError::Partial { detail };
            }
            match error {
                eventsource_stream::EventStreamError::Transport(error) => {
                    print_transport_error(error)
                }
                eventsource_stream::EventStreamError::Utf8(_)
                | eventsource_stream::EventStreamError::Parser(_) => {
                    PrintModeError::protocol(detail)
                }
            }
        })?;
        if event.data == "[DONE]" {
            state.terminal.observe_done();
            break;
        }
        let json = serde_json::from_str::<serde_json::Value>(&event.data)
            .map_err(|error| PrintModeError::protocol(format!("invalid SSE data JSON: {error}")))?;
        state
            .terminal
            .observe(&json)
            .map_err(provider_terminal_error)?;
        if let Some(event_usage) = openclaudia::proxy::extract_usage_from_sse_event(&json) {
            usage_observed = true;
            usage.accumulate(&event_usage);
        }
        if let Some(text) = extract_print_sse_text(&json, &mut state) {
            emitted_text |= !text.is_empty();
            response_text_truncated |= openclaudia::tui::safety::append_raw_bounded(
                &mut full_text,
                &text,
                MAX_PRINT_OUTPUT_BYTES,
            );
        }
    }

    let tool_call_count = if provider.eq_ignore_ascii_case("anthropic") {
        state
            .anthropic_accumulator
            .finalize_tool_calls_checked()
            .map_err(PrintModeError::protocol)?
            .len()
    } else {
        state
            .tool_accumulator
            .finalize_checked()
            .map_err(PrintModeError::protocol)?
            .len()
    };
    let terminal = state.terminal.finish().map_err(provider_terminal_error)?;
    require_print_terminal(terminal, tool_call_count)?;

    if response_text_truncated {
        return Err(PrintModeError::Length {
            detail: format!("assistant text exceeded the {MAX_PRINT_OUTPUT_BYTES}-byte limit"),
        });
    }

    if !emitted_text {
        return Err(PrintModeError::partial(
            "provider stream did not contain printable assistant text",
        ));
    }
    Ok(PrintCandidate {
        content: validate_print_content(full_text)?,
        usage: usage_observed.then_some(usage),
        native_state_digest: None,
    })
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
) -> Result<PrintCandidate, PrintModeError> {
    let mut observed_output_bytes = 0usize;
    let decoded = openclaudia::pipeline::decode_openai_responses_stream(
        openclaudia::pipeline::OpenAiResponsesStreamParams {
            response,
            headers,
            provider,
            model_identity: model,
            provider_native_state: None,
            assistant_message_ordinal,
        },
        |text| {
            observed_output_bytes = observed_output_bytes
                .checked_add(text.len())
                .ok_or_else(|| "print output byte accounting overflow".to_string())?;
            if observed_output_bytes > MAX_PRINT_OUTPUT_BYTES {
                return Err(format!(
                    "print output exceeded the {MAX_PRINT_OUTPUT_BYTES}-byte limit"
                ));
            }
            Ok(())
        },
        |_| Ok(()),
        |_, _| Ok(()),
    )
    .await
    .map_err(provider_terminal_error)?;

    require_print_terminal(decoded.terminal_outcome, decoded.tool_calls.len())?;
    Ok(PrintCandidate {
        content: validate_print_content(decoded.content)?,
        usage: reported_print_usage(decoded.usage),
        native_state_digest: Some(decoded.provider_native_state.digest()),
    })
}

async fn finalize_print_candidate(
    config: &openclaudia::config::AppConfig,
    run: &std::sync::Arc<openclaudia::tools::ToolRunContext>,
    engine: Option<&openclaudia::vdd::VddEngine>,
    request: &openclaudia::proxy::ChatCompletionRequest,
    api_key: Option<&openclaudia::providers::ApiKey>,
    mut candidate: PrintCandidate,
) -> Result<PrintCandidate, PrintModeError> {
    let messages = print_message_values(request).map_err(PrintModeError::setup)?;
    let policy = openclaudia::vdd::VddFinalizationPolicy::from_config(&config.vdd);
    if policy.requirement() != openclaudia::vdd::VddFinalizationRequirement::Disabled {
        let user_task = messages
            .iter()
            .rev()
            .find(|message| message.get("role").and_then(|role| role.as_str()) == Some("user"))
            .and_then(|message| message.get("content").and_then(|content| content.as_str()))
            .unwrap_or("");
        let builder = openclaudia::vdd::BuilderProvider::new(&config.proxy.target, api_key)
            .with_model(&request.model);
        let scope = format!(
            "print:{}:{user_task}",
            run.runtime().descriptor().session_id
        );
        let content = std::mem::take(&mut candidate.content);
        let finalization = openclaudia::vdd::finalize_text_candidate(
            engine, run, &policy, content, &scope, user_task, builder,
        )
        .await;
        let (publication, _observation) = finalization.into_parts();
        candidate.content = match publication {
            openclaudia::vdd::VddPublication::Publish(published) => {
                tracing::info!(
                    outcome = ?published.outcome(),
                    "VDD finalization admitted print output"
                );
                published.into_candidate()
            }
            openclaudia::vdd::VddPublication::Withhold(withheld) => {
                if withheld.outcome() == openclaudia::vdd::VddNonPassOutcome::Cancelled {
                    return Err(PrintModeError::Cancelled {
                        reason: run.runtime().cancellation().receipt().map_or(
                            openclaudia::runtime::CancellationReason::ParentTerminated,
                            |receipt| receipt.reason,
                        ),
                    });
                }
                return Err(PrintModeError::finalization(format!(
                    "VDD withheld assistant success ({:?}): {}",
                    withheld.outcome(),
                    withheld.detail()
                )));
            }
        };
    }
    candidate.content = prepare_print_output(&candidate.content)?;
    Ok(candidate)
}

struct PreparedPrintTransport {
    request_body: serde_json::Value,
    endpoint: String,
    headers: openclaudia::secrets::SensitiveHeaders,
    wire_api: openclaudia::pipeline::WireApi,
    assistant_message_ordinal: u64,
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
    let wire_api = if p.auth.codex_agent_sdk.is_some() {
        openclaudia::pipeline::WireApi::OpenAiResponses
    } else {
        openclaudia::pipeline::WireApi::ChatCompletions
    };
    let messages = print_message_values(p.chat_request)?;
    let assistant_message_ordinal =
        openclaudia::pipeline::next_assistant_message_ordinal(&messages)
            .map_err(anyhow::Error::msg)?;
    let request_body = if wire_api.is_responses() {
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
        .map_err(anyhow::Error::msg)?
    } else {
        build_print_request(
            p.adapter,
            p.chat_request,
            &p.provider.thinking,
            p.auth.claude_code_token.as_ref(),
        )
        .map_err(anyhow::Error::msg)?
    };
    let extra_headers = p.provider.headers.clone();
    let (endpoint, headers) = if p.auth.codex_agent_sdk.is_some() {
        (
            openclaudia::pipeline::resolve_endpoint_for_wire(
                wire_api,
                &p.config.proxy.target,
                p.model,
                &p.provider.base_url,
                None,
            )?,
            openclaudia::secrets::SensitiveHeaders::new(),
        )
    } else {
        (
            resolve_print_endpoint(
                p.model,
                p.provider,
                p.adapter,
                p.auth.claude_code_token.as_ref(),
            )
            .map_err(anyhow::Error::msg)?,
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
        assistant_message_ordinal,
    })
}

fn codex_sdk_error(error: openclaudia::codex_agent_sdk::CodexAgentSdkError) -> PrintModeError {
    use openclaudia::codex_agent_sdk::CodexAgentSdkError;

    match error {
        CodexAgentSdkError::Timeout(_) | CodexAgentSdkError::Deadline => {
            PrintModeError::Cancelled {
                reason: openclaudia::runtime::CancellationReason::Deadline,
            }
        }
        CodexAgentSdkError::Cancelled(reason) => PrintModeError::Cancelled { reason },
        CodexAgentSdkError::OutputTooLarge(limit) => PrintModeError::Length {
            detail: format!("Codex SDK output exceeded its {limit}-byte limit"),
        },
        invalid @ (CodexAgentSdkError::InvalidOutput(_)
        | CodexAgentSdkError::InvalidRequest(_)
        | CodexAgentSdkError::NativeToolUse(_)) => PrintModeError::protocol(invalid),
        other => PrintModeError::provider(other),
    }
}

fn claude_sdk_error(error: openclaudia::claude_agent_sdk::ClaudeAgentSdkError) -> PrintModeError {
    use openclaudia::claude_agent_sdk::ClaudeAgentSdkError;

    match error {
        ClaudeAgentSdkError::Timeout(_) | ClaudeAgentSdkError::Deadline => {
            PrintModeError::Cancelled {
                reason: openclaudia::runtime::CancellationReason::Deadline,
            }
        }
        ClaudeAgentSdkError::Cancelled(reason) => PrintModeError::Cancelled { reason },
        ClaudeAgentSdkError::OutputTooLarge(limit) => PrintModeError::Length {
            detail: format!("Claude Agent SDK output exceeded its {limit}-byte limit"),
        },
        invalid @ (ClaudeAgentSdkError::InvalidOutput(_)
        | ClaudeAgentSdkError::InvalidRequest(_)) => PrintModeError::protocol(invalid),
        other => PrintModeError::provider(other),
    }
}

#[allow(clippy::too_many_arguments)]
async fn dispatch_print_http(
    provider: &str,
    model: &str,
    adapter: &dyn ProviderAdapter,
    headers: &openclaudia::secrets::SensitiveHeaders,
    wire_api: openclaudia::pipeline::WireApi,
    assistant_message_ordinal: u64,
    endpoint: String,
    request_body: &serde_json::Value,
) -> Result<PrintCandidate, PrintModeError> {
    let client = openclaudia::provider_transport::shared_client().map_err(print_transport_error)?;
    let request = headers
        .apply(client.post(endpoint).json(request_body))
        .map_err(PrintModeError::provider)?;
    let response = openclaudia::provider_transport::send(request)
        .await
        .map_err(print_transport_error)?;
    if !response.status().is_success() {
        let status = response.status();
        let body = openclaudia::secrets::read_bounded_diagnostic_body(response)
            .await
            .unwrap_or_else(|_| zeroize::Zeroizing::new(String::new()));
        let diagnostic = headers.sanitize_diagnostic(&body);
        return Err(PrintModeError::provider(format!(
            "API error {}: {diagnostic}",
            status.as_u16()
        )));
    }

    if wire_api.is_responses() {
        print_responses_stream(
            response,
            headers,
            provider,
            model,
            assistant_message_ordinal,
        )
        .await
    } else if response_is_json(&response) {
        print_json_response(
            response,
            adapter,
            provider,
            model,
            assistant_message_ordinal,
        )
        .await
    } else {
        print_sse_response(response, provider).await
    }
}

/// Run one-shot print mode.
///
/// # Errors
///
/// Returns an error when configuration/auth cannot be resolved, the provider
/// rejects the request, or the response stream cannot be decoded.
#[allow(clippy::too_many_lines)] // One-shot mode owns setup, budgeted transport, and terminal output.
pub async fn cmd_print(options: PrintOptions) -> Result<(), PrintModeError> {
    crate::chdir_to_git_root();

    let PrintOptions {
        model_override,
        target_override,
        prompt,
    } = options;
    if prompt.len() > MAX_PRINT_PROMPT_BYTES {
        return Err(PrintModeError::InputTooLarge {
            limit: MAX_PRINT_PROMPT_BYTES,
        });
    }
    let explicit_model_override = model_override.is_some();
    let config = load_print_config(model_override.as_deref(), target_override.as_deref())
        .map_err(PrintModeError::setup)?;
    let print_root = std::env::current_dir()
        .map_err(|error| PrintModeError::setup(format!("project root unavailable: {error}")))?;
    let host_home = dirs::home_dir().and_then(|path| path.canonicalize().ok());
    let skill_access =
        openclaudia::skills::SkillRunAccess::capture(&print_root, host_home.as_deref());
    let remote_actions = config
        .remote_actions
        .build_registry()
        .map_err(PrintModeError::setup)?;
    let web_egress_grants = config
        .build_web_egress_grants()
        .map_err(PrintModeError::setup)?;
    let print_run = openclaudia::tools::ToolRunContext::builder(
        openclaudia::state::SessionId::new(),
        &print_root,
    )
    .working_directory(&print_root)
    .read_only_roots(Vec::new())
    .read_write_roots(Vec::new())
    .environment_grants(std::collections::HashMap::new())
    .skill_access(skill_access)
    .remote_actions(remote_actions)
    .web_egress_grants(web_egress_grants)
    .workspace_access(openclaudia::tools::WorkspaceAccess::ReadOnly)
    .process(false)
    .network(true)
    .secrets(true)
    .provider(config.proxy.target.clone())
    .budget_limits(
        config
            .session
            .run_budget
            .limits_for_session(&config.session),
    )
    .bounded_print_profile()
    .build()
    .map_err(PrintModeError::setup)?;
    let mut runtime = PrintRuntime::start(&print_run).await?;
    let mut print_turn = match resolve_print_turn(prompt, &print_run) {
        Ok(turn) => turn,
        Err(error) => {
            let error = runtime
                .terminate_failure(PrintModeError::setup(error))
                .await;
            openclaudia::tools::retire_run(&print_run);
            return Err(error);
        }
    };
    let mut hook_engine = crate::build_hook_engine(&config);
    if let Some(skill_hooks) = print_turn.skill_hooks.take() {
        hook_engine = hook_engine.with_scoped_hooks(skill_hooks);
    }
    let session_id = print_run.session_id().to_string();
    let outcome: Result<(), PrintModeError> = async {
        let start_call = runtime
            .begin_call(openclaudia::runtime::CallKind::Hook)
            .await?;
        let start_input = openclaudia::hooks::HookInput::for_run(
            &print_run,
            openclaudia::hooks::HookEvent::SessionStart,
        )
        .with_session_id(&session_id);
        let start_receipt = hook_engine
            .run_lifecycle(openclaudia::hooks::HookEvent::SessionStart, &start_input)
            .await;
        if let Some(reason) = start_receipt.blocking_reason() {
            return Err(runtime
                .terminate_call_failure(
                    start_call,
                    PrintModeError::Hook {
                        detail: bounded_error_detail(&reason),
                    },
                )
                .await);
        }
        runtime
            .finish_call_success(start_call, format!("{:?}", start_receipt.status))
            .await?;

        let prompt_call = runtime
            .begin_call(openclaudia::runtime::CallKind::Hook)
            .await?;
        let hook_input = openclaudia::hooks::HookInput::for_run(
            &print_run,
            openclaudia::hooks::HookEvent::UserPromptSubmit,
        )
        .with_session_id(&session_id)
        .with_prompt(&print_turn.prompt);
        let prompt_receipt = hook_engine
            .run_lifecycle(openclaudia::hooks::HookEvent::UserPromptSubmit, &hook_input)
            .await;
        if let Some(reason) = prompt_receipt.blocking_reason() {
            return Err(runtime
                .terminate_call_failure(
                    prompt_call,
                    PrintModeError::Hook {
                        detail: bounded_error_detail(&reason),
                    },
                )
                .await);
        }
        runtime
            .finish_call_success(prompt_call, format!("{:?}", prompt_receipt.status))
            .await?;
        print_turn
            .context_items
            .extend(openclaudia::context::hook_result_reference_items(
                &prompt_receipt.into_result(),
                "print_user_prompt_submit",
                500,
            ));

        let Some(mut provider) = config.active_provider().cloned() else {
            return Err(runtime
                .terminate_failure(PrintModeError::setup(format!(
                    "no provider configured for target '{}'",
                    config.proxy.target
                )))
                .await);
        };
        let chat_auth = match resolve_chat_auth(
            &config.proxy.target,
            &provider,
            ChatAuthSelectionMode::Automatic,
        )
        .await
        {
            Ok(Some(auth)) => auth,
            Ok(None) => {
                return Err(runtime
                    .terminate_failure(PrintModeError::setup(format!(
                        "authentication unavailable for target '{}'",
                        config.proxy.target
                    )))
                    .await);
            }
            Err(error) => {
                return Err(runtime
                    .terminate_failure(PrintModeError::setup(error))
                    .await);
            }
        };
        let mut model = match resolve_model_name(
            model_override,
            provider.model.clone(),
            &config.proxy.target,
        ) {
            Ok(model) => model,
            Err(error) => {
                return Err(runtime
                    .terminate_failure(PrintModeError::setup(error))
                    .await);
            }
        };
        if !explicit_model_override {
            if let Some(skill_model) = print_turn.skill_model.as_deref() {
                if print_provider_accepts_model(&config, skill_model) {
                    model = skill_model.to_string();
                } else {
                    tracing::debug!(
                        model = %skill_model,
                        provider = %config.proxy.target,
                        "ignoring skill model hint for a different provider in print mode"
                    );
                }
            }
        }
        if let Some(skill_effort) = print_turn.skill_effort.take() {
            provider.thinking.reasoning_effort = Some(skill_effort);
        }
        let adapter = match openclaudia::providers::get_adapter(&config.proxy.target) {
            Ok(adapter) => adapter,
            Err(error) => {
                return Err(runtime
                    .terminate_failure(PrintModeError::setup(error))
                    .await);
            }
        };
        let mut chat_request = build_print_chat_request_with_items(
            adapter,
            &model,
            print_turn.prompt,
            &print_run,
            print_turn.context_items,
        );
        if config.vdd.enabled {
            chat_request.stream = Some(false);
        }
        if let Err(error) = enforce_print_request_policy(&config, &chat_request) {
            return Err(runtime
                .terminate_failure(PrintModeError::policy(error))
                .await);
        }
        let vdd_engine = crate::init_vdd_engine_if_enabled(&config);
        let prepared = match prepare_print_transport(&PreparePrintTransport {
            config: &config,
            provider: &provider,
            adapter,
            model: &model,
            chat_request: &chat_request,
            auth: &chat_auth,
        }) {
            Ok(prepared) => prepared,
            Err(error) => {
                return Err(runtime
                    .terminate_failure(PrintModeError::setup(error))
                    .await);
            }
        };
        let PreparedPrintTransport {
            mut request_body,
            endpoint,
            headers,
            wire_api,
            assistant_message_ordinal,
        } = prepared;
        let provider_budget = match openclaudia::provider_budget::reserve_provider_call(
            &print_run,
            &config.proxy.target,
            &model,
            &mut request_body,
            u64::from(config.session.token_tracking.max_output_tokens),
        ) {
            Ok(reservation) => reservation,
            Err(error) => {
                return Err(runtime
                    .terminate_failure(PrintModeError::policy(format!(
                        "run budget denied provider call: {error}"
                    )))
                    .await);
            }
        };
        let provider_call = runtime
            .begin_call(openclaudia::runtime::CallKind::Provider)
            .await?;
        let effort = provider
            .thinking
            .reasoning_effort
            .as_deref()
            .unwrap_or("medium");
        let provider_result = if let Some(sdk) = chat_auth.codex_agent_sdk.as_ref() {
            sdk.complete_turn(&request_body, effort)
                .await
                .map_err(codex_sdk_error)
                .and_then(|turn| {
                    require_print_terminal(
                        if turn.tool_calls.is_empty() {
                            openclaudia::pipeline::ProviderTerminalOutcome::Completed
                        } else {
                            openclaudia::pipeline::ProviderTerminalOutcome::ToolCalls
                        },
                        turn.tool_calls.len(),
                    )?;
                    Ok(PrintCandidate {
                        content: validate_print_content(turn.content)?,
                        usage: reported_print_usage(turn.usage),
                        native_state_digest: None,
                    })
                })
        } else if let Some(sdk) = chat_auth.claude_agent_sdk.as_ref() {
            sdk.complete_turn(&request_body, effort)
                .await
                .map_err(claude_sdk_error)
                .and_then(|turn| {
                    require_print_terminal(
                        if turn.tool_calls.is_empty() {
                            openclaudia::pipeline::ProviderTerminalOutcome::Completed
                        } else {
                            openclaudia::pipeline::ProviderTerminalOutcome::ToolCalls
                        },
                        turn.tool_calls.len(),
                    )?;
                    Ok(PrintCandidate {
                        content: validate_print_content(turn.content)?,
                        usage: reported_print_usage(turn.usage),
                        native_state_digest: None,
                    })
                })
        } else {
            dispatch_print_http(
                &config.proxy.target,
                &model,
                adapter,
                &headers,
                wire_api,
                assistant_message_ordinal,
                endpoint,
                &request_body,
            )
            .await
        };
        let candidate = match provider_result {
            Ok(candidate) => {
                let budget_result = match candidate.usage.as_ref() {
                    Some(usage) => provider_budget.reconcile(usage),
                    None => provider_budget.finish_unknown(),
                };
                if let Err(error) = budget_result {
                    return Err(runtime
                        .terminate_call_failure(
                            provider_call,
                            PrintModeError::provider(format!(
                                "budget reconciliation failed: {error}"
                            )),
                        )
                        .await);
                }
                candidate
            }
            Err(error) => {
                let error = match provider_budget.finish_unknown() {
                    Ok(_) => error,
                    Err(budget_error) => PrintModeError::provider(format!(
                        "{error}; budget reconciliation failed: {budget_error}"
                    )),
                };
                return Err(runtime.terminate_call_failure(provider_call, error).await);
            }
        };
        runtime
            .finish_call_success(provider_call, candidate.result_digest().to_string())
            .await?;

        let review_call = runtime
            .begin_call(openclaudia::runtime::CallKind::Review)
            .await?;
        let candidate = match finalize_print_candidate(
            &config,
            &print_run,
            vdd_engine.as_ref(),
            &chat_request,
            chat_auth.api_key.as_ref(),
            candidate,
        )
        .await
        {
            Ok(candidate) => candidate,
            Err(error) => {
                return Err(runtime.terminate_call_failure(review_call, error).await);
            }
        };
        runtime
            .finish_call_success(review_call, candidate.result_digest().to_string())
            .await?;
        if let Err(error) = runtime.commit_candidate(&candidate).await {
            return Err(runtime.terminate_failure(error).await);
        }

        let delivery_call = runtime
            .begin_call(openclaudia::runtime::CallKind::Frontend)
            .await?;
        let delivery = {
            let stdout = std::io::stdout();
            let mut locked = stdout.lock();
            deliver_print_output(&mut locked, &candidate.content)
        };
        if let Err(error) = delivery {
            return Err(runtime.terminate_call_failure(delivery_call, error).await);
        }
        runtime
            .finish_call_success(delivery_call, candidate.result_digest().to_string())
            .await?;
        Ok(())
    }
    .await;

    let end_input = openclaudia::hooks::HookInput::for_run(
        &print_run,
        openclaudia::hooks::HookEvent::SessionEnd,
    )
    .with_session_id(session_id);
    let outcome = if outcome.is_ok() {
        match runtime
            .begin_call(openclaudia::runtime::CallKind::Hook)
            .await
        {
            Ok(end_call) => {
                let receipt = hook_engine
                    .run_lifecycle(openclaudia::hooks::HookEvent::SessionEnd, &end_input)
                    .await;
                match runtime
                    .finish_call_success(end_call, format!("{:?}", receipt.status))
                    .await
                {
                    Ok(()) => runtime.succeed().await,
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        }
    } else {
        let _receipt = hook_engine
            .run_lifecycle(openclaudia::hooks::HookEvent::SessionEnd, &end_input)
            .await;
        outcome
    };
    openclaudia::tools::retire_run(&print_run);
    outcome
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

    fn print_skill_run(root: &std::path::Path) -> Arc<openclaudia::tools::ToolRunContext> {
        let policy =
            openclaudia::skills::SkillCapabilityPolicy::project(Vec::new(), true, true, false)
                .expect("print skill policy");
        let access = openclaudia::skills::SkillRunAccess::host_granted_project(root, policy)
            .expect("print skill access");
        openclaudia::tools::ToolRunContext::builder(openclaudia::state::SessionId::new(), root)
            .working_directory(root)
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(HashMap::new())
            .skill_access(access)
            .workspace_access(openclaudia::tools::WorkspaceAccess::ReadOnly)
            .process(false)
            .network(true)
            .secrets(true)
            .provider("openai")
            .build()
            .expect("print skill run")
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
            remote_actions: openclaudia::config::RemoteActionsConfig::default(),
            policy,
            managed_settings_path: None,
        }
    }

    #[test]
    fn print_terminal_outcomes_remain_typed_and_fail_closed() {
        assert!(matches!(
            require_print_terminal(openclaudia::pipeline::ProviderTerminalOutcome::Refused, 0),
            Err(PrintModeError::Refused)
        ));
        assert!(matches!(
            require_print_terminal(
                openclaudia::pipeline::ProviderTerminalOutcome::LengthLimited,
                0
            ),
            Err(PrintModeError::Length { .. })
        ));
        assert!(matches!(
            require_print_terminal(openclaudia::pipeline::ProviderTerminalOutcome::ToolCalls, 1),
            Err(PrintModeError::Partial { .. })
        ));
    }

    #[test]
    fn absent_print_usage_remains_unknown_instead_of_zero() {
        assert!(reported_print_usage(openclaudia::session::TokenUsage::default()).is_none());
        let usage = openclaudia::session::TokenUsage {
            input_tokens: 11,
            output_tokens: 7,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
        };
        let reported = reported_print_usage(usage).expect("reported usage");
        assert_eq!(reported.input_tokens, 11);
        assert_eq!(reported.output_tokens, 7);
    }

    #[test]
    fn print_output_limit_is_an_error_instead_of_truncation() {
        let oversized = "x".repeat(MAX_PRINT_OUTPUT_BYTES + 1);
        assert!(matches!(
            validate_print_content(oversized),
            Err(PrintModeError::Length { .. })
        ));
    }

    #[test]
    fn broken_pipe_is_a_typed_delivery_failure() {
        struct BrokenPipeWriter;

        impl std::io::Write for BrokenPipeWriter {
            fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        assert!(matches!(
            deliver_print_output(&mut BrokenPipeWriter, "committed"),
            Err(PrintModeError::BrokenPipe)
        ));
    }

    #[test]
    fn print_mode_resolves_an_explicit_skill_as_one_turn_reference_context() {
        let root = tempfile::tempdir().expect("print skill project");
        let directory = root.path().join(".openclaudia/skills/review");
        std::fs::create_dir_all(&directory).expect("print skill directory");
        std::fs::write(
            directory.join("SKILL.md"),
            "---\nname: review\ndescription: review code\nmodel: gpt-5.6\neffort: high\n---\nPRINT_SKILL_REFERENCE_BODY\n",
        )
        .expect("print skill fixture");
        let run = print_skill_run(root.path());

        let turn = resolve_print_turn("/skill review src/lib.rs".to_string(), &run)
            .expect("print skill invocation");
        assert_eq!(turn.skill_model.as_deref(), Some("gpt-5.6"));
        assert_eq!(turn.skill_effort.as_deref(), Some("high"));
        assert!(turn.prompt.contains("User arguments:\nsrc/lib.rs"));
        assert!(!turn.prompt.contains("PRINT_SKILL_REFERENCE_BODY"));

        let request = build_print_chat_request_with_items(
            openclaudia::providers::get_adapter("openai").expect("adapter"),
            "gpt-5.6",
            turn.prompt,
            &run,
            turn.context_items,
        );
        let user_projection = request
            .messages
            .iter()
            .filter(|message| message.role == "user")
            .map(|message| serde_json::to_string(&message.content).expect("message content"))
            .collect::<String>();
        let system_projection = request
            .messages
            .iter()
            .filter(|message| message.role == "system")
            .map(|message| serde_json::to_string(&message.content).expect("message content"))
            .collect::<String>();
        assert!(user_projection.contains("PRINT_SKILL_REFERENCE_BODY"));
        assert!(!system_projection.contains("PRINT_SKILL_REFERENCE_BODY"));
    }

    #[test]
    fn print_mode_rejects_untrusted_project_skill_body() {
        let root = tempfile::tempdir().expect("print skill project");
        let directory = root.path().join(".openclaudia/skills/review");
        std::fs::create_dir_all(&directory).expect("print skill directory");
        std::fs::write(
            directory.join("SKILL.md"),
            "---\nname: review\ndescription: review code\n---\nUNTRUSTED_PRINT_SKILL_BODY\n",
        )
        .expect("print skill fixture");
        let run = openclaudia::tools::ToolRunContext::builder(
            openclaudia::state::SessionId::new(),
            root.path(),
        )
        .working_directory(root.path())
        .read_only_roots(Vec::new())
        .read_write_roots(Vec::new())
        .environment_grants(HashMap::new())
        .workspace_access(openclaudia::tools::WorkspaceAccess::ReadOnly)
        .process(false)
        .network(true)
        .secrets(true)
        .provider("openai")
        .build()
        .expect("untrusted print run");

        let error = resolve_print_turn("/skill review".to_string(), &run)
            .err()
            .expect("untrusted skill must be unavailable");
        assert!(error.to_string().contains("unknown or unavailable skill"));
        assert!(!error.to_string().contains("UNTRUSTED_PRINT_SKILL_BODY"));
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
    fn print_responses_profile_has_no_host_tools() {
        let body = openclaudia::pipeline::build_request_for_wire_with_exact_tools_and_state(
            openclaudia::pipeline::WireApi::OpenAiResponses,
            "openai",
            "gpt-test",
            &[serde_json::json!({"role": "user", "content": "inspect the workspace"})],
            "high",
            None,
            None,
            &[],
            None,
        )
        .expect("Responses print profile");

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
        let endpoint =
            resolve_print_endpoint("gemini-3.5-flash", &provider, adapter, None).expect("endpoint");
        assert!(endpoint.ends_with("/v1beta/models/gemini-3.5-flash:generateContent"));
        assert!(!endpoint.contains("streamGenerateContent"));
    }
}
