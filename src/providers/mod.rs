//! Provider Adapters - Translate between OpenAI-compatible format and provider APIs.
//!
//! Supports:
//! - Anthropic Messages API
//! - `OpenAI` Chat Completions API
//! - Google Gemini API
//! - `DeepSeek` API (with thinking/reasoning support)
//! - Qwen/Alibaba API (with thinking support)
//! - Z.AI/GLM API (with thinking support)
//! - Kimi/Moonshot API
//! - `MiniMax` API
//! - Ollama (local LLM inference)
//! - Any OpenAI-compatible server (LM Studio, `LocalAI`, etc.)
//!
//! Handles message format translation and tool/function calling conversion.

mod anthropic;
pub mod api_key;
mod deepseek;
mod google;
mod kimi;
mod minimax;
mod model_catalog;
mod ollama;
mod openai;
mod openai_compat;
mod qwen;
mod zai;

use async_trait::async_trait;
use serde_json::Value;
use thiserror::Error;

use crate::config::ThinkingConfig;
use crate::proxy::ChatCompletionRequest;
use crate::runtime::{
    ProviderNativeState, ProviderStateContract, ProviderStateSupport, ProviderWireProtocol,
};
use crate::secrets::SensitiveHeaders;
use crate::session::TokenUsage;

// Re-export all adapter types and public functions
pub use anthropic::{
    anthropic_output_effort, anthropic_rejects_manual_thinking, apply_anthropic_adaptive_thinking,
    build_system_blocks, build_system_blocks_from_string, convert_messages_to_anthropic,
    convert_messages_to_anthropic_checked, convert_tool_definitions_to_anthropic_checked,
    convert_tools_to_anthropic, convert_tools_to_anthropic_checked, AnthropicAdapter,
};
pub use api_key::{ApiKey, ApiKeyError, MAX_API_KEY_LEN, REDACTED_PLACEHOLDER};
pub use deepseek::DeepSeekAdapter;
pub use google::{
    advance_gemini_generate_content_state, convert_tools_to_gemini,
    convert_tools_to_gemini_functions, extract_gemini_text_content,
    GeminiGenerateContentTurnOutput, GoogleAdapter,
};
pub use kimi::KimiAdapter;
pub use minimax::MiniMaxAdapter;
pub use model_catalog::{
    cached_model_catalog, canonical_static_catalog_provider, emergency_fallback_catalog,
    known_model_context_window, resolve_model, static_models_for_provider, ModelAccessState,
    ModelCapabilities, ModelCatalogEntry, ModelCatalogFormat, ModelCatalogProvenance,
    ModelCatalogSnapshot, ModelEvidenceSource, ModelLifecycle, ModelPricingState, ModelSupport,
    ReasoningProfile, ResolvedModel, ANTHROPIC_MODELS, DEEPSEEK_MODELS, GOOGLE_MODELS, KIMI_MODELS,
    MINIMAX_MODELS, OPENAI_MODELS, QWEN_MODELS, STATIC_MODEL_CATALOG_PROVIDERS, ZAI_MODELS,
};
pub use ollama::{advance_ollama_chat_state, OllamaAdapter, OllamaChatTurnOutput};
pub(crate) use openai::finalize_responses_request;
pub use openai::{advance_openai_responses_state, OpenAIAdapter, OpenAiResponsesTurnOutput};
pub use qwen::QwenAdapter;
pub use zai::ZaiAdapter;

/// Errors that can occur during provider operations
#[derive(Error, Debug)]
pub enum ProviderError {
    #[error("Request failed: {0}")]
    RequestFailed(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("Unsupported feature: {0}")]
    Unsupported(String),

    /// The provider name supplied to [`get_adapter`] does not match any
    /// registered adapter. Carries the unrecognised name AND the list of
    /// supported names so the caller can surface a helpful error to the
    /// user (e.g. a 400 Bad Request body that lists what is valid).
    ///
    /// See crosslink #433 — the previous behaviour was a `tracing::warn!`
    /// followed by a silent fallback to `OpenAIAdapter`, meaning a typo
    /// in `proxy.target` (`"anthrpic"`) resulted in API calls being sent
    /// to a configured `OpenAI` endpoint with no user-visible error.
    #[error(
        "Unknown provider: '{name}'. Supported providers: {}",
        supported.join(", ")
    )]
    UnknownProvider {
        name: String,
        supported: Vec<&'static str>,
    },
}

/// Model information returned from provider
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ModelInfo {
    pub id: String,
    #[serde(default)]
    pub owned_by: Option<String>,
    #[serde(default)]
    pub created: Option<i64>,
}

/// Trait for provider adapters
#[async_trait]
pub trait ProviderAdapter: Send + Sync {
    /// Get the provider name
    fn name(&self) -> &str;

    /// Declare lossless native-state behavior for one concrete wire protocol.
    ///
    /// Implementations must reject protocols they do not speak.  There is no
    /// default declaration because silently inheriting a generic chat fallback
    /// is precisely what native continuation state must prevent.
    ///
    /// # Errors
    ///
    /// Returns [`ProviderError::Unsupported`] for a protocol the adapter does
    /// not implement.
    fn state_contract(
        &self,
        protocol: ProviderWireProtocol,
    ) -> Result<&'static ProviderStateContract, ProviderError>;

    /// Apply validated provider-native state to an already transformed request.
    ///
    /// The default is intentionally fail-closed: evidence-only items require no
    /// request mutation, while any continuation item requires an adapter
    /// override. Provider-specific continuation slices must add the override at
    /// the same time they declare a facet round-trippable.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported facets or unapplied continuation state.
    fn apply_provider_native_state(
        &self,
        _request: &mut Value,
        state: &ProviderNativeState,
    ) -> Result<(), ProviderError> {
        self.state_contract(state.protocol())?
            .validate_state(state)
            .map_err(|error| ProviderError::Unsupported(error.to_string()))?;
        if state.has_continuation_items() {
            return Err(ProviderError::Unsupported(format!(
                "{} declares native continuation items but has no lossless request applicator",
                self.name()
            )));
        }
        Ok(())
    }

    /// Transform an OpenAI-compatible request to provider format.
    ///
    /// # Errors
    ///
    /// Returns a `ProviderError` if the request cannot be transformed.
    fn transform_request(&self, request: &ChatCompletionRequest) -> Result<Value, ProviderError>;

    /// Transform request with thinking config applied.
    ///
    /// # Errors
    ///
    /// Returns a `ProviderError` if the request cannot be transformed.
    fn transform_request_with_thinking(
        &self,
        request: &ChatCompletionRequest,
        thinking: &ThinkingConfig,
    ) -> Result<Value, ProviderError> {
        // Default: ignore thinking config, just call transform_request
        let _ = thinking;
        self.transform_request(request)
    }

    /// Transform a provider response to OpenAI-compatible format.
    ///
    /// # Errors
    ///
    /// Returns a `ProviderError` if the response cannot be transformed.
    fn transform_response(&self, response: Value, stream: bool) -> Result<Value, ProviderError>;

    /// Get the endpoint path for chat completions.
    /// The model parameter allows providers like Google to build model-specific URLs.
    fn chat_endpoint(&self, _model: &str) -> String;

    /// Get the endpoint path for *streaming* chat completions, when the
    /// provider exposes one that differs from [`Self::chat_endpoint`].
    ///
    /// Most providers (Anthropic, `OpenAI`, `DeepSeek`, Qwen, Z.AI,
    /// Kimi/Moonshot, `MiniMax`) toggle
    /// streaming via the `stream: true` request field on the same URL, so
    /// the default implementation returns `None` — the caller continues to
    /// use [`Self::chat_endpoint`].
    ///
    /// Google's Gemini API is the exception: streaming uses a different
    /// path suffix (`:streamGenerateContent?alt=sse`) instead of a request
    /// flag. The Google adapter overrides this method so the pipeline can
    /// switch endpoints when streaming is requested.
    ///
    /// See crosslink #602.
    fn stream_endpoint(&self, _model: &str) -> Option<String> {
        None
    }

    /// True when this provider supports server-sent-event streaming.
    ///
    /// The default returns `true` — every provider currently wired into
    /// `OpenClaudia` supports streaming, but the flag is exposed so that
    /// future providers (or test doubles) can disable streaming via a
    /// single override instead of plumbing the capability through
    /// `pipeline.rs`.
    ///
    /// See crosslink #602.
    fn supports_streaming(&self) -> bool {
        true
    }

    /// Get required headers for this provider.
    ///
    /// Raw key bytes stay inside [`SensitiveHeaders`] and are materialized
    /// only when that collection is applied to a request at the transport
    /// boundary.
    fn get_headers(&self, api_key: &ApiKey) -> SensitiveHeaders;

    /// Check if this provider supports model listing
    fn supports_model_listing(&self) -> bool {
        false
    }

    /// Response schema used by the provider's model-list endpoint.
    fn model_catalog_format(&self) -> Option<ModelCatalogFormat> {
        self.supports_model_listing()
            .then_some(ModelCatalogFormat::OpenAi)
    }

    /// Get the models endpoint path (for providers that support it)
    fn models_endpoint(&self) -> &'static str {
        "/v1/models"
    }

    /// Extract the assistant text content from a *raw* provider response.
    ///
    /// This is the inverse of [`Self::transform_request`]: it consumes the
    /// upstream provider's native shape and returns the plain-text body
    /// of the assistant turn (no tool calls, no function payloads —
    /// just the text the user would see).
    ///
    /// Default implementation reads the `OpenAI` Chat Completions shape
    /// (`choices[0].message.content`). Providers with a different native
    /// response shape (Anthropic content blocks, Gemini `candidates`,
    /// Ollama `message.content`) override this with their own extractor.
    ///
    /// Returns `None` when no text content can be located — callers must
    /// treat that as "empty response" rather than fabricating a sentinel.
    ///
    /// See crosslink #479 — VDD previously rolled its own multi-shape
    /// extractor in `src/vdd/parsing.rs`, which silently returned an
    /// empty string for any provider it did not recognise (`DeepSeek`,
    /// `Qwen`, Z.AI). Routing through the adapter restores parity with
    /// the main proxy hot path.
    fn extract_response_text(&self, response: &Value) -> Option<String> {
        response
            .get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(|c| c.as_str())
            .map(std::string::ToString::to_string)
    }

    /// Extract token usage from a *raw* provider response.
    ///
    /// Default implementation reads the `OpenAI`/`Anthropic` shared
    /// `usage` object (`prompt_tokens`/`completion_tokens`, with
    /// fallback to `input_tokens`/`output_tokens` for Anthropic).
    /// Providers that use a different envelope (notably Gemini's
    /// `usageMetadata`) override this.
    ///
    /// Returns `None` when no usage data is present. Callers that need
    /// `TokenUsage::default()` semantics should call `.unwrap_or_default()`
    /// at the call site so the absence is visible in code review.
    ///
    /// See crosslink #479.
    fn extract_token_usage(&self, response: &Value) -> Option<TokenUsage> {
        let usage = response.get("usage")?;
        let raw_input_tokens = usage
            .get("prompt_tokens")
            .or_else(|| usage.get("input_tokens"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let cached_tokens_from_details = usage
            .get("prompt_tokens_details")
            .or_else(|| usage.get("input_tokens_details"))
            .and_then(|details| details.get("cached_tokens"))
            .and_then(Value::as_u64);
        let cache_read_tokens = usage
            .get("cache_read_input_tokens")
            .and_then(Value::as_u64)
            .or(cached_tokens_from_details)
            .unwrap_or(0);
        let input_tokens = if cached_tokens_from_details.is_some() {
            raw_input_tokens.saturating_sub(cache_read_tokens)
        } else {
            raw_input_tokens
        };

        Some(TokenUsage {
            input_tokens,
            output_tokens: usage
                .get("completion_tokens")
                .or_else(|| usage.get("output_tokens"))
                .and_then(Value::as_u64)
                .unwrap_or(0),
            cache_read_tokens,
            cache_write_tokens: usage
                .get("cache_creation_input_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(0),
        })
    }
}

const NATIVE_MESSAGES_PENDING: ProviderStateSupport =
    ProviderStateSupport::Unsupported("native message replay is not wired yet");
const TOOL_CALLS_PENDING: ProviderStateSupport =
    ProviderStateSupport::Unsupported("native tool-call replay is not wired yet");
const PARALLEL_TOOLS_PENDING: ProviderStateSupport =
    ProviderStateSupport::Unsupported("native parallel tool-call ordering is not wired yet");
const REASONING_PENDING: ProviderStateSupport =
    ProviderStateSupport::Unsupported("native reasoning continuation is not wired yet");
const COMPACTION_PENDING: ProviderStateSupport =
    ProviderStateSupport::Unsupported("native compaction state is not wired yet");
const SERVER_CONTINUATION_PENDING: ProviderStateSupport =
    ProviderStateSupport::Unsupported("server continuation identifiers are not wired yet");

const fn retained_evidence_contract(protocol: ProviderWireProtocol) -> ProviderStateContract {
    ProviderStateContract {
        protocol,
        native_message: NATIVE_MESSAGES_PENDING,
        tool_calls: TOOL_CALLS_PENDING,
        parallel_tool_calls: PARALLEL_TOOLS_PENDING,
        reasoning: REASONING_PENDING,
        refusal: ProviderStateSupport::EvidenceOnly,
        usage: ProviderStateSupport::EvidenceOnly,
        cache_metadata: ProviderStateSupport::EvidenceOnly,
        compaction: COMPACTION_PENDING,
        server_continuation: SERVER_CONTINUATION_PENDING,
        terminal_state: ProviderStateSupport::EvidenceOnly,
    }
}

static ANTHROPIC_STATE_CONTRACT: ProviderStateContract =
    retained_evidence_contract(ProviderWireProtocol::AnthropicMessages);
static OPENAI_CHAT_STATE_CONTRACT: ProviderStateContract =
    retained_evidence_contract(ProviderWireProtocol::OpenAiChatCompletions);
static OPENAI_RESPONSES_STATE_CONTRACT: ProviderStateContract = ProviderStateContract {
    protocol: ProviderWireProtocol::OpenAiResponses,
    native_message: ProviderStateSupport::RoundTrip,
    tool_calls: ProviderStateSupport::RoundTrip,
    parallel_tool_calls: ProviderStateSupport::RoundTrip,
    reasoning: ProviderStateSupport::RoundTrip,
    refusal: ProviderStateSupport::EvidenceOnly,
    usage: ProviderStateSupport::EvidenceOnly,
    cache_metadata: ProviderStateSupport::EvidenceOnly,
    compaction: ProviderStateSupport::RoundTrip,
    // The Responses transport is deliberately stateless (`store:false`).
    // Response IDs are retained for evidence and trace correlation, but are
    // not sent back as `previous_response_id`; exact output items carry the
    // continuation instead.
    server_continuation: ProviderStateSupport::EvidenceOnly,
    terminal_state: ProviderStateSupport::EvidenceOnly,
};
static GEMINI_GENERATE_CONTENT_STATE_CONTRACT: ProviderStateContract = ProviderStateContract {
    protocol: ProviderWireProtocol::GeminiGenerateContent,
    native_message: ProviderStateSupport::RoundTrip,
    tool_calls: ProviderStateSupport::RoundTrip,
    parallel_tool_calls: ProviderStateSupport::RoundTrip,
    // Thought signatures remain opaque inside their exact native content
    // parts. They are replayed but never projected into portable messages.
    reasoning: ProviderStateSupport::RoundTrip,
    refusal: ProviderStateSupport::EvidenceOnly,
    usage: ProviderStateSupport::EvidenceOnly,
    cache_metadata: ProviderStateSupport::EvidenceOnly,
    compaction: COMPACTION_PENDING,
    server_continuation: SERVER_CONTINUATION_PENDING,
    terminal_state: ProviderStateSupport::EvidenceOnly,
};
static GEMINI_INTERACTIONS_STATE_CONTRACT: ProviderStateContract =
    retained_evidence_contract(ProviderWireProtocol::GeminiInteractions);
static OLLAMA_STATE_CONTRACT: ProviderStateContract = ProviderStateContract {
    protocol: ProviderWireProtocol::OllamaChat,
    native_message: ProviderStateSupport::RoundTrip,
    tool_calls: ProviderStateSupport::RoundTrip,
    parallel_tool_calls: ProviderStateSupport::RoundTrip,
    // Ollama's `thinking` field is retained only in the exact native message;
    // S-049 owns its eventual display/privacy projection.
    reasoning: ProviderStateSupport::RoundTrip,
    refusal: ProviderStateSupport::EvidenceOnly,
    usage: ProviderStateSupport::EvidenceOnly,
    cache_metadata: ProviderStateSupport::EvidenceOnly,
    compaction: COMPACTION_PENDING,
    server_continuation: SERVER_CONTINUATION_PENDING,
    terminal_state: ProviderStateSupport::EvidenceOnly,
};

fn unsupported_state_protocol(adapter: &str, protocol: ProviderWireProtocol) -> ProviderError {
    ProviderError::Unsupported(format!(
        "provider adapter {adapter} does not implement wire protocol {protocol}"
    ))
}

/// Typed enum of every provider this proxy knows how to route to.
///
/// Replaces the stringly-typed `if/else-if` chain in `determine_provider`
/// (crosslink #332). All callers that need a wire-format name go through
/// [`ProviderKind::name`], which returns `&'static str` and allocates nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderKind {
    Anthropic,
    OpenAI,
    Google,
    DeepSeek,
    Qwen,
    Zai,
    Kimi,
    MiniMax,
    Unknown,
}

impl ProviderKind {
    /// Classify a model name to its provider. Explicit match arms,
    /// lowercased input, no overlapping prefix heuristics — `"o1"` no
    /// longer matches `"o100"`.
    #[must_use]
    pub fn from_model(model: &str) -> Self {
        let m = model.to_ascii_lowercase();
        if m.starts_with("claude") || m.starts_with("anthropic") {
            return Self::Anthropic;
        }
        if m.starts_with("gpt-") || m == "gpt" {
            return Self::OpenAI;
        }
        if m.starts_with("codex-") || m == "codex" || m == "chat-latest" {
            return Self::OpenAI;
        }
        for prefix in ["o1-", "o3-", "o4-"] {
            if m.starts_with(prefix) {
                return Self::OpenAI;
            }
        }
        if matches!(m.as_str(), "o1" | "o3" | "o4") {
            return Self::OpenAI;
        }
        if m.starts_with("gemini") {
            return Self::Google;
        }
        if m.starts_with("deepseek") {
            return Self::DeepSeek;
        }
        if m.starts_with("qwen") || m.starts_with("qwq") || m.starts_with("qvq") {
            return Self::Qwen;
        }
        if m.starts_with("kimi") || m.starts_with("moonshot") {
            return Self::Kimi;
        }
        if m.starts_with("minimax") || m == "m2-her" {
            return Self::MiniMax;
        }
        if m.starts_with("glm") {
            return Self::Zai;
        }
        Self::Unknown
    }

    /// Static name used as the key into `AppConfig.providers` and as the
    /// adapter selector in [`get_adapter`]. `Unknown` returns `"unknown"`.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAI => "openai",
            Self::Google => "google",
            Self::DeepSeek => "deepseek",
            Self::Qwen => "qwen",
            Self::Zai => "zai",
            Self::Kimi => "kimi",
            Self::MiniMax => "minimax",
            Self::Unknown => "unknown",
        }
    }
}

// ── Crosslink #433: static adapter singletons ───────────────────────────────
//
// Each `*Adapter` struct exposes a `pub const fn new()`, so every adapter
// can be constructed at compile time and stored as a `static` value with
// `'static` lifetime. Previously [`get_adapter`] returned
// `Box<dyn ProviderAdapter>`, allocating one boxed instance per *request*
// in the proxy hot path (`proxy_chat_completions`). The trait objects below
// replace that with a single shared instance per provider, looked up by name
// and returned as `&'static dyn ProviderAdapter` — zero allocation, zero
// per-request work.
//
// The slice [`SUPPORTED_PROVIDERS`] is the authoritative list of names
// `get_adapter` recognises. It's used both for dispatch and to populate the
// "supported providers" hint inside [`ProviderError::UnknownProvider`], so
// the error message can never drift from the dispatch table.

static ANTHROPIC: AnthropicAdapter = AnthropicAdapter::new();
static OPENAI: OpenAIAdapter = OpenAIAdapter::new();
static GOOGLE: GoogleAdapter = GoogleAdapter::new();
static DEEPSEEK: DeepSeekAdapter = DeepSeekAdapter::new();
static QWEN: QwenAdapter = QwenAdapter::new();
static ZAI: ZaiAdapter = ZaiAdapter::new();
static KIMI: KimiAdapter = KimiAdapter::new();
static MINIMAX: MiniMaxAdapter = MiniMaxAdapter::new();
static OLLAMA: OllamaAdapter = OllamaAdapter::new();

/// Canonical names accepted by [`get_adapter`]. Aliases are listed in the
/// same order they appear in the dispatch `match` so the error message hint
/// matches what the function actually resolves.
///
/// Re-exported so `main.rs` can wire this into clap's `PossibleValuesParser`
/// for `--target`, ensuring CLI validation matches runtime dispatch
/// (closes the gap surfaced by the binary-verification audit).
pub const SUPPORTED_PROVIDERS: &[&str] = &[
    "anthropic",
    "openai",
    "google",
    "gemini",
    "deepseek",
    "qwen",
    "alibaba",
    "zai",
    "glm",
    "zhipu",
    "kimi",
    "moonshot",
    "minimax",
    "ollama",
    "local",
    "lmstudio",
    "localai",
    "text-generation-webui",
    "openrouter",
    "opencode",
    "opencode-go",
    "openai-compatible",
];

/// Canonical per-target default model table.
///
/// Shared by CLI startup and TUI live provider switching so a provider
/// change inside an existing session uses the same fallback model as a
/// freshly-started session.
pub const DEFAULT_MODELS_BY_TARGET: &[(&str, &str)] = &[
    ("anthropic", "claude-opus-4-8"),
    ("openai", "gpt-5.6-sol"),
    ("google", "gemini-3.7-flash"),
    ("gemini", "gemini-3.7-flash"),
    ("zai", "glm-5.2"),
    ("glm", "glm-5.2"),
    ("zhipu", "glm-5.2"),
    ("deepseek", "deepseek-v4-pro"),
    ("qwen", "qwen3.7-plus"),
    ("alibaba", "qwen3.7-plus"),
    ("kimi", "kimi-k2.7-code"),
    ("moonshot", "kimi-k2.7-code"),
    ("minimax", "MiniMax-M3"),
    ("openrouter", "~openai/gpt-latest"),
    ("opencode", "kimi-k2.7-code"),
    ("opencode-go", "kimi-k2.7-code"),
];

/// Look up the canonical default model for a provider with a maintained default.
///
/// Local and custom OpenAI-compatible targets intentionally return `None`:
/// their installed model inventory is runtime state, not an `OpenAI` default.
#[must_use]
pub fn default_model_for_target(target: &str) -> Option<&'static str> {
    let target = target.trim();
    DEFAULT_MODELS_BY_TARGET
        .iter()
        .find_map(|(t, m)| t.eq_ignore_ascii_case(target).then_some(*m))
}

/// Environment variable users should set for a provider API key.
///
/// Matching is ASCII-case-insensitive so diagnostics stay aligned with the
/// case-insensitive provider dispatch surface.
#[must_use]
pub fn api_key_env_var_for_target(provider_name: &str) -> &'static str {
    match provider_name.trim().to_ascii_lowercase().as_str() {
        "anthropic" => "ANTHROPIC_API_KEY",
        "openai" => "OPENAI_API_KEY",
        "google" | "gemini" => "GOOGLE_API_KEY or GEMINI_API_KEY",
        "zai" | "glm" | "zhipu" => "ZAI_API_KEY",
        "deepseek" => "DEEPSEEK_API_KEY",
        "qwen" | "alibaba" => "QWEN_API_KEY, DASHSCOPE_API_KEY, or ALIYUN_API_KEY",
        "kimi" | "moonshot" => "KIMI_API_KEY or MOONSHOT_API_KEY",
        "minimax" => "MINIMAX_API_KEY",
        "openrouter" => "OPENROUTER_API_KEY or OPEN_ROUTER_API_KEY",
        "opencode" | "opencode-go" => "OPENCODE_API_KEY or OPENCODE_GO_API_KEY",
        "openai-compatible" => "OPENAI_COMPATIBLE_API_KEY or API_KEY",
        _ => "API_KEY",
    }
}

/// Targets that should keep the selected provider even when a model ID looks
/// like another vendor's namespace.
///
/// Aggregators such as `OpenRouter` intentionally use slugs like
/// `anthropic/claude-...`; local OpenAI-compatible servers often expose
/// arbitrary names too. Prefix-based provider inference would otherwise route
/// those requests to a different configured provider.
#[must_use]
pub fn is_openai_compatible_passthrough_target(target: &str) -> bool {
    matches!(
        target.trim().to_ascii_lowercase().as_str(),
        "local"
            | "lmstudio"
            | "localai"
            | "text-generation-webui"
            | "openrouter"
            | "opencode"
            | "opencode-go"
            | "openai-compatible"
    )
}

/// Resolve a provider name to its singleton adapter.
///
/// Returns `&'static dyn ProviderAdapter` — no allocation, no per-call
/// construction. The dispatch is case-insensitive (the input is lowercased
/// for matching) to preserve the prior contract: `proxy.target: OpenAI` in
/// `config.yaml` resolves to the same adapter as `proxy.target: openai`.
///
/// # Errors
///
/// Returns [`ProviderError::UnknownProvider`] when `provider` does not
/// match any registered adapter name (no silent fallback — see #433). The
/// error includes the unrecognised name and the list of supported names so
/// callers can surface a helpful diagnostic (e.g. a 400 response body).
///
/// # Examples
///
/// ```
/// use openclaudia::providers::get_adapter;
/// let adapter = get_adapter("anthropic").expect("known provider");
/// assert_eq!(adapter.name(), "anthropic");
///
/// // Typos surface as errors, not silent OpenAI fallbacks.
/// assert!(get_adapter("anthrpic").is_err());
/// ```
pub fn get_adapter(provider: &str) -> Result<&'static dyn ProviderAdapter, ProviderError> {
    let adapter: &'static dyn ProviderAdapter = match provider.to_ascii_lowercase().as_str() {
        "anthropic" => &ANTHROPIC,
        "google" | "gemini" => &GOOGLE,
        "zai" | "glm" | "zhipu" => &ZAI,
        "deepseek" => &DEEPSEEK,
        "qwen" | "alibaba" => &QWEN,
        "kimi" | "moonshot" => &KIMI,
        "minimax" => &MINIMAX,
        "ollama" => &OLLAMA,
        // OpenAI-compatible providers: explicitly named (no silent fallback
        // for unrecognised names — see the `_ =>` arm below).
        "openai"
        | "local"
        | "lmstudio"
        | "localai"
        | "text-generation-webui"
        | "openrouter"
        | "opencode"
        | "opencode-go"
        | "openai-compatible" => &OPENAI,
        _ => {
            return Err(ProviderError::UnknownProvider {
                name: provider.to_string(),
                supported: SUPPORTED_PROVIDERS.to_vec(),
            });
        }
    };
    Ok(adapter)
}

#[cfg(test)]
fn parse_models_response(body: &Value) -> Result<Vec<ModelInfo>, ProviderError> {
    let snapshot = model_catalog::parse_discovered_catalog(
        "openai",
        "https://example.invalid/v1/models",
        ModelCatalogFormat::OpenAi,
        body,
        chrono::Utc::now().timestamp(),
    )
    .map_err(ProviderError::InvalidResponse)?;
    Ok(snapshot
        .models
        .into_iter()
        .map(|model| ModelInfo {
            id: model.canonical_id,
            owned_by: model.owned_by,
            created: model.created,
        })
        .collect())
}

/// Fetch available models from a provider's `/v1/models` endpoint.
/// Works with OpenAI-compatible APIs (LM Studio, `LocalAI`, Ollama, etc.)
///
/// # Errors
///
/// Returns a `ProviderError` if the provider does not support model listing or the request fails.
pub async fn fetch_models(
    base_url: &str,
    api_key: Option<&ApiKey>,
    adapter: &dyn ProviderAdapter,
) -> Result<Vec<ModelInfo>, ProviderError> {
    fetch_models_for_provider_with_headers(
        adapter.name(),
        base_url,
        api_key,
        &SensitiveHeaders::new(),
        adapter,
    )
    .await
}

/// Fetch available models with optional operator-supplied headers.
///
/// Custom OpenAI-compatible providers often require routing or attribution
/// headers in addition to bearer auth; this mirrors chat request forwarding.
///
/// # Errors
///
/// Returns a `ProviderError` if the provider does not support model listing or the request fails.
pub async fn fetch_models_with_headers(
    base_url: &str,
    api_key: Option<&ApiKey>,
    extra_headers: &SensitiveHeaders,
    adapter: &dyn ProviderAdapter,
) -> Result<Vec<ModelInfo>, ProviderError> {
    fetch_models_for_provider_with_headers(
        adapter.name(),
        base_url,
        api_key,
        extra_headers,
        adapter,
    )
    .await
}

/// Fetch available models while retaining the configured provider identity.
///
/// OpenAI-compatible local targets share the `openai` adapter, but their
/// configured names carry the security policy that permits loopback/LAN model
/// servers. Product call sites should use this function when that identity is
/// available; the compatibility helpers above remain suitable for canonical
/// remote providers.
///
/// # Errors
///
/// Returns a [`ProviderError`] if the endpoint is disallowed, listing is
/// unsupported, the request fails, or the response is malformed.
pub async fn fetch_models_for_provider_with_headers(
    provider_name: &str,
    base_url: &str,
    api_key: Option<&ApiKey>,
    extra_headers: &SensitiveHeaders,
    adapter: &dyn ProviderAdapter,
) -> Result<Vec<ModelInfo>, ProviderError> {
    let snapshot = discover_model_catalog_for_provider_with_headers(
        provider_name,
        base_url,
        api_key,
        extra_headers,
        adapter,
    )
    .await?;
    Ok(snapshot
        .models
        .into_iter()
        .map(|model| ModelInfo {
            id: model.canonical_id,
            owned_by: model.owned_by,
            created: model.created,
        })
        .collect())
}

/// Discover and cache the account-scoped model catalogue exposed by a provider.
///
/// # Errors
///
/// Returns a `ProviderError` when listing is unsupported, the endpoint fails,
/// or the provider returns a malformed response.
pub async fn discover_model_catalog_with_headers(
    base_url: &str,
    api_key: Option<&ApiKey>,
    extra_headers: &SensitiveHeaders,
    adapter: &dyn ProviderAdapter,
) -> Result<ModelCatalogSnapshot, ProviderError> {
    discover_model_catalog_for_provider_with_headers(
        adapter.name(),
        base_url,
        api_key,
        extra_headers,
        adapter,
    )
    .await
}

/// Discover models using the configured provider name for endpoint policy.
///
/// # Errors
///
/// Returns a [`ProviderError`] if the endpoint is disallowed, listing is
/// unsupported, the request fails, or the response is malformed.
pub async fn discover_model_catalog_for_provider_with_headers(
    provider_name: &str,
    base_url: &str,
    api_key: Option<&ApiKey>,
    extra_headers: &SensitiveHeaders,
    adapter: &dyn ProviderAdapter,
) -> Result<ModelCatalogSnapshot, ProviderError> {
    discover_model_catalog_impl(
        provider_name,
        base_url,
        api_key,
        extra_headers,
        adapter,
        true,
    )
    .await
}

async fn discover_model_catalog_impl(
    provider_name: &str,
    base_url: &str,
    api_key: Option<&ApiKey>,
    extra_headers: &SensitiveHeaders,
    adapter: &dyn ProviderAdapter,
    validate_endpoint: bool,
) -> Result<ModelCatalogSnapshot, ProviderError> {
    if !adapter.supports_model_listing() {
        return Err(ProviderError::Unsupported(format!(
            "Provider '{}' does not support model listing",
            adapter.name()
        )));
    }
    let format = adapter.model_catalog_format().ok_or_else(|| {
        ProviderError::Unsupported(format!(
            "Provider '{}' does not declare a model catalogue format",
            adapter.name()
        ))
    })?;

    let client = crate::provider_transport::shared_client()
        .map_err(|error| ProviderError::RequestFailed(error.to_string()))?;

    // Single source of truth for base-URL normalisation (crosslink #493 —
    // this used to be a hand-inlined three-line trim that drifted from
    // `proxy::normalize_base_url`; any future fix, e.g. also stripping
    // `/v1beta` for Gemini, now only needs to land in one place).
    let normalized_base = crate::proxy::normalize_base_url(base_url);
    let url = format!("{}{}", normalized_base, adapter.models_endpoint());
    if validate_endpoint {
        crate::provider_transport::validate_endpoint(provider_name, &url)
            .map_err(|error| ProviderError::RequestFailed(error.to_string()))?;
    }
    let now_unix = chrono::Utc::now().timestamp();
    if let Some(snapshot) = cached_model_catalog(adapter.name(), &url, now_unix) {
        return Ok(snapshot);
    }

    let mut headers = SensitiveHeaders::new();

    // Use the adapter's auth contract rather than assuming every provider
    // authenticates model-list requests with a Bearer token.
    if let Some(key) = api_key {
        headers.extend(&adapter.get_headers(key));
    }
    headers.extend(extra_headers);
    let request = headers
        .apply(client.get(&url))
        .map_err(|error| ProviderError::RequestFailed(error.to_string()))?;

    let response = crate::provider_transport::send(request)
        .await
        .map_err(|e| ProviderError::RequestFailed(format!("Failed to fetch models: {e}")))?;

    if !response.status().is_success() {
        return Err(ProviderError::RequestFailed(format!(
            "Models endpoint returned status {}",
            response.status()
        )));
    }

    let body: Value = crate::provider_transport::read_json_capped(
        response,
        crate::provider_transport::MAX_JSON_RESPONSE_BYTES,
    )
    .await
    .map_err(|e| ProviderError::InvalidResponse(format!("Failed to parse models response: {e}")))?;

    let snapshot =
        model_catalog::parse_discovered_catalog(adapter.name(), &url, format, &body, now_unix)
            .map_err(ProviderError::InvalidResponse)?;
    model_catalog::cache_discovered_catalog(&url, snapshot.clone());
    Ok(snapshot)
}

#[cfg(test)]
async fn fetch_models_with_headers_for_test(
    base_url: &str,
    api_key: Option<&ApiKey>,
    extra_headers: &SensitiveHeaders,
    adapter: &dyn ProviderAdapter,
) -> Result<Vec<ModelInfo>, ProviderError> {
    let snapshot = discover_model_catalog_impl(
        adapter.name(),
        base_url,
        api_key,
        extra_headers,
        adapter,
        false,
    )
    .await?;
    Ok(snapshot
        .models
        .into_iter()
        .map(|model| ModelInfo {
            id: model.canonical_id,
            owned_by: model.owned_by,
            created: model.created,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::{ChatCompletionRequest, ChatMessage, MessageContent};
    use crate::runtime::{
        ContinuationGeneration, ProviderNativeItem, ProviderNativeItemPurpose, ProviderNativeState,
        ProviderStateFacet,
    };
    use serde_json::json;

    struct ApiKeyHeaderModelAdapter;

    impl ProviderAdapter for ApiKeyHeaderModelAdapter {
        fn name(&self) -> &'static str {
            "api-key-header-test"
        }

        fn state_contract(
            &self,
            protocol: ProviderWireProtocol,
        ) -> Result<&'static ProviderStateContract, ProviderError> {
            match protocol {
                ProviderWireProtocol::OpenAiChatCompletions => Ok(&OPENAI_CHAT_STATE_CONTRACT),
                other => Err(unsupported_state_protocol(self.name(), other)),
            }
        }

        fn transform_request(
            &self,
            request: &ChatCompletionRequest,
        ) -> Result<Value, ProviderError> {
            serde_json::to_value(request)
                .map_err(|error| ProviderError::RequestFailed(error.to_string()))
        }

        fn transform_response(
            &self,
            response: Value,
            _stream: bool,
        ) -> Result<Value, ProviderError> {
            Ok(response)
        }

        fn chat_endpoint(&self, _model: &str) -> String {
            "/v1/chat/completions".to_string()
        }

        fn get_headers(&self, api_key: &ApiKey) -> SensitiveHeaders {
            let mut headers = SensitiveHeaders::new();
            headers.insert_header_secret(
                reqwest::header::HeaderName::from_static("x-api-key"),
                api_key.secret(),
            );
            headers
        }

        fn supports_model_listing(&self) -> bool {
            true
        }
    }

    fn native_state(
        facet: ProviderStateFacet,
        purpose: ProviderNativeItemPurpose,
    ) -> ProviderNativeState {
        ProviderNativeState::new(
            "openai",
            "gpt-test",
            ProviderWireProtocol::OpenAiChatCompletions,
            ContinuationGeneration::new(1).expect("non-zero generation"),
            vec![
                ProviderNativeItem::new(facet, purpose, json!({"native": true}))
                    .expect("valid native item"),
            ],
        )
        .expect("valid native state")
    }

    fn native_state_for(
        provider: &str,
        protocol: ProviderWireProtocol,
        facet: ProviderStateFacet,
        purpose: ProviderNativeItemPurpose,
    ) -> ProviderNativeState {
        ProviderNativeState::new(
            provider,
            "model-test",
            protocol,
            ContinuationGeneration::new(1).expect("non-zero generation"),
            vec![
                ProviderNativeItem::new(facet, purpose, json!({"provider_item": provider}))
                    .expect("valid native item"),
            ],
        )
        .expect("valid native state")
    }

    #[test]
    fn every_registered_adapter_declares_its_native_protocol() {
        for provider in SUPPORTED_PROVIDERS {
            let adapter = get_adapter(provider).expect("registered adapter");
            let protocol = match *provider {
                "anthropic" => ProviderWireProtocol::AnthropicMessages,
                "google" | "gemini" => ProviderWireProtocol::GeminiGenerateContent,
                "ollama" => ProviderWireProtocol::OllamaChat,
                _ => ProviderWireProtocol::OpenAiChatCompletions,
            };
            let contract = adapter
                .state_contract(protocol)
                .unwrap_or_else(|error| panic!("{provider} lacks {protocol}: {error}"));
            assert_eq!(contract.protocol, protocol, "provider {provider}");

            for facet in [
                ProviderStateFacet::Refusal,
                ProviderStateFacet::Usage,
                ProviderStateFacet::CacheMetadata,
                ProviderStateFacet::TerminalState,
            ] {
                contract
                    .validate_state(&native_state_for(
                        provider,
                        protocol,
                        facet,
                        ProviderNativeItemPurpose::Evidence,
                    ))
                    .unwrap_or_else(|error| {
                        panic!("{provider} must retain {facet:?} evidence: {error}")
                    });
            }
            for facet in [
                ProviderStateFacet::NativeMessage,
                ProviderStateFacet::ToolCalls,
                ProviderStateFacet::ParallelToolCalls,
                ProviderStateFacet::Reasoning,
                ProviderStateFacet::Compaction,
                ProviderStateFacet::ServerContinuation,
            ] {
                let state = native_state_for(
                    provider,
                    protocol,
                    facet,
                    ProviderNativeItemPurpose::Continuation,
                );
                let support = contract.support(facet);
                let should_round_trip = matches!(*provider, "google" | "gemini" | "ollama")
                    && matches!(
                        facet,
                        ProviderStateFacet::NativeMessage
                            | ProviderStateFacet::ToolCalls
                            | ProviderStateFacet::ParallelToolCalls
                            | ProviderStateFacet::Reasoning
                    );
                assert_eq!(
                    matches!(support, ProviderStateSupport::RoundTrip),
                    should_round_trip,
                    "provider {provider}, facet {facet:?} has the wrong continuation contract"
                );
                match support {
                    ProviderStateSupport::RoundTrip => {
                        contract.validate_state(&state).unwrap_or_else(|error| {
                            panic!("provider {provider} must round-trip {facet:?}: {error}")
                        });
                    }
                    ProviderStateSupport::EvidenceOnly => {
                        let error = contract
                            .validate_state(&state)
                            .expect_err("evidence-only facets cannot be continuation input");
                        assert!(
                            matches!(
                                error,
                                crate::runtime::ProviderStateContractError::EvidenceOnlyContinuation { .. }
                            ),
                            "provider {provider}, facet {facet:?}: {error}"
                        );
                    }
                    ProviderStateSupport::Unsupported(_) => {
                        let error = contract
                            .validate_state(&state)
                            .expect_err("unwired continuation facet must be explicit");
                        assert!(
                            matches!(
                                error,
                                crate::runtime::ProviderStateContractError::UnsupportedFacet { .. }
                            ),
                            "provider {provider}, facet {facet:?}: {error}"
                        );
                    }
                }
            }
        }
        assert_eq!(
            get_adapter("openai")
                .expect("OpenAI adapter")
                .state_contract(ProviderWireProtocol::OpenAiResponses)
                .expect("Responses contract")
                .protocol,
            ProviderWireProtocol::OpenAiResponses
        );
    }

    #[test]
    fn openai_responses_native_contract_is_stateless_and_round_trip() {
        let responses = get_adapter("openai")
            .expect("OpenAI adapter")
            .state_contract(ProviderWireProtocol::OpenAiResponses)
            .expect("Responses contract");
        for facet in [
            ProviderStateFacet::NativeMessage,
            ProviderStateFacet::ToolCalls,
            ProviderStateFacet::ParallelToolCalls,
            ProviderStateFacet::Reasoning,
            ProviderStateFacet::Compaction,
        ] {
            responses
                .validate_state(&native_state_for(
                    "openai",
                    ProviderWireProtocol::OpenAiResponses,
                    facet,
                    ProviderNativeItemPurpose::Continuation,
                ))
                .unwrap_or_else(|error| panic!("Responses must round-trip {facet:?}: {error}"));
        }
        let response_id_evidence = native_state_for(
            "openai",
            ProviderWireProtocol::OpenAiResponses,
            ProviderStateFacet::ServerContinuation,
            ProviderNativeItemPurpose::Evidence,
        );
        responses
            .validate_state(&response_id_evidence)
            .expect("stateless Responses retains response ids as evidence");
        let error = responses
            .validate_state(&native_state_for(
                "openai",
                ProviderWireProtocol::OpenAiResponses,
                ProviderStateFacet::ServerContinuation,
                ProviderNativeItemPurpose::Continuation,
            ))
            .expect_err("store:false must not claim previous_response_id replay");
        assert!(matches!(
            error,
            crate::runtime::ProviderStateContractError::EvidenceOnlyContinuation { .. }
        ));
    }

    #[test]
    fn adapter_native_state_application_is_fail_closed() {
        let adapter = get_adapter("openai").expect("OpenAI adapter");
        let mut body = json!({"model": "gpt-test", "messages": []});
        let original = body.clone();
        adapter
            .apply_provider_native_state(
                &mut body,
                &native_state(
                    ProviderStateFacet::Usage,
                    ProviderNativeItemPurpose::Evidence,
                ),
            )
            .expect("retained evidence does not become provider input");
        assert_eq!(body, original);

        let error = adapter
            .apply_provider_native_state(
                &mut body,
                &native_state(
                    ProviderStateFacet::ServerContinuation,
                    ProviderNativeItemPurpose::Continuation,
                ),
            )
            .expect_err("unwired continuation must not be ignored");
        assert!(error.to_string().contains("not wired yet"));
    }

    fn create_test_request() -> ChatCompletionRequest {
        ChatCompletionRequest {
            model: "gpt-4".to_string(),
            messages: vec![
                ChatMessage {
                    role: "system".to_string(),
                    content: MessageContent::Text("You are helpful.".to_string()),
                    name: None,
                    tool_calls: None,
                    tool_call_id: None,
                    extra: std::collections::HashMap::new(),
                },
                ChatMessage {
                    role: "user".to_string(),
                    content: MessageContent::Text("Hello!".to_string()),
                    name: None,
                    tool_calls: None,
                    tool_call_id: None,
                    extra: std::collections::HashMap::new(),
                },
            ],
            temperature: Some(0.7),
            max_tokens: Some(1000),
            stream: None,
            tools: None,
            tool_choice: None,
            extra: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn test_anthropic_transform_request() {
        let adapter = AnthropicAdapter::new();
        let request = create_test_request();
        let result = adapter.transform_request(&request).unwrap();

        assert_eq!(result["model"], "gpt-4");
        assert_eq!(result["max_tokens"], 1000);
        // Float comparison with tolerance
        let temp = result["temperature"].as_f64().unwrap();
        assert!((temp - 0.7).abs() < 0.01);

        // System should be array format with cache_control for prompt caching
        let system = result["system"].as_array().unwrap();
        assert_eq!(system.len(), 1);
        assert_eq!(system[0]["type"], "text");
        assert_eq!(system[0]["text"], "You are helpful.");
        assert_eq!(system[0]["cache_control"]["type"], "ephemeral");

        // Messages should not include system
        let messages = result["messages"].as_array().unwrap();
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], "user");
    }

    #[test]
    fn test_anthropic_transform_response() {
        let adapter = AnthropicAdapter::new();
        let response = json!({
            "id": "msg_123",
            "model": "claude-3-sonnet",
            "content": [{"type": "text", "text": "Hello!"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 10, "output_tokens": 5}
        });

        let result = adapter.transform_response(response, false).unwrap();

        assert_eq!(result["object"], "chat.completion");
        assert_eq!(result["choices"][0]["message"]["content"], "Hello!");
        assert_eq!(result["choices"][0]["finish_reason"], "stop");
    }

    #[test]
    fn test_anthropic_tool_caching() {
        // Test that tools have cache_control on the last tool
        let adapter = AnthropicAdapter::new();
        let mut request = create_test_request();
        request.tools = Some(vec![
            json!({
                "type": "function",
                "function": {
                    "name": "tool1",
                    "description": "First tool",
                    "parameters": {}
                }
            }),
            json!({
                "type": "function",
                "function": {
                    "name": "tool2",
                    "description": "Second tool",
                    "parameters": {}
                }
            }),
        ]);

        let result = adapter.transform_request(&request).unwrap();
        let tools = result["tools"].as_array().unwrap();

        assert_eq!(tools.len(), 2);

        // First tool should NOT have cache_control
        assert!(tools[0].get("cache_control").is_none());

        // Last tool SHOULD have cache_control for prompt caching
        assert_eq!(tools[1]["cache_control"]["type"], "ephemeral");
    }

    #[test]
    fn test_openai_passthrough() {
        let adapter = OpenAIAdapter::new();
        let request = create_test_request();
        let result = adapter.transform_request(&request).unwrap();

        // Should preserve original structure
        assert_eq!(result["model"], "gpt-4");
        assert!(result["messages"].is_array());
    }

    #[test]
    fn test_google_transform_request() {
        let adapter = GoogleAdapter::new();
        let request = create_test_request();
        let result = adapter.transform_request(&request).unwrap();

        assert!(result["contents"].is_array());
        assert!(result["systemInstruction"].is_object());
        // Float comparison with tolerance
        let temp = result["generationConfig"]["temperature"].as_f64().unwrap();
        assert!((temp - 0.7).abs() < 0.01);
        assert_eq!(result["generationConfig"]["maxOutputTokens"], 1000);
    }

    #[test]
    fn test_get_adapter() {
        assert_eq!(get_adapter("anthropic").unwrap().name(), "anthropic");
        assert_eq!(get_adapter("google").unwrap().name(), "google");
        assert_eq!(get_adapter("openai").unwrap().name(), "openai");
        assert_eq!(get_adapter("zai").unwrap().name(), "zai");
        assert_eq!(get_adapter("glm").unwrap().name(), "zai");
        assert_eq!(get_adapter("zhipu").unwrap().name(), "zai");
        // DeepSeek and Qwen have dedicated adapters for thinking support.
        assert_eq!(get_adapter("deepseek").unwrap().name(), "deepseek");
        assert_eq!(get_adapter("qwen").unwrap().name(), "qwen");
        assert_eq!(get_adapter("alibaba").unwrap().name(), "qwen");
        // Kimi/Moonshot and MiniMax are OpenAI-compatible, but their
        // thinking controls are provider-specific and intentionally
        // not mapped to OpenAI reasoning_effort.
        assert_eq!(get_adapter("kimi").unwrap().name(), "kimi");
        assert_eq!(get_adapter("moonshot").unwrap().name(), "kimi");
        assert_eq!(get_adapter("minimax").unwrap().name(), "minimax");
        // Ollama for local LLM inference
        assert_eq!(get_adapter("ollama").unwrap().name(), "ollama");
        // OpenAI-compatible local providers
        assert_eq!(get_adapter("local").unwrap().name(), "openai");
        assert_eq!(get_adapter("lmstudio").unwrap().name(), "openai");
        assert_eq!(get_adapter("localai").unwrap().name(), "openai");
        assert_eq!(get_adapter("openrouter").unwrap().name(), "openai");
        assert_eq!(get_adapter("opencode").unwrap().name(), "openai");
        assert_eq!(get_adapter("opencode-go").unwrap().name(), "openai");
        assert_eq!(get_adapter("openai-compatible").unwrap().name(), "openai");
        // Crosslink #433: unknown names are now an explicit error, NOT a
        // silent OpenAI fallback. See `get_adapter_unknown_provider_*`
        // tests below for the full forensic pin.
        assert!(get_adapter("unknown").is_err());
    }

    #[test]
    fn test_ollama_adapter() {
        let adapter = OllamaAdapter::new();
        assert_eq!(adapter.name(), "ollama");
        assert_eq!(adapter.chat_endpoint("llama3"), "/api/chat");
    }

    #[test]
    fn test_ollama_transform_request() {
        let adapter = OllamaAdapter::new();
        let request = create_test_request();
        let result = adapter.transform_request(&request).unwrap();

        assert_eq!(result["model"], "gpt-4");
        assert!(result["messages"].is_array());
        // Ollama uses "options" for settings
        let temp = result["options"]["temperature"].as_f64().unwrap();
        assert!((temp - 0.7).abs() < 0.01);
        assert_eq!(result["options"]["num_predict"], 1000);
    }

    #[test]
    fn test_ollama_transform_response() {
        let adapter = OllamaAdapter::new();
        let response = json!({
            "model": "llama3",
            "message": {
                "role": "assistant",
                "content": "Hello from Ollama!"
            },
            "done": true,
            "prompt_eval_count": 10,
            "eval_count": 5
        });

        let result = adapter.transform_response(response, false).unwrap();
        assert_eq!(result["object"], "chat.completion");
        assert_eq!(result["model"], "llama3");
        assert_eq!(
            result["choices"][0]["message"]["content"],
            "Hello from Ollama!"
        );
        assert_eq!(result["choices"][0]["finish_reason"], "stop");
        assert_eq!(result["usage"]["prompt_tokens"], 10);
        assert_eq!(result["usage"]["completion_tokens"], 5);
    }

    #[test]
    fn test_zai_adapter() {
        let adapter = ZaiAdapter::new();
        assert_eq!(adapter.name(), "zai");
        // Z.AI uses /chat/completions without /v1/ prefix
        assert_eq!(adapter.chat_endpoint("glm-4"), "/chat/completions");
    }

    #[test]
    fn test_zai_transform_request() {
        let adapter = ZaiAdapter::new();
        let request = create_test_request();
        let result = adapter.transform_request(&request).unwrap();

        // Should preserve OpenAI-compatible structure
        assert_eq!(result["model"], "gpt-4");
        assert!(result["messages"].is_array());
    }

    #[test]
    fn test_provider_error_variants() {
        // Test InvalidResponse variant
        let err = ProviderError::InvalidResponse("missing field".to_string());
        assert!(err.to_string().contains("missing field"));

        // Test Unsupported variant
        let err = ProviderError::Unsupported("streaming not available".to_string());
        assert!(err.to_string().contains("streaming"));

        // Test RequestFailed variant
        let err = ProviderError::RequestFailed("connection refused".to_string());
        assert!(err.to_string().contains("connection"));
    }

    #[test]
    fn parse_models_response_accepts_valid_openai_style_list() {
        let body = json!({
            "object": "list",
            "data": [
                {"id": "gpt-4.1", "owned_by": "openai", "created": 1_735_689_600},
                {"id": "local-model"}
            ]
        });

        let models = parse_models_response(&body).expect("valid model list should parse");

        assert_eq!(models.len(), 2);
        assert_eq!(models[0].id, "gpt-4.1");
        assert_eq!(models[0].owned_by.as_deref(), Some("openai"));
        assert_eq!(models[0].created, Some(1_735_689_600));
        assert_eq!(models[1].id, "local-model");
        assert_eq!(models[1].owned_by, None);
        assert_eq!(models[1].created, None);
    }

    #[test]
    fn parse_models_response_rejects_missing_data_array() {
        let err = parse_models_response(&json!({"object": "list"}))
            .expect_err("missing data array must be invalid");

        match err {
            ProviderError::InvalidResponse(msg) => assert!(msg.contains("'data' array"), "{msg}"),
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn parse_models_response_rejects_model_missing_id() {
        let body = json!({
            "data": [
                {"id": "good"},
                {"owned_by": "provider"}
            ]
        });
        let err = parse_models_response(&body).expect_err("missing model id must be invalid");

        match err {
            ProviderError::InvalidResponse(msg) => {
                assert!(msg.contains("entry 1"), "{msg}");
                assert!(msg.contains("'id'"), "{msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn parse_models_response_rejects_model_empty_id() {
        let body = json!({"data": [{"id": ""}]});
        let err = parse_models_response(&body).expect_err("empty model id must be invalid");

        match err {
            ProviderError::InvalidResponse(msg) => {
                assert!(msg.contains("entry 0"), "{msg}");
                assert!(msg.contains("'id'"), "{msg}");
            }
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[test]
    fn parse_models_response_rejects_malformed_optional_fields() {
        let bad_owner = parse_models_response(&json!({
            "data": [{"id": "m", "owned_by": 123}]
        }))
        .expect_err("non-string owned_by must be invalid");
        match bad_owner {
            ProviderError::InvalidResponse(msg) => assert!(msg.contains("owned_by"), "{msg}"),
            other => panic!("expected InvalidResponse, got {other:?}"),
        }

        let bad_created = parse_models_response(&json!({
            "data": [{"id": "m", "created": "yesterday"}]
        }))
        .expect_err("non-integer created must be invalid");
        match bad_created {
            ProviderError::InvalidResponse(msg) => assert!(msg.contains("created"), "{msg}"),
            other => panic!("expected InvalidResponse, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fetch_models_with_headers_preserves_versioned_provider_roots() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");
            let mut buf = [0_u8; 4096];
            let read = stream.read(&mut buf).expect("read request");
            let request = String::from_utf8_lossy(&buf[..read]).to_ascii_lowercase();
            assert!(
                request.starts_with("get /api/v1/models "),
                "request used unexpected path:\n{request}"
            );
            assert!(
                request.contains("authorization: bearer sk-test-model-key"),
                "request missing bearer auth:\n{request}"
            );
            assert!(
                request.contains("x-custom-route: test-value"),
                "request missing custom header:\n{request}"
            );

            let body =
                r#"{"object":"list","has_more":true,"data":[{"id":"openrouter/test-model"}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        });

        let key = ApiKey::try_from_string("sk-test-model-key".to_string()).expect("valid key");
        let mut headers = SensitiveHeaders::new();
        headers
            .insert_literal("X-Custom-Route", "test-value".to_string())
            .expect("valid custom header");
        let models = fetch_models_with_headers_for_test(
            &format!("http://{addr}/api/v1"),
            Some(&key),
            &headers,
            &OPENAI,
        )
        .await
        .expect("model list should fetch");

        server.join().expect("server thread must finish");
        assert_eq!(models.len(), 1);
        assert_eq!(models[0].id, "openrouter/test-model");
    }

    #[tokio::test]
    async fn fetch_models_uses_the_adapter_auth_headers() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::time::Duration;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        let addr = listener.local_addr().expect("local addr");
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("set read timeout");
            let mut buf = [0_u8; 4096];
            let read = stream.read(&mut buf).expect("read request");
            let request = String::from_utf8_lossy(&buf[..read]).to_ascii_lowercase();
            assert!(
                request.contains("x-api-key: model-list-key"),
                "request missing adapter auth header:\n{request}"
            );
            assert!(
                !request.contains("authorization:"),
                "request incorrectly assumed bearer auth:\n{request}"
            );

            let body = r#"{"object":"list","data":[{"id":"test-model"}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .expect("write response");
        });

        let key = ApiKey::try_from_string("model-list-key".to_string()).expect("valid key");
        let models = fetch_models_with_headers_for_test(
            &format!("http://{addr}"),
            Some(&key),
            &SensitiveHeaders::new(),
            &ApiKeyHeaderModelAdapter,
        )
        .await
        .expect("model list should fetch");

        server.join().expect("server thread must finish");
        assert_eq!(models[0].id, "test-model");
    }

    #[tokio::test]
    async fn native_google_catalog_discovery_uses_gemini_shape_and_auth() {
        use wiremock::matchers::{header, method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1beta/models"))
            .and(query_param("pageSize", "1000"))
            .and(header("x-goog-api-key", "google-model-key"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "models": [{
                    "name": "models/gemini-live",
                    "inputTokenLimit": 1_048_576,
                    "outputTokenLimit": 65536,
                    "supportedGenerationMethods": ["generateContent"]
                }],
                "nextPageToken": "more"
            })))
            .mount(&server)
            .await;

        let key = ApiKey::try_from_string("google-model-key".to_string()).expect("valid key");
        let snapshot = discover_model_catalog_impl(
            "google",
            &server.uri(),
            Some(&key),
            &SensitiveHeaders::new(),
            &GOOGLE,
            false,
        )
        .await
        .expect("Gemini model discovery");
        assert_eq!(snapshot.models[0].canonical_id, "gemini-live");
        assert_eq!(
            snapshot.models[0].capabilities.input_context_tokens,
            Some(1_048_576)
        );
        assert!(!snapshot.complete);
    }

    #[tokio::test]
    async fn native_anthropic_catalog_discovery_uses_models_shape() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/models"))
            .and(query_param("limit", "1000"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": [{
                    "id": "claude-live",
                    "display_name": "Claude Live",
                    "created_at": "2026-08-22T00:00:00Z",
                    "max_input_tokens": 1_000_000,
                    "max_tokens": 128_000
                }],
                "has_more": true
            })))
            .mount(&server)
            .await;

        let key = ApiKey::try_from_string("anthropic-model-key".to_string()).expect("valid key");
        let snapshot = discover_model_catalog_impl(
            "anthropic",
            &server.uri(),
            Some(&key),
            &SensitiveHeaders::new(),
            &ANTHROPIC,
            false,
        )
        .await
        .expect("Anthropic model discovery");
        assert_eq!(snapshot.models[0].canonical_id, "claude-live");
        assert_eq!(snapshot.models[0].access, ModelAccessState::Available);
        assert!(!snapshot.complete);
    }

    #[tokio::test]
    async fn native_ollama_catalog_discovery_uses_installed_tags() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/tags"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "models": [{"name": "local-model:latest"}]
            })))
            .mount(&server)
            .await;

        let snapshot = discover_model_catalog_with_headers(
            &server.uri(),
            None,
            &SensitiveHeaders::new(),
            &OLLAMA,
        )
        .await
        .expect("Ollama model discovery");
        assert_eq!(snapshot.models[0].canonical_id, "local-model:latest");
        assert_eq!(snapshot.models[0].access, ModelAccessState::Available);
    }

    #[test]
    fn test_openai_transform_response() {
        let adapter = OpenAIAdapter::new();
        let response = json!({
            "id": "chatcmpl-123",
            "object": "chat.completion",
            "choices": [{
                "message": {"role": "assistant", "content": "Hello!"},
                "finish_reason": "stop"
            }]
        });

        let result = adapter.transform_response(response.clone(), false).unwrap();
        // OpenAI adapter passes through unchanged
        assert_eq!(result, response);
    }

    #[test]
    fn test_google_transform_response() {
        let adapter = GoogleAdapter::new();
        let response = json!({
            "candidates": [{
                "content": {
                    "parts": [{"text": "Hello from Gemini!"}],
                    "role": "model"
                },
                "finishReason": "STOP"
            }],
            "usageMetadata": {
                "promptTokenCount": 10,
                "candidatesTokenCount": 5,
                "totalTokenCount": 15
            }
        });

        let result = adapter.transform_response(response, false).unwrap();
        assert_eq!(result["object"], "chat.completion");
        assert_eq!(
            result["choices"][0]["message"]["content"],
            "Hello from Gemini!"
        );
        assert_eq!(result["choices"][0]["finish_reason"], "stop");
    }

    #[test]
    fn test_google_transform_response_no_candidates() {
        let adapter = GoogleAdapter::new();
        let response = json!({"candidates": []});

        let result = adapter.transform_response(response, false);
        assert!(matches!(result, Err(ProviderError::InvalidResponse(_))));
    }

    #[test]
    fn test_convert_tool_result_with_error_flag() {
        let messages = vec![
            json!({"role": "user", "content": "test"}),
            json!({
                "role": "assistant",
                "content": "Let me try.",
                "tool_calls": [{"id": "t1", "type": "function", "function": {"name": "bash", "arguments": "{\"command\":\"ls\"}"}}]
            }),
            json!({"role": "tool", "tool_call_id": "t1", "content": "[ERROR] command not found", "is_error": true}),
        ];
        let result = convert_messages_to_anthropic(&messages);
        // result[0]=user, result[1]=assistant+tool_use, result[2]=user+tool_result
        assert_eq!(result.len(), 3);
        let tool_msg = &result[2];
        assert_eq!(tool_msg["role"], "user");
        let content = tool_msg["content"].as_array().unwrap();
        assert_eq!(content[0]["type"], "tool_result");
        assert_eq!(content[0]["is_error"], true);
    }

    // ── Crosslink #332: ProviderKind typed dispatch ─────────────────────────

    #[test]
    fn provider_kind_name_round_trip() {
        assert_eq!(ProviderKind::Anthropic.name(), "anthropic");
        assert_eq!(ProviderKind::OpenAI.name(), "openai");
        assert_eq!(ProviderKind::Google.name(), "google");
        assert_eq!(ProviderKind::DeepSeek.name(), "deepseek");
        assert_eq!(ProviderKind::Qwen.name(), "qwen");
        assert_eq!(ProviderKind::Zai.name(), "zai");
        assert_eq!(ProviderKind::Kimi.name(), "kimi");
        assert_eq!(ProviderKind::MiniMax.name(), "minimax");
        assert_eq!(ProviderKind::Unknown.name(), "unknown");
        for kind in [
            ProviderKind::Anthropic,
            ProviderKind::OpenAI,
            ProviderKind::Google,
            ProviderKind::DeepSeek,
            ProviderKind::Qwen,
            ProviderKind::Zai,
            ProviderKind::Kimi,
            ProviderKind::MiniMax,
        ] {
            let adapter = get_adapter(kind.name()).expect("known provider");
            assert_eq!(
                adapter.name(),
                kind.name(),
                "adapter name drift for {kind:?}"
            );
        }
    }

    #[test]
    fn provider_kind_from_model_known_prefixes() {
        assert_eq!(
            ProviderKind::from_model("claude-opus-4"),
            ProviderKind::Anthropic
        );
        assert_eq!(
            ProviderKind::from_model("claude-fable-5"),
            ProviderKind::Anthropic
        );
        assert_eq!(
            ProviderKind::from_model("claude-mythos-5"),
            ProviderKind::Anthropic
        );
        assert_eq!(
            ProviderKind::from_model("anthropic/claude-3"),
            ProviderKind::Anthropic
        );
        assert_eq!(ProviderKind::from_model("gpt-4o"), ProviderKind::OpenAI);
        assert_eq!(ProviderKind::from_model("gpt-5.5"), ProviderKind::OpenAI);
        assert_eq!(
            ProviderKind::from_model("gpt-5.4-mini"),
            ProviderKind::OpenAI
        );
        assert_eq!(
            ProviderKind::from_model("chat-latest"),
            ProviderKind::OpenAI
        );
        assert_eq!(
            ProviderKind::from_model("codex-mini-latest"),
            ProviderKind::OpenAI
        );
        assert_eq!(ProviderKind::from_model("o1-preview"), ProviderKind::OpenAI);
        assert_eq!(ProviderKind::from_model("o3-mini"), ProviderKind::OpenAI);
        assert_eq!(ProviderKind::from_model("o4-pro"), ProviderKind::OpenAI);
        assert_eq!(
            ProviderKind::from_model("gemini-2.5-pro"),
            ProviderKind::Google
        );
        assert_eq!(
            ProviderKind::from_model("gemini-3.5-flash"),
            ProviderKind::Google
        );
        assert_eq!(
            ProviderKind::from_model("deepseek-r1"),
            ProviderKind::DeepSeek
        );
        assert_eq!(
            ProviderKind::from_model("deepseek-v4-pro"),
            ProviderKind::DeepSeek
        );
        assert_eq!(ProviderKind::from_model("qwen-long"), ProviderKind::Qwen);
        assert_eq!(ProviderKind::from_model("qwen3.7-plus"), ProviderKind::Qwen);
        assert_eq!(ProviderKind::from_model("qwq-32b"), ProviderKind::Qwen);
        assert_eq!(ProviderKind::from_model("qvq-72b"), ProviderKind::Qwen);
        assert_eq!(ProviderKind::from_model("glm-4"), ProviderKind::Zai);
        assert_eq!(ProviderKind::from_model("GLM-5.2"), ProviderKind::Zai);
        assert_eq!(
            ProviderKind::from_model("kimi-k2.7-code"),
            ProviderKind::Kimi
        );
        assert_eq!(
            ProviderKind::from_model("kimi-k2.7-code-highspeed"),
            ProviderKind::Kimi
        );
        assert_eq!(
            ProviderKind::from_model("moonshot-v1-128k"),
            ProviderKind::Kimi
        );
        assert_eq!(
            ProviderKind::from_model("MiniMax-M3"),
            ProviderKind::MiniMax
        );
        assert_eq!(ProviderKind::from_model("M2-her"), ProviderKind::MiniMax);
    }

    #[test]
    fn provider_kind_from_model_unknown_returns_unknown_variant() {
        assert_eq!(
            ProviderKind::from_model("some-unknown-model-xyz"),
            ProviderKind::Unknown
        );
        assert_eq!(
            ProviderKind::from_model("mistral-large"),
            ProviderKind::Unknown
        );
        assert_eq!(ProviderKind::from_model(""), ProviderKind::Unknown);
    }

    #[test]
    fn provider_kind_from_model_is_case_insensitive() {
        assert_eq!(
            ProviderKind::from_model("CLAUDE-3-OPUS"),
            ProviderKind::Anthropic
        );
        assert_eq!(ProviderKind::from_model("GPT-4"), ProviderKind::OpenAI);
        assert_eq!(ProviderKind::from_model("Gemini-Pro"), ProviderKind::Google);
    }

    #[test]
    fn provider_kind_from_model_no_false_positive_on_o_prefix() {
        assert_eq!(ProviderKind::from_model("o100"), ProviderKind::Unknown);
        assert_eq!(
            ProviderKind::from_model("observer-1"),
            ProviderKind::Unknown
        );
        assert_eq!(ProviderKind::from_model("o1"), ProviderKind::OpenAI);
        assert_eq!(ProviderKind::from_model("o3"), ProviderKind::OpenAI);
    }

    #[test]
    fn test_convert_tool_result_without_error_flag() {
        let messages = vec![
            json!({"role": "user", "content": "test"}),
            json!({
                "role": "assistant",
                "content": serde_json::Value::Null,
                "tool_calls": [{"id": "t2", "type": "function", "function": {"name": "read_file", "arguments": "{\"path\":\"a.rs\"}"}}]
            }),
            json!({"role": "tool", "tool_call_id": "t2", "content": "file contents here"}),
        ];
        let result = convert_messages_to_anthropic(&messages);
        assert_eq!(result.len(), 3);
        let tool_msg = &result[2];
        let content = tool_msg["content"].as_array().unwrap();
        assert_eq!(content[0]["type"], "tool_result");
        // is_error should not be present for successful results
        assert!(content[0].get("is_error").is_none());
    }

    // ── Crosslink #479: ProviderAdapter response-text / token-usage ─────────
    //
    // These methods replaced the free functions in `src/vdd/parsing.rs` that
    // hardcoded OpenAI/Anthropic/Gemini response shapes and silently returned
    // empty defaults for any other provider. The tests below pin the new
    // contract: each adapter understands its OWN native response shape, and
    // unsupported providers fall back to the trait default (OpenAI shape).

    #[test]
    fn anthropic_extract_response_text_reads_native_content_blocks() {
        let adapter = AnthropicAdapter::new();
        let response = json!({
            "content": [
                {"type": "text", "text": "hello from Claude"},
                {"type": "tool_use", "id": "tu_1", "name": "x", "input": {}}
            ]
        });
        assert_eq!(
            adapter.extract_response_text(&response),
            Some("hello from Claude".to_string())
        );
    }

    #[test]
    fn anthropic_extract_token_usage_reads_native_envelope_with_cache() {
        let adapter = AnthropicAdapter::new();
        let response = json!({
            "usage": {
                "input_tokens": 123,
                "output_tokens": 45,
                "cache_read_input_tokens": 17,
                "cache_creation_input_tokens": 8
            }
        });
        let usage = adapter
            .extract_token_usage(&response)
            .expect("usage present");
        assert_eq!(usage.input_tokens, 123);
        assert_eq!(usage.output_tokens, 45);
        assert_eq!(usage.cache_read_tokens, 17);
        assert_eq!(usage.cache_write_tokens, 8);
    }

    #[test]
    fn google_extract_response_text_concatenates_parts() {
        let adapter = GoogleAdapter::new();
        let response = json!({
            "candidates": [{
                "content": {
                    "parts": [
                        {"text": "hello "},
                        {"text": "from Gemini"}
                    ]
                }
            }]
        });
        assert_eq!(
            adapter.extract_response_text(&response),
            Some("hello from Gemini".to_string())
        );
    }

    #[test]
    fn google_extract_token_usage_reads_usage_metadata() {
        let adapter = GoogleAdapter::new();
        let response = json!({
            "usageMetadata": {
                "promptTokenCount": 200,
                "candidatesTokenCount": 90,
                "cachedContentTokenCount": 30
            }
        });
        let usage = adapter
            .extract_token_usage(&response)
            .expect("usage present");
        assert_eq!(usage.input_tokens, 200);
        assert_eq!(usage.output_tokens, 90);
        assert_eq!(usage.cache_read_tokens, 30);
        assert_eq!(usage.cache_write_tokens, 0);
    }

    #[test]
    fn ollama_extract_response_text_reads_message_content() {
        let adapter = OllamaAdapter::new();
        let response = json!({
            "model": "llama3",
            "message": {"role": "assistant", "content": "hi from Ollama"},
            "done": true
        });
        assert_eq!(
            adapter.extract_response_text(&response),
            Some("hi from Ollama".to_string())
        );
    }

    #[test]
    fn ollama_extract_token_usage_reads_top_level_counters() {
        let adapter = OllamaAdapter::new();
        let response = json!({
            "prompt_eval_count": 22,
            "eval_count": 11
        });
        let usage = adapter
            .extract_token_usage(&response)
            .expect("usage present");
        assert_eq!(usage.input_tokens, 22);
        assert_eq!(usage.output_tokens, 11);
        // Ollama has no cache layer
        assert_eq!(usage.cache_read_tokens, 0);
        assert_eq!(usage.cache_write_tokens, 0);
    }

    /// The default trait impl reads the `OpenAI` Chat Completions shape.
    /// `DeepSeek`/`Qwen`/Z.AI all share that shape so they now succeed
    /// where the old hand-rolled extractor would also have succeeded — but
    /// any *future* OpenAI-compatible provider added to `get_adapter` will
    /// keep working without VDD-specific patches.
    #[test]
    fn deepseek_extract_response_text_via_default_openai_shape() {
        let adapter = DeepSeekAdapter::new();
        let response = json!({
            "choices": [{"message": {"content": "deepseek reply"}}]
        });
        assert_eq!(
            adapter.extract_response_text(&response),
            Some("deepseek reply".to_string())
        );
    }

    #[test]
    fn qwen_extract_token_usage_via_default_openai_shape() {
        let adapter = QwenAdapter::new();
        let response = json!({
            "usage": {"prompt_tokens": 7, "completion_tokens": 3}
        });
        let usage = adapter
            .extract_token_usage(&response)
            .expect("usage present");
        assert_eq!(usage.input_tokens, 7);
        assert_eq!(usage.output_tokens, 3);
    }

    #[test]
    fn openai_extract_token_usage_splits_cached_prompt_details() {
        let adapter = OpenAIAdapter::new();
        let response = json!({
            "usage": {
                "prompt_tokens": 300_000,
                "completion_tokens": 12_000,
                "prompt_tokens_details": {"cached_tokens": 125_000}
            }
        });
        let usage = adapter
            .extract_token_usage(&response)
            .expect("usage present");
        assert_eq!(
            usage.input_tokens, 175_000,
            "OpenAI prompt_tokens includes cached tokens; cost input must keep only uncached tokens"
        );
        assert_eq!(usage.output_tokens, 12_000);
        assert_eq!(usage.cache_read_tokens, 125_000);
        assert_eq!(usage.cache_write_tokens, 0);
    }

    /// A response with NO recognisable usage envelope must return `None`,
    /// not silently fabricate a zero-token record. Forces callers to make
    /// a conscious choice (e.g. `.unwrap_or_default()`).
    #[test]
    fn extract_token_usage_returns_none_for_unknown_shape() {
        let adapter = GoogleAdapter::new();
        let response = json!({"unrelated": "payload"});
        assert!(adapter.extract_token_usage(&response).is_none());

        let adapter = OllamaAdapter::new();
        let response = json!({"message": {"content": "x"}}); // no counters
        assert!(adapter.extract_token_usage(&response).is_none());
    }

    /// A response with NO recognisable text content must return `None` —
    /// callers see the absence rather than an empty string sentinel.
    #[test]
    fn extract_response_text_returns_none_for_unknown_shape() {
        let adapter = AnthropicAdapter::new();
        let response = json!({"id": "msg_1", "model": "x"});
        assert!(adapter.extract_response_text(&response).is_none());

        let adapter = OllamaAdapter::new();
        let response = json!({"model": "llama3"});
        assert!(adapter.extract_response_text(&response).is_none());
    }

    // ── Crosslink #433: static dispatch + explicit UnknownProvider ──────────
    //
    // These tests pin the contract enforced by the refactor:
    //
    //   1. `get_adapter` returns a `&'static dyn ProviderAdapter`, so two
    //      calls for the same name return the **same** pointer. The previous
    //      `Box<dyn ProviderAdapter>` allocation produced a distinct heap
    //      address per call (one allocation per request on the proxy hot
    //      path, see `proxy_chat_completions`).
    //   2. Lookup is case-insensitive — `get_adapter("OpenAI")` must
    //      resolve, matching the pre-refactor behaviour where
    //      `provider.to_lowercase()` was applied before matching.
    //   3. Unknown names return `Err(UnknownProvider)`. They do NOT silently
    //      fall back to `OpenAIAdapter`. The error carries the typo'd name
    //      AND the supported list so the proxy can render a useful 400.
    //   4. Every known name registered in the dispatch table round-trips
    //      via `.name()` to its expected canonical adapter name. This
    //      catches drift between aliases (`"glm"` → `"zai"`) and the
    //      adapter's own self-reported name.

    /// Same pointer across calls — proves the static-singleton refactor.
    /// Under the old `Box::new(...)` implementation this would have been
    /// two distinct heap addresses; under the new `&'static` return type
    /// the address is constant for the lifetime of the process.
    #[test]
    fn get_adapter_returns_same_pointer_across_calls() {
        let a = get_adapter("anthropic").expect("known");
        let b = get_adapter("anthropic").expect("known");
        assert!(
            std::ptr::eq(
                std::ptr::from_ref::<dyn ProviderAdapter>(a).cast::<()>(),
                std::ptr::from_ref::<dyn ProviderAdapter>(b).cast::<()>(),
            ),
            "expected the same static instance on repeated calls"
        );
    }

    /// Case-insensitive lookup — preserves the pre-refactor behaviour
    /// (`provider.to_lowercase()` before matching).
    #[test]
    fn get_adapter_is_case_insensitive() {
        assert_eq!(get_adapter("OpenAI").unwrap().name(), "openai");
        assert_eq!(get_adapter("ANTHROPIC").unwrap().name(), "anthropic");
        assert_eq!(get_adapter("Gemini").unwrap().name(), "google");
        assert_eq!(get_adapter("DeepSeek").unwrap().name(), "deepseek");
    }

    /// Typo'd names surface as an explicit `UnknownProvider` error — NOT a
    /// silent `OpenAIAdapter` fallback. Forensic pin: the previous
    /// implementation emitted `tracing::warn!` and returned `OpenAIAdapter`,
    /// so a config typo like `proxy.target: "anthrpic"` would silently
    /// route Anthropic-formatted requests to an `OpenAI` endpoint, billing
    /// the wrong account and producing 4xx responses with confusing causes.
    #[test]
    fn get_adapter_unknown_provider_returns_explicit_error() {
        let result = get_adapter("anthrpic"); // common typo
        match result {
            Err(ProviderError::UnknownProvider { name, supported }) => {
                assert_eq!(name, "anthrpic");
                // The hint must list at least the known canonical names so
                // the caller can surface a helpful diagnostic.
                assert!(supported.contains(&"anthropic"));
                assert!(supported.contains(&"openai"));
                assert!(supported.contains(&"google"));
            }
            Err(other) => panic!("expected UnknownProvider, got {other:?}"),
            Ok(adapter) => panic!(
                "expected UnknownProvider error, got silent fallback to '{}'",
                adapter.name()
            ),
        }

        // Same assertion via a separate typo and the error's `Display`
        // impl — the rendered message must mention the bad name and at
        // least one supported provider. We can't use `.unwrap_err()`
        // because the `Ok` branch holds `&dyn ProviderAdapter` which is
        // not `Debug`, so destructure explicitly.
        let rendered = match get_adapter("typo-provider") {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected UnknownProvider error for 'typo-provider'"),
        };
        assert!(rendered.contains("typo-provider"));
        assert!(rendered.contains("anthropic"));
    }

    /// Round-trip: every name registered in the dispatch table resolves to
    /// an adapter whose `.name()` matches the canonical name for that
    /// family. Aliases (`"glm"` → `"zai"`, `"gemini"` → `"google"`) are
    /// included because the previous bug would not have caught alias
    /// drift either.
    #[test]
    fn get_adapter_known_names_round_trip_via_name() {
        let cases: &[(&str, &str)] = &[
            ("anthropic", "anthropic"),
            ("openai", "openai"),
            ("google", "google"),
            ("gemini", "google"),
            ("deepseek", "deepseek"),
            ("qwen", "qwen"),
            ("alibaba", "qwen"),
            ("zai", "zai"),
            ("glm", "zai"),
            ("zhipu", "zai"),
            ("kimi", "kimi"),
            ("moonshot", "kimi"),
            ("minimax", "minimax"),
            ("ollama", "ollama"),
            ("local", "openai"),
            ("lmstudio", "openai"),
            ("localai", "openai"),
            ("text-generation-webui", "openai"),
            ("openrouter", "openai"),
            ("opencode", "openai"),
            ("opencode-go", "openai"),
            ("openai-compatible", "openai"),
        ];
        for (input, expected) in cases {
            let adapter = get_adapter(input)
                .unwrap_or_else(|e| panic!("'{input}' should be a known provider but got: {e}"));
            assert_eq!(
                adapter.name(),
                *expected,
                "alias '{input}' resolved to wrong adapter"
            );
        }
    }

    /// Every name listed in [`SUPPORTED_PROVIDERS`] must itself be a
    /// resolvable name. Guards against drift between the dispatch table
    /// and the hint list inside the error.
    #[test]
    fn supported_providers_list_matches_dispatch_table() {
        for name in SUPPORTED_PROVIDERS {
            assert!(
                get_adapter(name).is_ok(),
                "name '{name}' appears in SUPPORTED_PROVIDERS but \
                 get_adapter rejects it"
            );
        }
    }

    #[test]
    fn default_model_lookup_is_case_insensitive() {
        assert_eq!(
            default_model_for_target("Anthropic"),
            default_model_for_target("anthropic")
        );
        assert_eq!(
            default_model_for_target("  GEMINI  "),
            default_model_for_target("gemini")
        );
    }

    #[test]
    fn api_key_env_var_lookup_is_case_insensitive() {
        assert_eq!(api_key_env_var_for_target("OpenAI"), "OPENAI_API_KEY");
        assert_eq!(
            api_key_env_var_for_target("  MOONSHOT  "),
            "KIMI_API_KEY or MOONSHOT_API_KEY"
        );
        assert_eq!(
            api_key_env_var_for_target("OpenRouter"),
            "OPENROUTER_API_KEY or OPEN_ROUTER_API_KEY"
        );
        assert_eq!(
            api_key_env_var_for_target("opencode-go"),
            "OPENCODE_API_KEY or OPENCODE_GO_API_KEY"
        );
        assert_eq!(
            api_key_env_var_for_target("gemini"),
            "GOOGLE_API_KEY or GEMINI_API_KEY"
        );
        assert_eq!(
            api_key_env_var_for_target("alibaba"),
            "QWEN_API_KEY, DASHSCOPE_API_KEY, or ALIYUN_API_KEY"
        );
        assert_eq!(
            api_key_env_var_for_target("openai-compatible"),
            "OPENAI_COMPATIBLE_API_KEY or API_KEY"
        );
        assert_eq!(api_key_env_var_for_target("unknown"), "API_KEY");
    }
}
