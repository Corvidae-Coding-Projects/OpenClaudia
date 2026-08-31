//! Typed provider model discovery, capability evidence, and emergency fallback.
//!
//! Provider APIs are the authority for account access and for every metadata
//! field they actually return. The bundled manifest is deliberately small,
//! dated, and short-lived: it keeps a fresh installation usable when discovery
//! is temporarily unavailable without turning model-name substrings into
//! capabilities.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, VecDeque};
use std::sync::{OnceLock, RwLock};

/// Version of the bundled emergency manifest schema and contents.
pub const FALLBACK_CATALOG_VERSION: &str = "2026-08-22.v1";
/// UTC timestamp at which the bundled evidence was verified.
pub const FALLBACK_VERIFIED_AT_UNIX: i64 = 1_787_356_800;
/// Bundled evidence cannot enable optional features after this age.
pub const FALLBACK_MAX_AGE_SECONDS: i64 = 30 * 24 * 60 * 60;
/// Authenticated discovery snapshots are refreshed after six hours.
pub const DISCOVERY_TTL_SECONDS: i64 = 6 * 60 * 60;
/// Bound process-local cache growth across custom provider endpoints.
const MAX_CACHED_SNAPSHOTS: usize = 64;
/// Bound one provider snapshot even if an upstream returns an absurd list.
pub const MAX_MODELS_PER_SNAPSHOT: usize = 2_048;

/// Whether evidence proves that a model supports a feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelSupport {
    Supported,
    Unsupported,
    Unknown,
}

impl ModelSupport {
    fn fill_unknown_from(&mut self, fallback: Self) {
        if *self == Self::Unknown {
            *self = fallback;
        }
    }
}

/// Account-scoped availability of a model selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelAccessState {
    Available,
    Limited,
    Unavailable,
    Unknown,
}

/// Provider lifecycle state, separate from account access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelLifecycle {
    Active,
    Preview,
    Deprecated,
    Retired,
    Unknown,
}

/// Whether cost calculation has attributable model pricing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelPricingState {
    Known,
    Unknown,
    NotApplicable,
}

/// Exact request-control family for provider reasoning.
///
/// This is intentionally not inferred from arbitrary model substrings. It is
/// populated only by provider metadata or a fresh exact fallback entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasoningProfile {
    None,
    Unknown,
    AnthropicManual,
    AnthropicAdaptive,
    OpenAiEffort,
    GeminiThinking,
    DeepSeekThinking,
    QwenThinking,
    GlmThinking,
    GlmThinkingWithEffort,
    KimiAlways,
    KimiToggle,
    MiniMaxAdaptive,
    OllamaThinking,
}

/// Model behavior that can be validated before request construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelCapabilities {
    pub chat: ModelSupport,
    pub tools: ModelSupport,
    pub streaming: ModelSupport,
    pub thinking: ModelSupport,
    pub reasoning_profile: ReasoningProfile,
    pub input_context_tokens: Option<u64>,
    pub max_output_tokens: Option<u64>,
    pub pricing: ModelPricingState,
}

impl ModelCapabilities {
    /// No capability claim can be made from the available evidence.
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            chat: ModelSupport::Unknown,
            tools: ModelSupport::Unknown,
            streaming: ModelSupport::Unknown,
            thinking: ModelSupport::Unknown,
            reasoning_profile: ReasoningProfile::Unknown,
            input_context_tokens: None,
            max_output_tokens: None,
            pricing: ModelPricingState::Unknown,
        }
    }

    fn fill_unknown_from(&mut self, fallback: &Self) {
        self.chat.fill_unknown_from(fallback.chat);
        self.tools.fill_unknown_from(fallback.tools);
        self.streaming.fill_unknown_from(fallback.streaming);
        self.thinking.fill_unknown_from(fallback.thinking);
        if self.reasoning_profile == ReasoningProfile::Unknown {
            self.reasoning_profile = fallback.reasoning_profile;
        }
        if self.input_context_tokens.is_none() {
            self.input_context_tokens = fallback.input_context_tokens;
        }
        if self.max_output_tokens.is_none() {
            self.max_output_tokens = fallback.max_output_tokens;
        }
        if self.pricing == ModelPricingState::Unknown {
            self.pricing = fallback.pricing;
        }
    }
}

impl Default for ModelCapabilities {
    fn default() -> Self {
        Self::unknown()
    }
}

/// Origin of model access or capability evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelEvidenceSource {
    ProviderApi,
    EmergencyFallback,
}

/// Wire shape returned by a provider's model-discovery endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelCatalogFormat {
    OpenAi,
    Anthropic,
    Gemini,
    Ollama,
}

/// Dated evidence attached to a model snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelCatalogProvenance {
    pub source: ModelEvidenceSource,
    pub provider: String,
    pub endpoint: Option<String>,
    pub schema_version: String,
    pub observed_at_unix: i64,
    pub expires_at_unix: i64,
}

impl ModelCatalogProvenance {
    #[must_use]
    pub const fn is_fresh_at(&self, now_unix: i64) -> bool {
        now_unix <= self.expires_at_unix
    }
}

/// One canonical selectable model and its exact aliases.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelCatalogEntry {
    pub canonical_id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub owned_by: Option<String>,
    #[serde(default)]
    pub created: Option<i64>,
    pub access: ModelAccessState,
    pub lifecycle: ModelLifecycle,
    #[serde(default)]
    pub retirement_date: Option<String>,
    pub capabilities: ModelCapabilities,
}

impl ModelCatalogEntry {
    #[must_use]
    pub fn matches(&self, model: &str) -> bool {
        self.canonical_id.eq_ignore_ascii_case(model)
            || self
                .aliases
                .iter()
                .any(|alias| alias.eq_ignore_ascii_case(model))
    }

    fn enrich_from(&mut self, fallback: &Self) {
        for alias in &fallback.aliases {
            if !self
                .aliases
                .iter()
                .any(|candidate| candidate.eq_ignore_ascii_case(alias))
            {
                self.aliases.push(alias.clone());
            }
        }
        if self.display_name.is_none() {
            self.display_name.clone_from(&fallback.display_name);
        }
        if self.owned_by.is_none() {
            self.owned_by.clone_from(&fallback.owned_by);
        }
        if self.lifecycle == ModelLifecycle::Unknown {
            self.lifecycle = fallback.lifecycle;
            self.retirement_date.clone_from(&fallback.retirement_date);
        }
        self.capabilities.fill_unknown_from(&fallback.capabilities);
    }
}

/// One bounded provider catalogue generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelCatalogSnapshot {
    pub provider: String,
    pub complete: bool,
    pub provenance: ModelCatalogProvenance,
    pub models: Vec<ModelCatalogEntry>,
}

impl ModelCatalogSnapshot {
    /// Resolve an exact canonical ID or declared alias.
    #[must_use]
    pub fn find(&self, model: &str) -> Option<&ModelCatalogEntry> {
        self.models.iter().find(|entry| entry.matches(model))
    }

    /// Normalize, deduplicate, and enforce the snapshot bound.
    pub(crate) fn normalize(&mut self) {
        self.models
            .retain(|entry| valid_model_id(&entry.canonical_id));
        self.models.sort_by(|left, right| {
            left.canonical_id
                .to_ascii_lowercase()
                .cmp(&right.canonical_id.to_ascii_lowercase())
        });
        self.models
            .dedup_by(|left, right| left.canonical_id.eq_ignore_ascii_case(&right.canonical_id));
        if self.models.len() > MAX_MODELS_PER_SNAPSHOT {
            self.models.truncate(MAX_MODELS_PER_SNAPSHOT);
            self.complete = false;
        }
    }
}

/// Resolution returned to selectors and request builders.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedModel {
    pub requested_id: String,
    pub entry: Option<ModelCatalogEntry>,
    pub provenance: Option<ModelCatalogProvenance>,
    pub absent_from_complete_discovery: bool,
    pub stale: bool,
}

impl ResolvedModel {
    #[must_use]
    pub fn access(&self) -> ModelAccessState {
        if self.absent_from_complete_discovery {
            ModelAccessState::Unavailable
        } else {
            self.entry
                .as_ref()
                .map_or(ModelAccessState::Unknown, |entry| entry.access)
        }
    }

    #[must_use]
    pub fn capabilities(&self) -> ModelCapabilities {
        self.entry
            .as_ref()
            .map_or_else(ModelCapabilities::unknown, |entry| {
                entry.capabilities.clone()
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CacheKey {
    provider: String,
    endpoint: String,
}

#[derive(Default)]
struct ModelCatalogCache {
    snapshots: BTreeMap<CacheKey, ModelCatalogSnapshot>,
    insertion_order: VecDeque<CacheKey>,
}

impl ModelCatalogCache {
    fn insert(&mut self, key: CacheKey, snapshot: ModelCatalogSnapshot) {
        if let Some(index) = self.insertion_order.iter().position(|item| item == &key) {
            self.insertion_order.remove(index);
        }
        while self.snapshots.len() >= MAX_CACHED_SNAPSHOTS {
            let Some(oldest) = self.insertion_order.pop_front() else {
                break;
            };
            self.snapshots.remove(&oldest);
        }
        self.insertion_order.push_back(key.clone());
        self.snapshots.insert(key, snapshot);
    }
}

static MODEL_CATALOG_CACHE: OnceLock<RwLock<ModelCatalogCache>> = OnceLock::new();

fn cache() -> &'static RwLock<ModelCatalogCache> {
    MODEL_CATALOG_CACHE.get_or_init(|| RwLock::new(ModelCatalogCache::default()))
}

fn canonical_provider(provider: &str) -> String {
    canonical_static_catalog_provider(provider)
        .trim()
        .to_ascii_lowercase()
}

fn cache_key(provider: &str, endpoint: &str) -> CacheKey {
    CacheKey {
        provider: canonical_provider(provider),
        endpoint: endpoint.trim_end_matches('/').to_ascii_lowercase(),
    }
}

/// Store a provider discovery generation in the bounded process cache.
pub(super) fn cache_discovered_catalog(endpoint: &str, snapshot: ModelCatalogSnapshot) {
    let key = cache_key(&snapshot.provider, endpoint);
    let Ok(mut cache) = cache().write() else {
        tracing::warn!("model catalog cache lock is poisoned; discovery result not cached");
        return;
    };
    cache.insert(key, snapshot);
}

/// Return a fresh exact-endpoint snapshot when available.
#[must_use]
pub fn cached_model_catalog(
    provider: &str,
    endpoint: &str,
    now_unix: i64,
) -> Option<ModelCatalogSnapshot> {
    let cache = cache().read().ok()?;
    let snapshot = cache.snapshots.get(&cache_key(provider, endpoint))?.clone();
    let fresh = snapshot.provenance.is_fresh_at(now_unix);
    drop(cache);
    fresh.then_some(snapshot)
}

fn latest_cached_catalog(provider: &str) -> Option<ModelCatalogSnapshot> {
    let provider = canonical_provider(provider);
    let cache = cache().read().ok()?;
    cache
        .insertion_order
        .iter()
        .rev()
        .filter(|key| key.provider == provider)
        .find_map(|key| cache.snapshots.get(key).cloned())
}

/// Resolve a model against fresh authenticated discovery first and the dated
/// emergency manifest second.
#[must_use]
pub fn resolve_model_at(provider: &str, model: &str, now_unix: i64) -> ResolvedModel {
    let requested = normalize_model_id(model);
    let fallback = emergency_fallback_catalog(provider);
    let fallback_fresh = fallback.provenance.is_fresh_at(now_unix);
    let fallback_entry = fallback.find(&requested).cloned();

    if let Some(snapshot) = latest_cached_catalog(provider) {
        let stale = !snapshot.provenance.is_fresh_at(now_unix);
        if !stale {
            let discovered = snapshot.find(&requested).or_else(|| {
                fallback_entry
                    .as_ref()
                    .filter(|_| fallback_fresh)
                    .and_then(|fallback| snapshot.find(&fallback.canonical_id))
            });
            if let Some(mut entry) = discovered.cloned() {
                if fallback_fresh {
                    if let Some(fallback) = fallback_entry.as_ref() {
                        entry.enrich_from(fallback);
                    }
                }
                return ResolvedModel {
                    requested_id: requested,
                    entry: Some(entry),
                    provenance: Some(snapshot.provenance),
                    absent_from_complete_discovery: false,
                    stale: false,
                };
            }
            if snapshot.complete {
                return ResolvedModel {
                    requested_id: requested,
                    entry: fallback_entry.map(|mut entry| {
                        entry.access = ModelAccessState::Unavailable;
                        entry
                    }),
                    provenance: Some(snapshot.provenance),
                    absent_from_complete_discovery: true,
                    stale: false,
                };
            }
        }
    }

    ResolvedModel {
        requested_id: requested,
        entry: fallback_fresh.then_some(fallback_entry).flatten(),
        provenance: Some(fallback.provenance),
        absent_from_complete_discovery: false,
        stale: !fallback_fresh,
    }
}

/// Resolve using the current UTC timestamp.
#[must_use]
pub fn resolve_model(provider: &str, model: &str) -> ResolvedModel {
    resolve_model_at(provider, model, chrono::Utc::now().timestamp())
}

/// Find an exact context-window claim across cached and fallback providers.
///
/// This compatibility helper intentionally returns `None` rather than guessing
/// from a substring. Callers that need a conservative operational ceiling can
/// apply their own explicit unknown-model bound.
#[must_use]
pub fn known_model_context_window(model: &str) -> Option<usize> {
    let now = chrono::Utc::now().timestamp();
    for provider in STATIC_MODEL_CATALOG_PROVIDERS {
        let resolved = resolve_model_at(provider, model, now);
        if let Some(tokens) = resolved.capabilities().input_context_tokens {
            if let Ok(tokens) = usize::try_from(tokens) {
                return Some(tokens);
            }
        }
    }
    None
}

#[must_use]
pub fn normalize_model_id(model: &str) -> String {
    let model = model.trim();
    model.strip_prefix("models/").unwrap_or(model).to_string()
}

#[must_use]
pub fn valid_model_id(model: &str) -> bool {
    !model.is_empty()
        && model.len() <= 512
        && !model.chars().any(char::is_control)
        && model.trim() == model
}

/// Canonical provider name used by fallback data and aliases.
#[must_use]
pub fn canonical_static_catalog_provider(provider: &str) -> &str {
    let provider = provider.trim();
    if provider.eq_ignore_ascii_case("gemini") {
        "google"
    } else if provider.eq_ignore_ascii_case("glm") || provider.eq_ignore_ascii_case("zhipu") {
        "zai"
    } else if provider.eq_ignore_ascii_case("alibaba") {
        "qwen"
    } else if provider.eq_ignore_ascii_case("moonshot") {
        "kimi"
    } else if provider.eq_ignore_ascii_case("opencode-go") {
        "opencode"
    } else {
        provider
    }
}

pub const STATIC_MODEL_CATALOG_PROVIDERS: &[&str] = &[
    "anthropic",
    "openai",
    "google",
    "deepseek",
    "qwen",
    "zai",
    "kimi",
    "minimax",
];

pub const ANTHROPIC_MODELS: &[&str] = &[
    "claude-opus-4-8",
    "claude-sonnet-4-6",
    "claude-haiku-4-5",
    "claude-fable-5",
    "claude-mythos-5",
];
pub const OPENAI_MODELS: &[&str] = &["gpt-5.6-sol", "gpt-5.6-terra", "gpt-5.6-luna", "gpt-5.5"];
pub const GOOGLE_MODELS: &[&str] = &[
    "gemini-3.7-flash",
    "gemini-3.6-flash",
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite",
];
pub const DEEPSEEK_MODELS: &[&str] = &["deepseek-v4-pro", "deepseek-v4-flash"];
pub const QWEN_MODELS: &[&str] = &["qwen3.7-max", "qwen3.7-plus", "qwen3.6-flash"];
pub const ZAI_MODELS: &[&str] = &["glm-5.2", "glm-5-turbo"];
pub const KIMI_MODELS: &[&str] = &["kimi-k2.7-code", "kimi-k2.7-code-highspeed", "kimi-k2.6"];
pub const MINIMAX_MODELS: &[&str] = &["MiniMax-M3", "MiniMax-M2.7-highspeed"];
pub const FALLBACK_MODELS: &[&str] = &[];

#[must_use]
pub fn static_models_for_provider(provider: &str) -> &'static [&'static str] {
    match canonical_provider(provider).as_str() {
        "anthropic" => ANTHROPIC_MODELS,
        "openai" => OPENAI_MODELS,
        "google" => GOOGLE_MODELS,
        "zai" => ZAI_MODELS,
        "deepseek" => DEEPSEEK_MODELS,
        "qwen" => QWEN_MODELS,
        "kimi" => KIMI_MODELS,
        "minimax" => MINIMAX_MODELS,
        _ => FALLBACK_MODELS,
    }
}

const fn supported_capabilities(
    reasoning_profile: ReasoningProfile,
    context: u64,
    output: u64,
) -> ModelCapabilities {
    ModelCapabilities {
        chat: ModelSupport::Supported,
        tools: ModelSupport::Supported,
        streaming: ModelSupport::Supported,
        thinking: if matches!(reasoning_profile, ReasoningProfile::None) {
            ModelSupport::Unsupported
        } else {
            ModelSupport::Supported
        },
        reasoning_profile,
        input_context_tokens: Some(context),
        max_output_tokens: Some(output),
        // Prices are intentionally not embedded in this capability manifest.
        // S-051 owns attributable pricing and cost accounting.
        pricing: ModelPricingState::Unknown,
    }
}

fn fallback_entry(
    canonical_id: &str,
    aliases: &[&str],
    access: ModelAccessState,
    lifecycle: ModelLifecycle,
    capabilities: ModelCapabilities,
) -> ModelCatalogEntry {
    ModelCatalogEntry {
        canonical_id: canonical_id.to_string(),
        aliases: aliases.iter().map(|alias| (*alias).to_string()).collect(),
        display_name: None,
        owned_by: None,
        created: None,
        access,
        lifecycle,
        retirement_date: None,
        capabilities,
    }
}

#[allow(clippy::too_many_lines)]
fn fallback_entries(provider: &str) -> Vec<ModelCatalogEntry> {
    match canonical_provider(provider).as_str() {
        "anthropic" => vec![
            fallback_entry(
                "claude-opus-4-8",
                &[],
                ModelAccessState::Unknown,
                ModelLifecycle::Active,
                supported_capabilities(ReasoningProfile::AnthropicAdaptive, 1_000_000, 128_000),
            ),
            fallback_entry(
                "claude-sonnet-4-6",
                &[],
                ModelAccessState::Unknown,
                ModelLifecycle::Active,
                supported_capabilities(ReasoningProfile::AnthropicManual, 1_000_000, 64_000),
            ),
            fallback_entry(
                "claude-haiku-4-5-20251001",
                &["claude-haiku-4-5"],
                ModelAccessState::Unknown,
                ModelLifecycle::Active,
                supported_capabilities(ReasoningProfile::AnthropicManual, 200_000, 64_000),
            ),
            fallback_entry(
                "claude-fable-5",
                &[],
                ModelAccessState::Limited,
                ModelLifecycle::Active,
                supported_capabilities(ReasoningProfile::AnthropicAdaptive, 1_000_000, 128_000),
            ),
            fallback_entry(
                "claude-mythos-5",
                &[],
                ModelAccessState::Limited,
                ModelLifecycle::Active,
                supported_capabilities(ReasoningProfile::AnthropicAdaptive, 1_000_000, 128_000),
            ),
            fallback_entry(
                "claude-mythos-preview",
                &[],
                ModelAccessState::Unavailable,
                ModelLifecycle::Deprecated,
                ModelCapabilities::unknown(),
            ),
        ],
        "openai" => vec![
            fallback_entry(
                "gpt-5.6-sol",
                &["gpt-5.6"],
                ModelAccessState::Unknown,
                ModelLifecycle::Active,
                supported_capabilities(ReasoningProfile::OpenAiEffort, 1_050_000, 128_000),
            ),
            fallback_entry(
                "gpt-5.6-terra",
                &[],
                ModelAccessState::Unknown,
                ModelLifecycle::Active,
                supported_capabilities(ReasoningProfile::OpenAiEffort, 1_050_000, 128_000),
            ),
            fallback_entry(
                "gpt-5.6-luna",
                &[],
                ModelAccessState::Unknown,
                ModelLifecycle::Active,
                supported_capabilities(ReasoningProfile::OpenAiEffort, 1_050_000, 128_000),
            ),
            fallback_entry(
                "gpt-5.5",
                &[],
                ModelAccessState::Unknown,
                ModelLifecycle::Active,
                supported_capabilities(ReasoningProfile::OpenAiEffort, 1_050_000, 128_000),
            ),
        ],
        "google" => vec![
            fallback_entry(
                "gemini-3.7-flash",
                &[],
                ModelAccessState::Unknown,
                ModelLifecycle::Active,
                supported_capabilities(ReasoningProfile::GeminiThinking, 1_048_576, 65_536),
            ),
            fallback_entry(
                "gemini-3.6-flash",
                &[],
                ModelAccessState::Unknown,
                ModelLifecycle::Active,
                supported_capabilities(ReasoningProfile::GeminiThinking, 1_048_576, 65_536),
            ),
            fallback_entry(
                "gemini-3.5-flash",
                &[],
                ModelAccessState::Unknown,
                ModelLifecycle::Active,
                supported_capabilities(ReasoningProfile::GeminiThinking, 1_000_000, 65_536),
            ),
            fallback_entry(
                "gemini-3.5-flash-lite",
                &[],
                ModelAccessState::Unknown,
                ModelLifecycle::Active,
                supported_capabilities(ReasoningProfile::GeminiThinking, 1_000_000, 65_536),
            ),
        ],
        "deepseek" => vec![
            fallback_entry(
                "deepseek-v4-pro",
                &[],
                ModelAccessState::Unknown,
                ModelLifecycle::Active,
                supported_capabilities(ReasoningProfile::DeepSeekThinking, 1_000_000, 128_000),
            ),
            fallback_entry(
                "deepseek-v4-flash",
                &[],
                ModelAccessState::Unknown,
                ModelLifecycle::Active,
                supported_capabilities(ReasoningProfile::DeepSeekThinking, 1_000_000, 128_000),
            ),
            fallback_entry(
                "deepseek-chat",
                &[],
                ModelAccessState::Unavailable,
                ModelLifecycle::Retired,
                ModelCapabilities::unknown(),
            ),
            fallback_entry(
                "deepseek-reasoner",
                &[],
                ModelAccessState::Unavailable,
                ModelLifecycle::Retired,
                ModelCapabilities::unknown(),
            ),
        ],
        "qwen" => vec![
            fallback_entry(
                "qwen3.7-max",
                &[],
                ModelAccessState::Unknown,
                ModelLifecycle::Active,
                supported_capabilities(ReasoningProfile::QwenThinking, 1_000_000, 128_000),
            ),
            fallback_entry(
                "qwen3.7-plus",
                &[],
                ModelAccessState::Unknown,
                ModelLifecycle::Active,
                supported_capabilities(ReasoningProfile::QwenThinking, 1_000_000, 128_000),
            ),
            fallback_entry(
                "qwen3.6-flash",
                &[],
                ModelAccessState::Unknown,
                ModelLifecycle::Active,
                supported_capabilities(ReasoningProfile::QwenThinking, 1_000_000, 128_000),
            ),
        ],
        "zai" => vec![
            fallback_entry(
                "glm-5.2",
                &[],
                ModelAccessState::Unknown,
                ModelLifecycle::Active,
                supported_capabilities(ReasoningProfile::GlmThinkingWithEffort, 1_000_000, 128_000),
            ),
            fallback_entry(
                "glm-5-turbo",
                &[],
                ModelAccessState::Unknown,
                ModelLifecycle::Active,
                supported_capabilities(ReasoningProfile::GlmThinking, 200_000, 128_000),
            ),
        ],
        "kimi" => vec![
            fallback_entry(
                "kimi-k2.7-code",
                &[],
                ModelAccessState::Unknown,
                ModelLifecycle::Active,
                supported_capabilities(ReasoningProfile::KimiAlways, 262_144, 65_536),
            ),
            fallback_entry(
                "kimi-k2.7-code-highspeed",
                &[],
                ModelAccessState::Unknown,
                ModelLifecycle::Active,
                supported_capabilities(ReasoningProfile::KimiAlways, 262_144, 65_536),
            ),
            fallback_entry(
                "kimi-k2.6",
                &[],
                ModelAccessState::Unknown,
                ModelLifecycle::Active,
                supported_capabilities(ReasoningProfile::KimiToggle, 262_144, 65_536),
            ),
        ],
        "minimax" => vec![
            fallback_entry(
                "MiniMax-M3",
                &[],
                ModelAccessState::Unknown,
                ModelLifecycle::Active,
                supported_capabilities(ReasoningProfile::MiniMaxAdaptive, 1_000_000, 128_000),
            ),
            fallback_entry(
                "MiniMax-M2.7-highspeed",
                &[],
                ModelAccessState::Unknown,
                ModelLifecycle::Active,
                ModelCapabilities {
                    chat: ModelSupport::Supported,
                    tools: ModelSupport::Supported,
                    streaming: ModelSupport::Supported,
                    thinking: ModelSupport::Unknown,
                    reasoning_profile: ReasoningProfile::Unknown,
                    input_context_tokens: Some(204_800),
                    max_output_tokens: None,
                    pricing: ModelPricingState::Unknown,
                },
            ),
        ],
        _ => Vec::new(),
    }
}

fn required_model_id<'a>(value: &'a Value, key: &str, index: usize) -> Result<&'a str, String> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| format!("model entry {index} is missing non-empty string '{key}'"))
}

fn bool_support(value: Option<&Value>) -> ModelSupport {
    match value.and_then(Value::as_bool) {
        Some(true) => ModelSupport::Supported,
        Some(false) => ModelSupport::Unsupported,
        None => ModelSupport::Unknown,
    }
}

fn lifecycle(value: &Value) -> ModelLifecycle {
    let status = value
        .get("lifecycle")
        .or_else(|| value.get("status"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if status.eq_ignore_ascii_case("active") || status.eq_ignore_ascii_case("generally_available") {
        ModelLifecycle::Active
    } else if status.eq_ignore_ascii_case("preview") || status.eq_ignore_ascii_case("beta") {
        ModelLifecycle::Preview
    } else if status.eq_ignore_ascii_case("deprecated") {
        ModelLifecycle::Deprecated
    } else if status.eq_ignore_ascii_case("retired") || status.eq_ignore_ascii_case("disabled") {
        ModelLifecycle::Retired
    } else {
        ModelLifecycle::Unknown
    }
}

fn explicit_capabilities(value: &Value) -> ModelCapabilities {
    let capabilities = value.get("capabilities");
    let mut result = ModelCapabilities::unknown();
    result.tools = bool_support(
        capabilities
            .and_then(|value| value.get("tools"))
            .or_else(|| capabilities.and_then(|value| value.get("tool_calling"))),
    );
    result.streaming = bool_support(capabilities.and_then(|value| value.get("streaming")));
    result.thinking = bool_support(
        capabilities
            .and_then(|value| value.get("thinking"))
            .or_else(|| capabilities.and_then(|value| value.get("reasoning"))),
    );
    result.input_context_tokens = value
        .get("max_input_tokens")
        .or_else(|| value.get("context_window"))
        .and_then(Value::as_u64);
    result.max_output_tokens = value
        .get("max_tokens")
        .or_else(|| value.get("max_output_tokens"))
        .and_then(Value::as_u64);
    result
}

fn optional_string(value: &Value, key: &str, index: usize) -> Result<Option<String>, String> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(_) => Err(format!("model entry {index} has non-string '{key}'")),
    }
}

fn optional_i64(value: &Value, key: &str, index: usize) -> Result<Option<i64>, String> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_i64()
            .map(Some)
            .ok_or_else(|| format!("model entry {index} has non-integer '{key}'")),
    }
}

fn openai_entries(body: &Value) -> Result<Vec<ModelCatalogEntry>, String> {
    let data = body
        .get("data")
        .and_then(Value::as_array)
        .ok_or_else(|| "expected 'data' array in model response".to_string())?;
    data.iter()
        .take(MAX_MODELS_PER_SNAPSHOT + 1)
        .enumerate()
        .map(|(index, value)| {
            Ok(ModelCatalogEntry {
                canonical_id: normalize_model_id(required_model_id(value, "id", index)?),
                aliases: Vec::new(),
                display_name: optional_string(value, "display_name", index)?,
                owned_by: optional_string(value, "owned_by", index)?,
                created: optional_i64(value, "created", index)?,
                access: ModelAccessState::Available,
                lifecycle: lifecycle(value),
                retirement_date: value
                    .get("retirement_date")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                capabilities: explicit_capabilities(value),
            })
        })
        .collect()
}

fn anthropic_entries(body: &Value) -> Result<Vec<ModelCatalogEntry>, String> {
    let mut entries = openai_entries(body)?;
    let Some(data) = body.get("data").and_then(Value::as_array) else {
        return Ok(entries);
    };
    for (entry, value) in entries.iter_mut().zip(data) {
        entry.created = value
            .get("created_at")
            .and_then(Value::as_str)
            .and_then(|timestamp| chrono::DateTime::parse_from_rfc3339(timestamp).ok())
            .map(|timestamp| timestamp.timestamp())
            .or(entry.created);
    }
    Ok(entries)
}

fn gemini_entries(body: &Value) -> Result<Vec<ModelCatalogEntry>, String> {
    let data = body
        .get("models")
        .and_then(Value::as_array)
        .ok_or_else(|| "expected 'models' array in Gemini model response".to_string())?;
    data.iter()
        .take(MAX_MODELS_PER_SNAPSHOT + 1)
        .enumerate()
        .map(|(index, value)| {
            let canonical_id = normalize_model_id(required_model_id(value, "name", index)?);
            let aliases = value
                .get("baseModelId")
                .and_then(Value::as_str)
                .map(normalize_model_id)
                .filter(|alias| !alias.eq_ignore_ascii_case(&canonical_id))
                .into_iter()
                .collect();
            let methods = value
                .get("supportedGenerationMethods")
                .and_then(Value::as_array);
            let method_supported = |method: &str| {
                methods.is_some_and(|items| items.iter().any(|item| item.as_str() == Some(method)))
            };
            let mut capabilities = explicit_capabilities(value);
            capabilities.chat = if method_supported("generateContent") {
                ModelSupport::Supported
            } else {
                ModelSupport::Unknown
            };
            if method_supported("streamGenerateContent") {
                capabilities.streaming = ModelSupport::Supported;
            }
            capabilities.input_context_tokens = value
                .get("inputTokenLimit")
                .and_then(Value::as_u64)
                .or(capabilities.input_context_tokens);
            capabilities.max_output_tokens = value
                .get("outputTokenLimit")
                .and_then(Value::as_u64)
                .or(capabilities.max_output_tokens);
            if value.get("thinking").is_some() {
                capabilities.thinking = ModelSupport::Supported;
                capabilities.reasoning_profile = ReasoningProfile::GeminiThinking;
            }
            Ok(ModelCatalogEntry {
                canonical_id,
                aliases,
                display_name: value
                    .get("displayName")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                owned_by: Some("google".to_string()),
                created: None,
                access: ModelAccessState::Available,
                lifecycle: lifecycle(value),
                retirement_date: None,
                capabilities,
            })
        })
        .collect()
}

fn ollama_entries(body: &Value) -> Result<Vec<ModelCatalogEntry>, String> {
    let data = body
        .get("models")
        .and_then(Value::as_array)
        .ok_or_else(|| "expected 'models' array in Ollama tags response".to_string())?;
    data.iter()
        .take(MAX_MODELS_PER_SNAPSHOT + 1)
        .enumerate()
        .map(|(index, value)| {
            let id = value
                .get("model")
                .and_then(Value::as_str)
                .or_else(|| value.get("name").and_then(Value::as_str))
                .filter(|id| !id.is_empty())
                .ok_or_else(|| format!("Ollama model entry {index} is missing model/name"))?;
            Ok(ModelCatalogEntry {
                canonical_id: normalize_model_id(id),
                aliases: Vec::new(),
                display_name: None,
                owned_by: Some("ollama".to_string()),
                created: value
                    .get("modified_at")
                    .and_then(Value::as_str)
                    .and_then(|timestamp| chrono::DateTime::parse_from_rfc3339(timestamp).ok())
                    .map(|timestamp| timestamp.timestamp()),
                access: ModelAccessState::Available,
                lifecycle: ModelLifecycle::Unknown,
                retirement_date: None,
                capabilities: ModelCapabilities::unknown(),
            })
        })
        .collect()
}

/// Parse one authenticated provider response into a bounded, attributable snapshot.
pub(super) fn parse_discovered_catalog(
    provider: &str,
    endpoint: &str,
    format: ModelCatalogFormat,
    body: &Value,
    now_unix: i64,
) -> Result<ModelCatalogSnapshot, String> {
    let models = match format {
        ModelCatalogFormat::OpenAi => openai_entries(body)?,
        ModelCatalogFormat::Anthropic => anthropic_entries(body)?,
        ModelCatalogFormat::Gemini => gemini_entries(body)?,
        ModelCatalogFormat::Ollama => ollama_entries(body)?,
    };
    let complete = match format {
        ModelCatalogFormat::OpenAi | ModelCatalogFormat::Anthropic => {
            body.get("has_more").and_then(Value::as_bool) != Some(true)
        }
        ModelCatalogFormat::Gemini => body.get("nextPageToken").is_none(),
        ModelCatalogFormat::Ollama => true,
    };
    let provider = canonical_provider(provider);
    let mut snapshot = ModelCatalogSnapshot {
        provider: provider.clone(),
        complete,
        provenance: ModelCatalogProvenance {
            source: ModelEvidenceSource::ProviderApi,
            provider,
            endpoint: Some(endpoint.to_string()),
            schema_version: "provider-api.v1".to_string(),
            observed_at_unix: now_unix,
            expires_at_unix: now_unix + DISCOVERY_TTL_SECONDS,
        },
        models,
    };
    snapshot.normalize();
    Ok(snapshot)
}

/// Construct the current dated emergency snapshot for one provider.
#[must_use]
pub fn emergency_fallback_catalog(provider: &str) -> ModelCatalogSnapshot {
    let provider = canonical_provider(provider);
    ModelCatalogSnapshot {
        provider: provider.clone(),
        complete: false,
        provenance: ModelCatalogProvenance {
            source: ModelEvidenceSource::EmergencyFallback,
            provider: provider.clone(),
            endpoint: None,
            schema_version: FALLBACK_CATALOG_VERSION.to_string(),
            observed_at_unix: FALLBACK_VERIFIED_AT_UNIX,
            expires_at_unix: FALLBACK_VERIFIED_AT_UNIX + FALLBACK_MAX_AGE_SECONDS,
        },
        models: fallback_entries(&provider),
    }
}

#[cfg(test)]
fn clear_model_catalog_cache_for_test() {
    if let Ok(mut cache) = cache().write() {
        *cache = ModelCatalogCache::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn discovered_snapshot(
        provider: &str,
        now: i64,
        models: Vec<ModelCatalogEntry>,
    ) -> ModelCatalogSnapshot {
        ModelCatalogSnapshot {
            provider: provider.to_string(),
            complete: true,
            provenance: ModelCatalogProvenance {
                source: ModelEvidenceSource::ProviderApi,
                provider: provider.to_string(),
                endpoint: Some("https://example.invalid/v1/models".to_string()),
                schema_version: "provider-api".to_string(),
                observed_at_unix: now,
                expires_at_unix: now + DISCOVERY_TTL_SECONDS,
            },
            models,
        }
    }

    #[test]
    fn fallback_is_small_dated_and_unknown_access() {
        let catalog = emergency_fallback_catalog("openai");
        assert_eq!(
            catalog.provenance.source,
            ModelEvidenceSource::EmergencyFallback
        );
        assert_eq!(catalog.provenance.schema_version, FALLBACK_CATALOG_VERSION);
        assert!(catalog.models.len() < 10);
        assert_eq!(
            catalog
                .find("gpt-5.6")
                .expect("declared alias")
                .canonical_id,
            "gpt-5.6-sol"
        );
        assert_eq!(
            catalog.find("gpt-5.6-sol").expect("fallback").access,
            ModelAccessState::Unknown
        );
    }

    #[test]
    fn expired_fallback_cannot_enable_features() {
        clear_model_catalog_cache_for_test();
        let now = FALLBACK_VERIFIED_AT_UNIX + FALLBACK_MAX_AGE_SECONDS + 1;
        let resolved = resolve_model_at("openai", "gpt-5.6-sol", now);
        assert!(resolved.stale);
        assert!(resolved.entry.is_none());
        assert_eq!(resolved.capabilities().thinking, ModelSupport::Unknown);
    }

    #[test]
    fn authenticated_discovery_proves_access_and_uses_fresh_exact_metadata() {
        clear_model_catalog_cache_for_test();
        let now = FALLBACK_VERIFIED_AT_UNIX + 1;
        let entry = ModelCatalogEntry {
            canonical_id: "gpt-5.6-sol".to_string(),
            aliases: Vec::new(),
            display_name: None,
            owned_by: Some("openai".to_string()),
            created: Some(now),
            access: ModelAccessState::Available,
            lifecycle: ModelLifecycle::Unknown,
            retirement_date: None,
            capabilities: ModelCapabilities::unknown(),
        };
        let mut snapshot = discovered_snapshot("openai", now, vec![entry]);
        snapshot.complete = false;
        cache_discovered_catalog("https://api.openai.com", snapshot);
        let resolved = resolve_model_at("openai", "gpt-5.6", now);
        assert_eq!(resolved.access(), ModelAccessState::Available);
        assert_eq!(
            resolved
                .entry
                .expect("resolved")
                .capabilities
                .reasoning_profile,
            ReasoningProfile::OpenAiEffort
        );
    }

    #[test]
    fn complete_discovery_marks_missing_fallback_model_unavailable() {
        clear_model_catalog_cache_for_test();
        let now = FALLBACK_VERIFIED_AT_UNIX + 1;
        cache_discovered_catalog(
            "https://api.deepseek.com",
            discovered_snapshot("test-deepseek", now, Vec::new()),
        );
        let resolved = resolve_model_at("test-deepseek", "missing-model", now);
        assert!(resolved.absent_from_complete_discovery);
        assert_eq!(resolved.access(), ModelAccessState::Unavailable);
    }

    #[test]
    fn unknown_provider_has_no_unrelated_openai_fallback() {
        clear_model_catalog_cache_for_test();
        let resolved = resolve_model_at("local", "custom-model", FALLBACK_VERIFIED_AT_UNIX + 1);
        assert!(resolved.entry.is_none());
        assert!(static_models_for_provider("local").is_empty());
    }

    #[test]
    fn parses_gemini_limits_aliases_and_incomplete_pagination() {
        let snapshot = parse_discovered_catalog(
            "google",
            "https://example.invalid/v1beta/models",
            ModelCatalogFormat::Gemini,
            &json!({
                "models": [{
                    "name": "models/gemini-current-001",
                    "baseModelId": "gemini-current",
                    "displayName": "Gemini Current",
                    "inputTokenLimit": 1_048_576,
                    "outputTokenLimit": 65536,
                    "supportedGenerationMethods": ["generateContent"]
                }],
                "nextPageToken": "more"
            }),
            100,
        )
        .expect("valid Gemini catalogue");
        let entry = snapshot.find("gemini-current").expect("declared alias");
        assert_eq!(entry.canonical_id, "gemini-current-001");
        assert_eq!(entry.access, ModelAccessState::Available);
        assert_eq!(entry.capabilities.chat, ModelSupport::Supported);
        assert_eq!(entry.capabilities.input_context_tokens, Some(1_048_576));
        assert!(!snapshot.complete);
    }

    #[test]
    fn parses_anthropic_metadata_without_inventing_capabilities() {
        let snapshot = parse_discovered_catalog(
            "anthropic",
            "https://example.invalid/v1/models",
            ModelCatalogFormat::Anthropic,
            &json!({
                "data": [{
                    "id": "claude-current",
                    "display_name": "Claude Current",
                    "created_at": "2026-08-22T00:00:00Z",
                    "max_input_tokens": 1_000_000,
                    "max_tokens": 128_000
                }],
                "has_more": false
            }),
            100,
        )
        .expect("valid Anthropic catalogue");
        let entry = snapshot.find("claude-current").expect("model");
        assert_eq!(entry.access, ModelAccessState::Available);
        assert_eq!(entry.capabilities.input_context_tokens, Some(1_000_000));
        assert_eq!(entry.capabilities.tools, ModelSupport::Unknown);
        assert!(snapshot.complete);
    }

    #[test]
    fn parses_native_ollama_tags_as_installed_unknown_capability_models() {
        let snapshot = parse_discovered_catalog(
            "ollama",
            "http://localhost:11434/api/tags",
            ModelCatalogFormat::Ollama,
            &json!({"models": [{"name": "qwen-local:latest"}]}),
            100,
        )
        .expect("valid Ollama tags");
        let entry = snapshot.find("qwen-local:latest").expect("installed model");
        assert_eq!(entry.access, ModelAccessState::Available);
        assert_eq!(entry.capabilities.thinking, ModelSupport::Unknown);
        assert!(snapshot.complete);
    }
}
