use serde::Deserialize;
use std::collections::HashMap;
use url::Url;

// Re-export `ApiKey` so `crate::config::provider::ApiKey` resolves for
// the ProviderConfig field type declaration below. The free-function
// redaction/validation helpers live at `crate::providers::api_key` and
// are not re-exported here — no call site needed them through
// `config::provider`. See crosslink #256.
pub use crate::providers::api_key::ApiKey;

/// Validate that a provider `base_url` is safe to use as an HTTP target.
///
/// Defensive layers (crosslink #329):
///  1. Must parse as a [`url::Url`].
///  2. Scheme must be `http` or `https` — `file://`, `data:`, `ftp://`,
///     `gopher://` etc. are rejected.
///  3. Host must NOT resolve to a private / loopback / link-local /
///     cloud-metadata / reserved IP. Reuses the SSRF guard from
///     [`crate::web::validate_url`] (crosslink #290).
///
/// # Errors
///
/// Returns `Err(String)` with a human-readable explanation when the URL is
/// malformed, uses a forbidden scheme, or points to a non-public address.
pub fn validate_base_url(url: &str) -> Result<(), String> {
    crate::web::validate_url(url).map_err(|e| format!("provider base_url '{url}' rejected: {e}"))
}

/// Validate a provider `base_url`, allowing private/loopback hosts only for
/// explicitly local provider targets.
///
/// Remote providers keep the full SSRF guard from [`validate_base_url`].
/// Local providers intentionally point at loopback or LAN services such as
/// Ollama, LM Studio, `LocalAI`, and text-generation-webui, so their validation
/// is limited to URL shape and HTTP(S) schemes.
///
/// # Errors
///
/// Returns an error when a remote provider URL fails the full SSRF guard, or
/// when a local provider URL is malformed, lacks a host, or uses a non-HTTP
/// scheme.
pub fn validate_provider_base_url(provider_name: &str, url: &str) -> Result<(), String> {
    if is_local_provider_name(provider_name) {
        validate_local_provider_base_url(provider_name, url)
    } else {
        validate_base_url(url)
    }
}

/// Return true for provider targets that intentionally point at user-owned
/// local or LAN inference servers and therefore do not require a remote API key.
#[must_use]
pub fn is_local_provider_name(provider_name: &str) -> bool {
    matches!(
        provider_name.to_ascii_lowercase().as_str(),
        "ollama" | "local" | "lmstudio" | "localai" | "text-generation-webui"
    )
}

fn validate_local_provider_base_url(provider_name: &str, url: &str) -> Result<(), String> {
    let parsed = Url::parse(url).map_err(|e| {
        format!("provider '{provider_name}' base_url '{url}' rejected: invalid URL: {e}")
    })?;
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "provider '{provider_name}' base_url '{url}' rejected: scheme '{scheme}' is not allowed; use http or https"
            ));
        }
    }
    if parsed.host_str().is_none() {
        return Err(format!(
            "provider '{provider_name}' base_url '{url}' rejected: missing host"
        ));
    }
    Ok(())
}

/// Thinking/reasoning mode configuration
#[derive(Debug, Deserialize, Clone)]
pub struct ThinkingConfig {
    /// Enable thinking mode (default: true for supported providers)
    #[serde(default = "default_thinking_enabled")]
    pub enabled: bool,
    /// Token budget for thinking (provider-specific)
    /// - Anthropic: min 1024, no max
    /// - Google Gemini: 128-32768
    /// - Z.AI/GLM: no explicit budget
    #[serde(default)]
    pub budget_tokens: Option<u32>,
    /// Preserve thinking across turns (Z.AI/GLM specific)
    #[serde(default)]
    pub preserve_across_turns: bool,
    /// Reasoning effort level for `OpenAI` GPT-5/o1/o3/o4:
    /// "none", "low", "medium", "high", "xhigh" (`max` aliases to `xhigh`).
    #[serde(default)]
    pub reasoning_effort: Option<String>,
    /// When `budget_tokens` is `None`, derive the budget from
    /// `reasoning_effort` via [`adaptive_budget_for`].
    ///
    /// Default: `true` — CC's parity behavior. Setting an explicit
    /// `budget_tokens` always wins over the adaptive derivation, and
    /// setting `adaptive: false` makes a missing budget fall back to
    /// each provider's hard-coded default (e.g. Anthropic 5000, Gemini
    /// 8192) instead of effort-derived.
    ///
    /// See crosslink #599.
    #[serde(default = "default_thinking_adaptive")]
    pub adaptive: bool,
}

const fn default_thinking_enabled() -> bool {
    true
}

const fn default_thinking_adaptive() -> bool {
    true
}

/// Derive a thinking-token budget from a reasoning-effort string.
///
/// Mirrors CC's `getAdaptiveThinkingBudget`:
///   * `low`    → 1024 tokens (Anthropic minimum)
///   * `medium` → 8000 tokens (sane default for tool-use turns)
///   * `high`   → 16000 tokens (deep reasoning ceiling)
///
/// Any other value — including missing/empty — returns 0, which the
/// provider adapters interpret as "fall back to the provider default".
/// The mapping is intentionally a small step function rather than a
/// continuous scale so the user-visible cost of switching effort
/// levels is predictable.
///
/// See crosslink #599.
#[must_use]
pub fn adaptive_budget_for(effort: &str) -> u32 {
    match effort.to_ascii_lowercase().as_str() {
        "low" => 1024,
        "medium" | "med" => 8000,
        "high" => 16000,
        _ => 0,
    }
}

impl ThinkingConfig {
    /// Resolve the effective thinking budget, applying the adaptive
    /// derivation when [`Self::budget_tokens`] is `None` and
    /// [`Self::adaptive`] is `true`.
    ///
    /// Precedence (highest first):
    ///   1. Explicit `budget_tokens` set by the user.
    ///   2. Adaptive derivation from `reasoning_effort` (when
    ///      `adaptive == true`).
    ///   3. The supplied `provider_default` (e.g. Anthropic 5000).
    ///
    /// `provider_default` is the value the adapter would have used
    /// before #599 — callers pass their existing fallback so the
    /// behaviour change is opt-in by setting `adaptive=true` (the new
    /// default) with no explicit budget.
    ///
    /// See crosslink #599.
    #[must_use]
    pub fn effective_budget(&self, provider_default: u32) -> u32 {
        if let Some(b) = self.budget_tokens {
            return b;
        }
        if self.adaptive {
            if let Some(effort) = self.reasoning_effort.as_deref() {
                let derived = adaptive_budget_for(effort);
                if derived > 0 {
                    return derived;
                }
            }
        }
        provider_default
    }
}

impl Default for ThinkingConfig {
    fn default() -> Self {
        Self {
            enabled: default_thinking_enabled(),
            budget_tokens: None,
            preserve_across_turns: false,
            reasoning_effort: None,
            adaptive: default_thinking_adaptive(),
        }
    }
}

/// Provider configuration (Anthropic, `OpenAI`, Google, etc.)
///
/// `api_key` is an [`ApiKey`] newtype whose own `Debug`/`Display` redact
/// the value and whose `Deserialize` impl validates the structure
/// (rejects empty / CRLF / non-ASCII). We keep the derived `Debug` on
/// this struct because the redaction guarantee is now structural on the
/// field type — one less place to regress. See crosslink #256.
#[derive(Debug, Deserialize, Clone)]
pub struct ProviderConfig {
    #[serde(default)]
    pub api_key: Option<ApiKey>,
    pub base_url: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub thinking: ThinkingConfig,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thinking_config_default() {
        // Default and serde deserialization now both return enabled=true
        let config = ThinkingConfig::default();
        assert!(config.enabled);
        assert!(config.budget_tokens.is_none());
        assert!(!config.preserve_across_turns);
        assert!(config.reasoning_effort.is_none());
        // Crosslink #599: adaptive defaults to true so a missing
        // budget_tokens with reasoning_effort=medium/high derives a
        // sensible budget without user intervention.
        assert!(config.adaptive);
    }

    // ── crosslink #599 — adaptive thinking budget ───────────────────────────

    /// `#599-a`: `adaptive_budget_for` maps effort strings to the
    /// documented step function (low=1024, medium=8000, high=16000).
    /// Anything else returns 0 (caller falls back to provider default).
    #[test]
    fn issue_599_adaptive_budget_step_function() {
        assert_eq!(adaptive_budget_for("low"), 1024);
        assert_eq!(adaptive_budget_for("medium"), 8000);
        assert_eq!(adaptive_budget_for("med"), 8000);
        assert_eq!(adaptive_budget_for("high"), 16000);
        // Case-insensitive
        assert_eq!(adaptive_budget_for("HIGH"), 16000);
        assert_eq!(adaptive_budget_for("Medium"), 8000);
        // Unknown values fall through to 0 — caller's provider_default wins.
        assert_eq!(adaptive_budget_for(""), 0);
        assert_eq!(adaptive_budget_for("ultra"), 0);
    }

    /// `#599-b`: `effective_budget` precedence — explicit `budget_tokens`
    /// always wins, otherwise adaptive derivation from
    /// `reasoning_effort`, otherwise the `provider_default`.
    #[test]
    fn issue_599_effective_budget_precedence() {
        // Explicit budget wins even when reasoning_effort is set
        let cfg = ThinkingConfig {
            budget_tokens: Some(2048),
            reasoning_effort: Some("high".to_string()),
            adaptive: true,
            ..Default::default()
        };
        assert_eq!(cfg.effective_budget(99999), 2048);

        // No explicit budget + adaptive + medium effort → 8000
        let cfg = ThinkingConfig {
            budget_tokens: None,
            reasoning_effort: Some("medium".to_string()),
            adaptive: true,
            ..Default::default()
        };
        assert_eq!(cfg.effective_budget(5000), 8000);

        // No explicit budget + adaptive + high effort → 16000
        let cfg = ThinkingConfig {
            budget_tokens: None,
            reasoning_effort: Some("high".to_string()),
            adaptive: true,
            ..Default::default()
        };
        assert_eq!(cfg.effective_budget(5000), 16000);

        // Adaptive disabled → provider_default
        let cfg = ThinkingConfig {
            budget_tokens: None,
            reasoning_effort: Some("high".to_string()),
            adaptive: false,
            ..Default::default()
        };
        assert_eq!(cfg.effective_budget(5000), 5000);

        // No effort at all → provider_default
        let cfg = ThinkingConfig {
            budget_tokens: None,
            reasoning_effort: None,
            adaptive: true,
            ..Default::default()
        };
        assert_eq!(cfg.effective_budget(5000), 5000);
    }

    /// `#599-c`: serde deserialises the new `adaptive` field with default
    /// true; explicit false is honoured.
    #[test]
    fn issue_599_adaptive_field_serde_round_trip() {
        let cfg: ThinkingConfig = serde_json::from_str("{}").expect("default");
        assert!(cfg.adaptive, "missing field → default true (CC parity)");

        let cfg: ThinkingConfig =
            serde_json::from_str(r#"{"adaptive": false}"#).expect("explicit false");
        assert!(!cfg.adaptive, "explicit false must be honoured");

        let cfg: ThinkingConfig =
            serde_json::from_str(r#"{"adaptive": true}"#).expect("explicit true");
        assert!(cfg.adaptive);
    }

    #[test]
    fn test_thinking_config_serde_default() {
        // When deserializing, the serde default function is used
        let config: ThinkingConfig = serde_json::from_str("{}").unwrap();
        assert!(config.enabled); // serde uses default_thinking_enabled() = true
        assert!(config.budget_tokens.is_none());
    }

    #[test]
    fn test_thinking_config_with_budget() {
        let json = r#"{
            "enabled": true,
            "budget_tokens": 10000,
            "preserve_across_turns": true,
            "reasoning_effort": "high"
        }"#;

        let config: ThinkingConfig = serde_json::from_str(json).unwrap();
        assert!(config.enabled);
        assert_eq!(config.budget_tokens, Some(10000));
        assert!(config.preserve_across_turns);
        assert_eq!(config.reasoning_effort, Some("high".to_string()));
    }

    #[test]
    fn test_provider_config_minimal() {
        let json = r#"{
            "base_url": "https://api.example.com"
        }"#;

        let config: ProviderConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.base_url, "https://api.example.com");
        assert!(config.api_key.is_none());
        assert!(config.model.is_none());
        assert!(config.headers.is_empty());
    }

    #[test]
    fn test_provider_config_full() {
        let json = r#"{
            "base_url": "https://api.example.com",
            "api_key": "sk-test123",
            "model": "gpt-4",
            "headers": {"X-Custom": "value"},
            "thinking": {
                "enabled": true,
                "budget_tokens": 5000
            }
        }"#;

        let config: ProviderConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.base_url, "https://api.example.com");
        assert_eq!(
            config.api_key.as_ref().map(ApiKey::as_str),
            Some("sk-test123")
        );
        assert_eq!(config.model, Some("gpt-4".to_string()));
        assert_eq!(config.headers.get("X-Custom"), Some(&"value".to_string()));
        assert!(config.thinking.enabled);
        assert_eq!(config.thinking.budget_tokens, Some(5000));
    }

    // --- Regression tests for crosslink #256 ---

    #[test]
    fn provider_config_debug_does_not_leak_key() {
        let cfg = ProviderConfig {
            api_key: Some(
                ApiKey::try_from_string("sk-ant-api03-SECRET_VALUE_HERE_XYZ".to_string())
                    .expect("valid test key"),
            ),
            base_url: "https://api.anthropic.com".to_string(),
            model: None,
            headers: HashMap::new(),
            thinking: ThinkingConfig::default(),
        };
        let s = format!("{cfg:?}");
        assert!(!s.contains("SECRET_VALUE_HERE"), "Debug leaked middle: {s}");
        assert!(
            !s.contains("sk-ant-api03-SECRET"),
            "Debug leaked prefix-middle: {s}"
        );
        assert!(
            s.contains("sk-a") || s.contains("…"),
            "no redaction fingerprint: {s}"
        );
    }

    #[test]
    fn provider_config_rejects_crlf_api_key_at_deserialize() {
        let json = r#"{
            "base_url": "https://api.example.com",
            "api_key": "sk-legit\r\nX-Injected: evil"
        }"#;
        let result: Result<ProviderConfig, _> = serde_json::from_str(json);
        assert!(result.is_err(), "CRLF api_key must fail deserialize");
    }

    #[test]
    fn provider_config_rejects_empty_api_key_at_deserialize() {
        let json = r#"{
            "base_url": "https://api.example.com",
            "api_key": ""
        }"#;
        let result: Result<ProviderConfig, _> = serde_json::from_str(json);
        assert!(result.is_err(), "empty api_key must fail deserialize");
    }

    // ── Crosslink #329: base_url validation (SSRF / scheme allowlist) ───────

    #[test]
    fn validate_base_url_accepts_public_https() {
        assert!(
            validate_base_url("https://1.1.1.1/v1").is_ok(),
            "public https URL must pass validation"
        );
    }

    #[test]
    fn validate_base_url_rejects_file_scheme() {
        let err = validate_base_url("file:///etc/passwd").expect_err("file:// must be rejected");
        assert!(
            err.contains("Unsupported URL scheme") || err.contains("rejected"),
            "expected scheme-rejection error, got: {err}"
        );
    }

    #[test]
    fn validate_base_url_rejects_data_scheme() {
        let err = validate_base_url("data:text/plain,exfil").expect_err("data: must be rejected");
        assert!(
            err.contains("rejected"),
            "expected rejection error, got: {err}"
        );
    }

    #[test]
    fn validate_base_url_rejects_ftp_scheme() {
        let err =
            validate_base_url("ftp://files.example.com/").expect_err("ftp:// must be rejected");
        assert!(
            err.contains("Unsupported URL scheme") || err.contains("rejected"),
            "expected scheme rejection, got: {err}"
        );
    }

    #[test]
    fn validate_base_url_rejects_metadata_ip() {
        let err = validate_base_url("http://169.254.169.254/latest/meta-data/")
            .expect_err("link-local metadata IP must be rejected");
        assert!(
            err.contains("reserved/internal") || err.contains("rejected"),
            "expected SSRF rejection, got: {err}"
        );
    }

    #[test]
    fn validate_base_url_rejects_metadata_hostname() {
        let err = validate_base_url("http://metadata.google.internal/")
            .expect_err("metadata hostname must be denylisted");
        assert!(
            err.contains("metadata endpoint") || err.contains("rejected"),
            "expected metadata-endpoint rejection, got: {err}"
        );
    }

    #[test]
    fn validate_base_url_rejects_rfc1918_private() {
        let err =
            validate_base_url("http://10.0.0.1/").expect_err("RFC1918 private IP must be rejected");
        assert!(
            err.contains("reserved/internal") || err.contains("rejected"),
            "expected SSRF rejection, got: {err}"
        );
    }

    #[test]
    fn validate_base_url_rejects_malformed() {
        let err = validate_base_url("not a url").expect_err("garbage must fail to parse");
        assert!(
            err.contains("Invalid URL") || err.contains("rejected"),
            "expected parse-error message, got: {err}"
        );
    }
}
