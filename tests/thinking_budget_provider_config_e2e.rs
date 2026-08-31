//! End-to-end tests for `config::adaptive_budget_for` step function +
//! `ThinkingConfig::effective_budget` precedence chain +
//! `ProviderConfig` serde wire-shape contract.
//!
//! Sprint 88 of the verification effort. Sprint 29 covered
//! per-provider thinking injection at request time; this file
//! covers the upstream budget-resolution logic in
//! `config::provider`: the documented step-function mapping
//! (low/medium/high → 1024/8000/16000) and the precedence
//! chain (`budget_tokens` > adaptive-from-effort >
//! `provider_default`).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::config::{adaptive_budget_for, ProviderConfig, ThinkingConfig};

// ───────────────────────────────────────────────────────────────────────────
// Section A — adaptive_budget_for step function
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn adaptive_budget_low_maps_to_1024() {
    // Anthropic minimum budget.
    assert_eq!(adaptive_budget_for("low"), 1024);
}

#[test]
fn adaptive_budget_medium_maps_to_8000() {
    assert_eq!(adaptive_budget_for("medium"), 8000);
}

#[test]
fn adaptive_budget_med_is_alias_for_medium() {
    // Documented alias.
    assert_eq!(adaptive_budget_for("med"), 8000);
}

#[test]
fn adaptive_budget_high_maps_to_16000() {
    assert_eq!(adaptive_budget_for("high"), 16000);
}

#[test]
fn adaptive_budget_is_case_insensitive() {
    assert_eq!(adaptive_budget_for("LOW"), 1024);
    assert_eq!(adaptive_budget_for("Medium"), 8000);
    assert_eq!(adaptive_budget_for("HIGH"), 16000);
}

#[test]
fn adaptive_budget_unknown_effort_returns_zero() {
    // Documented: 0 means "fall back to provider default".
    assert_eq!(adaptive_budget_for(""), 0);
    assert_eq!(adaptive_budget_for("unknown"), 0);
    assert_eq!(adaptive_budget_for("max"), 0); // "max" not in step function
    assert_eq!(adaptive_budget_for("none"), 0);
}

#[test]
fn adaptive_budget_step_function_is_monotonic() {
    // low < medium < high — pinning the step ordering.
    let l = adaptive_budget_for("low");
    let m = adaptive_budget_for("medium");
    let h = adaptive_budget_for("high");
    assert!(l < m);
    assert!(m < h);
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — ThinkingConfig::effective_budget precedence
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn effective_budget_explicit_budget_tokens_wins_over_everything() {
    // PINS PRECEDENCE 1: explicit budget_tokens always wins.
    let config = ThinkingConfig {
        enabled: true,
        budget_tokens: Some(99_999),
        preserve_across_turns: false,
        reasoning_effort: Some("low".to_string()), // would derive 1024
        adaptive: true,
    };
    assert_eq!(
        config.effective_budget(5000),
        99_999,
        "explicit budget_tokens MUST override both adaptive + provider_default"
    );
}

#[test]
fn effective_budget_adaptive_derives_from_reasoning_effort_when_no_explicit() {
    // PINS PRECEDENCE 2: adaptive derivation when budget_tokens None + adaptive on.
    let config = ThinkingConfig {
        enabled: true,
        budget_tokens: None,
        preserve_across_turns: false,
        reasoning_effort: Some("high".to_string()),
        adaptive: true,
    };
    assert_eq!(
        config.effective_budget(5000),
        16000,
        "high effort MUST derive to 16000 via adaptive_budget_for"
    );
}

#[test]
fn effective_budget_falls_back_to_provider_default_when_adaptive_off() {
    // PINS PRECEDENCE 3: provider_default when adaptive disabled
    // even though reasoning_effort is set.
    let config = ThinkingConfig {
        enabled: true,
        budget_tokens: None,
        preserve_across_turns: false,
        reasoning_effort: Some("high".to_string()),
        adaptive: false,
    };
    assert_eq!(
        config.effective_budget(5000),
        5000,
        "adaptive=false MUST defer to provider_default"
    );
}

#[test]
fn effective_budget_falls_back_to_provider_default_when_effort_unknown() {
    let config = ThinkingConfig {
        enabled: true,
        budget_tokens: None,
        preserve_across_turns: false,
        reasoning_effort: Some("totally-unknown-tier".to_string()),
        adaptive: true,
    };
    assert_eq!(
        config.effective_budget(5000),
        5000,
        "unknown effort tier MUST fall through to provider_default"
    );
}

#[test]
fn effective_budget_falls_back_to_provider_default_when_no_effort_set() {
    let config = ThinkingConfig {
        enabled: true,
        budget_tokens: None,
        preserve_across_turns: false,
        reasoning_effort: None,
        adaptive: true,
    };
    assert_eq!(config.effective_budget(5000), 5000);
}

#[test]
fn effective_budget_default_config_returns_provider_default() {
    // ThinkingConfig::default = {adaptive: true, all None/false}.
    // No budget + no effort → provider_default.
    let config = ThinkingConfig::default();
    assert_eq!(config.effective_budget(8192), 8192);
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — ThinkingConfig defaults
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn thinking_config_default_has_enabled_true_adaptive_true() {
    let config = ThinkingConfig::default();
    assert!(config.enabled, "thinking MUST default to enabled");
    assert!(config.adaptive, "adaptive MUST default to true (#599)");
    assert!(config.budget_tokens.is_none());
    assert!(!config.preserve_across_turns);
    assert!(config.reasoning_effort.is_none());
}

#[test]
fn thinking_config_empty_yaml_yields_documented_defaults() {
    let config: ThinkingConfig = serde_yaml::from_str("{}").expect("de");
    assert!(config.enabled);
    assert!(config.adaptive);
    assert!(config.budget_tokens.is_none());
}

#[test]
fn thinking_config_disabled_yaml_round_trips() {
    let config: ThinkingConfig = serde_yaml::from_str("enabled: false").expect("de");
    assert!(!config.enabled);
}

#[test]
fn thinking_config_full_shape_round_trips_through_yaml() {
    let yaml = r"
enabled: true
budget_tokens: 12345
preserve_across_turns: true
reasoning_effort: high
adaptive: false
";
    let config: ThinkingConfig = serde_yaml::from_str(yaml).expect("de");
    assert!(config.enabled);
    assert_eq!(config.budget_tokens, Some(12345));
    assert!(config.preserve_across_turns);
    assert_eq!(config.reasoning_effort.as_deref(), Some("high"));
    assert!(!config.adaptive);
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — ProviderConfig deserialization
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn provider_config_minimal_yaml_with_base_url_only() {
    let yaml = "base_url: https://api.example.com";
    let config: ProviderConfig = serde_yaml::from_str(yaml).expect("de");
    assert_eq!(config.base_url, "https://api.example.com");
    assert!(config.api_key.is_none());
    assert!(config.model.is_none());
    assert!(config.headers.is_empty());
    // Default ThinkingConfig.
    assert!(config.thinking.enabled);
    assert!(config.thinking.adaptive);
}

#[test]
fn provider_config_with_api_key_validates_format() {
    let yaml = r#"base_url: https://api.x.com
api_key: "sk-test-key-12345""#;
    let config: ProviderConfig = serde_yaml::from_str(yaml).expect("de");
    let api_key = config.api_key.expect("api_key MUST be Some");
    assert!(api_key.matches("sk-test-key-12345"));
}

#[test]
fn provider_config_rejects_empty_api_key_via_validator() {
    let yaml = r#"base_url: https://api.x.com
api_key: """#;
    let outcome: Result<ProviderConfig, _> = serde_yaml::from_str(yaml);
    assert!(
        outcome.is_err(),
        "empty api_key MUST be rejected at deserialize time; got {outcome:?}"
    );
}

#[test]
fn provider_config_rejects_api_key_with_control_char() {
    let yaml = "base_url: https://api.x.com\napi_key: \"sk-test\\rinjection\"";
    let outcome: Result<ProviderConfig, _> = serde_yaml::from_str(yaml);
    assert!(
        outcome.is_err(),
        "control char in api_key MUST be rejected (CRLF guard); got {outcome:?}"
    );
}

#[test]
fn provider_config_with_custom_headers_round_trips() {
    let yaml = r"
base_url: https://api.x.com
headers:
  X-Custom-Header: custom-value
  Authorization: handled-elsewhere
";
    let config: ProviderConfig = serde_yaml::from_str(yaml).expect("de");
    assert_eq!(config.headers.len(), 2);
    assert!(config
        .headers
        .matches_value("X-Custom-Header", "custom-value"));
}

#[test]
fn provider_config_with_thinking_subsection_parses() {
    let yaml = r"
base_url: https://api.x.com
thinking:
  enabled: false
  budget_tokens: 5000
";
    let config: ProviderConfig = serde_yaml::from_str(yaml).expect("de");
    assert!(!config.thinking.enabled);
    assert_eq!(config.thinking.budget_tokens, Some(5000));
}

#[test]
fn provider_config_missing_required_base_url_errors() {
    let yaml = "api_key: sk-x";
    let outcome: Result<ProviderConfig, _> = serde_yaml::from_str(yaml);
    assert!(outcome.is_err(), "base_url is required; missing MUST error");
}

#[test]
fn provider_config_with_model_field_round_trips() {
    let yaml = r"
base_url: https://api.x.com
model: claude-3-5-sonnet-20241022
";
    let config: ProviderConfig = serde_yaml::from_str(yaml).expect("de");
    assert_eq!(config.model.as_deref(), Some("claude-3-5-sonnet-20241022"));
}

#[test]
fn provider_config_clone_preserves_all_fields() {
    let yaml = r#"base_url: https://api.x.com
api_key: "sk-test"
model: "test-model"
headers:
  X-Test: value
thinking:
  budget_tokens: 1000"#;
    let original: ProviderConfig = serde_yaml::from_str(yaml).expect("de");
    let cloned = original.clone();
    assert_eq!(cloned.base_url, original.base_url);
    assert_eq!(cloned.model, original.model);
    assert_eq!(cloned.headers.len(), original.headers.len());
    assert_eq!(
        cloned.thinking.budget_tokens,
        original.thinking.budget_tokens
    );
    assert_eq!(cloned.api_key, original.api_key);
}
