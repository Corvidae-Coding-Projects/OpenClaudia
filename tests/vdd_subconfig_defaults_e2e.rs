//! End-to-end tests for `config::VddAdversaryConfig`,
//! `config::VddStaticAnalysis`, `config::VddTracking`,
//! and `config::VddThresholds` defaults + YAML round-trip.
//!
//! Sprint 134 of the verification effort. Sprint 100
//! covered `vdd::review::VddSession` lifecycle; this file
//! pins the configuration sub-types — defaults for
//! adversary provider/temperature/timeout, static-analysis
//! enabled-by-default, tracking persist-by-default, and
//! threshold caps.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::config::{VddAdversaryConfig, VddStaticAnalysis, VddThresholds, VddTracking};
use std::path::PathBuf;

// ───────────────────────────────────────────────────────────────────────────
// Section A — VddAdversaryConfig defaults
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn vdd_adversary_config_default_provider_is_google() {
    // PINS DEFAULT: Google as the cross-provider adversary
    // (provider MUST differ from proxy.target for genuine
    // cross-model critique).
    let cfg = VddAdversaryConfig::default();
    assert_eq!(cfg.provider, "google");
}

#[test]
fn vdd_adversary_config_default_temperature_is_0_3() {
    // PINS DEFAULT: lower temperature for deterministic
    // critique.
    let cfg = VddAdversaryConfig::default();
    assert!(
        (cfg.temperature - 0.3).abs() < 1e-6,
        "default temperature MUST be ≈0.3; got {}",
        cfg.temperature
    );
}

#[test]
fn vdd_adversary_config_default_max_tokens_is_4096() {
    let cfg = VddAdversaryConfig::default();
    assert_eq!(cfg.max_tokens, 4096);
}

#[test]
fn vdd_adversary_config_default_request_timeout_is_120_seconds() {
    // PINS DEFAULT #496: 120s — generous for reasoning
    // models but fails fast when provider is down.
    let cfg = VddAdversaryConfig::default();
    assert_eq!(cfg.request_timeout_seconds, 120);
}

#[test]
fn vdd_adversary_config_default_model_and_api_key_are_none() {
    let cfg = VddAdversaryConfig::default();
    assert!(cfg.model.is_none());
    assert!(cfg.api_key.is_none());
}

#[test]
fn vdd_adversary_config_yaml_empty_object_matches_default() {
    let yaml_cfg: VddAdversaryConfig = serde_yaml::from_str("{}").expect("parse");
    let default_cfg = VddAdversaryConfig::default();
    assert_eq!(yaml_cfg.provider, default_cfg.provider);
    assert!((yaml_cfg.temperature - default_cfg.temperature).abs() < 1e-6);
    assert_eq!(yaml_cfg.max_tokens, default_cfg.max_tokens);
    assert_eq!(
        yaml_cfg.request_timeout_seconds,
        default_cfg.request_timeout_seconds
    );
}

#[test]
fn vdd_adversary_config_yaml_overrides_provider() {
    let yaml = "provider: openai";
    let cfg: VddAdversaryConfig = serde_yaml::from_str(yaml).expect("parse");
    assert_eq!(cfg.provider, "openai");
}

#[test]
fn vdd_adversary_config_clone_preserves_all_fields() {
    let original = VddAdversaryConfig::default();
    let cloned = original.clone();
    assert_eq!(cloned.provider, original.provider);
    assert!((cloned.temperature - original.temperature).abs() < 1e-6);
    assert_eq!(cloned.max_tokens, original.max_tokens);
    assert_eq!(
        cloned.request_timeout_seconds,
        original.request_timeout_seconds
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — VddStaticAnalysis defaults
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn vdd_static_analysis_default_is_enabled() {
    let cfg = VddStaticAnalysis::default();
    assert!(cfg.enabled, "static_analysis enabled-by-default");
}

#[test]
fn vdd_static_analysis_default_auto_detect_is_true() {
    let cfg = VddStaticAnalysis::default();
    assert!(cfg.auto_detect, "auto_detect on by default");
}

#[test]
fn vdd_static_analysis_default_commands_is_empty_vec() {
    let cfg = VddStaticAnalysis::default();
    assert!(cfg.commands.is_empty());
}

#[test]
fn vdd_static_analysis_default_timeout_is_120_seconds() {
    let cfg = VddStaticAnalysis::default();
    assert_eq!(cfg.timeout_seconds, 120);
}

#[test]
fn vdd_static_analysis_yaml_can_disable() {
    let yaml = "enabled: false";
    let cfg: VddStaticAnalysis = serde_yaml::from_str(yaml).expect("parse");
    assert!(!cfg.enabled);
    // auto_detect default still true (independent field).
    assert!(cfg.auto_detect);
}

#[test]
fn vdd_static_analysis_yaml_with_commands_list() {
    let yaml = "commands:\n  - cargo test\n  - cargo clippy";
    let cfg: VddStaticAnalysis = serde_yaml::from_str(yaml).expect("parse");
    assert_eq!(cfg.commands.len(), 2);
    assert_eq!(cfg.commands[0], "cargo test");
    assert_eq!(cfg.commands[1], "cargo clippy");
}

#[test]
fn vdd_static_analysis_yaml_empty_object_matches_default() {
    let cfg: VddStaticAnalysis = serde_yaml::from_str("{}").expect("parse");
    let default_cfg = VddStaticAnalysis::default();
    assert_eq!(cfg.enabled, default_cfg.enabled);
    assert_eq!(cfg.auto_detect, default_cfg.auto_detect);
    assert_eq!(cfg.commands, default_cfg.commands);
    assert_eq!(cfg.timeout_seconds, default_cfg.timeout_seconds);
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — VddTracking defaults
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn vdd_tracking_default_persist_is_true() {
    let cfg = VddTracking::default();
    assert!(cfg.persist);
}

#[test]
fn vdd_tracking_default_path_is_openclaudia_vdd() {
    let cfg = VddTracking::default();
    assert_eq!(cfg.path, PathBuf::from(".openclaudia/vdd"));
}

#[test]
fn vdd_tracking_default_log_adversary_responses_is_false() {
    let cfg = VddTracking::default();
    assert!(!cfg.log_adversary_responses);
}

#[test]
fn vdd_tracking_defaults_to_retry_safe_verified_finding_projection() {
    let cfg = VddTracking::default();
    assert!(cfg.promote_verified_findings);
    assert_eq!(cfg.retention_days, 30);
}

#[test]
fn vdd_tracking_yaml_can_override_path() {
    let yaml = "path: /tmp/custom-vdd";
    let cfg: VddTracking = serde_yaml::from_str(yaml).expect("parse");
    assert_eq!(cfg.path, PathBuf::from("/tmp/custom-vdd"));
}

#[test]
fn vdd_tracking_yaml_can_disable_persist() {
    let yaml = "persist: false";
    let cfg: VddTracking = serde_yaml::from_str(yaml).expect("parse");
    assert!(!cfg.persist);
}

#[test]
fn vdd_tracking_clone_preserves_all_fields() {
    let original = VddTracking::default();
    let cloned = original.clone();
    assert_eq!(cloned.persist, original.persist);
    assert_eq!(cloned.path, original.path);
    assert_eq!(
        cloned.promote_verified_findings,
        original.promote_verified_findings
    );
    assert_eq!(cloned.retention_days, original.retention_days);
    assert_eq!(
        cloned.log_adversary_responses,
        original.log_adversary_responses
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — VddThresholds defaults
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn vdd_thresholds_default_max_iterations_is_positive() {
    let cfg = VddThresholds::default();
    assert!(cfg.max_iterations > 0, "max_iterations MUST be > 0");
}

#[test]
fn vdd_thresholds_default_min_iterations_is_below_max() {
    let cfg = VddThresholds::default();
    assert!(
        cfg.min_iterations <= cfg.max_iterations,
        "min_iterations ({}) MUST be <= max_iterations ({})",
        cfg.min_iterations,
        cfg.max_iterations
    );
}

#[test]
fn vdd_thresholds_default_false_positive_rate_in_unit_range() {
    let cfg = VddThresholds::default();
    assert!(
        (0.0..=1.0).contains(&cfg.false_positive_rate),
        "false_positive_rate MUST be in [0.0, 1.0]; got {}",
        cfg.false_positive_rate
    );
}

#[test]
fn vdd_thresholds_yaml_round_trip_preserves_overrides() {
    let yaml = r"
max_iterations: 25
false_positive_rate: 0.5
min_iterations: 3
";
    let cfg: VddThresholds = serde_yaml::from_str(yaml).expect("parse");
    assert_eq!(cfg.max_iterations, 25);
    assert!((cfg.false_positive_rate - 0.5).abs() < 1e-6);
    assert_eq!(cfg.min_iterations, 3);
}

#[test]
fn vdd_thresholds_clone_preserves_all_fields() {
    let original = VddThresholds::default();
    let cloned = original.clone();
    assert_eq!(cloned.max_iterations, original.max_iterations);
    assert!((cloned.false_positive_rate - original.false_positive_rate).abs() < 1e-6);
    assert_eq!(cloned.min_iterations, original.min_iterations);
}
