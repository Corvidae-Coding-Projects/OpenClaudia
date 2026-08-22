//! End-to-end tests for `GuardrailsConfig` (+ `BlastRadius` /
//! `DiffMonitor` / `QualityGates`) + `SessionConfig` /
//! `TokenTrackingConfig` defaults + YAML deserialization.
//!
//! Sprint 57 of the verification effort.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::config::{
    BlastRadiusConfig, DiffMonitorConfig, GuardrailAction, GuardrailMode, GuardrailsConfig,
    MemoryConfig, ProxyConfig, QualityCheck, QualityGatesConfig, RunAfter, SessionConfig,
    TokenTrackingConfig,
};

// ───────────────────────────────────────────────────────────────────────────
// Section A — GuardrailMode + GuardrailAction + RunAfter enums
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn guardrail_mode_default_is_advisory() {
    assert_eq!(GuardrailMode::default(), GuardrailMode::Advisory);
}

#[test]
fn guardrail_mode_display_matches_serde_lowercase() {
    assert_eq!(format!("{}", GuardrailMode::Strict), "strict");
    assert_eq!(format!("{}", GuardrailMode::Advisory), "advisory");
}

#[test]
fn guardrail_mode_yaml_round_trips_lowercase() {
    let s: GuardrailMode = serde_yaml::from_str("strict").expect("parse");
    assert_eq!(s, GuardrailMode::Strict);
    let a: GuardrailMode = serde_yaml::from_str("advisory").expect("parse");
    assert_eq!(a, GuardrailMode::Advisory);
}

#[test]
fn guardrail_action_default_is_warn() {
    assert_eq!(GuardrailAction::default(), GuardrailAction::Warn);
}

#[test]
fn guardrail_action_display_matches_documented_strings() {
    assert_eq!(format!("{}", GuardrailAction::Warn), "warn");
    assert_eq!(format!("{}", GuardrailAction::Block), "block");
    assert_eq!(
        format!("{}", GuardrailAction::InjectFindings),
        "inject_findings"
    );
}

#[test]
fn guardrail_action_yaml_uses_snake_case() {
    let block: GuardrailAction = serde_yaml::from_str("block").expect("parse");
    assert_eq!(block, GuardrailAction::Block);
    let inj: GuardrailAction = serde_yaml::from_str("inject_findings").expect("parse");
    assert_eq!(inj, GuardrailAction::InjectFindings);
}

#[test]
fn run_after_default_is_every_turn() {
    assert_eq!(RunAfter::default(), RunAfter::EveryTurn);
}

#[test]
fn run_after_display_matches_documented_snake_case() {
    assert_eq!(format!("{}", RunAfter::EveryEdit), "every_edit");
    assert_eq!(format!("{}", RunAfter::EveryTurn), "every_turn");
    assert_eq!(format!("{}", RunAfter::OnCommit), "on_commit");
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — GuardrailsConfig deserialization
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn guardrails_default_has_no_subconfigs_set() {
    let cfg = GuardrailsConfig::default();
    assert!(cfg.blast_radius.is_none());
    assert!(cfg.diff_monitor.is_none());
    assert!(cfg.quality_gates.is_none());
}

#[test]
fn guardrails_empty_yaml_yields_default() {
    let cfg: GuardrailsConfig = serde_yaml::from_str("{}").expect("parse");
    assert!(cfg.blast_radius.is_none());
    assert!(cfg.diff_monitor.is_none());
    assert!(cfg.quality_gates.is_none());
}

#[test]
fn guardrails_with_all_three_subconfigs_round_trips() {
    let yaml = r"
blast_radius:
  enabled: true
  mode: strict
  allowed_paths:
    - 'src/**'
  denied_paths:
    - '.env'
  max_files_per_turn: 5
  max_lines_per_run: 200
  max_tool_calls_per_run: 50
  max_mutations_per_run: 20
diff_monitor:
  enabled: true
  max_lines_changed: 200
  max_files_changed: 8
  action: block
quality_gates:
  enabled: true
  run_after: on_commit
  fail_action: block
  checks:
    - name: 'cargo fmt'
      command: 'cargo fmt --check'
      required: true
  timeout_seconds: 60
";
    let cfg: GuardrailsConfig = serde_yaml::from_str(yaml).expect("parse");
    let br = cfg.blast_radius.expect("blast_radius");
    assert!(br.enabled);
    assert_eq!(br.mode, GuardrailMode::Strict);
    assert_eq!(br.allowed_paths, vec!["src/**".to_string()]);
    assert_eq!(br.denied_paths, vec![".env".to_string()]);
    assert_eq!(br.max_files_per_run.map(std::num::NonZeroU32::get), Some(5));
    assert_eq!(
        br.max_lines_per_run.map(std::num::NonZeroU32::get),
        Some(200)
    );
    assert_eq!(
        br.max_tool_calls_per_run.map(std::num::NonZeroU32::get),
        Some(50)
    );
    assert_eq!(
        br.max_mutations_per_run.map(std::num::NonZeroU32::get),
        Some(20)
    );

    let dm = cfg.diff_monitor.expect("diff_monitor");
    assert!(dm.enabled);
    assert_eq!(dm.max_lines_changed, 200);
    assert_eq!(dm.max_files_changed, 8);
    assert_eq!(dm.action, GuardrailAction::Block);

    let qg = cfg.quality_gates.expect("quality_gates");
    assert!(qg.enabled);
    assert_eq!(qg.run_after, RunAfter::OnCommit);
    assert_eq!(qg.fail_action, GuardrailAction::Block);
    assert_eq!(qg.checks.len(), 1);
    assert_eq!(qg.checks[0].name, "cargo fmt");
    assert_eq!(qg.checks[0].command, "cargo fmt --check");
    assert!(qg.checks[0].required);
    assert_eq!(qg.timeout_seconds, 60);
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — BlastRadiusConfig defaults
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn blast_radius_default_is_disabled_advisory_and_has_no_run_limits() {
    let cfg = BlastRadiusConfig::default();
    assert!(!cfg.enabled);
    assert_eq!(cfg.mode, GuardrailMode::Advisory);
    assert!(cfg.allowed_paths.is_empty());
    assert!(cfg.denied_paths.is_empty());
    assert!(cfg.max_files_per_run.is_none());
    assert!(cfg.max_lines_per_run.is_none());
    assert!(cfg.max_tool_calls_per_run.is_none());
    assert!(cfg.max_mutations_per_run.is_none());
}

#[test]
fn blast_radius_zero_and_ambiguous_legacy_limits_fail_deserialization() {
    let zero = serde_yaml::from_str::<BlastRadiusConfig>("max_files_per_run: 0")
        .expect_err("zero must not ambiguously mean unlimited");
    assert!(zero.to_string().contains("nonzero"), "{zero}");

    let duplicate =
        serde_yaml::from_str::<BlastRadiusConfig>("max_files_per_run: 2\nmax_files_per_turn: 3\n")
            .expect_err("legacy and canonical keys together are ambiguous");
    assert!(
        duplicate.to_string().contains("duplicate field"),
        "{duplicate}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — DiffMonitorConfig defaults + boundary
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn diff_monitor_default_uses_documented_thresholds() {
    let cfg = DiffMonitorConfig::default();
    assert!(!cfg.enabled);
    assert_eq!(cfg.max_lines_changed, 500);
    assert_eq!(cfg.max_files_changed, 10);
    assert_eq!(cfg.action, GuardrailAction::Warn);
}

#[test]
fn diff_monitor_partial_yaml_uses_defaults_for_unset_fields() {
    let cfg: DiffMonitorConfig = serde_yaml::from_str("enabled: true").expect("parse");
    assert!(cfg.enabled);
    assert_eq!(cfg.max_lines_changed, 500, "unset field MUST default");
    assert_eq!(cfg.max_files_changed, 10);
    assert_eq!(cfg.action, GuardrailAction::Warn);
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — QualityGatesConfig defaults + checks
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn quality_gates_default_uses_documented_timeout() {
    let cfg = QualityGatesConfig::default();
    assert!(!cfg.enabled);
    assert_eq!(cfg.run_after, RunAfter::EveryTurn);
    assert_eq!(cfg.fail_action, GuardrailAction::Warn);
    assert!(cfg.checks.is_empty());
    assert_eq!(cfg.timeout_seconds, 120);
}

#[test]
fn quality_check_required_field_defaults_to_true() {
    // QualityCheck.required uses `default = "default_true"`,
    // so omitting it must yield true.
    let yaml = r"
name: 'check'
command: 'echo'
";
    let check: QualityCheck = serde_yaml::from_str(yaml).expect("parse");
    assert!(check.required, "required MUST default to true");
}

#[test]
fn quality_check_required_explicit_false_round_trips() {
    let yaml = r"
name: 'optional-check'
command: 'echo'
required: false
";
    let check: QualityCheck = serde_yaml::from_str(yaml).expect("parse");
    assert!(!check.required);
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — SessionConfig defaults
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn session_config_default_uses_documented_values() {
    let cfg = SessionConfig::default();
    assert_eq!(cfg.timeout_minutes, 30, "default timeout MUST be 30 min");
    assert_eq!(
        cfg.persist_path,
        std::path::PathBuf::from(".openclaudia/session"),
        "default persist path MUST be .openclaudia/session"
    );
    assert_eq!(cfg.max_turns, 0, "max_turns=0 MUST mean unlimited");
    assert!(cfg.token_tracking.enabled);
}

#[test]
fn session_config_empty_yaml_yields_default() {
    let cfg: SessionConfig = serde_yaml::from_str("{}").expect("parse");
    assert_eq!(cfg.timeout_minutes, 30);
    assert_eq!(cfg.max_turns, 0);
}

#[test]
fn session_config_yaml_round_trips_named_fields() {
    let yaml = r"
timeout_minutes: 60
persist_path: /tmp/custom-session
max_turns: 10
";
    let cfg: SessionConfig = serde_yaml::from_str(yaml).expect("parse");
    assert_eq!(cfg.timeout_minutes, 60);
    assert_eq!(
        cfg.persist_path,
        std::path::PathBuf::from("/tmp/custom-session")
    );
    assert_eq!(cfg.max_turns, 10);
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — TokenTrackingConfig defaults
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn token_tracking_default_uses_documented_values() {
    let cfg = TokenTrackingConfig::default();
    assert!(cfg.enabled, "default MUST be enabled");
    assert!(cfg.log_usage, "default MUST log usage");
    assert!(
        (cfg.warn_threshold - 0.75_f32).abs() < f32::EPSILON,
        "default warn_threshold MUST be 0.75; got {}",
        cfg.warn_threshold
    );
    assert_eq!(cfg.max_output_tokens, 0, "0 MUST mean provider default");
}

#[test]
fn token_tracking_partial_yaml_preserves_set_overrides() {
    let yaml = "warn_threshold: 0.9\nmax_output_tokens: 4000";
    let cfg: TokenTrackingConfig = serde_yaml::from_str(yaml).expect("parse");
    assert!(cfg.enabled, "enabled MUST default to true");
    assert!(cfg.log_usage);
    assert!((cfg.warn_threshold - 0.9_f32).abs() < f32::EPSILON);
    assert_eq!(cfg.max_output_tokens, 4000);
}

// ───────────────────────────────────────────────────────────────────────────
// Section H — MemoryConfig defaults + authenticated selector / legacy path
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn memory_config_default_has_no_team_store_path() {
    let cfg = MemoryConfig::default();
    assert!(cfg.team_id.is_none());
    assert!(cfg.team_memory_path.is_none());
}

#[test]
fn memory_config_accepts_only_a_strict_team_selector() {
    let yaml = "team_id: team-0123456789abcdef0123456789abcdef";
    let cfg: MemoryConfig = serde_yaml::from_str(yaml).expect("parse");
    assert_eq!(
        cfg.team_id
            .as_ref()
            .map(openclaudia::team_memory::TeamId::as_str),
        Some("team-0123456789abcdef0123456789abcdef")
    );
    assert!(serde_yaml::from_str::<MemoryConfig>("team_id: /shared/memory.db").is_err());
}

#[test]
fn memory_config_yaml_sets_team_path_when_specified() {
    let yaml = "team_memory_path: /shared/memory.db";
    let cfg: MemoryConfig = serde_yaml::from_str(yaml).expect("parse");
    assert_eq!(
        cfg.team_memory_path.as_deref(),
        Some(std::path::Path::new("/shared/memory.db"))
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section I — ProxyConfig defaults
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn proxy_config_default_uses_documented_target_and_localhost() {
    let cfg = ProxyConfig::default();
    // The default host is documented as 127.0.0.1 (localhost
    // only). port is the documented default (8080-ish).
    assert!(
        cfg.host == "127.0.0.1" || cfg.host == "localhost",
        "default host MUST be loopback; got {}",
        cfg.host
    );
    assert!(cfg.port > 0, "default port MUST be set; got {}", cfg.port);
    assert!(
        !cfg.target.is_empty(),
        "default target MUST be set; got {:?}",
        cfg.target
    );
}
