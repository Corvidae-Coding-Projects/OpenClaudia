//! End-to-end tests for `config::SandboxMode` enum +
//! `config::HookPolicy` defaults + `allowed_commands`
//! allowlist YAML deserialization.
//!
//! Sprint 135 of the verification effort. Sprint 87
//! covered `HookEntry` + `HookMatcherTarget` serde +
//! basic `HookPolicy` deserialization; this file pins
//! the `SandboxMode` 3-variant `snake_case` wire shape,
//! the `FullSandbox` default, and the `HookPolicy`
//! `allowed_commands` None vs Some-empty vs Some-populated
//! semantics.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::config::{HookPolicy, SandboxMode};

// ───────────────────────────────────────────────────────────────────────────
// Section A — SandboxMode default
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn sandbox_mode_default_is_full_sandbox() {
    // Repository hooks must be OS-contained unless the host operator
    // separately makes an explicit trust decision at process startup.
    assert_eq!(SandboxMode::default(), SandboxMode::FullSandbox);
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — SandboxMode serde snake_case
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn sandbox_mode_serde_uses_snake_case_form_via_yaml() {
    // None variant
    let yaml = "none";
    let mode: SandboxMode = serde_yaml::from_str(yaml).expect("none parses");
    assert_eq!(mode, SandboxMode::None);

    // EnvScrub
    let yaml = "env_scrub";
    let mode: SandboxMode = serde_yaml::from_str(yaml).expect("env_scrub parses");
    assert_eq!(mode, SandboxMode::EnvScrub);

    // FullSandbox
    let yaml = "full_sandbox";
    let mode: SandboxMode = serde_yaml::from_str(yaml).expect("full_sandbox parses");
    assert_eq!(mode, SandboxMode::FullSandbox);
}

#[test]
fn sandbox_mode_serde_rejects_pascal_case_wire_form() {
    // PINS WIRE: PascalCase NOT accepted (serde rename_all =
    // snake_case is strict).
    let outcome: Result<SandboxMode, _> = serde_yaml::from_str("EnvScrub");
    assert!(outcome.is_err(), "PascalCase EnvScrub MUST be rejected");
}

#[test]
fn sandbox_mode_serde_rejects_unknown_variant() {
    let outcome: Result<SandboxMode, _> = serde_yaml::from_str("unknown_mode");
    assert!(outcome.is_err());
}

#[test]
fn sandbox_mode_eq_distinguishes_all_3_variants() {
    assert_ne!(SandboxMode::None, SandboxMode::EnvScrub);
    assert_ne!(SandboxMode::EnvScrub, SandboxMode::FullSandbox);
    assert_ne!(SandboxMode::None, SandboxMode::FullSandbox);
}

#[test]
fn sandbox_mode_clone_preserves_variant() {
    let original = SandboxMode::FullSandbox;
    let cloned = original.clone();
    assert_eq!(cloned, SandboxMode::FullSandbox);
    // Use original post-clone to make the Clone non-redundant.
    assert_eq!(original, SandboxMode::FullSandbox);
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — HookPolicy::default
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn hook_policy_default_allowed_commands_is_none() {
    // PINS DOC: None means backwards-compatible allow-all
    // legacy mode (with deprecation warning emitted once).
    let policy = HookPolicy::default();
    assert!(
        policy.allowed_commands.is_none(),
        "Default allowed_commands MUST be None (allow-all)"
    );
}

#[test]
fn hook_policy_default_sandbox_is_full_sandbox() {
    let policy = HookPolicy::default();
    assert_eq!(policy.sandbox, SandboxMode::FullSandbox);
}

#[test]
fn hook_policy_empty_yaml_object_matches_default() {
    let policy: HookPolicy = serde_yaml::from_str("{}").expect("parse empty");
    assert!(policy.allowed_commands.is_none());
    assert_eq!(policy.sandbox, SandboxMode::FullSandbox);
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — HookPolicy allowed_commands variants
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn hook_policy_allowed_commands_empty_array_is_some_empty_deny_all() {
    // PINS DOC: Some([]) → deny every command hook.
    let yaml = "allowed_commands: []";
    let policy: HookPolicy = serde_yaml::from_str(yaml).expect("parse");
    let allowed = policy.allowed_commands.expect("Some([])");
    assert!(allowed.is_empty(), "deny-all allowlist MUST be Some(empty)");
}

#[test]
fn hook_policy_allowed_commands_populated_yaml_round_trips() {
    let yaml = "allowed_commands:\n  - python\n  - node\n  - jq";
    let policy: HookPolicy = serde_yaml::from_str(yaml).expect("parse");
    let allowed = policy.allowed_commands.expect("Some");
    assert_eq!(allowed.len(), 3);
    assert!(allowed.contains("python"));
    assert!(allowed.contains("node"));
    assert!(allowed.contains("jq"));
}

#[test]
fn hook_policy_allowed_commands_dedup_via_hashset() {
    // PINS HashSet semantics: duplicate entries dedup.
    let yaml = "allowed_commands:\n  - python\n  - python\n  - python";
    let policy: HookPolicy = serde_yaml::from_str(yaml).expect("parse");
    let allowed = policy.allowed_commands.expect("Some");
    assert_eq!(allowed.len(), 1, "HashSet MUST dedup duplicates");
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — HookPolicy sandbox override
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn hook_policy_with_sandbox_none_overrides_full_sandbox_default() {
    let yaml = "sandbox: none";
    let policy: HookPolicy = serde_yaml::from_str(yaml).expect("parse");
    assert_eq!(policy.sandbox, SandboxMode::None);
}

#[test]
fn hook_policy_with_sandbox_full_sandbox_overrides_default() {
    let yaml = "sandbox: full_sandbox";
    let policy: HookPolicy = serde_yaml::from_str(yaml).expect("parse");
    assert_eq!(policy.sandbox, SandboxMode::FullSandbox);
}

#[test]
fn hook_policy_with_explicit_env_scrub_is_a_weaker_explicit_mode() {
    let yaml = "sandbox: env_scrub";
    let policy: HookPolicy = serde_yaml::from_str(yaml).expect("parse");
    assert_eq!(policy.sandbox, SandboxMode::EnvScrub);
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — HookPolicy combined fields
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn hook_policy_with_both_fields_populates_both() {
    let yaml = r"
allowed_commands: [python, node]
sandbox: full_sandbox
";
    let policy: HookPolicy = serde_yaml::from_str(yaml).expect("parse");
    let allowed = policy.allowed_commands.expect("Some");
    assert_eq!(allowed.len(), 2);
    assert_eq!(policy.sandbox, SandboxMode::FullSandbox);
}

#[test]
fn hook_policy_clone_preserves_both_fields() {
    let yaml = "allowed_commands: [python]\nsandbox: env_scrub";
    let original: HookPolicy = serde_yaml::from_str(yaml).expect("parse");
    let cloned = original.clone();
    assert_eq!(
        cloned
            .allowed_commands
            .as_ref()
            .map(std::collections::HashSet::len),
        original
            .allowed_commands
            .as_ref()
            .map(std::collections::HashSet::len)
    );
    assert_eq!(cloned.sandbox, original.sandbox);
}

#[test]
fn hook_policy_debug_format_includes_documented_fields() {
    let policy = HookPolicy::default();
    let dbg = format!("{policy:?}");
    assert!(dbg.contains("allowed_commands"));
    assert!(dbg.contains("sandbox"));
}
