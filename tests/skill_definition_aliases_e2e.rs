//! End-to-end tests for `skills::SkillDefinition` serde
//! aliases — `when_to_use` ↔ `whenToUse`, `argument-hint`
//! ↔ `argument_hint`, plus the optional CC-parity fields
//! `model`, `effort`, `paths` field-level serde shape.
//!
//! Sprint 198 of the verification effort. Sprint 116
//! covered the basic `SkillDefinition` fields; this file
//! pins each documented alias and rename specifically.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::skills::SkillDefinition;
use serde_json::json;

fn parse(value: serde_json::Value) -> SkillDefinition {
    serde_json::from_value(value).expect("deserialize")
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Required fields
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn name_and_description_required_for_deserialize() {
    let skill = parse(json!({
        "name": "test_skill_198",
        "description": "a test"
    }));
    assert_eq!(skill.name, "test_skill_198");
    assert_eq!(skill.description, "a test");
}

#[test]
fn missing_name_rejected_on_deserialize() {
    let outcome: Result<SkillDefinition, _> = serde_json::from_value(json!({
        "description": "no name"
    }));
    assert!(outcome.is_err(), "missing name MUST be rejected");
}

#[test]
fn missing_description_rejected_on_deserialize() {
    let outcome: Result<SkillDefinition, _> = serde_json::from_value(json!({
        "name": "no_desc"
    }));
    assert!(outcome.is_err(), "missing description MUST be rejected");
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — when_to_use canonical name + whenToUse alias
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn when_to_use_snake_case_canonical_accepted() {
    // PINS DOC: canonical is snake_case via rename = "when_to_use".
    let skill = parse(json!({
        "name": "x",
        "description": "y",
        "when_to_use": "when running tests"
    }));
    assert_eq!(skill.when_to_use.as_deref(), Some("when running tests"));
}

#[test]
fn when_to_use_camel_case_alias_accepted() {
    // PINS ALIAS: alias = "whenToUse" for CC parity.
    let skill = parse(json!({
        "name": "x",
        "description": "y",
        "whenToUse": "when running tests"
    }));
    assert_eq!(skill.when_to_use.as_deref(), Some("when running tests"));
}

#[test]
fn when_to_use_absent_yields_none() {
    let skill = parse(json!({
        "name": "x",
        "description": "y"
    }));
    assert!(skill.when_to_use.is_none());
}

#[test]
fn when_to_use_serializes_with_canonical_snake_case_name() {
    let skill = SkillDefinition {
        name: "x".to_string(),
        description: "y".to_string(),
        allowed_tools: None,
        when_to_use: Some("hint".to_string()),
        argument_hint: None,
        model: None,
        effort: None,
        paths: None,
        hooks: None,
        user_invocable: false,
        prompt: String::new(),
        path: std::path::PathBuf::new(),
    };
    let json = serde_json::to_value(&skill).expect("ser");
    // Canonical wire form is snake_case.
    assert!(
        json.get("when_to_use").is_some(),
        "canonical serialized form MUST be 'when_to_use'; got {json:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — argument-hint kebab-case rename + argument_hint alias
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn argument_hint_kebab_case_canonical_accepted() {
    // PINS DOC: canonical is "argument-hint".
    let skill = parse(json!({
        "name": "x",
        "description": "y",
        "argument-hint": "<file>"
    }));
    assert_eq!(skill.argument_hint.as_deref(), Some("<file>"));
}

#[test]
fn argument_hint_snake_case_alias_accepted() {
    // PINS ALIAS: alias = "argument_hint" backward compat.
    let skill = parse(json!({
        "name": "x",
        "description": "y",
        "argument_hint": "<file>"
    }));
    assert_eq!(skill.argument_hint.as_deref(), Some("<file>"));
}

#[test]
fn argument_hint_absent_yields_none() {
    let skill = parse(json!({"name": "x", "description": "y"}));
    assert!(skill.argument_hint.is_none());
}

#[test]
fn argument_hint_serializes_with_canonical_kebab_case() {
    let skill = SkillDefinition {
        name: "x".to_string(),
        description: "y".to_string(),
        allowed_tools: None,
        when_to_use: None,
        argument_hint: Some("<f>".to_string()),
        model: None,
        effort: None,
        paths: None,
        hooks: None,
        user_invocable: false,
        prompt: String::new(),
        path: std::path::PathBuf::new(),
    };
    let json = serde_json::to_value(&skill).expect("ser");
    assert!(
        json.get("argument-hint").is_some(),
        "canonical wire MUST be 'argument-hint'; got {json:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Optional CC-parity fields default behavior
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn allowed_tools_absent_yields_none() {
    let skill = parse(json!({"name": "x", "description": "y"}));
    assert!(skill.allowed_tools.is_none());
}

#[test]
fn allowed_tools_with_list_preserves_order() {
    let skill = parse(json!({
        "name": "x",
        "description": "y",
        "allowed_tools": ["bash", "read_file", "edit_file"]
    }));
    let tools = skill.allowed_tools.expect("Some");
    assert_eq!(tools.len(), 3);
    assert_eq!(tools[0], "bash");
    assert_eq!(tools[2], "edit_file");
}

#[test]
fn allowed_tools_accepts_hyphenated_scalar_alias() {
    let skill = parse(json!({
        "name": "x",
        "description": "y",
        "allowed-tools": "Bash(git add *) Bash(git status *)"
    }));
    assert_eq!(
        skill.allowed_tools.as_deref(),
        Some(
            [
                "Bash(git add *)".to_string(),
                "Bash(git status *)".to_string()
            ]
            .as_slice()
        )
    );
}

#[test]
fn model_field_serde_round_trip() {
    let skill = parse(json!({
        "name": "x",
        "description": "y",
        "model": "claude-opus-4"
    }));
    assert_eq!(skill.model.as_deref(), Some("claude-opus-4"));
}

#[test]
fn effort_field_accepts_low_medium_high() {
    for tier in ["low", "medium", "high"] {
        let skill = parse(json!({
            "name": "x",
            "description": "y",
            "effort": tier
        }));
        assert_eq!(skill.effort.as_deref(), Some(tier));
    }
}

#[test]
fn effort_field_accepts_unknown_values_for_forward_compat() {
    // PINS DOC: effort is String, not enum — unknown values pass through.
    let skill = parse(json!({
        "name": "x",
        "description": "y",
        "effort": "future-tier-xyz"
    }));
    assert_eq!(skill.effort.as_deref(), Some("future-tier-xyz"));
}

#[test]
fn paths_glob_list_round_trips() {
    let skill = parse(json!({
        "name": "x",
        "description": "y",
        "paths": ["**/*.rs", "tests/*.rs"]
    }));
    let paths = skill.paths.expect("Some");
    assert_eq!(paths.len(), 2);
    assert_eq!(paths[0], "**/*.rs");
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Combined: both alias forms in same document
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn both_alias_forms_in_separate_docs_yield_identical_skill() {
    let canonical = parse(json!({
        "name": "x",
        "description": "y",
        "when_to_use": "hint",
        "argument-hint": "<f>"
    }));
    let alias = parse(json!({
        "name": "x",
        "description": "y",
        "whenToUse": "hint",
        "argument_hint": "<f>"
    }));
    assert_eq!(canonical.when_to_use, alias.when_to_use);
    assert_eq!(canonical.argument_hint, alias.argument_hint);
}

#[test]
fn round_trip_serialize_then_deserialize_preserves_aliased_fields() {
    let original = parse(json!({
        "name": "x",
        "description": "y",
        "whenToUse": "via alias",
        "argument_hint": "<f>"
    }));
    let serialized = serde_json::to_value(&original).expect("ser");
    let back: SkillDefinition = serde_json::from_value(serialized).expect("de");
    assert_eq!(back.when_to_use, original.when_to_use);
    assert_eq!(back.argument_hint, original.argument_hint);
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Unknown schema fields are rejected
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn extra_unknown_fields_rejected_when_deserializing() {
    let outcome: Result<SkillDefinition, _> = serde_json::from_value(json!({
        "name": "x",
        "description": "y",
        "unknown_future_field": "ignored",
        "another_extra": 42
    }));
    assert!(outcome.is_err(), "unknown fields MUST be rejected");
}
