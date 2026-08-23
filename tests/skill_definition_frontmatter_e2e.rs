//! End-to-end tests for `skills::parse_skill_file` frontmatter
//! field-by-field handling (CC-parity aliases, optional fields,
//! defaults) + env-var constants.
//!
//! Sprint 108 of the verification effort. Sprint 31
//! (`skills_loader_e2e`) covered the path-matcher + walker;
//! sprint 41 (`plugin_skill_security_e2e`) covered the parser
//! robustness (missing frontmatter, BOM, CRLF); this file
//! pins the FIELD-level frontmatter handling that CC expects
//! (`when_to_use` / `whenToUse` alias, `argument-hint` /
//! `argument_hint`, `model`, `effort`, `paths`, `hooks`,
//! `user_invocable` default).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::skills::{
    parse_skill_file, SkillDefinition, DISABLE_POLICY_SKILLS_ENV, MANAGED_PATH_ENV,
};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

// ───────────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────────

fn write_skill(dir: &Path, name: &str, frontmatter: &str, body: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    let content = format!("---\n{frontmatter}\n---\n{body}\n");
    fs::write(&path, content).expect("write");
    path
}

fn parse_or_fail(path: &Path) -> SkillDefinition {
    parse_skill_file(path).expect("parse")
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Required fields (name + description)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn parse_minimal_skill_with_name_and_description_succeeds() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_skill(
        tmp.path(),
        "min.md",
        "name: minimal\ndescription: a minimal skill",
        "body content",
    );
    let skill = parse_or_fail(&path);
    assert_eq!(skill.name, "minimal");
    assert_eq!(skill.description, "a minimal skill");
}

#[test]
fn parse_skill_captures_body_verbatim_after_frontmatter() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_skill(
        tmp.path(),
        "s.md",
        "name: x\ndescription: y",
        "# Heading\n\nBody paragraph 1.\n\nParagraph 2.",
    );
    let skill = parse_or_fail(&path);
    assert!(skill.prompt.contains("Heading"));
    assert!(skill.prompt.contains("Body paragraph 1"));
    assert!(skill.prompt.contains("Paragraph 2"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — when_to_use field (CC alias whenToUse)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn parse_skill_with_snake_case_when_to_use_field() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_skill(
        tmp.path(),
        "s.md",
        "name: x\ndescription: y\nwhen_to_use: when you need it",
        "body",
    );
    let skill = parse_or_fail(&path);
    assert_eq!(skill.when_to_use.as_deref(), Some("when you need it"));
}

#[test]
fn parse_skill_with_cc_alias_when_to_use_camel_case() {
    // PINS CC PARITY: whenToUse (camelCase) MUST be accepted.
    let tmp = TempDir::new().expect("tempdir");
    let path = write_skill(
        tmp.path(),
        "s.md",
        "name: x\ndescription: y\nwhenToUse: alias form",
        "body",
    );
    let skill = parse_or_fail(&path);
    assert_eq!(skill.when_to_use.as_deref(), Some("alias form"));
}

#[test]
fn parse_skill_without_when_to_use_defaults_to_none() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_skill(tmp.path(), "s.md", "name: x\ndescription: y", "body");
    let skill = parse_or_fail(&path);
    assert!(skill.when_to_use.is_none());
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — argument-hint field (CC parity)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn parse_skill_with_argument_hint_kebab_case_field() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_skill(
        tmp.path(),
        "s.md",
        "name: x\ndescription: y\nargument-hint: \"<file>\"",
        "body",
    );
    let skill = parse_or_fail(&path);
    assert_eq!(skill.argument_hint.as_deref(), Some("<file>"));
}

#[test]
fn parse_skill_with_argument_hint_snake_case_alias() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_skill(
        tmp.path(),
        "s.md",
        "name: x\ndescription: y\nargument_hint: \"<dir>\"",
        "body",
    );
    let skill = parse_or_fail(&path);
    assert_eq!(skill.argument_hint.as_deref(), Some("<dir>"));
}

#[test]
fn parse_skill_without_argument_hint_defaults_to_none() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_skill(tmp.path(), "s.md", "name: x\ndescription: y", "body");
    let skill = parse_or_fail(&path);
    assert!(skill.argument_hint.is_none());
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — model / effort fields
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn parse_skill_with_model_field() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_skill(
        tmp.path(),
        "s.md",
        "name: x\ndescription: y\nmodel: claude-opus-4-7",
        "body",
    );
    let skill = parse_or_fail(&path);
    assert_eq!(skill.model.as_deref(), Some("claude-opus-4-7"));
}

#[test]
fn parse_skill_with_effort_field() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_skill(
        tmp.path(),
        "s.md",
        "name: x\ndescription: y\neffort: high",
        "body",
    );
    let skill = parse_or_fail(&path);
    assert_eq!(skill.effort.as_deref(), Some("high"));
}

#[test]
fn parse_skill_with_unknown_effort_value_still_deserializes_as_string() {
    // Documented contract: effort is loose for forward-compat.
    let tmp = TempDir::new().expect("tempdir");
    let path = write_skill(
        tmp.path(),
        "s.md",
        "name: x\ndescription: y\neffort: ultra-high-future-tier",
        "body",
    );
    let skill = parse_or_fail(&path);
    assert_eq!(
        skill.effort.as_deref(),
        Some("ultra-high-future-tier"),
        "unknown effort MUST still parse (forward-compat)"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — paths field (glob list)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn parse_skill_with_single_paths_entry() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_skill(
        tmp.path(),
        "s.md",
        "name: x\ndescription: y\npaths: [\"src/**/*.rs\"]",
        "body",
    );
    let skill = parse_or_fail(&path);
    let paths = skill.paths.as_ref().expect("paths Some");
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0], "src/**/*.rs");
}

#[test]
fn parse_skill_with_multiple_paths_entries() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_skill(
        tmp.path(),
        "s.md",
        "name: x\ndescription: y\npaths:\n  - \"**/*.rs\"\n  - \"**/*.toml\"\n  - \"tests/**/*.rs\"",
        "body",
    );
    let skill = parse_or_fail(&path);
    let paths = skill.paths.as_ref().expect("Some");
    assert_eq!(paths.len(), 3);
    assert!(paths.contains(&"**/*.rs".to_string()));
    assert!(paths.contains(&"**/*.toml".to_string()));
    assert!(paths.contains(&"tests/**/*.rs".to_string()));
}

#[test]
fn parse_skill_without_paths_defaults_to_none() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_skill(tmp.path(), "s.md", "name: x\ndescription: y", "body");
    let skill = parse_or_fail(&path);
    assert!(skill.paths.is_none());
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — allowed_tools field
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn parse_skill_with_allowed_tools_list_preserved() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_skill(
        tmp.path(),
        "s.md",
        "name: x\ndescription: y\nallowed_tools: [\"read_file\", \"grep\"]",
        "body",
    );
    let skill = parse_or_fail(&path);
    let tools = skill.allowed_tools.as_ref().expect("Some");
    assert_eq!(tools.len(), 2);
    assert!(tools.contains(&"read_file".to_string()));
    assert!(tools.contains(&"grep".to_string()));
}

#[test]
fn parse_skill_with_allowed_tools_hyphen_scalar_preserved() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_skill(
        tmp.path(),
        "s.md",
        "name: x\ndescription: y\nallowed-tools: Bash(git add *) Bash(git status *)",
        "body",
    );
    let skill = parse_or_fail(&path);
    let tools = skill.allowed_tools.as_ref().expect("Some");
    assert_eq!(
        tools,
        &vec![
            "Bash(git add *)".to_string(),
            "Bash(git status *)".to_string()
        ]
    );
}

#[test]
fn parse_skill_without_allowed_tools_defaults_to_none() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_skill(tmp.path(), "s.md", "name: x\ndescription: y", "body");
    let skill = parse_or_fail(&path);
    assert!(skill.allowed_tools.is_none());
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — hooks field (validated native schema)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn parse_skill_with_valid_hooks_field_is_preserved() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_skill(
        tmp.path(),
        "s.md",
        "name: x\ndescription: y\nhooks:\n  pre_tool_use:\n    - matcher: read_file\n      hooks:\n        - { type: command, command: ls }",
        "body",
    );
    let skill = parse_or_fail(&path);
    let hooks = skill.hooks.as_ref().expect("Some");
    assert!(!hooks.is_null());
}

#[test]
fn parse_skill_rejects_malformed_hook_schema() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_skill(
        tmp.path(),
        "s.md",
        "name: x\ndescription: y\nhooks:\n  pre_tool_use:\n    - { type: command, command: ls }",
        "body",
    );
    let error = parse_skill_file(&path).expect_err("malformed hook entry must be inert");
    assert!(error.to_string().contains("hooks schema is invalid"));
}

#[test]
fn parse_skill_without_hooks_defaults_to_none() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_skill(tmp.path(), "s.md", "name: x\ndescription: y", "body");
    let skill = parse_or_fail(&path);
    assert!(skill.hooks.is_none());
}

// ───────────────────────────────────────────────────────────────────────────
// Section H — Full-shape round-trip
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn parse_full_shape_skill_with_every_documented_field() {
    let tmp = TempDir::new().expect("tempdir");
    let frontmatter = "
name: full
description: full-shape skill
when_to_use: comprehensive testing
argument-hint: \"<arg>\"
model: claude-opus-4-7
effort: medium
paths: [\"**/*.rs\"]
allowed_tools: [\"read_file\"]
";
    let path = write_skill(tmp.path(), "full.md", frontmatter, "body");
    let skill = parse_or_fail(&path);
    assert_eq!(skill.name, "full");
    assert_eq!(skill.description, "full-shape skill");
    assert_eq!(skill.when_to_use.as_deref(), Some("comprehensive testing"));
    assert_eq!(skill.argument_hint.as_deref(), Some("<arg>"));
    assert_eq!(skill.model.as_deref(), Some("claude-opus-4-7"));
    assert_eq!(skill.effort.as_deref(), Some("medium"));
    assert_eq!(skill.paths.as_ref().unwrap()[0], "**/*.rs");
    assert_eq!(skill.allowed_tools.as_ref().unwrap()[0], "read_file");
}

// ───────────────────────────────────────────────────────────────────────────
// Section I — Env-var constants
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn disable_policy_skills_env_var_constant_matches_documented_name() {
    assert_eq!(
        DISABLE_POLICY_SKILLS_ENV,
        "OPENCLAUDIA_DISABLE_POLICY_SKILLS"
    );
}

#[test]
fn managed_path_env_var_constant_matches_documented_name() {
    assert_eq!(MANAGED_PATH_ENV, "OPENCLAUDIA_MANAGED_PATH");
}

#[test]
fn env_constants_have_openclaudia_prefix_for_namespace_safety() {
    // PINS NAMING: both env vars MUST share OPENCLAUDIA_ prefix
    // to avoid colliding with host-process env names.
    assert!(DISABLE_POLICY_SKILLS_ENV.starts_with("OPENCLAUDIA_"));
    assert!(MANAGED_PATH_ENV.starts_with("OPENCLAUDIA_"));
}

#[test]
fn env_constants_are_distinct() {
    assert_ne!(DISABLE_POLICY_SKILLS_ENV, MANAGED_PATH_ENV);
}

// ───────────────────────────────────────────────────────────────────────────
// Section J — SkillDefinition path field populated on parse
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn parse_skill_populates_path_field_with_source_file_path() {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_skill(tmp.path(), "s.md", "name: x\ndescription: y", "body");
    let skill = parse_or_fail(&path);
    assert_eq!(skill.path, path);
}
