//! End-to-end tests for `prompt::SystemPromptBlocks::to_combined` —
//! the helper that concatenates `stable_prefix` + `dynamic_suffix`
//! with a `\n\n` separator unless suffix is empty (in which case
//! returns clone of prefix verbatim).
//!
//! Sprint 205 of the verification effort. Sprint 122 covered
//! typed prompt-builder happy paths; this file pins
//! the exact `to_combined` join semantics + boundary cases.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::prompt::SystemPromptBlocks;

fn blocks(prefix: &str, suffix: &str) -> SystemPromptBlocks {
    let mut items = Vec::new();
    if !prefix.is_empty() {
        items.push(openclaudia::context::ContextItem::host_instruction(
            "test.stable",
            openclaudia::context::HostInstructionSource::CorePolicy,
            "compiled:test",
            prefix,
            openclaudia::context::ContextFreshness::Static,
            1,
        ));
    }
    if !suffix.is_empty() {
        items.push(openclaudia::context::ContextItem::host_instruction(
            "test.dynamic",
            openclaudia::context::HostInstructionSource::RuntimePolicy,
            "host:test",
            suffix,
            openclaudia::context::ContextFreshness::Turn,
            2,
        ));
    }
    SystemPromptBlocks::from_items(items, openclaudia::context::ContextBudget::default())
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — to_combined join semantics
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn to_combined_with_both_non_empty_joins_with_double_newline() {
    // PINS DOC: "{prefix}\n\n{suffix}" join.
    let b = blocks("PREFIX", "SUFFIX");
    assert_eq!(b.to_combined(), "PREFIX\n\nSUFFIX");
}

#[test]
fn to_combined_with_suffix_empty_returns_only_prefix_no_trailing_newlines() {
    // PINS DOC: empty suffix means "no dynamic content";
    // returns clone of prefix as-is (NO trailing "\n\n").
    let b = blocks("PREFIX", "");
    assert_eq!(
        b.to_combined(),
        "PREFIX",
        "empty suffix MUST NOT append trailing newlines"
    );
}

#[test]
fn to_combined_with_prefix_empty_returns_dynamic_without_leading_separator() {
    let b = blocks("", "SUFFIX");
    assert_eq!(b.to_combined(), "SUFFIX");
}

#[test]
fn to_combined_with_both_empty_returns_empty_string() {
    let b = blocks("", "");
    assert_eq!(b.to_combined(), "");
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Edge whitespace
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn projection_trims_existing_trailing_newline_in_prefix() {
    let b = blocks("PREFIX\n", "SUFFIX");
    assert_eq!(b.to_combined(), "PREFIX\n\nSUFFIX");
}

#[test]
fn projection_trims_existing_leading_newline_in_suffix() {
    let b = blocks("PREFIX", "\nSUFFIX");
    assert_eq!(b.to_combined(), "PREFIX\n\nSUFFIX");
}

#[test]
fn projection_trims_outer_whitespace_deterministically() {
    let b = blocks("  PREFIX  ", "  SUFFIX  ");
    assert_eq!(b.to_combined(), "PREFIX\n\nSUFFIX");
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Clone vs to_combined identity
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn to_combined_with_empty_suffix_equals_prefix_clone() {
    let b = blocks("Identity\n\nTools\n\nPrinciples", "");
    let combined = b.to_combined();
    assert_eq!(combined, b.stable_prefix());
}

#[test]
fn to_combined_is_deterministic_across_calls() {
    let b = blocks("PREFIX", "SUFFIX");
    let s1 = b.to_combined();
    let s2 = b.to_combined();
    let s3 = b.to_combined();
    assert_eq!(s1, s2);
    assert_eq!(s2, s3);
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Length invariants
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn to_combined_with_both_non_empty_length_equals_sum_plus_2() {
    let b = blocks("AAA", "BBB");
    let combined = b.to_combined();
    // 3 + 2 (for "\n\n") + 3 = 8.
    assert_eq!(combined.len(), 8);
    assert_eq!(
        combined.len(),
        b.stable_prefix().len() + 2 + b.dynamic_suffix().len()
    );
}

#[test]
fn to_combined_with_empty_suffix_length_equals_prefix_length() {
    let b = blocks("ABCDEFGH", "");
    assert_eq!(b.to_combined().len(), b.stable_prefix().len());
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Unicode
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn to_combined_with_unicode_preserves_bytes() {
    let b = blocks("日本語プレフィックス", "サフィックス");
    let combined = b.to_combined();
    assert!(combined.contains("日本語プレフィックス"));
    assert!(combined.contains("サフィックス"));
    assert!(combined.contains("\n\n"));
}

#[test]
fn to_combined_with_emoji_preserves_bytes() {
    let b = blocks("hello 🎯", "world 🚀");
    let combined = b.to_combined();
    assert_eq!(combined, "hello 🎯\n\nworld 🚀");
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — SystemPromptBlocks Clone
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn clone_preserves_both_fields() {
    let original = blocks("PREFIX-clone-marker", "SUFFIX-clone-marker");
    let cloned = original.clone();
    assert_eq!(cloned.stable_prefix(), original.stable_prefix());
    assert_eq!(cloned.dynamic_suffix(), original.dynamic_suffix());
}

#[test]
fn clone_then_to_combined_yields_same_result() {
    let original = blocks("A", "B");
    let cloned = original.clone();
    assert_eq!(original.to_combined(), cloned.to_combined());
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — Realistic prompt-like content
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn to_combined_with_realistic_multi_section_prompt() {
    let prefix = "# Identity\nYou are Claude.\n\n# Tools\n- bash\n- read_file";
    let suffix = "# Current directory\n/home/user/project";
    let b = blocks(prefix, suffix);
    let combined = b.to_combined();
    assert!(combined.starts_with("# Identity"));
    assert!(combined.ends_with("/home/user/project"));
    assert!(combined.contains("\n\n# Current directory"));
}
