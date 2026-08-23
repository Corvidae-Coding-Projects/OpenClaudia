//! End-to-end contract for catalog-backed context-window resolution.
//!
//! Only exact provider-discovered IDs or aliases from the fresh, dated
//! emergency catalog may raise the conservative unknown-model ceiling.

use openclaudia::compaction::get_context_window;

const UNKNOWN_CONTEXT: usize = 128_000;

#[test]
fn current_exact_catalog_models_return_attributed_limits() {
    for (model, expected) in [
        ("claude-opus-4-8", 1_000_000),
        ("claude-haiku-4-5", 200_000),
        ("gpt-5.6-sol", 1_050_000),
        ("gpt-5.6", 1_050_000),
        ("gemini-3.7-flash", 1_048_576),
        ("deepseek-v4-pro", 1_000_000),
        ("qwen3.7-plus", 1_000_000),
        ("glm-5.2", 1_000_000),
        ("kimi-k2.7-code", 262_144),
        ("MiniMax-M3", 1_000_000),
    ] {
        assert_eq!(get_context_window(model), expected, "{model}");
    }
}

#[test]
fn exact_ids_and_aliases_are_ascii_case_insensitive() {
    assert_eq!(get_context_window("CLAUDE-OPUS-4-8"), 1_000_000);
    assert_eq!(get_context_window("GPT-5.6"), 1_050_000);
}

#[test]
fn unknown_and_substring_collisions_keep_conservative_ceiling() {
    for model in [
        "unknown-model",
        "prefix-gpt-5.6-sol-copy",
        "claude",
        "gpt-4o-compatible",
        "qwen3.7-plus-unverified-snapshot",
    ] {
        assert_eq!(get_context_window(model), UNKNOWN_CONTEXT, "{model}");
    }
}
