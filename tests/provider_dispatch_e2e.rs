//! End-to-end tests for `get_adapter` alias-resolution and the
//! cross-name pointer-equality invariant.
//!
//! Sprint 32 of the verification effort.
//!
//! Existing `tests/providers_e2e.rs` (sprint-1) pins that every
//! canonical name resolves and that typos error. This file fills
//! the alias-equivalence gap: every alias MUST resolve to the
//! SAME static adapter as its canonical name (pointer equality),
//! AND every adapter MUST report its canonical `name()` regardless
//! of which alias was used to look it up.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::providers::{get_adapter, ProviderAdapter};
use std::ptr;

/// Documented alias table mirrored from
/// `src/providers/mod.rs::get_adapter` so a future addition that
/// introduces a new alias trips this test until the table is
/// updated AND the corresponding equality check is added.
///
/// Format: `(canonical, &[aliases])`.
const ALIASES: &[(&str, &[&str])] = &[
    ("anthropic", &[]),
    (
        "openai",
        &["local", "lmstudio", "localai", "text-generation-webui"],
    ),
    ("google", &["gemini"]),
    ("deepseek", &[]),
    ("qwen", &["alibaba"]),
    ("zai", &["glm", "zhipu"]),
    ("kimi", &["moonshot"]),
    ("minimax", &[]),
    ("ollama", &[]),
];

// ───────────────────────────────────────────────────────────────────────────
// Section A — alias resolves to the SAME static adapter as canonical
// ───────────────────────────────────────────────────────────────────────────

fn adapter_ptr(name: &str) -> *const dyn ProviderAdapter {
    ptr::from_ref::<dyn ProviderAdapter>(
        get_adapter(name).unwrap_or_else(|e| panic!("get_adapter({name}) failed: {e}")),
    )
}

#[test]
fn every_alias_resolves_to_same_pointer_as_canonical() {
    let mut mismatches = Vec::new();
    for (canonical, aliases) in ALIASES {
        let canonical_ptr = adapter_ptr(canonical);
        for alias in *aliases {
            let alias_ptr = adapter_ptr(alias);
            if !ptr::eq(canonical_ptr, alias_ptr) {
                mismatches.push(format!(
                    "{alias:?} ({canonical_ptr:p}) does NOT resolve to same ptr \
                     as {canonical:?} ({canonical_ptr:p})"
                ));
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} alias mismatches — aliases MUST be pointer-equal to canonical:\n  {}",
        mismatches.len(),
        mismatches.join("\n  "),
    );
}

#[test]
fn alias_resolution_preserves_adapter_canonical_name() {
    // The `.name()` of an adapter resolved by alias MUST return
    // the canonical provider id, NOT the alias the caller used.
    // This is what downstream code (logging, telemetry, config
    // lookups) keys on — silent drift would break per-provider
    // metric attribution.
    let mut wrong = Vec::new();
    for (canonical, aliases) in ALIASES {
        let canonical_adapter = get_adapter(canonical).expect("canonical resolves");
        let canonical_name = canonical_adapter.name();
        for alias in *aliases {
            let alias_adapter = get_adapter(alias).expect("alias resolves");
            let alias_name = alias_adapter.name();
            if alias_name != canonical_name {
                wrong.push(format!(
                    "alias {alias:?} → adapter.name() = {alias_name:?} \
                     (expected canonical {canonical_name:?})"
                ));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} aliases produce wrong adapter.name():\n  {}",
        wrong.len(),
        wrong.join("\n  "),
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — case-insensitivity is preserved across aliases
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn alias_case_variants_all_resolve_to_same_pointer() {
    // For each alias, lower/upper/mixed-case all MUST resolve
    // to the same adapter. Pins crosslink #332's
    // case-insensitive dispatch contract uniformly across the
    // alias table (not just for canonical names).
    let mut mismatches = Vec::new();
    for (_canonical, aliases) in ALIASES {
        for alias in *aliases {
            let lower_ptr = adapter_ptr(&alias.to_ascii_lowercase());
            let upper_ptr = adapter_ptr(&alias.to_ascii_uppercase());
            if !ptr::eq(lower_ptr, upper_ptr) {
                mismatches.push(format!(
                    "{alias:?}: lower ({lower_ptr:p}) != upper ({upper_ptr:p})"
                ));
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} case-variant alias mismatches:\n  {}",
        mismatches.len(),
        mismatches.join("\n  "),
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — adapter reports its documented name
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn each_adapter_reports_its_documented_canonical_name() {
    // Per the docs at get_adapter callsite (and aligned with
    // the SUPPORTED_PROVIDERS table), each canonical-named
    // adapter MUST advertise that exact name.
    let expected: &[(&str, &str)] = &[
        ("anthropic", "anthropic"),
        ("openai", "openai"),
        ("google", "google"),
        ("deepseek", "deepseek"),
        ("qwen", "qwen"),
        ("zai", "zai"),
        ("kimi", "kimi"),
        ("minimax", "minimax"),
        ("ollama", "ollama"),
    ];
    for (lookup, expected_name) in expected {
        let adapter = get_adapter(lookup).expect("canonical name resolves");
        assert_eq!(
            adapter.name(),
            *expected_name,
            "adapter resolved by {lookup:?} must report name {expected_name:?}; \
             got {:?}",
            adapter.name()
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — unknown / empty input error shape
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn unknown_provider_error_carries_the_offending_name() {
    // Map Ok → adapter.name() so we can Display the
    // (rare) success-shaped panic message; the dyn trait
    // itself isn't Debug.
    let outcome = get_adapter("totally-unknown-provider-9999").map(ProviderAdapter::name);
    let err = outcome.unwrap_err();
    let display = format!("{err}");
    assert!(
        display.contains("totally-unknown-provider-9999"),
        "error message must contain the offending name; got {display:?}"
    );
}

#[test]
fn empty_provider_name_errors_with_unknown_provider() {
    let outcome = get_adapter("").map(ProviderAdapter::name);
    assert!(
        outcome.is_err(),
        "empty provider name MUST error; got {outcome:?}"
    );
}

#[test]
fn whitespace_only_provider_name_errors() {
    let outcome = get_adapter("   ").map(ProviderAdapter::name);
    assert!(
        outcome.is_err(),
        "whitespace-only provider name MUST error (no trim-and-match \
         silent fallback); got {outcome:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — supports_model_listing per provider
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn anthropic_advertises_native_model_listing() {
    let adapter = get_adapter("anthropic").expect("anthropic adapter");
    assert!(
        adapter.supports_model_listing(),
        "anthropic adapter must advertise its native model catalog"
    );
    assert_eq!(adapter.models_endpoint(), "/v1/models?limit=1000");
}

#[test]
fn openai_deepseek_kimi_minimax_and_ollama_advertise_model_listing() {
    // Authoring discovery: the OpenAiCompatibleAdapter
    // constructor takes a `supports_models: bool`. Only
    // providers with documented OpenAI-compatible model-listing endpoints pass
    // `true`; Qwen and Z.AI stay false unless their public docs expose a
    // parseable /models shape.
    for provider in &["openai", "deepseek", "kimi", "minimax", "ollama"] {
        let adapter = get_adapter(provider)
            .unwrap_or_else(|e| panic!("{provider} adapter must resolve: {e}"));
        assert!(
            adapter.supports_model_listing(),
            "{provider} adapter MUST advertise model listing"
        );
    }
}

#[test]
fn qwen_zai_do_not_advertise_model_listing() {
    // Counter-test pinning the disable contract for
    // providers that don't expose a usable /v1/models.
    // A future change that flips one to `true` will fail
    // here and call out the migration: ensure the endpoint
    // actually exists AND that fetch_models can parse the
    // response shape.
    for provider in &["qwen", "zai"] {
        let adapter = get_adapter(provider)
            .unwrap_or_else(|e| panic!("{provider} adapter must resolve: {e}"));
        assert!(
            !adapter.supports_model_listing(),
            "{provider} adapter MUST NOT advertise model listing \
             without a parseable /v1/models endpoint"
        );
    }
}

#[test]
fn listing_capable_adapters_expose_their_native_endpoint() {
    for (provider, expected) in [
        ("openai", "/v1/models"),
        ("deepseek", "/models"),
        ("kimi", "/v1/models"),
        ("minimax", "/v1/models"),
        ("ollama", "/api/tags"),
        ("anthropic", "/v1/models?limit=1000"),
        ("google", "/v1beta/models?pageSize=1000"),
    ] {
        let adapter = get_adapter(provider).expect("adapter");
        assert!(adapter.supports_model_listing(), "{provider}");
        assert_eq!(adapter.models_endpoint(), expected, "{provider}");
    }
}
