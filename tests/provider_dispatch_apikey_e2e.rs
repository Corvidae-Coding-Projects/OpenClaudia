//! End-to-end tests for `providers::get_adapter` dispatch +
//! per-adapter `chat_endpoint` + `ProviderKind::from_model`
//! classification + `ApiKey` validator.
//!
//! Sprint 72 of the verification effort. Sprint 0/32 covered
//! some adapter behaviours; this file pins the dispatch table
//! (all 15 documented aliases including normalization), the
//! per-adapter endpoint paths, the model→provider
//! classification table, and the `ApiKey::try_from_string`
//! validator (length + control-char + non-ASCII rejection).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::providers::{
    get_adapter, ApiKey, ApiKeyError, ProviderError, ProviderKind, MAX_API_KEY_LEN,
    REDACTED_PLACEHOLDER,
};

// ───────────────────────────────────────────────────────────────────────────
// Section A — get_adapter dispatch
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn get_adapter_anthropic_resolves() {
    let a = get_adapter("anthropic").expect("anthropic resolves");
    assert_eq!(a.name(), "anthropic");
}

#[test]
fn get_adapter_openai_resolves() {
    let a = get_adapter("openai").expect("openai resolves");
    assert_eq!(a.name(), "openai");
}

#[test]
fn get_adapter_google_via_gemini_alias_resolves_to_google() {
    let direct = get_adapter("google").expect("google");
    let alias = get_adapter("gemini").expect("gemini alias");
    assert_eq!(direct.name(), alias.name());
}

#[test]
fn get_adapter_zai_aliases_resolve_to_same_adapter() {
    for alias in &["zai", "glm", "zhipu"] {
        let a = get_adapter(alias).unwrap_or_else(|_| panic!("{alias} MUST resolve"));
        assert_eq!(a.name(), "zai", "alias {alias} MUST resolve to zai adapter");
    }
}

#[test]
fn get_adapter_qwen_alibaba_alias_resolves_to_qwen() {
    let direct = get_adapter("qwen").expect("qwen");
    let alias = get_adapter("alibaba").expect("alibaba alias");
    assert_eq!(direct.name(), alias.name());
}

#[test]
fn get_adapter_kimi_moonshot_alias_resolves_to_kimi() {
    let direct = get_adapter("kimi").expect("kimi");
    let alias = get_adapter("moonshot").expect("moonshot alias");
    assert_eq!(direct.name(), "kimi");
    assert_eq!(direct.name(), alias.name());
}

#[test]
fn get_adapter_minimax_resolves() {
    let adapter = get_adapter("minimax").expect("minimax");
    assert_eq!(adapter.name(), "minimax");
}

#[test]
fn get_adapter_openai_compat_aliases_resolve_to_openai() {
    for alias in &["local", "lmstudio", "localai", "text-generation-webui"] {
        let a = get_adapter(alias).unwrap_or_else(|_| panic!("{alias} MUST resolve"));
        assert_eq!(a.name(), "openai");
    }
}

#[test]
fn get_adapter_is_case_insensitive() {
    let lower = get_adapter("anthropic").unwrap();
    let upper = get_adapter("ANTHROPIC").unwrap();
    let mixed = get_adapter("AnThRoPiC").unwrap();
    assert_eq!(lower.name(), upper.name());
    assert_eq!(lower.name(), mixed.name());
}

#[test]
fn get_adapter_unknown_provider_returns_unknown_provider_error() {
    // dyn ProviderAdapter isn't Debug; map Ok side to ()
    // so the let-else has a Debug-formattable shape.
    let outcome = get_adapter("anthrpic").map(|_| ()); // typo
    let Err(ProviderError::UnknownProvider { name, supported }) = outcome else {
        panic!("expected UnknownProvider; got {outcome:?}");
    };
    assert_eq!(name, "anthrpic");
    assert!(!supported.is_empty(), "supported list MUST be non-empty");
    assert!(
        supported.contains(&"anthropic"),
        "supported MUST include the canonical name; got {supported:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Per-adapter chat_endpoint
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn anthropic_chat_endpoint_is_v1_messages() {
    let a = get_adapter("anthropic").unwrap();
    assert_eq!(a.chat_endpoint("any-model"), "/v1/messages");
}

#[test]
fn openai_chat_endpoint_is_v1_chat_completions() {
    let a = get_adapter("openai").unwrap();
    assert_eq!(a.chat_endpoint("any-model"), "/v1/chat/completions");
}

#[test]
fn google_chat_endpoint_embeds_model_name_in_path() {
    let a = get_adapter("google").unwrap();
    let endpoint = a.chat_endpoint("gemini-2.5-pro");
    assert!(endpoint.contains("gemini-2.5-pro"));
    assert!(endpoint.contains("generateContent"));
    assert!(endpoint.starts_with("/v1beta/"));
}

#[test]
fn deepseek_chat_endpoint_uses_documented_root_chat_completions() {
    let a = get_adapter("deepseek").unwrap();
    assert_eq!(a.chat_endpoint("anything"), "/chat/completions");
    assert_eq!(a.models_endpoint(), "/models");
}

#[test]
fn qwen_chat_endpoint_is_v1_chat_completions() {
    let a = get_adapter("qwen").unwrap();
    assert_eq!(a.chat_endpoint("anything"), "/v1/chat/completions");
}

#[test]
fn kimi_chat_endpoint_is_v1_chat_completions() {
    let a = get_adapter("kimi").unwrap();
    assert_eq!(a.chat_endpoint("anything"), "/v1/chat/completions");
}

#[test]
fn minimax_chat_endpoint_is_v1_chat_completions() {
    let a = get_adapter("minimax").unwrap();
    assert_eq!(a.chat_endpoint("anything"), "/v1/chat/completions");
}

#[test]
fn zai_chat_endpoint_omits_v1_prefix() {
    // Documented quirk: Z.AI's base_url already carries /v1,
    // so the chat endpoint MUST NOT add another /v1.
    let a = get_adapter("zai").unwrap();
    let endpoint = a.chat_endpoint("anything");
    assert_eq!(endpoint, "/chat/completions");
}

#[test]
fn ollama_chat_endpoint_is_api_chat() {
    let a = get_adapter("ollama").unwrap();
    assert_eq!(a.chat_endpoint("anything"), "/api/chat");
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — ProviderKind::from_model
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn from_model_anthropic_prefixes() {
    assert_eq!(
        ProviderKind::from_model("claude-3-5-sonnet"),
        ProviderKind::Anthropic
    );
    assert_eq!(
        ProviderKind::from_model("anthropic/claude"),
        ProviderKind::Anthropic
    );
}

#[test]
fn from_model_openai_prefixes() {
    assert_eq!(ProviderKind::from_model("gpt-4o"), ProviderKind::OpenAI);
    assert_eq!(ProviderKind::from_model("gpt"), ProviderKind::OpenAI);
    assert_eq!(ProviderKind::from_model("o1"), ProviderKind::OpenAI);
    assert_eq!(ProviderKind::from_model("o3-mini"), ProviderKind::OpenAI);
    assert_eq!(ProviderKind::from_model("o4-preview"), ProviderKind::OpenAI);
}

#[test]
fn from_model_o1_does_not_match_o100_anti_prefix_bug() {
    // Documented regression guard: the old prefix-only matcher
    // resolved "o100" to OpenAI when intended as another
    // model entirely. New matcher uses exact "o1"/"o3"/"o4"
    // or "o1-"/"o3-"/"o4-" prefix.
    assert_eq!(
        ProviderKind::from_model("o100"),
        ProviderKind::Unknown,
        "o100 MUST NOT classify as OpenAI"
    );
}

#[test]
fn from_model_google_prefixes() {
    assert_eq!(
        ProviderKind::from_model("gemini-3.5-flash"),
        ProviderKind::Google
    );
}

#[test]
fn from_model_deepseek_prefixes() {
    assert_eq!(
        ProviderKind::from_model("deepseek-coder"),
        ProviderKind::DeepSeek
    );
    assert_eq!(
        ProviderKind::from_model("deepseek-reasoner"),
        ProviderKind::DeepSeek
    );
}

#[test]
fn from_model_qwen_prefixes_including_qwq_qvq() {
    assert_eq!(ProviderKind::from_model("qwen-72b"), ProviderKind::Qwen);
    assert_eq!(ProviderKind::from_model("qwq-32b"), ProviderKind::Qwen);
    assert_eq!(ProviderKind::from_model("qvq-72b"), ProviderKind::Qwen);
}

#[test]
fn from_model_zai_glm_prefix() {
    assert_eq!(ProviderKind::from_model("glm-4"), ProviderKind::Zai);
}

#[test]
fn from_model_kimi_and_moonshot_prefixes() {
    assert_eq!(
        ProviderKind::from_model("kimi-k2.7-code"),
        ProviderKind::Kimi
    );
    assert_eq!(
        ProviderKind::from_model("moonshot-v1-128k"),
        ProviderKind::Kimi
    );
}

#[test]
fn from_model_minimax_prefixes() {
    assert_eq!(
        ProviderKind::from_model("MiniMax-M3"),
        ProviderKind::MiniMax
    );
    assert_eq!(ProviderKind::from_model("M2-her"), ProviderKind::MiniMax);
}

#[test]
fn from_model_is_case_insensitive() {
    assert_eq!(
        ProviderKind::from_model("CLAUDE-3-5-SONNET"),
        ProviderKind::Anthropic
    );
    assert_eq!(ProviderKind::from_model("GPT-4O"), ProviderKind::OpenAI);
}

#[test]
fn from_model_unknown_returns_unknown() {
    assert_eq!(
        ProviderKind::from_model("totally-unknown-model"),
        ProviderKind::Unknown
    );
    assert_eq!(ProviderKind::from_model(""), ProviderKind::Unknown);
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — supports_streaming + supports_model_listing per adapter
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn anthropic_supports_streaming() {
    let a = get_adapter("anthropic").unwrap();
    assert!(a.supports_streaming());
}

#[test]
fn openai_supports_model_listing() {
    let a = get_adapter("openai").unwrap();
    assert!(a.supports_model_listing());
}

#[test]
fn ollama_supports_model_listing() {
    let a = get_adapter("ollama").unwrap();
    assert!(a.supports_model_listing());
}

#[test]
fn deepseek_advertises_documented_model_listing() {
    let a = get_adapter("deepseek").unwrap();
    assert!(a.supports_model_listing());
    assert_eq!(a.models_endpoint(), "/models");
}

#[test]
fn qwen_does_not_advertise_model_listing() {
    let a = get_adapter("qwen").unwrap();
    assert!(!a.supports_model_listing());
}

#[test]
fn zai_does_not_advertise_model_listing() {
    let a = get_adapter("zai").unwrap();
    assert!(!a.supports_model_listing());
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — ApiKey::try_from_string validator
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn apikey_accepts_typical_anthropic_format() {
    let key = ApiKey::try_from_string("sk-ant-abc123def456".to_string()).expect("valid");
    assert!(key.matches("sk-ant-abc123def456"));
}

#[test]
fn apikey_accepts_typical_openai_format() {
    let key = ApiKey::try_from_string("sk-1234567890ABCDEFghij".to_string()).expect("valid");
    assert!(key.matches("sk-1234567890ABCDEFghij"));
}

#[test]
fn apikey_rejects_empty_string() {
    let outcome = ApiKey::try_from_string(String::new());
    assert!(matches!(outcome, Err(ApiKeyError::Empty)));
}

#[test]
fn apikey_rejects_whitespace_only() {
    let outcome = ApiKey::try_from_string("   \t   ".to_string());
    assert!(matches!(outcome, Err(ApiKeyError::Empty)));
}

#[test]
fn apikey_rejects_non_ascii_bytes() {
    let outcome = ApiKey::try_from_string("sk-with-日本-emoji".to_string());
    assert!(
        matches!(outcome, Err(ApiKeyError::NonAscii)),
        "MUST reject non-ASCII; got {outcome:?}"
    );
}

#[test]
fn apikey_rejects_control_characters_for_crlf_injection() {
    // Documented contract: \r, \n, \0, etc. all rejected as
    // CRLF-injection guard.
    for bad in &["sk-\rinject", "sk-\ninject", "sk-\0inject", "sk-\tinject"] {
        let outcome = ApiKey::try_from_string((*bad).to_string());
        assert!(
            matches!(outcome, Err(ApiKeyError::ControlChar { .. })),
            "MUST reject control char in {bad:?}; got {outcome:?}"
        );
    }
}

#[test]
fn apikey_rejects_keys_over_max_length_cap() {
    let huge = "x".repeat(MAX_API_KEY_LEN + 1);
    let outcome = ApiKey::try_from_string(huge);
    let Err(ApiKeyError::TooLong { actual, max }) = outcome else {
        panic!("expected TooLong; got {outcome:?}");
    };
    assert_eq!(actual, MAX_API_KEY_LEN + 1);
    assert_eq!(max, MAX_API_KEY_LEN);
}

#[test]
fn apikey_accepts_keys_at_exactly_max_length() {
    let just_at_max = "x".repeat(MAX_API_KEY_LEN);
    let outcome = ApiKey::try_from_string(just_at_max);
    assert!(outcome.is_ok());
}

#[test]
fn max_api_key_len_constant_is_512() {
    assert_eq!(MAX_API_KEY_LEN, 512);
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — ApiKey redaction-preserving Debug + Display + serde
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn apikey_debug_format_redacts_value() {
    let key = ApiKey::try_from_string("sk-SECRET-XYZ".to_string()).unwrap();
    let debug = format!("{key:?}");
    assert!(
        !debug.contains("SECRET-XYZ"),
        "Debug MUST NOT leak raw value; got {debug:?}"
    );
}

#[test]
fn apikey_display_format_redacts_value() {
    let key = ApiKey::try_from_string("sk-SECRET-XYZ".to_string()).unwrap();
    let display = format!("{key}");
    assert!(
        !display.contains("SECRET-XYZ"),
        "Display MUST NOT leak raw value; got {display:?}"
    );
}

#[test]
fn apikey_serde_serializes_as_redacted_placeholder() {
    let key = ApiKey::try_from_string("sk-SECRET-XYZ".to_string()).unwrap();
    let json = serde_json::to_string(&key).expect("serialize");
    assert!(
        !json.contains("SECRET-XYZ"),
        "serialized JSON MUST NOT leak raw value; got {json:?}"
    );
    assert!(
        json.contains(REDACTED_PLACEHOLDER),
        "serialized JSON MUST contain redacted placeholder; got {json:?}"
    );
}

#[test]
fn apikey_candidate_comparison_confirms_value_without_public_exposure() {
    // The public compatibility probe confirms equality without returning a
    // raw borrow that production callers could log or retain.
    let key = ApiKey::try_from_string("sk-REAL".to_string()).unwrap();
    assert!(key.matches("sk-REAL"));
}
