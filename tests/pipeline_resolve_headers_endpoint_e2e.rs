//! End-to-end tests for `pipeline::resolve_endpoint` and
//! `pipeline::resolve_headers` — dispatch through adapter
//! based on provider + handling of the OAuth
//! `claude_code_token` path (no API key required).
//!
//! Sprint 119 of the verification effort. Sprint 70
//! (`pipeline_helpers_e2e`) covered `build_*_request` per
//! provider + `overload_fallback_for` + sse-cap enforcement;
//! this file pins `resolve_endpoint` + `resolve_headers` —
//! the dispatch points between proxy + adapter + OAuth.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::pipeline::{resolve_endpoint, resolve_headers};
use openclaudia::providers::{ApiKey, ProviderError};
use openclaudia::secrets::{OAuthToken, SensitiveHeaders};

fn key() -> ApiKey {
    ApiKey::try_from_string("sk-test-key-123".to_string()).expect("valid")
}

fn token() -> OAuthToken {
    OAuthToken::try_from_string("oauth-token".to_string()).expect("valid token")
}

fn extras(values: &[(&str, &str)]) -> SensitiveHeaders {
    let mut headers = SensitiveHeaders::new();
    for (name, value) in values {
        headers
            .insert_literal(name, (*value).to_string())
            .expect("valid extra header");
    }
    headers
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — resolve_endpoint (no OAuth path)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn resolve_endpoint_anthropic_appends_v1_messages() {
    let endpoint = resolve_endpoint(
        "anthropic",
        "claude-sonnet-4-5",
        "https://api.anthropic.com",
        None,
    )
    .expect("ok");
    assert!(
        endpoint.ends_with("/v1/messages"),
        "anthropic endpoint MUST end with /v1/messages; got {endpoint:?}"
    );
}

#[test]
fn resolve_endpoint_openai_appends_v1_chat_completions() {
    let endpoint =
        resolve_endpoint("openai", "gpt-4o", "https://api.openai.com", None).expect("ok");
    assert!(endpoint.ends_with("/v1/chat/completions"));
}

#[test]
fn resolve_endpoint_deepseek_uses_documented_root_chat_completions() {
    let endpoint = resolve_endpoint(
        "deepseek",
        "deepseek-v4-pro",
        "https://api.deepseek.com",
        None,
    )
    .expect("ok");
    assert_eq!(endpoint, "https://api.deepseek.com/chat/completions");
}

#[test]
fn resolve_endpoint_google_embeds_model_in_path() {
    let endpoint = resolve_endpoint(
        "google",
        "gemini-2.5-pro",
        "https://generativelanguage.googleapis.com",
        None,
    )
    .expect("ok");
    // Google embeds the model name in the path.
    assert!(
        endpoint.contains("gemini-2.5-pro"),
        "Google endpoint MUST embed model name; got {endpoint:?}"
    );
}

#[test]
fn resolve_endpoint_ollama_uses_api_chat_path() {
    let endpoint =
        resolve_endpoint("ollama", "llama3", "http://localhost:11434", None).expect("ok");
    assert!(endpoint.contains("/api/chat"));
}

#[test]
fn resolve_endpoint_unknown_provider_returns_unknown_provider_error() {
    let outcome = resolve_endpoint("nonexistent", "model", "https://x.com", None);
    let err = outcome.unwrap_err();
    assert!(matches!(err, ProviderError::UnknownProvider { .. }));
}

#[test]
fn resolve_endpoint_strips_trailing_v1_from_base_url_before_appending() {
    // normalize_base_url strips trailing /v1 to prevent /v1/v1.
    let with_v1 =
        resolve_endpoint("openai", "gpt-4o", "https://api.openai.com/v1", None).expect("ok");
    let without_v1 =
        resolve_endpoint("openai", "gpt-4o", "https://api.openai.com", None).expect("ok");
    // Both produce the same canonical endpoint.
    assert_eq!(with_v1, without_v1);
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — resolve_endpoint (OAuth claude_code_token path)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn resolve_endpoint_with_claude_code_token_routes_through_oauth_path() {
    // Token-provided path bypasses adapter dispatch.
    let token = token();
    let endpoint = resolve_endpoint(
        "anthropic",
        "claude-sonnet-4-5",
        "https://api.anthropic.com",
        Some(&token),
    )
    .expect("ok");
    // OAuth endpoint is provider-determined; just verify
    // we get a non-empty string (no panic, no error).
    assert!(!endpoint.is_empty());
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — resolve_headers (API key path)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn resolve_headers_anthropic_uses_x_api_key_header() {
    let api_key = key();
    let headers =
        resolve_headers("anthropic", Some(&api_key), None, &SensitiveHeaders::new()).expect("ok");
    // Anthropic adapter uses x-api-key.
    let has_xapikey = headers.contains_name("x-api-key");
    assert!(
        has_xapikey,
        "anthropic MUST emit x-api-key header; got {headers:?}"
    );
}

#[test]
fn resolve_headers_openai_uses_authorization_bearer() {
    let api_key = key();
    let headers =
        resolve_headers("openai", Some(&api_key), None, &SensitiveHeaders::new()).expect("ok");
    let has_bearer = headers.matches_value("authorization", "Bearer sk-test-key-123");
    assert!(
        has_bearer,
        "openai MUST emit Authorization: Bearer; got {headers:?}"
    );
}

#[test]
fn resolve_headers_unknown_provider_with_api_key_errors() {
    let api_key = key();
    let outcome = resolve_headers(
        "nonexistent",
        Some(&api_key),
        None,
        &SensitiveHeaders::new(),
    );
    assert!(matches!(
        outcome.unwrap_err(),
        ProviderError::UnknownProvider { .. }
    ));
}

#[test]
fn resolve_headers_no_api_key_no_token_returns_only_extras() {
    let extras = extras(&[("X-Custom", "value")]);
    let headers = resolve_headers("anthropic", None, None, &extras).expect("ok");
    // Only the extras passed through (no provider auth).
    assert_eq!(headers.len(), 1);
    assert!(headers.matches_value("X-Custom", "value"));
}

#[test]
fn resolve_headers_extras_appended_after_auth_headers() {
    let api_key = key();
    let extras = extras(&[("X-Extra", "value")]);
    let headers = resolve_headers("openai", Some(&api_key), None, &extras).expect("ok");
    assert!(headers.matches_value("X-Extra", "value"));
    // Auth header is still present.
    assert!(
        headers.contains_name("authorization"),
        "auth header MUST survive when extras appended"
    );
}

#[test]
fn resolve_headers_multiple_extras_all_appended() {
    let api_key = key();
    let extras = extras(&[("X-A", "1"), ("X-B", "2"), ("X-C", "3")]);
    let headers = resolve_headers("openai", Some(&api_key), None, &extras).expect("ok");
    assert!(headers.matches_value("X-A", "1"));
    assert!(headers.matches_value("X-B", "2"));
    assert!(headers.matches_value("X-C", "3"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — resolve_headers (OAuth claude_code_token path)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn resolve_headers_with_oauth_token_bypasses_adapter_dispatch() {
    // claude_code_token path skips get_adapter — so an
    // unknown provider name with a token MUST NOT error.
    let token = token();
    let outcome = resolve_headers(
        "any-name-token-bypasses-this",
        None,
        Some(&token),
        &SensitiveHeaders::new(),
    );
    assert!(outcome.is_ok());
    let headers = outcome.unwrap();
    assert!(!headers.is_empty(), "OAuth path MUST inject auth headers");
}

#[test]
fn resolve_headers_oauth_path_extras_still_appended() {
    let extras = extras(&[("X-Custom", "v")]);
    let token = token();
    let headers = resolve_headers("any", None, Some(&token), &extras).expect("ok");
    assert!(headers.matches_value("X-Custom", "v"));
}

#[test]
fn resolve_headers_token_takes_precedence_over_api_key() {
    // When BOTH are supplied, token wins (per documented contract).
    let api_key = key();
    let token = token();
    let headers = resolve_headers(
        "openai",
        Some(&api_key),
        Some(&token),
        &SensitiveHeaders::new(),
    )
    .expect("ok");
    assert!(headers.matches_value("authorization", "Bearer oauth-token"));
    assert!(!headers.contains_name("x-api-key"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Cross-consistency: endpoint + headers
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn endpoint_and_headers_both_succeed_for_documented_provider_matrix() {
    let providers = [
        "anthropic",
        "openai",
        "google",
        "deepseek",
        "qwen",
        "zai",
        "kimi",
        "minimax",
    ];
    let models = [
        "claude-sonnet-4-5",
        "gpt-4o",
        "gemini-2.5-pro",
        "deepseek-chat",
        "qwen2.5",
        "glm-4",
        "kimi-k2.7-code",
        "MiniMax-M3",
    ];
    let api_key = key();
    for (provider, model) in providers.iter().zip(models.iter()) {
        let endpoint = resolve_endpoint(provider, model, "https://api.x.com", None);
        assert!(
            endpoint.is_ok(),
            "endpoint MUST resolve for known provider {provider:?}"
        );
        let headers = resolve_headers(provider, Some(&api_key), None, &SensitiveHeaders::new());
        assert!(
            headers.is_ok(),
            "headers MUST resolve for known provider {provider:?}"
        );
    }
}

#[test]
fn endpoint_and_headers_both_error_for_unknown_provider() {
    let api_key = key();
    let endpoint = resolve_endpoint("xyz", "m", "https://x.com", None);
    let headers = resolve_headers("xyz", Some(&api_key), None, &SensitiveHeaders::new());
    assert!(endpoint.is_err());
    assert!(headers.is_err());
}
