//! End-to-end tests for `claude_credentials` OAuth-header builder +
//! `inject_oauth_prefix_only` + `strip_cache_control_ttl` recursion
//! cap + `CredentialsFile` serde shape.
//!
//! Sprint 68 of the verification effort. Security-sensitive surface
//! — pins the documented OAuth contract (Bearer header, beta
//! header value, prefix block insertion, `cache_control.ttl`
//! stripping, JSON-bomb stack-overflow guard).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]
#![cfg(feature = "experimental-claude-subscription-auth")]

use openclaudia::claude_credentials::{
    claude_code_beta_header_value as direct_beta_header_value,
    get_oauth_endpoint as direct_oauth_endpoint, get_oauth_headers as direct_oauth_headers,
    inject_oauth_prefix_only as direct_inject_oauth_prefix_only, strip_cache_control_ttl,
    ClaudeAiOauth, CredentialsFile, CLAUDE_CODE_SYSTEM_PROMPT,
    EXPERIMENTAL_DIRECT_SUBSCRIPTION_ACK, EXPERIMENTAL_DIRECT_SUBSCRIPTION_ENV,
};
use openclaudia::secrets::OAuthToken;
use serde_json::json;

fn token(value: &str) -> OAuthToken {
    OAuthToken::try_from_string(value.to_string()).expect("valid token")
}

fn enable_direct_experiment() {
    std::env::set_var(
        EXPERIMENTAL_DIRECT_SUBSCRIPTION_ENV,
        EXPERIMENTAL_DIRECT_SUBSCRIPTION_ACK,
    );
}

fn claude_code_beta_header_value() -> String {
    enable_direct_experiment();
    direct_beta_header_value().expect("experimental beta header")
}

fn get_oauth_headers(token: &OAuthToken) -> openclaudia::secrets::SensitiveHeaders {
    enable_direct_experiment();
    direct_oauth_headers(token).expect("experimental OAuth headers")
}

fn get_oauth_endpoint(model: &str) -> String {
    enable_direct_experiment();
    direct_oauth_endpoint(model).expect("experimental OAuth endpoint")
}

fn inject_oauth_prefix_only(request: &mut serde_json::Value) {
    enable_direct_experiment();
    direct_inject_oauth_prefix_only(request).expect("experimental OAuth prefix");
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — claude_code_beta_header_value
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn beta_header_contains_documented_oauth_token() {
    let v = claude_code_beta_header_value();
    assert!(
        v.contains("oauth-2025-04-20"),
        "beta header MUST contain oauth-2025-04-20; got {v:?}"
    );
}

#[test]
fn beta_header_contains_claude_code_token() {
    let v = claude_code_beta_header_value();
    assert!(
        v.contains("claude-code-20250219"),
        "beta header MUST contain claude-code-20250219; got {v:?}"
    );
}

#[test]
fn beta_header_is_comma_separated() {
    let v = claude_code_beta_header_value();
    // Documented format: comma-separated list of 4 tokens.
    assert!(
        v.contains(','),
        "beta header MUST be comma-separated; got {v:?}"
    );
    let tokens: Vec<&str> = v.split(',').collect();
    assert!(
        tokens.len() >= 2,
        "beta header MUST have multiple tokens; got {} ({v:?})",
        tokens.len()
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — get_oauth_headers
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn get_oauth_headers_includes_authorization_bearer() {
    let token = token("test-token-xyz");
    let headers = get_oauth_headers(&token);
    assert!(headers.matches_value("Authorization", "Bearer test-token-xyz"));
}

#[test]
fn get_oauth_headers_includes_anthropic_version() {
    let headers = get_oauth_headers(&token("t"));
    assert!(headers.matches_value("anthropic-version", "2023-06-01"));
}

#[test]
fn get_oauth_headers_includes_content_type_json() {
    let headers = get_oauth_headers(&token("t"));
    assert!(headers.matches_value("content-type", "application/json"));
}

#[test]
fn get_oauth_headers_anthropic_beta_matches_beta_header_value() {
    let headers = get_oauth_headers(&token("t"));
    // The header MUST match the single-source-of-truth value
    // — pins crosslink #272.
    assert!(headers.matches_value("anthropic-beta", &claude_code_beta_header_value()));
}

#[test]
fn get_oauth_headers_does_not_leak_access_token_into_other_headers() {
    // Defence-in-depth: the bearer token MUST appear in
    // Authorization ONLY. Spotting it leaking to
    // anthropic-version or content-type would indicate a
    // header-construction bug.
    let raw = "SECRET-BEARER-XYZ";
    let token = token(raw);
    let headers = get_oauth_headers(&token);
    assert!(headers.matches_value("Authorization", "Bearer SECRET-BEARER-XYZ"));
    assert!(!format!("{headers:?}").contains(raw));
    assert!(!serde_json::to_string(&headers)
        .expect("serialize redacted headers")
        .contains(raw));

    let request = headers
        .apply(reqwest::Client::new().get("https://example.com"))
        .expect("apply headers")
        .build()
        .expect("request");
    for (name, value) in request.headers() {
        let value = value.to_str().expect("ASCII header value");
        if name == reqwest::header::AUTHORIZATION {
            assert_eq!(value, "Bearer SECRET-BEARER-XYZ");
        } else {
            assert!(!value.contains(raw), "header {name} leaked the token");
        }
        assert!(request.headers()[name].is_sensitive());
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — get_oauth_endpoint
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn get_oauth_endpoint_returns_anthropic_messages_url() {
    let url = get_oauth_endpoint("claude-3-5-sonnet");
    assert_eq!(url, "https://api.anthropic.com/v1/messages");
}

#[test]
fn get_oauth_endpoint_ignores_model_argument() {
    // The contract: endpoint is the SAME regardless of model.
    let a = get_oauth_endpoint("model-a");
    let b = get_oauth_endpoint("model-b");
    let c = get_oauth_endpoint("");
    assert_eq!(a, b);
    assert_eq!(b, c);
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — inject_oauth_prefix_only
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn inject_oauth_prefix_into_empty_request_creates_array() {
    let mut req = json!({});
    inject_oauth_prefix_only(&mut req);
    // system MUST be an array.
    let sys = req.get("system").expect("system field");
    let arr = sys.as_array().expect("system is array");
    assert_eq!(arr.len(), 1, "single prefix block MUST be present");
    assert_eq!(arr[0]["type"], "text");
    assert_eq!(arr[0]["text"], CLAUDE_CODE_SYSTEM_PROMPT);
}

#[test]
fn inject_oauth_prefix_with_existing_string_system_creates_two_block_array() {
    let mut req = json!({"system": "existing user content"});
    inject_oauth_prefix_only(&mut req);
    let arr = req["system"].as_array().expect("array");
    assert_eq!(arr.len(), 2, "prefix + existing = 2 blocks");
    assert_eq!(arr[0]["text"], CLAUDE_CODE_SYSTEM_PROMPT);
    assert_eq!(arr[1]["text"], "existing user content");
}

#[test]
fn inject_oauth_prefix_with_existing_array_inserts_prefix_at_index_zero() {
    let mut req = json!({
        "system": [
            {"type": "text", "text": "block one"},
            {"type": "text", "text": "block two"}
        ]
    });
    inject_oauth_prefix_only(&mut req);
    let arr = req["system"].as_array().expect("array");
    assert_eq!(arr.len(), 3, "prefix + 2 existing");
    assert_eq!(
        arr[0]["text"], CLAUDE_CODE_SYSTEM_PROMPT,
        "prefix MUST be at index 0"
    );
    assert_eq!(arr[1]["text"], "block one");
    assert_eq!(arr[2]["text"], "block two");
}

#[test]
fn inject_oauth_prefix_does_not_modify_other_top_level_fields() {
    let mut req = json!({
        "model": "claude-3-5-sonnet",
        "messages": [{"role": "user", "content": "hi"}],
        "max_tokens": 100
    });
    inject_oauth_prefix_only(&mut req);
    assert_eq!(req["model"], "claude-3-5-sonnet");
    assert_eq!(req["max_tokens"], 100);
    assert!(req["messages"].is_array());
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — strip_cache_control_ttl
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn strip_cache_control_ttl_removes_ttl_field() {
    let mut value = json!({
        "cache_control": {"type": "ephemeral", "ttl": 300}
    });
    strip_cache_control_ttl(&mut value);
    let cc = value["cache_control"].as_object().expect("cc is obj");
    assert!(cc.contains_key("type"), "type field MUST be preserved");
    assert!(!cc.contains_key("ttl"), "ttl field MUST be removed");
}

#[test]
fn strip_cache_control_ttl_no_op_when_no_cache_control_present() {
    let mut value = json!({"text": "hello", "type": "text"});
    let before = value.clone();
    strip_cache_control_ttl(&mut value);
    assert_eq!(value, before, "no cache_control = no mutation");
}

#[test]
fn strip_cache_control_ttl_walks_into_nested_arrays() {
    let mut value = json!({
        "messages": [
            {"role": "user", "cache_control": {"type": "x", "ttl": 5}},
            {"role": "assistant", "cache_control": {"type": "y", "ttl": 10}}
        ]
    });
    strip_cache_control_ttl(&mut value);
    let msgs = value["messages"].as_array().unwrap();
    for m in msgs {
        let cc = m["cache_control"].as_object().unwrap();
        assert!(
            !cc.contains_key("ttl"),
            "ttl MUST be stripped from every nested message; got {cc:?}"
        );
    }
}

#[test]
fn strip_cache_control_ttl_recurses_into_content_blocks() {
    let mut value = json!({
        "system": [
            {
                "type": "text",
                "text": "hi",
                "cache_control": {"type": "ephemeral", "ttl": "5m"}
            }
        ]
    });
    strip_cache_control_ttl(&mut value);
    let block = &value["system"][0];
    let cc = block["cache_control"].as_object().unwrap();
    assert!(!cc.contains_key("ttl"));
    assert!(cc.contains_key("type"));
}

#[test]
fn strip_cache_control_ttl_terminates_on_pathologically_deep_input() {
    // Crosslink #805: depth cap protects against stack
    // overflow from a hostile JSON bomb.
    let mut value = json!(null);
    // Nest 100 deep — well past MAX_STRIP_DEPTH=32.
    for i in 0..100 {
        value = json!({format!("level_{i}"): value});
    }
    // MUST NOT panic / overflow.
    strip_cache_control_ttl(&mut value);
}

#[test]
fn strip_cache_control_ttl_terminates_on_pathologically_long_array() {
    let mut value = json!([]);
    for _ in 0..50 {
        value = json!([value]);
    }
    // MUST NOT panic.
    strip_cache_control_ttl(&mut value);
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — CredentialsFile / ClaudeAiOauth serde
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn credentials_file_generic_serde_redacts_and_refuses_lossy_round_trip() {
    let cred = CredentialsFile {
        claude_ai_oauth: Some(ClaudeAiOauth {
            access_token: token("tok-123"),
            refresh_token: Some(token("refresh-456")),
            expires_at: 1_700_000_000_000,
            scopes: vec!["read".to_string(), "write".to_string()],
            subscription_type: Some("pro".to_string()),
            rate_limit_tier: Some("tier1".to_string()),
        }),
    };
    let json = serde_json::to_string(&cred).expect("serialize");
    assert!(!json.contains("tok-123"));
    assert!(!json.contains("refresh-456"));
    assert!(serde_json::from_str::<CredentialsFile>(&json).is_err());
}

#[test]
fn credentials_file_deserializes_real_world_camel_case_keys() {
    // Pins the documented field renames matching CC's
    // ~/.claude/.credentials.json format.
    let json = r#"{
        "claudeAiOauth": {
            "accessToken": "AT",
            "refreshToken": "RT",
            "expiresAt": 9999,
            "scopes": ["a"],
            "subscriptionType": "pro",
            "rateLimitTier": "t1"
        }
    }"#;
    let cred: CredentialsFile = serde_json::from_str(json).expect("parse");
    let oauth = cred.claude_ai_oauth.expect("present");
    assert!(oauth.access_token.matches("AT"));
    assert!(oauth
        .refresh_token
        .as_ref()
        .is_some_and(|token| token.matches("RT")));
    assert_eq!(oauth.expires_at, 9999);
}

#[test]
fn credentials_file_with_no_oauth_block_deserializes_to_none() {
    let json = r#"{"claudeAiOauth": null}"#;
    let cred: CredentialsFile = serde_json::from_str(json).expect("parse");
    assert!(cred.claude_ai_oauth.is_none());
}

#[test]
fn claude_ai_oauth_refresh_token_is_optional() {
    let json = r#"{
        "accessToken": "AT",
        "expiresAt": 1,
        "scopes": []
    }"#;
    let oauth: ClaudeAiOauth = serde_json::from_str(json).expect("parse");
    assert!(oauth.refresh_token.is_none());
    assert!(oauth.subscription_type.is_none());
    assert!(oauth.rate_limit_tier.is_none());
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — CLAUDE_CODE_SYSTEM_PROMPT constant
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn claude_code_system_prompt_matches_documented_string() {
    // Documented exact-match string the Anthropic OAuth
    // endpoint validates. ANY drift here will 401 every
    // OAuth-authed request.
    assert_eq!(
        CLAUDE_CODE_SYSTEM_PROMPT,
        "You are Claude Code, Anthropic's official CLI for Claude."
    );
}
