//! End-to-end tests for `claude_credentials` beta-header
//! constants + `strip_cache_control_ttl` + `CredentialsFile`
//! / `ClaudeAiOauth` / `LoadedCredentials` serde shape.
//!
//! Sprint 120 of the verification effort. Sprint 68
//! (`claude_credentials_auth_e2e`) covered
//! `get_oauth_headers` + `get_oauth_endpoint` +
//! `claude_code_beta_header_value` + `inject_oauth_prefix_only`;
//! this file pins the documented beta-header constants
//! (versioned wire identifiers — drift breaks OAuth model
//! access) and the `cache_control.ttl` strip pass.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::claude_credentials::{strip_cache_control_ttl, ClaudeAiOauth, CredentialsFile};
#[cfg(feature = "experimental-claude-subscription-auth")]
use openclaudia::claude_credentials::{
    CLAUDE_CODE_BETA_HEADER, FINE_GRAINED_TOOL_STREAMING_BETA, INTERLEAVED_THINKING_BETA,
    OAUTH_BETA_HEADER,
};
use openclaudia::secrets::OAuthToken;
use serde_json::json;

fn token(value: &str) -> OAuthToken {
    OAuthToken::try_from_string(value.to_string()).expect("valid token")
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Versioned beta-header constants
// ───────────────────────────────────────────────────────────────────────────

#[cfg(feature = "experimental-claude-subscription-auth")]
#[test]
fn oauth_beta_header_constant_matches_documented_version() {
    assert_eq!(OAUTH_BETA_HEADER, "oauth-2025-04-20");
}

#[cfg(feature = "experimental-claude-subscription-auth")]
#[test]
fn claude_code_beta_header_constant_matches_documented_version() {
    assert_eq!(CLAUDE_CODE_BETA_HEADER, "claude-code-20250219");
}

#[cfg(feature = "experimental-claude-subscription-auth")]
#[test]
fn interleaved_thinking_beta_constant_matches_documented_version() {
    assert_eq!(INTERLEAVED_THINKING_BETA, "interleaved-thinking-2025-05-14");
}

#[cfg(feature = "experimental-claude-subscription-auth")]
#[test]
fn fine_grained_tool_streaming_beta_constant_matches_documented_version() {
    assert_eq!(
        FINE_GRAINED_TOOL_STREAMING_BETA,
        "fine-grained-tool-streaming-2025-05-14"
    );
}

#[cfg(feature = "experimental-claude-subscription-auth")]
#[test]
fn beta_constants_are_pairwise_distinct() {
    let consts = [
        OAUTH_BETA_HEADER,
        CLAUDE_CODE_BETA_HEADER,
        INTERLEAVED_THINKING_BETA,
        FINE_GRAINED_TOOL_STREAMING_BETA,
    ];
    let mut sorted: Vec<&str> = consts.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), consts.len());
}

#[cfg(feature = "experimental-claude-subscription-auth")]
#[test]
fn beta_constants_use_iso_date_suffix() {
    // Documented pattern: <feature>-YYYY-MM-DD.
    for c in [
        OAUTH_BETA_HEADER,
        CLAUDE_CODE_BETA_HEADER,
        INTERLEAVED_THINKING_BETA,
        FINE_GRAINED_TOOL_STREAMING_BETA,
    ] {
        let has_date = c.chars().filter(char::is_ascii_digit).count() >= 8;
        assert!(
            has_date,
            "beta header {c:?} MUST include an 8+ digit date suffix"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — strip_cache_control_ttl
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn strip_cache_control_ttl_removes_ttl_from_top_level_cache_control() {
    let mut v = json!({
        "cache_control": {"type": "ephemeral", "ttl": "5m"}
    });
    strip_cache_control_ttl(&mut v);
    assert!(
        v["cache_control"].get("ttl").is_none(),
        "ttl MUST be removed; got {v}"
    );
    assert_eq!(v["cache_control"]["type"], "ephemeral");
}

#[test]
fn strip_cache_control_ttl_preserves_other_cache_control_fields() {
    let mut v = json!({
        "cache_control": {"type": "ephemeral", "ttl": "1h", "other": "preserved"}
    });
    strip_cache_control_ttl(&mut v);
    assert_eq!(v["cache_control"]["type"], "ephemeral");
    assert_eq!(v["cache_control"]["other"], "preserved");
    assert!(v["cache_control"].get("ttl").is_none());
}

#[test]
fn strip_cache_control_ttl_recurses_into_nested_objects() {
    let mut v = json!({
        "outer": {
            "inner": {
                "cache_control": {"type": "ephemeral", "ttl": "5m"}
            }
        }
    });
    strip_cache_control_ttl(&mut v);
    assert!(v["outer"]["inner"]["cache_control"].get("ttl").is_none());
}

#[test]
fn strip_cache_control_ttl_recurses_into_arrays() {
    let mut v = json!({
        "messages": [
            {"role": "user", "cache_control": {"type": "ephemeral", "ttl": "5m"}},
            {"role": "assistant", "cache_control": {"type": "ephemeral", "ttl": "1h"}}
        ]
    });
    strip_cache_control_ttl(&mut v);
    assert!(v["messages"][0]["cache_control"].get("ttl").is_none());
    assert!(v["messages"][1]["cache_control"].get("ttl").is_none());
}

#[test]
fn strip_cache_control_ttl_no_op_when_no_cache_control_present() {
    let mut v = json!({"foo": "bar", "nested": {"baz": 42}});
    let original = v.clone();
    strip_cache_control_ttl(&mut v);
    assert_eq!(v, original, "no cache_control → identity pass");
}

#[test]
fn strip_cache_control_ttl_no_op_on_cache_control_already_missing_ttl() {
    let mut v = json!({"cache_control": {"type": "ephemeral"}});
    let before_clone = v.clone();
    strip_cache_control_ttl(&mut v);
    assert_eq!(v, before_clone);
}

#[test]
fn strip_cache_control_ttl_handles_primitive_root() {
    let mut v = json!("just a string");
    strip_cache_control_ttl(&mut v);
    assert_eq!(v, json!("just a string"));
}

#[test]
fn strip_cache_control_ttl_handles_null_root() {
    let mut v = json!(null);
    strip_cache_control_ttl(&mut v);
    assert_eq!(v, json!(null));
}

#[test]
fn strip_cache_control_ttl_handles_empty_object() {
    let mut v = json!({});
    strip_cache_control_ttl(&mut v);
    assert_eq!(v, json!({}));
}

#[test]
fn strip_cache_control_ttl_deep_recursion_does_not_panic() {
    // Deeply nested object — depth cap should kick in but
    // NOT panic.
    let mut v = json!(null);
    for _ in 0..50 {
        v = json!({"nested": v});
    }
    strip_cache_control_ttl(&mut v);
    // No panic; structure intact (or partially intact post cap).
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — CredentialsFile + ClaudeAiOauth serde
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn credentials_file_deserializes_with_claude_ai_oauth_field() {
    let json = r#"{
        "claudeAiOauth": {
            "accessToken": "sk-ant-oat01-abc",
            "refreshToken": "sk-ant-ort01-def",
            "expiresAt": 1700000000000,
            "scopes": ["user:inference"]
        }
    }"#;
    let creds: CredentialsFile = serde_json::from_str(json).expect("de");
    let oauth = creds.claude_ai_oauth.expect("Some");
    assert!(oauth.access_token.matches("sk-ant-oat01-abc"));
    assert!(oauth
        .refresh_token
        .as_ref()
        .is_some_and(|token| token.matches("sk-ant-ort01-def")));
    assert_eq!(oauth.expires_at, 1_700_000_000_000);
    assert_eq!(oauth.scopes, vec!["user:inference"]);
}

#[test]
fn credentials_file_with_missing_oauth_field_yields_none() {
    let json = "{}";
    let creds: CredentialsFile = serde_json::from_str(json).expect("de");
    assert!(creds.claude_ai_oauth.is_none());
}

#[test]
fn claude_ai_oauth_serde_uses_camelcase_wire_field_names() {
    let oauth = ClaudeAiOauth {
        access_token: token("at"),
        refresh_token: None,
        expires_at: 12345,
        scopes: Vec::new(),
        subscription_type: None,
        rate_limit_tier: None,
    };
    let json = serde_json::to_string(&oauth).expect("ser");
    // PINS WIRE: camelCase on wire (Claude Code parity).
    assert!(json.contains("\"accessToken\""));
    assert!(json.contains("\"expiresAt\""));
    assert!(
        !json.contains("\"access_token\""),
        "wire MUST NOT use snake_case; got {json:?}"
    );
}

#[test]
fn claude_ai_oauth_with_subscription_type_serializes_only_redactions() {
    let original = ClaudeAiOauth {
        access_token: token("at"),
        refresh_token: Some(token("rt")),
        expires_at: 1_700_000_000_000,
        scopes: vec!["scope-a".to_string(), "scope-b".to_string()],
        subscription_type: Some("max-5x".to_string()),
        rate_limit_tier: Some("standard".to_string()),
    };
    let json = serde_json::to_string(&original).expect("ser");
    assert!(!json.contains("\"at\""));
    assert!(!json.contains("\"rt\""));
    assert!(json.contains("[REDACTED]"));
    assert!(serde_json::from_str::<ClaudeAiOauth>(&json).is_err());
}

#[test]
fn claude_ai_oauth_deserializes_with_minimal_required_fields() {
    let json = r#"{
        "accessToken": "x",
        "expiresAt": 0,
        "scopes": []
    }"#;
    let oauth: ClaudeAiOauth = serde_json::from_str(json).expect("de");
    assert!(oauth.access_token.matches("x"));
    assert_eq!(oauth.expires_at, 0);
    assert!(oauth.refresh_token.is_none());
    assert!(oauth.subscription_type.is_none());
    assert!(oauth.rate_limit_tier.is_none());
}

#[test]
fn claude_ai_oauth_clone_preserves_all_fields() {
    let original = ClaudeAiOauth {
        access_token: token("a"),
        refresh_token: Some(token("r")),
        expires_at: 100,
        scopes: vec!["s".to_string()],
        subscription_type: Some("t".to_string()),
        rate_limit_tier: Some("rt".to_string()),
    };
    let cloned = original.clone();
    assert_eq!(cloned.access_token, original.access_token);
    assert_eq!(cloned.refresh_token, original.refresh_token);
    assert_eq!(cloned.expires_at, original.expires_at);
    assert_eq!(cloned.scopes, original.scopes);
    assert_eq!(cloned.subscription_type, original.subscription_type);
    assert_eq!(cloned.rate_limit_tier, original.rate_limit_tier);
}
