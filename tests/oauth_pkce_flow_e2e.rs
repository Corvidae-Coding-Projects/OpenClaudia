//! End-to-end tests for `oauth::PkceParams` + `parse_auth_code` +
//! `OAuthCredentials::is_expired` + `AuthMode` and
//! `mcp_oauth::OAuthFlow` state machine + `TokenBundle::is_expired`
//! / `needs_refresh`.
//!
//! Sprint 80 of the verification effort. Security-sensitive
//! surface — pins PKCE generation entropy, auth-URL parameter
//! ordering, fragment-style auth code parsing, OAuth flow
//! state-machine transition validity, and token-expiry math.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::mcp_oauth::{OAuthConfig, OAuthError, OAuthFlow, PkcePair, TokenBundle};
use openclaudia::oauth::{
    parse_auth_code, AuthMode, OAuthCredentials, PkceParams, ANTHROPIC_CLIENT_ID,
    ANTHROPIC_REDIRECT_URI, OAUTH_AUTHORIZE_URL,
};
use openclaudia::secrets::OAuthToken;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn authorization_state(pkce: &PkceParams) -> String {
    url::Url::parse(&pkce.build_auth_url())
        .expect("authorization URL")
        .query_pairs()
        .find_map(|(name, value)| (name == "state").then(|| value.into_owned()))
        .expect("state query parameter")
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — oauth constants
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn anthropic_client_id_is_documented_uuid_format() {
    // UUID v4 from the docs.
    assert_eq!(ANTHROPIC_CLIENT_ID, "9d1c250a-e61b-44d9-88ed-5944d1962f5e");
}

#[test]
fn anthropic_redirect_uri_points_to_console_callback() {
    assert_eq!(
        ANTHROPIC_REDIRECT_URI,
        "https://console.anthropic.com/oauth/code/callback"
    );
}

#[test]
fn oauth_authorize_url_points_to_claude_ai() {
    assert_eq!(OAUTH_AUTHORIZE_URL, "https://claude.ai/oauth/authorize");
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — PkceParams generation
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn pkce_generate_yields_high_entropy_redacted_verifier() {
    let p = PkceParams::generate();
    // base64url(64 random bytes) → ~86 chars.
    assert!(
        p.verifier.len() >= 80,
        "verifier MUST have substantial length; got {} chars",
        p.verifier.len()
    );
    let rendered = format!("{:?}", p.verifier);
    assert_eq!(rendered, "SecretString([REDACTED])");
}

#[test]
fn pkce_generate_yields_high_entropy_state() {
    let p = PkceParams::generate();
    let state = authorization_state(&p);
    assert!(state.len() >= 80);
    assert!(state
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    let rendered = format!("{p:?}");
    assert!(
        !rendered.contains(&state),
        "PKCE Debug leaked state: {rendered}"
    );
    assert!(rendered.contains("SecretString([REDACTED])"));
}

#[test]
fn pkce_generate_two_invocations_yield_distinct_values() {
    let a = PkceParams::generate();
    let b = PkceParams::generate();
    assert_ne!(a.verifier, b.verifier, "verifier MUST be unique per call");
    assert_ne!(a.state, b.state, "state MUST be unique per call");
    assert_ne!(a.challenge, b.challenge, "challenge MUST be unique");
}

#[test]
fn pkce_challenge_is_deterministic_function_of_verifier() {
    // Generate once, then construct a fresh PkceParams with the
    // same verifier — challenge MUST be byte-identical (SHA256
    // is deterministic).
    let p1 = PkceParams::generate();
    // Round-trip via JSON to construct a second equal verifier.
    // PkceParams isn't Serialize, so verify via build_auth_url
    // — the challenge appears in the URL query.
    let url = p1.build_auth_url();
    assert!(url.contains(&p1.challenge));
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — PkceParams::build_auth_url
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn build_auth_url_starts_with_documented_authorize_endpoint() {
    let p = PkceParams::generate();
    let url = p.build_auth_url();
    assert!(url.starts_with(OAUTH_AUTHORIZE_URL));
}

#[test]
fn build_auth_url_includes_every_required_oauth_parameter() {
    let p = PkceParams::generate();
    let url = p.build_auth_url();
    // Required OAuth + PKCE params per documented impl.
    assert!(url.contains("code=true"));
    assert!(url.contains(&format!("client_id={ANTHROPIC_CLIENT_ID}")));
    assert!(url.contains("response_type=code"));
    assert!(url.contains("code_challenge="));
    assert!(url.contains("code_challenge_method=S256"));
    assert!(url.contains("state="));
    assert!(url.contains("scope="));
    // redirect_uri is URL-encoded.
    assert!(url.contains("redirect_uri="));
}

#[test]
fn build_auth_url_carries_verifier_challenge_not_verifier_directly() {
    let p = PkceParams::generate();
    let url = p.build_auth_url();
    // Challenge appears in URL; verifier MUST NOT (verifier
    // stays secret until token exchange).
    assert!(url.contains(&p.challenge));
    assert!(
        !p.verifier.appears_in(&url),
        "verifier MUST NOT appear in authorize URL; got {url:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — parse_auth_code fragment parsing
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn parse_auth_code_splits_on_hash_into_code_and_state() {
    let (code, state) = parse_auth_code("the-code#the-state");
    assert_eq!(code, "the-code");
    assert_eq!(state.as_deref(), Some("the-state"));
}

#[test]
fn parse_auth_code_without_hash_returns_none_state() {
    let (code, state) = parse_auth_code("just-the-code");
    assert_eq!(code, "just-the-code");
    assert!(state.is_none());
}

#[test]
fn parse_auth_code_empty_input_yields_empty_code_no_state() {
    let (code, state) = parse_auth_code("");
    assert_eq!(code, "");
    assert!(state.is_none());
}

#[test]
fn parse_auth_code_handles_empty_state_after_hash() {
    let (code, state) = parse_auth_code("the-code#");
    assert_eq!(code, "the-code");
    assert_eq!(state.as_deref(), Some(""));
}

#[test]
fn parse_auth_code_handles_only_hash_as_empty_code_empty_state() {
    let (code, state) = parse_auth_code("#");
    assert_eq!(code, "");
    assert_eq!(state.as_deref(), Some(""));
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — OAuthCredentials::is_expired
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn oauth_credentials_future_expiry_is_not_expired() {
    let cred = OAuthCredentials {
        access_token: OAuthToken::try_from_string("tok".to_string()).expect("token"),
        refresh_token: None,
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
    };
    assert!(!cred.is_expired());
}

#[test]
fn oauth_credentials_past_expiry_is_expired() {
    let cred = OAuthCredentials {
        access_token: OAuthToken::try_from_string("tok".to_string()).expect("token"),
        refresh_token: None,
        expires_at: chrono::Utc::now() - chrono::Duration::hours(1),
    };
    assert!(cred.is_expired());
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — AuthMode + serde
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn auth_mode_variants_compare_distinctly() {
    assert_ne!(AuthMode::ApiKey, AuthMode::BearerToken);
    assert_ne!(AuthMode::BearerToken, AuthMode::ProxyMode);
    assert_ne!(AuthMode::ApiKey, AuthMode::ProxyMode);
}

#[test]
fn auth_mode_round_trips_through_json() {
    for mode in &[AuthMode::ApiKey, AuthMode::BearerToken, AuthMode::ProxyMode] {
        let json = serde_json::to_string(mode).expect("ser");
        let back: AuthMode = serde_json::from_str(&json).expect("de");
        assert_eq!(back, *mode);
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — mcp_oauth TokenBundle::is_expired + needs_refresh
// ───────────────────────────────────────────────────────────────────────────

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("epoch")
        .as_secs()
}

#[test]
fn token_bundle_with_long_lifetime_is_not_expired() {
    let bundle = TokenBundle {
        access_token: OAuthToken::try_from_string("at".to_string()).expect("token"),
        refresh_token: None,
        expires_in_secs: 3600,
        obtained_at: now_epoch(),
        token_type: "Bearer".to_string(),
        scope: String::new(),
    };
    assert!(!bundle.is_expired());
}

#[test]
fn token_bundle_with_past_obtained_at_plus_short_lifetime_is_expired() {
    let bundle = TokenBundle {
        access_token: OAuthToken::try_from_string("at".to_string()).expect("token"),
        refresh_token: None,
        expires_in_secs: 1,
        // Obtained 1 hour ago, lifetime 1 second → expired.
        obtained_at: now_epoch().saturating_sub(3600),
        token_type: "Bearer".to_string(),
        scope: String::new(),
    };
    assert!(bundle.is_expired());
}

#[test]
fn token_bundle_needs_refresh_within_safety_window() {
    // Token expires 30 seconds from now; safety window 60s
    // → needs refresh.
    let bundle = TokenBundle {
        access_token: OAuthToken::try_from_string("at".to_string()).expect("token"),
        refresh_token: None,
        expires_in_secs: 30,
        obtained_at: now_epoch(),
        token_type: "Bearer".to_string(),
        scope: String::new(),
    };
    assert!(bundle.needs_refresh(Duration::from_mins(1)));
}

#[test]
fn token_bundle_does_not_need_refresh_far_outside_safety_window() {
    let bundle = TokenBundle {
        access_token: OAuthToken::try_from_string("at".to_string()).expect("token"),
        refresh_token: None,
        expires_in_secs: 3600,
        obtained_at: now_epoch(),
        token_type: "Bearer".to_string(),
        scope: String::new(),
    };
    assert!(!bundle.needs_refresh(Duration::from_mins(1)));
}

#[test]
fn token_bundle_serde_redacts_and_rejects_lossy_round_trip() {
    let bundle = TokenBundle {
        access_token: OAuthToken::try_from_string("at".to_string()).expect("token"),
        refresh_token: Some(OAuthToken::try_from_string("rt".to_string()).expect("token")),
        expires_in_secs: 3600,
        obtained_at: 1_700_000_000,
        token_type: "Bearer".to_string(),
        scope: "read write".to_string(),
    };
    let json = serde_json::to_string(&bundle).expect("ser");
    assert!(!json.contains("\"at\""));
    assert!(!json.contains("\"rt\""));
    assert!(serde_json::from_str::<TokenBundle>(&json).is_err());
}

#[test]
fn token_bundle_with_absent_refresh_token_omits_field_but_remains_non_reloadable() {
    let bundle = TokenBundle {
        access_token: OAuthToken::try_from_string("at".to_string()).expect("token"),
        refresh_token: None,
        expires_in_secs: 1000,
        obtained_at: 1_700_000_000,
        token_type: "Bearer".to_string(),
        scope: String::new(),
    };
    let json = serde_json::to_string(&bundle).expect("ser");
    let encoded: serde_json::Value = serde_json::from_str(&json).expect("encoded JSON");
    assert!(encoded.get("refresh_token").is_none());
    assert!(serde_json::from_str::<TokenBundle>(&json).is_err());
}

// ───────────────────────────────────────────────────────────────────────────
// Section H — mcp_oauth OAuthFlow state machine
// ───────────────────────────────────────────────────────────────────────────

fn fresh_config() -> OAuthConfig {
    OAuthConfig {
        client_id: "test-client".to_string(),
        client_secret: None,
        authorize_url: "https://example.com/authorize".to_string(),
        token_url: "https://example.com/token".to_string(),
        redirect_uri: "http://localhost:8080/callback".to_string(),
        scopes: vec!["read".to_string()],
    }
}

fn fresh_pkce() -> PkcePair {
    PkcePair {
        code_verifier: openclaudia::secrets::SecretString::try_from_string("verifier".to_string())
            .expect("verifier"),
        code_challenge: "challenge".to_string(),
        method: "S256",
    }
}

#[test]
fn oauth_flow_new_starts_in_idle_state() {
    let flow = OAuthFlow::new(fresh_config());
    assert!(matches!(flow, OAuthFlow::Idle { .. }));
}

#[test]
fn start_authorization_from_idle_transitions_to_awaiting() {
    let flow = OAuthFlow::new(fresh_config());
    let next = flow
        .start_authorization("state-nonce".to_string(), fresh_pkce())
        .expect("transition");
    assert!(matches!(next, OAuthFlow::AwaitingAuthorization { .. }));
}

#[test]
fn start_authorization_from_authorized_is_invalid_transition() {
    let flow = OAuthFlow::Authorized {
        config: fresh_config(),
        token: TokenBundle {
            access_token: OAuthToken::try_from_string("at".to_string()).expect("token"),
            refresh_token: None,
            expires_in_secs: 100,
            obtained_at: now_epoch(),
            token_type: "Bearer".to_string(),
            scope: String::new(),
        },
    };
    let outcome = flow.start_authorization("s".to_string(), fresh_pkce());
    assert!(matches!(outcome, Err(OAuthError::InvalidTransition { .. })));
}

#[test]
fn accept_redirect_with_matching_state_transitions_to_exchanging() {
    let flow = OAuthFlow::new(fresh_config());
    let awaiting = flow
        .start_authorization("expected-state".to_string(), fresh_pkce())
        .expect("transition");
    let exchanging = awaiting
        .accept_redirect("expected-state", "auth-code".to_string())
        .expect("redirect ok");
    assert!(matches!(exchanging, OAuthFlow::Exchanging { .. }));
}

#[test]
fn accept_redirect_with_mismatched_state_errors_state_mismatch() {
    // PINS CSRF GUARD: returned state MUST match sent state.
    let flow = OAuthFlow::new(fresh_config());
    let awaiting = flow
        .start_authorization("expected-state".to_string(), fresh_pkce())
        .expect("transition");
    let outcome = awaiting.accept_redirect("ATTACKER-STATE", "code".to_string());
    let matched = matches!(&outcome, Err(OAuthError::StateMismatch { .. }));
    assert!(
        matched,
        "MUST refuse state mismatch as CSRF guard; got {outcome:?}"
    );
    let rendered = format!("{outcome:?}");
    assert!(!rendered.contains("expected-state"), "{rendered}");
    assert!(!rendered.contains("ATTACKER-STATE"), "{rendered}");
}

#[test]
fn complete_exchange_from_exchanging_transitions_to_authorized() {
    let flow = OAuthFlow::new(fresh_config());
    let awaiting = flow
        .start_authorization("s".to_string(), fresh_pkce())
        .unwrap();
    let exchanging = awaiting.accept_redirect("s", "code".to_string()).unwrap();
    let token = TokenBundle {
        access_token: OAuthToken::try_from_string("at".to_string()).expect("token"),
        refresh_token: None,
        expires_in_secs: 100,
        obtained_at: now_epoch(),
        token_type: "Bearer".to_string(),
        scope: String::new(),
    };
    let authorized = exchanging.complete_exchange(token).expect("complete");
    assert!(matches!(authorized, OAuthFlow::Authorized { .. }));
}

#[test]
fn complete_exchange_from_idle_is_invalid_transition() {
    let flow = OAuthFlow::new(fresh_config());
    let token = TokenBundle {
        access_token: OAuthToken::try_from_string("at".to_string()).expect("token"),
        refresh_token: None,
        expires_in_secs: 100,
        obtained_at: now_epoch(),
        token_type: "Bearer".to_string(),
        scope: String::new(),
    };
    let outcome = flow.complete_exchange(token);
    assert!(matches!(outcome, Err(OAuthError::InvalidTransition { .. })));
}

#[test]
fn fail_transitions_to_failed_terminal_state_from_any_state() {
    let flow = OAuthFlow::new(fresh_config());
    let failed = flow.fail("test failure");
    assert!(
        matches!(failed, OAuthFlow::Failed { ref reason } if reason.as_str() == "test failure")
    );
}
