//! End-to-end tests for `oauth::OAuthStore` — challenge
//! storage take-once semantics, session round-trip,
//! `OAuthCredentials::is_expired` boundary, and
//! `OAuthSession::can_create_api_key` scope check.
//!
//! Sprint 167 of the verification effort. Sprint 99
//! covered the PKCE flow state machine; this file pins
//! the storage operations distinct from the flow logic.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use chrono::{Duration, Utc};
use openclaudia::oauth::{AuthMode, OAuthCredentials, OAuthSession, OAuthStore, PkceParams};
use openclaudia::secrets::OAuthToken;

fn authorization_state(pkce: &PkceParams) -> String {
    url::Url::parse(&pkce.build_auth_url())
        .expect("authorization URL")
        .query_pairs()
        .find_map(|(name, value)| (name == "state").then(|| value.into_owned()))
        .expect("state query parameter")
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Challenge store/take round-trip
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn store_and_take_challenge_roundtrip_by_state() {
    let store = OAuthStore::ephemeral();
    let pkce = PkceParams::generate();
    let state = authorization_state(&pkce);
    let verifier = pkce.verifier.clone();
    store.store_challenge(pkce);

    let taken = store.take_challenge(&state).expect("present");
    assert!(taken.state.matches(&state));
    assert_eq!(taken.verifier, verifier);
}

#[test]
fn take_challenge_with_unknown_state_returns_none() {
    let store = OAuthStore::ephemeral();
    let outcome = store.take_challenge("bogus-state-167");
    assert!(outcome.is_none());
}

#[test]
fn take_challenge_consumes_entry_so_second_take_returns_none() {
    // PINS TAKE-ONCE: storing once + taking twice → second
    // call returns None (CSRF state is single-use).
    let store = OAuthStore::ephemeral();
    let pkce = PkceParams::generate();
    let state = authorization_state(&pkce);
    store.store_challenge(pkce);

    let first = store.take_challenge(&state);
    assert!(first.is_some(), "first take MUST succeed");
    let second = store.take_challenge(&state);
    assert!(second.is_none(), "PINS TAKE-ONCE: second take MUST be None");
}

#[test]
fn multiple_challenges_for_distinct_states_coexist() {
    let store = OAuthStore::ephemeral();
    let p1 = PkceParams::generate();
    let p2 = PkceParams::generate();
    let s1 = authorization_state(&p1);
    let s2 = authorization_state(&p2);
    assert_ne!(s1, s2, "PKCE states MUST be distinct");
    store.store_challenge(p1);
    store.store_challenge(p2);
    assert!(store.take_challenge(&s1).is_some());
    assert!(store.take_challenge(&s2).is_some());
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Session store/get round-trip
// ───────────────────────────────────────────────────────────────────────────

fn fresh_session(id: &str) -> OAuthSession {
    OAuthSession {
        id: id.to_string(),
        credentials: OAuthCredentials {
            access_token: OAuthToken::try_from_string("test-token-167".to_string()).unwrap(),
            refresh_token: Some(OAuthToken::try_from_string("refresh-167".to_string()).unwrap()),
            expires_at: Utc::now() + Duration::hours(1),
        },
        api_key: None,
        auth_mode: AuthMode::ApiKey,
        granted_scopes: vec![
            "org:create_api_key".to_string(),
            "user:inference".to_string(),
        ],
        created_at: Utc::now(),
        user_id: None,
    }
}

#[test]
fn store_and_get_session_roundtrip_preserves_id_and_token() {
    let store = OAuthStore::ephemeral();
    let session = fresh_session("session-167-a");
    let expected_token = session.credentials.access_token.clone();
    store.store_session(session);
    let retrieved = store.get_session("session-167-a").expect("present");
    assert_eq!(retrieved.id, "session-167-a");
    // PINS ROUND-TRIP: stored token matches what comes back.
    assert_eq!(retrieved.credentials.access_token, expected_token);
}

#[test]
fn get_session_unknown_id_returns_none() {
    let store = OAuthStore::ephemeral();
    let outcome = store.get_session("definitely-not-a-session-167");
    assert!(outcome.is_none());
}

#[test]
fn get_session_does_not_consume_entry_unlike_take_challenge() {
    // PINS ASYMMETRY: get_session is read-only; challenge.take is take-once.
    let store = OAuthStore::ephemeral();
    let session = fresh_session("session-167-b");
    store.store_session(session);
    let first = store.get_session("session-167-b");
    assert!(first.is_some());
    let second = store.get_session("session-167-b");
    assert!(second.is_some(), "get_session MUST be read-only");
}

#[test]
fn store_session_with_same_id_overwrites() {
    // PINS UPSERT: store_session with same id replaces prior.
    let store = OAuthStore::ephemeral();
    let mut s1 = fresh_session("session-167-c");
    s1.credentials.access_token = OAuthToken::try_from_string("token-v1".to_string()).unwrap();
    store.store_session(s1);

    let mut s2 = fresh_session("session-167-c");
    s2.credentials.access_token = OAuthToken::try_from_string("token-v2".to_string()).unwrap();
    store.store_session(s2);

    let retrieved = store.get_session("session-167-c").expect("present");
    assert!(retrieved.credentials.access_token.matches("token-v2"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — OAuthCredentials::is_expired
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn credentials_expired_when_expires_at_in_past() {
    let creds = OAuthCredentials {
        access_token: OAuthToken::try_from_string("x".to_string()).unwrap(),
        refresh_token: None,
        expires_at: Utc::now() - Duration::hours(1),
    };
    assert!(creds.is_expired(), "past expires_at MUST be expired");
}

#[test]
fn credentials_not_expired_when_expires_at_in_future() {
    let creds = OAuthCredentials {
        access_token: OAuthToken::try_from_string("x".to_string()).unwrap(),
        refresh_token: None,
        expires_at: Utc::now() + Duration::hours(1),
    };
    assert!(!creds.is_expired(), "future expires_at MUST NOT be expired");
}

#[test]
fn credentials_far_future_not_expired() {
    let creds = OAuthCredentials {
        access_token: OAuthToken::try_from_string("x".to_string()).unwrap(),
        refresh_token: None,
        expires_at: Utc::now() + Duration::days(365),
    };
    assert!(!creds.is_expired());
}

#[test]
fn credentials_far_past_expired() {
    let creds = OAuthCredentials {
        access_token: OAuthToken::try_from_string("x".to_string()).unwrap(),
        refresh_token: None,
        expires_at: Utc::now() - Duration::days(365),
    };
    assert!(creds.is_expired());
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — OAuthSession::can_create_api_key scope check
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn can_create_api_key_true_with_org_create_api_key_scope() {
    let mut session = fresh_session("scope-test-a");
    session.granted_scopes = vec!["org:create_api_key".to_string()];
    assert!(session.can_create_api_key());
}

#[test]
fn can_create_api_key_false_without_scope() {
    let mut session = fresh_session("scope-test-b");
    session.granted_scopes = vec!["user:read".to_string()];
    assert!(!session.can_create_api_key());
}

#[test]
fn can_create_api_key_false_on_empty_scopes() {
    let mut session = fresh_session("scope-test-c");
    session.granted_scopes = Vec::new();
    assert!(!session.can_create_api_key());
}

#[test]
fn can_create_api_key_true_when_scope_present_with_others() {
    let mut session = fresh_session("scope-test-d");
    session.granted_scopes = vec![
        "user:read".to_string(),
        "org:create_api_key".to_string(),
        "other:scope".to_string(),
    ];
    assert!(session.can_create_api_key());
}

#[test]
fn can_create_api_key_case_sensitive_rejects_uppercase() {
    let mut session = fresh_session("scope-test-e");
    // PINS CASE-SENSITIVE: scope check uses exact string match.
    session.granted_scopes = vec!["ORG:CREATE_API_KEY".to_string()];
    assert!(
        !session.can_create_api_key(),
        "uppercase scope MUST NOT match (exact-string check)"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Cross-store isolation
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn distinct_stores_have_independent_challenge_state() {
    let store_a = OAuthStore::ephemeral();
    let store_b = OAuthStore::ephemeral();
    let pkce = PkceParams::generate();
    let state = authorization_state(&pkce);
    store_a.store_challenge(pkce);
    // store_b knows nothing about it.
    assert!(store_b.take_challenge(&state).is_none());
    // store_a still has it.
    assert!(store_a.take_challenge(&state).is_some());
}

#[test]
fn store_a_session_is_visible_to_store_a_get() {
    // Tests use the explicit in-memory constructor and never mutate the
    // operator's real OAuth session document.
    let store_a = OAuthStore::ephemeral();
    let uniq = format!("sprint-167-{}", std::process::id());
    let session = fresh_session(&uniq);
    store_a.store_session(session);
    assert!(store_a.get_session(&uniq).is_some());
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — AuthMode enum
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn auth_mode_variants_are_distinct_under_partial_eq() {
    assert_ne!(AuthMode::ApiKey, AuthMode::BearerToken);
    assert_ne!(AuthMode::ApiKey, AuthMode::ProxyMode);
    assert_ne!(AuthMode::BearerToken, AuthMode::ProxyMode);
}

#[test]
fn auth_mode_supports_clone_and_eq() {
    let m = AuthMode::ApiKey;
    let cloned = m.clone();
    assert_eq!(m, cloned);
}

#[test]
fn auth_mode_serializes_to_camel_case_pascal_variant_names() {
    // PINS WIRE: serde default uses pascal-case variant names.
    let m = AuthMode::ApiKey;
    let s = serde_json::to_string(&m).expect("ser");
    // The default serde for tagged enums uses bare variant name string.
    assert!(s.contains("ApiKey") || s.contains("api_key"));
}
