//! End-to-end tests for `tools::remote_trigger::WebhookRegistry`
//! lifecycle (`register`, `replace`, `get`, `names`, `len`,
//! `is_empty`) + endpoint shape preservation.
//!
//! Sprint 104 of the verification effort. Sprint 39 covered the
//! URL validator + scheme matrix; this file pins the registry
//! lifecycle: register-then-get round-trip, replace as upsert,
//! `names` / `len` / `is_empty` accessor coherence.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::remote_trigger::{WebhookError, WebhookRegistry};
use std::collections::HashMap;

// ───────────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────────

fn no_headers() -> HashMap<String, String> {
    HashMap::new()
}

fn headers_with(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — register success path
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn register_then_get_round_trips_url() {
    let mut reg = WebhookRegistry::new();
    reg.register("ci", "https://ci.example.com/hook", no_headers())
        .expect("register");
    let ep = reg.get("ci").expect("get");
    assert!(ep.url.matches("https://ci.example.com/hook"));
    assert!(ep.headers.is_empty());
}

#[test]
fn register_with_headers_round_trips_full_endpoint_shape() {
    let mut reg = WebhookRegistry::new();
    let hdrs = headers_with(&[("Authorization", "Bearer token"), ("X-Custom", "value")]);
    reg.register("ci", "https://ci.example.com/hook", hdrs)
        .expect("register");
    let ep = reg.get("ci").expect("get");
    assert!(ep.url.matches("https://ci.example.com/hook"));
    assert_eq!(ep.headers.len(), 2);
    assert!(ep.headers.matches_value("Authorization", "Bearer token"));
    assert!(ep.headers.matches_value("X-Custom", "value"));
}

#[test]
fn register_upgrades_scheme_less_url_to_https_in_strict_registry() {
    let mut reg = WebhookRegistry::new();
    reg.register("ci", "ci.example.com/hook", no_headers())
        .expect("register");
    let ep = reg.get("ci").expect("get");
    assert!(ep.url.matches("https://ci.example.com/hook"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — register error paths
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn register_with_invalid_scheme_returns_invalid_scheme_error() {
    // Use ftp:// — a scheme that parses with a host but isn't
    // http/https. javascript: lacks a host so it's caught by the
    // Malformed gate before scheme validation; ftp:// reaches the
    // scheme-check branch. (Authoring discovery.)
    let mut reg = WebhookRegistry::new();
    let outcome = reg.register("evil", "ftp://ci.example.com/", no_headers());
    let err = outcome.unwrap_err();
    assert!(
        matches!(err, WebhookError::InvalidScheme { .. }),
        "ftp:// MUST hit InvalidScheme; got {err:?}"
    );
}

#[test]
fn register_with_malformed_url_returns_malformed_error() {
    let mut reg = WebhookRegistry::new();
    let outcome = reg.register("bad", "not a url", no_headers());
    let err = outcome.unwrap_err();
    assert!(matches!(err, WebhookError::Malformed { .. }));
}

#[test]
fn register_with_http_in_strict_registry_returns_insecure_scheme_error() {
    let mut reg = WebhookRegistry::new();
    let outcome = reg.register("plain", "http://ci.example.com/hook", no_headers());
    let err = outcome.unwrap_err();
    assert!(matches!(err, WebhookError::InsecureScheme { .. }));
}

#[test]
fn register_with_http_in_plaintext_registry_succeeds() {
    let mut reg = WebhookRegistry::new_allow_plaintext();
    reg.register("plain", "http://ci.example.com/hook", no_headers())
        .expect("plaintext registry MUST accept http");
    assert!(reg
        .get("plain")
        .unwrap()
        .url
        .matches("http://ci.example.com/hook"));
}

#[test]
fn register_duplicate_name_returns_duplicate_error_and_keeps_original() {
    let mut reg = WebhookRegistry::new();
    reg.register("ci", "https://first.example.com", no_headers())
        .expect("first register");
    let outcome = reg.register("ci", "https://second.example.com", no_headers());
    assert!(matches!(
        outcome.unwrap_err(),
        WebhookError::Duplicate { .. }
    ));
    // First registration MUST be preserved (url canonicalized
    // with trailing /).
    assert!(reg
        .get("ci")
        .unwrap()
        .url
        .matches("https://first.example.com/"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — replace as upsert
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn replace_overwrites_existing_entry() {
    let mut reg = WebhookRegistry::new();
    reg.register("ci", "https://old.example.com", no_headers())
        .expect("register");
    reg.replace(
        "ci",
        "https://new.example.com",
        headers_with(&[("X-New", "header")]),
    )
    .expect("replace");
    let ep = reg.get("ci").expect("get");
    assert!(ep.url.matches("https://new.example.com/"));
    assert!(ep.headers.matches_value("X-New", "header"));
}

#[test]
fn replace_inserts_when_name_does_not_exist() {
    // PINS UPSERT SEMANTICS: replace acts as insert when
    // the entry is absent.
    let mut reg = WebhookRegistry::new();
    reg.replace("brand-new", "https://new.example.com", no_headers())
        .expect("replace-as-insert");
    assert!(reg.get("brand-new").is_some());
}

#[test]
fn replace_with_invalid_url_does_not_clobber_existing_entry() {
    let mut reg = WebhookRegistry::new();
    reg.register("ci", "https://existing.example.com", no_headers())
        .expect("register");
    let outcome = reg.replace("ci", "ftp://other.example.com/", no_headers());
    assert!(outcome.is_err());
    // PINS SAFETY: original entry preserved on replace-with-invalid.
    assert!(reg
        .get("ci")
        .unwrap()
        .url
        .matches("https://existing.example.com/"));
}

#[test]
fn replace_drops_old_headers_when_new_headers_provided() {
    let mut reg = WebhookRegistry::new();
    reg.register(
        "ci",
        "https://ci.example.com",
        headers_with(&[("X-Old", "header1"), ("X-Old2", "header2")]),
    )
    .expect("register");
    reg.replace(
        "ci",
        "https://ci.example.com",
        headers_with(&[("X-New", "fresh")]),
    )
    .expect("replace");
    let ep = reg.get("ci").unwrap();
    assert_eq!(ep.headers.len(), 1);
    assert!(ep.headers.contains_name("X-New"));
    assert!(!ep.headers.contains_name("X-Old"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — get / names / len / is_empty accessors
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn get_unknown_name_returns_none() {
    let reg = WebhookRegistry::new();
    assert!(reg.get("never-registered").is_none());
}

#[test]
fn names_yields_every_registered_name() {
    let mut reg = WebhookRegistry::new();
    reg.register("ci", "https://ci.example.com", no_headers())
        .unwrap();
    reg.register("staging", "https://staging.example.com", no_headers())
        .unwrap();
    reg.register("prod", "https://prod.example.com", no_headers())
        .unwrap();
    let mut names: Vec<&str> = reg.names().collect();
    names.sort_unstable();
    assert_eq!(names, vec!["ci", "prod", "staging"]);
}

#[test]
fn len_matches_register_call_count() {
    let mut reg = WebhookRegistry::new();
    assert_eq!(reg.len(), 0);
    reg.register("a", "https://a.example.com", no_headers())
        .unwrap();
    assert_eq!(reg.len(), 1);
    reg.register("b", "https://b.example.com", no_headers())
        .unwrap();
    assert_eq!(reg.len(), 2);
}

#[test]
fn len_unchanged_by_failed_register() {
    let mut reg = WebhookRegistry::new();
    reg.register("a", "https://a.example.com", no_headers())
        .unwrap();
    let _ = reg.register("a", "https://duplicate.example.com", no_headers());
    assert_eq!(reg.len(), 1, "duplicate-register MUST NOT bump len");
}

#[test]
fn replace_does_not_bump_len_when_overwriting() {
    let mut reg = WebhookRegistry::new();
    reg.register("a", "https://a.example.com", no_headers())
        .unwrap();
    reg.replace("a", "https://b.example.com", no_headers())
        .unwrap();
    assert_eq!(reg.len(), 1, "replace MUST be upsert (not bump len)");
}

#[test]
fn replace_with_new_name_bumps_len() {
    let mut reg = WebhookRegistry::new();
    reg.replace("a", "https://a.example.com", no_headers())
        .unwrap();
    assert_eq!(reg.len(), 1);
    reg.replace("b", "https://b.example.com", no_headers())
        .unwrap();
    assert_eq!(reg.len(), 2);
}

#[test]
fn is_empty_returns_true_for_fresh_registry() {
    let reg = WebhookRegistry::new();
    assert!(reg.is_empty());
    assert_eq!(reg.len(), 0);
}

#[test]
fn is_empty_returns_false_after_at_least_one_register() {
    let mut reg = WebhookRegistry::new();
    reg.register("a", "https://a.example.com", no_headers())
        .unwrap();
    assert!(!reg.is_empty());
}

#[test]
fn names_iterator_is_empty_for_fresh_registry() {
    let reg = WebhookRegistry::new();
    assert_eq!(reg.names().count(), 0);
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — WebhookEndpoint Clone + PartialEq
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn endpoint_clone_preserves_url_and_headers() {
    let mut reg = WebhookRegistry::new();
    reg.register(
        "ci",
        "https://ci.example.com",
        headers_with(&[("X-Test", "val")]),
    )
    .unwrap();
    let ep = reg.get("ci").unwrap().clone();
    let ep2 = ep.clone();
    assert_eq!(ep, ep2, "Clone MUST preserve PartialEq");
}

#[test]
fn endpoints_with_same_url_and_headers_are_equal() {
    let mut reg1 = WebhookRegistry::new();
    let mut reg2 = WebhookRegistry::new();
    reg1.register("ci", "https://ci.example.com", no_headers())
        .unwrap();
    reg2.register("ci", "https://ci.example.com", no_headers())
        .unwrap();
    assert_eq!(reg1.get("ci").unwrap(), reg2.get("ci").unwrap());
}

#[test]
fn endpoints_with_different_urls_are_not_equal() {
    let mut reg = WebhookRegistry::new();
    reg.register("a", "https://a.example.com", no_headers())
        .unwrap();
    reg.register("b", "https://b.example.com", no_headers())
        .unwrap();
    assert_ne!(reg.get("a").unwrap(), reg.get("b").unwrap());
}
