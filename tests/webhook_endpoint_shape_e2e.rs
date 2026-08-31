//! End-to-end tests for `tools::remote_trigger::WebhookEndpoint`
//! shape — `url` + `headers` fields, `PartialEq`/`Eq` derive,
//! `Clone`, retrieval via `WebhookRegistry::get` + headers
//! propagation through register/replace.
//!
//! Sprint 216 of the verification effort.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::remote_trigger::{WebhookEndpoint, WebhookRegistry};
use std::collections::HashMap;

fn no_headers() -> HashMap<String, String> {
    HashMap::new()
}

fn one_header(k: &str, v: &str) -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert(k.to_string(), v.to_string());
    h
}

fn endpoint(url: &str, headers: HashMap<String, String>) -> WebhookEndpoint {
    let mut registry = WebhookRegistry::new();
    registry
        .register("endpoint", url, headers)
        .expect("valid endpoint");
    registry.get("endpoint").expect("stored endpoint").clone()
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — WebhookEndpoint Default construction shape
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn endpoint_constructible_with_explicit_fields() {
    let ep = endpoint("https://example.com/x", no_headers());
    assert!(ep.url.matches("https://example.com/x"));
    assert!(ep.headers.is_empty());
}

#[test]
fn endpoint_with_headers_preserves_kv_pairs() {
    let ep = endpoint("https://x.com/", one_header("Authorization", "Bearer xyz"));
    assert!(ep.headers.matches_value("Authorization", "Bearer xyz"));
    assert_eq!(ep.headers.len(), 1);
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — register propagates fields into stored endpoint
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn register_propagates_url_into_endpoint() {
    let mut reg = WebhookRegistry::new();
    reg.register("notify", "https://example.com/hook", no_headers())
        .expect("register ok");
    let ep = reg.get("notify").expect("entry exists");
    assert!(ep.url.matches("https://example.com/hook"));
}

#[test]
fn register_propagates_headers_into_endpoint() {
    let mut reg = WebhookRegistry::new();
    let seeded = "s025-webhook-secret-773a";
    let h = one_header("X-Secret", seeded);
    reg.register("notify", "https://x.com/", h)
        .expect("register ok");
    let ep = reg.get("notify").expect("entry exists");
    assert!(ep.headers.matches_value("X-Secret", seeded));
    assert!(!format!("{:?}", ep.headers).contains(seeded));
}

#[test]
fn register_with_multiple_headers_preserves_all() {
    let mut reg = WebhookRegistry::new();
    let mut h = HashMap::new();
    h.insert("X-A".to_string(), "1".to_string());
    h.insert("X-B".to_string(), "2".to_string());
    h.insert("X-C".to_string(), "3".to_string());
    reg.register("hook", "https://x.com/", h)
        .expect("register ok");
    let ep = reg.get("hook").expect("entry");
    assert_eq!(ep.headers.len(), 3);
    assert!(ep.headers.matches_value("X-A", "1"));
    assert!(ep.headers.matches_value("X-B", "2"));
    assert!(ep.headers.matches_value("X-C", "3"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — register URL upgrade semantics
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn register_scheme_less_input_upgraded_to_https() {
    // PINS DOC: scheme-less inputs get https:// prefix.
    let mut reg = WebhookRegistry::new();
    reg.register("notify", "example.com/hook", no_headers())
        .expect("register ok");
    let ep = reg.get("notify").expect("entry");
    assert!(ep.url.matches("https://example.com/hook"));
}

#[test]
fn register_explicit_https_preserved() {
    let mut reg = WebhookRegistry::new();
    reg.register("notify", "https://api.example.com/v1/x", no_headers())
        .expect("register ok");
    let ep = reg.get("notify").expect("entry");
    assert!(ep.url.matches("https://api.example.com/v1/x"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — replace overwrites entry
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn replace_overwrites_url_and_headers() {
    let mut reg = WebhookRegistry::new();
    reg.register("hook", "https://a.com/", one_header("X", "1"))
        .expect("register");
    reg.replace("hook", "https://b.com/", one_header("Y", "2"))
        .expect("replace ok");
    let ep = reg.get("hook").expect("entry");
    assert!(ep.url.matches("https://b.com/"));
    assert!(ep.headers.contains_name("Y"));
    assert!(!ep.headers.contains_name("X"));
}

#[test]
fn replace_inserts_when_name_absent() {
    let mut reg = WebhookRegistry::new();
    // No prior register.
    reg.replace("new_hook", "https://x.com/", no_headers())
        .expect("replace inserts");
    assert!(reg.get("new_hook").is_some());
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Endpoint PartialEq + Clone + Debug
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn endpoint_partial_eq_with_same_fields() {
    let a = endpoint("https://x.com/", one_header("X", "1"));
    let b = endpoint("https://x.com/", one_header("X", "1"));
    assert_eq!(a, b);
}

#[test]
fn endpoint_partial_eq_distinguishes_different_urls() {
    let a = endpoint("https://a.com/", no_headers());
    let b = endpoint("https://b.com/", no_headers());
    assert_ne!(a, b);
}

#[test]
fn endpoint_partial_eq_distinguishes_different_headers() {
    let a = endpoint("https://x.com/", one_header("X", "1"));
    let b = endpoint("https://x.com/", one_header("X", "2"));
    assert_ne!(a, b);
}

#[test]
fn endpoint_clone_preserves_url_and_headers() {
    let original = endpoint("https://marker.com/", one_header("X-Marker", "marker_216"));
    let cloned = original.clone();
    assert_eq!(cloned, original);
    assert!(cloned.url.matches("https://marker.com/"));
    assert!(cloned.headers.matches_value("X-Marker", "marker_216"));
    assert!(!format!("{cloned:?}").contains("marker_216"));
}

#[test]
fn endpoint_debug_redacts_signed_url() {
    let ep = endpoint(
        "https://debug.com/hook?token=webhook-url-secret-sentinel",
        no_headers(),
    );
    let d = format!("{ep:?}");
    assert!(d.contains("WebhookEndpoint"));
    assert!(d.contains("[REDACTED]"));
    assert!(!d.contains("debug.com"));
    assert!(!d.contains("webhook-url-secret-sentinel"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — get returns None for unknown
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn get_unknown_name_returns_none() {
    let reg = WebhookRegistry::new();
    assert!(reg.get("nonexistent_xyz").is_none());
}

#[test]
fn get_after_register_returns_some() {
    let mut reg = WebhookRegistry::new();
    reg.register("x", "https://x.com/", no_headers())
        .expect("ok");
    assert!(reg.get("x").is_some());
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — Unicode + edge content
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn endpoint_with_unicode_header_value_preserved() {
    let mut reg = WebhookRegistry::new();
    reg.register("u", "https://x.com/", one_header("X-Note", "日本語の値"))
        .expect("valid opaque header bytes");
    let endpoint = reg.get("u").expect("entry");
    assert!(endpoint.headers.matches_value("X-Note", "日本語の値"));
}

#[test]
fn endpoint_with_control_character_header_value_is_rejected() {
    let mut reg = WebhookRegistry::new();
    let error = reg
        .register(
            "bad",
            "https://x.com/",
            one_header("X-Note", "value\r\ninjected: true"),
        )
        .expect_err("control characters must fail before registration");
    assert!(matches!(
        error,
        openclaudia::tools::remote_trigger::WebhookError::InvalidHeaders { .. }
    ));
    assert!(reg.get("bad").is_none());
}

#[test]
fn endpoint_with_empty_header_value_preserved() {
    let mut reg = WebhookRegistry::new();
    let h = one_header("X-Empty", "");
    reg.register("e", "https://x.com/", h).expect("ok");
    let ep = reg.get("e").expect("entry");
    assert!(ep.headers.matches_value("X-Empty", ""));
}
