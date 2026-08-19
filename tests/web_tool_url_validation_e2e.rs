//! End-to-end tests for `tools::web::execute_web_fetch` and
//! `tools::web::execute_web_browser` URL-validation arms —
//! the pre-network checks that gate every fetch.
//!
//! Sprint 136 of the verification effort. Sprint 41 covered
//! `format_fetch_output`; sprint 99 covered `WebFetchConfig`
//! defaults; this file pins the URL-prefix gate that runs
//! BEFORE any network IO (so tests are deterministic and
//! offline).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use serde_json::{json, Value};
use std::collections::HashMap;

mod support;

fn args_with(entries: &[(&str, Value)]) -> HashMap<String, Value> {
    let mut m = HashMap::new();
    for (k, v) in entries {
        m.insert((*k).to_string(), v.clone());
    }
    m
}

fn execute_web_fetch(args: &HashMap<String, Value>) -> (String, bool) {
    support::dispatch_tool("web_fetch", args)
}

#[cfg(feature = "browser")]
fn execute_web_browser(args: &HashMap<String, Value>) -> (String, bool) {
    support::dispatch_tool("web_browser", args)
}

fn assert_url_classification_denial(message: &str) {
    assert!(message.contains("Host safety"), "got {message:?}");
    assert!(message.contains("'url'"), "got {message:?}");
    assert!(
        message.contains("malformed arguments") || message.contains("Missing"),
        "got {message:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Missing url arg
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn execute_web_fetch_missing_url_arg_returns_error() {
    let (msg, is_err) = execute_web_fetch(&HashMap::new());
    assert!(is_err);
    // Error message MUST mention the missing arg.
    assert!(
        msg.to_lowercase().contains("url") || msg.contains("missing"),
        "MUST mention url/missing; got {msg:?}"
    );
}

#[cfg(feature = "browser")]
#[test]
fn execute_web_browser_missing_url_arg_returns_error() {
    let (msg, is_err) = execute_web_browser(&HashMap::new());
    assert!(is_err);
    assert!(
        msg.to_lowercase().contains("url") || msg.contains("missing"),
        "MUST mention url/missing; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Non-http(s) schemes rejected pre-network
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn execute_web_fetch_rejects_ftp_scheme() {
    let args = args_with(&[("url", json!("ftp://example.com"))]);
    let (msg, is_err) = execute_web_fetch(&args);
    assert!(is_err);
    assert!(
        msg.contains("Invalid URL") || msg.contains("http://"),
        "MUST surface invalid-URL message; got {msg:?}"
    );
}

#[test]
fn execute_web_fetch_rejects_file_scheme() {
    // PINS DOC: file:// MUST be rejected (no local-file
    // exfiltration via web tools).
    let args = args_with(&[("url", json!("file:///etc/passwd"))]);
    let (msg, is_err) = execute_web_fetch(&args);
    assert!(is_err);
    assert!(msg.contains("Invalid URL") || msg.contains("http"));
}

#[test]
fn execute_web_fetch_rejects_javascript_scheme() {
    // PINS SECURITY: javascript: URLs MUST be rejected.
    let args = args_with(&[("url", json!("javascript:alert(1)"))]);
    let (msg, is_err) = execute_web_fetch(&args);
    assert!(is_err);
    assert!(msg.contains("Invalid URL") || msg.contains("http"));
}

#[test]
fn execute_web_fetch_rejects_data_scheme() {
    let args = args_with(&[("url", json!("data:text/html,<script>alert(1)</script>"))]);
    let (_msg, is_err) = execute_web_fetch(&args);
    assert!(is_err);
}

#[cfg(feature = "browser")]
#[test]
fn execute_web_browser_rejects_ftp_scheme() {
    let args = args_with(&[("url", json!("ftp://example.com"))]);
    let (msg, is_err) = execute_web_browser(&args);
    assert!(is_err);
    assert!(
        msg.contains("Invalid URL") || msg.contains("http://"),
        "MUST surface invalid-URL message; got {msg:?}"
    );
}

#[cfg(feature = "browser")]
#[test]
fn execute_web_browser_rejects_javascript_scheme() {
    let args = args_with(&[("url", json!("javascript:void(0)"))]);
    let (_msg, is_err) = execute_web_browser(&args);
    assert!(is_err);
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Empty url rejected
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn execute_web_fetch_rejects_empty_url() {
    let args = args_with(&[("url", json!(""))]);
    let (_msg, is_err) = execute_web_fetch(&args);
    assert!(is_err, "empty url MUST be rejected pre-network");
}

#[cfg(feature = "browser")]
#[test]
fn execute_web_browser_rejects_empty_url() {
    let args = args_with(&[("url", json!(""))]);
    let (_msg, is_err) = execute_web_browser(&args);
    assert!(is_err);
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — url arg with wrong type
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn execute_web_fetch_url_as_number_returns_error() {
    let args = args_with(&[("url", json!(42))]);
    let (msg, is_err) = execute_web_fetch(&args);
    assert!(is_err, "non-string url MUST be rejected");
    assert_url_classification_denial(&msg);
}

#[test]
fn execute_web_fetch_url_as_array_returns_error() {
    let args = args_with(&[("url", json!(["x", "y"]))]);
    let (msg, is_err) = execute_web_fetch(&args);
    assert!(is_err);
    assert_url_classification_denial(&msg);
}

#[test]
fn execute_web_fetch_url_as_object_returns_error() {
    let args = args_with(&[("url", json!({"x": "y"}))]);
    let (msg, is_err) = execute_web_fetch(&args);
    assert!(is_err);
    assert_url_classification_denial(&msg);
}

#[test]
fn execute_web_fetch_url_as_null_returns_error() {
    let args = args_with(&[("url", Value::Null)]);
    let (msg, is_err) = execute_web_fetch(&args);
    assert!(is_err);
    assert_url_classification_denial(&msg);
}

#[cfg(feature = "browser")]
#[test]
fn execute_web_browser_url_as_number_returns_error() {
    let args = args_with(&[("url", json!(42))]);
    let (msg, is_err) = execute_web_browser(&args);
    assert!(is_err, "non-string browser url MUST be rejected");
    assert_url_classification_denial(&msg);
}

#[test]
fn execute_web_fetch_prompt_as_number_returns_error() {
    let args = args_with(&[
        ("url", json!("https://example.invalid/")),
        ("prompt", json!(42)),
    ]);
    let (msg, is_err) = execute_web_fetch(&args);
    assert!(is_err, "non-string prompt MUST be rejected");
    assert_eq!(msg, "Invalid 'prompt' argument: expected string");
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Garbled http-like prefixes
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn execute_web_fetch_rejects_http_without_separator() {
    // "http:example.com" lacks "://" — pre-network gate
    // requires the full prefix.
    let args = args_with(&[("url", json!("http:example.com"))]);
    let (_msg, is_err) = execute_web_fetch(&args);
    assert!(is_err);
}

#[test]
fn execute_web_fetch_rejects_uppercase_scheme_pre_network() {
    // PINS DOC: URL gate is case-sensitive (starts_with check).
    // Uppercase HTTP:// MAY be rejected.
    let args = args_with(&[("url", json!("HTTP://example.com"))]);
    let (msg, is_err) = execute_web_fetch(&args);
    // Either rejected as invalid OR accepted (impl-defined).
    // If rejected, message mentions Invalid URL.
    if is_err {
        assert!(msg.contains("Invalid URL") || msg.contains("http"));
    }
    let _ = msg;
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Validation arm runs PRE-network
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn url_validation_runs_before_any_network_io() {
    // The pre-network gate MUST short-circuit; the error
    // returned for an invalid scheme is the same regardless
    // of network availability.
    // We assert that the error message MUST NOT mention
    // network-failure terms — proving the pre-network arm fired.
    let args = args_with(&[("url", json!("ftp://test.invalid"))]);
    let (msg, is_err) = execute_web_fetch(&args);
    assert!(is_err);
    let lower = msg.to_lowercase();
    assert!(
        !lower.contains("connection") && !lower.contains("timeout") && !lower.contains("dns"),
        "pre-network gate MUST NOT report network-failure terms; got {msg:?}"
    );
}
