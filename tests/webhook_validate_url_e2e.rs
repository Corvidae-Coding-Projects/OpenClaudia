//! End-to-end tests for `tools::remote_trigger::WebhookRegistry::validate_url`
//! — the URL safety guard. Pins documented semantics: empty
//! rejection, scheme upgrade for scheme-less input, explicit
//! `http://` rejected in strict mode (default), `http://`
//! accepted via `new_allow_plaintext`, non-http(s) schemes
//! rejected, missing host rejected.
//!
//! Sprint 217 of the verification effort.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::remote_trigger::{WebhookError, WebhookRegistry};

fn strict() -> WebhookRegistry {
    WebhookRegistry::new()
}

fn plaintext_ok() -> WebhookRegistry {
    WebhookRegistry::new_allow_plaintext()
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — Empty / whitespace-only rejection
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn empty_url_rejected_with_malformed() {
    let r = strict();
    let outcome = r.validate_url("");
    assert!(matches!(outcome, Err(WebhookError::Malformed { .. })));
}

#[test]
fn whitespace_only_url_rejected_with_malformed() {
    let r = strict();
    let outcome = r.validate_url("   ");
    assert!(matches!(outcome, Err(WebhookError::Malformed { .. })));
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Scheme upgrade for scheme-less input
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn scheme_less_url_upgraded_to_https() {
    // PINS DOC: example.com/hook → https://example.com/hook
    let r = strict();
    let outcome = r.validate_url("example.com/hook").expect("ok");
    assert!(outcome.matches("https://example.com/hook"));
}

#[test]
fn scheme_less_url_preserves_path_after_upgrade() {
    let r = strict();
    let outcome = r.validate_url("api.example.com/v1/x").expect("ok");
    assert!(outcome.matches("https://api.example.com/v1/x"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Explicit https accepted
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn explicit_https_url_accepted_in_strict_mode() {
    let r = strict();
    assert!(r.validate_url("https://example.com/").is_ok());
}

#[test]
fn explicit_https_url_accepted_in_plaintext_mode() {
    let r = plaintext_ok();
    assert!(r.validate_url("https://example.com/").is_ok());
}

#[test]
fn https_url_with_port_accepted() {
    let r = strict();
    assert!(r.validate_url("https://example.com:8443/").is_ok());
}

#[test]
fn https_url_with_userinfo_accepted() {
    let r = strict();
    // Userinfo present — still a valid host-bearing URL.
    assert!(r.validate_url("https://u:p@example.com/").is_ok());
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Explicit http rejection in strict mode
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn explicit_http_url_rejected_in_strict_mode() {
    // PINS DOC: strict registry rejects http://.
    let r = strict();
    let outcome = r.validate_url("http://example.com/");
    assert!(matches!(outcome, Err(WebhookError::InsecureScheme { .. })));
}

#[test]
fn explicit_http_url_with_path_rejected_in_strict_mode() {
    let r = strict();
    let outcome = r.validate_url("http://example.com/hook/path");
    assert!(matches!(outcome, Err(WebhookError::InsecureScheme { .. })));
}

#[test]
fn http_insecure_error_does_not_carry_raw_url_for_diagnostics() {
    let r = strict();
    let sentinel = "http://marker-217.com/hook?token=webhook-secret-sentinel";
    let err = r.validate_url(sentinel).unwrap_err();
    assert!(matches!(err, WebhookError::InsecureScheme { .. }));
    assert!(!format!("{err:?}").contains("webhook-secret-sentinel"));
    assert!(!err.to_string().contains("webhook-secret-sentinel"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — http accepted in plaintext-allowed mode
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn explicit_http_url_accepted_in_plaintext_mode() {
    let r = plaintext_ok();
    assert!(r.validate_url("http://example.com/").is_ok());
}

#[test]
fn explicit_http_with_port_accepted_in_plaintext_mode() {
    let r = plaintext_ok();
    assert!(r.validate_url("http://localhost:8080/").is_ok());
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Non-http(s) schemes rejected with InvalidScheme
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn ftp_scheme_rejected_with_invalid_scheme() {
    let r = strict();
    let outcome = r.validate_url("ftp://example.com/x");
    assert!(matches!(outcome, Err(WebhookError::InvalidScheme { .. })));
}

#[test]
fn file_scheme_rejected() {
    // PINS SECURITY: file:// MUST NOT register as webhook.
    // file:///etc/passwd has no host, so the host-check fires
    // before the scheme branch — yielding Malformed rather
    // than InvalidScheme. Either error is acceptable as long
    // as the URL is rejected.
    let r = strict();
    let outcome = r.validate_url("file:///etc/passwd");
    assert!(outcome.is_err(), "file:// MUST be rejected");
}

#[test]
fn javascript_scheme_rejected() {
    let r = strict();
    let outcome = r.validate_url("javascript:alert(1)");
    assert!(matches!(
        outcome,
        Err(WebhookError::InvalidScheme { .. } | WebhookError::Malformed { .. })
    ));
}

#[test]
fn invalid_scheme_error_does_not_carry_untrusted_scheme() {
    let r = strict();
    let err = r.validate_url("FTP://example.com/").unwrap_err();
    assert!(matches!(err, WebhookError::InvalidScheme { .. }));
    assert!(!format!("{err:?}").contains("ftp"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — Missing host rejection
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn scheme_only_url_rejected_with_malformed() {
    let r = strict();
    let outcome = r.validate_url("https://");
    assert!(matches!(outcome, Err(WebhookError::Malformed { .. })));
}

#[test]
fn malformed_url_with_garbage_rejected() {
    let r = strict();
    let outcome = r.validate_url("https:// not a url");
    assert!(outcome.is_err());
}

// ───────────────────────────────────────────────────────────────────────────
// Section H — Determinism
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn validate_url_is_deterministic_across_calls() {
    let r = strict();
    let url = "https://example.com/";
    let r1 = r.validate_url(url);
    let r2 = r.validate_url(url);
    assert_eq!(r1.is_ok(), r2.is_ok());
}

#[test]
fn validate_url_error_message_is_deterministic() {
    let r = strict();
    let e1 = r.validate_url("ftp://x.com/").unwrap_err();
    let e2 = r.validate_url("ftp://x.com/").unwrap_err();
    assert_eq!(e1.to_string(), e2.to_string());
}

// ───────────────────────────────────────────────────────────────────────────
// Section I — Cross-mode parity for happy path
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn https_url_validates_identically_in_strict_and_plaintext() {
    let strict_r = strict();
    let plaintext_r = plaintext_ok();
    let url = "https://example.com/x";
    let strict_outcome = strict_r.validate_url(url);
    let plaintext_outcome = plaintext_r.validate_url(url);
    assert_eq!(strict_outcome.is_ok(), plaintext_outcome.is_ok());
    assert_eq!(strict_outcome.unwrap(), plaintext_outcome.unwrap());
}
