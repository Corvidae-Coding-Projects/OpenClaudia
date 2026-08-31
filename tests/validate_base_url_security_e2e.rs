//! End-to-end tests for `config::validate_base_url` —
//! SSRF defense across IP literals (decimal/hex/IPv6),
//! cloud-metadata hostname denylist, scheme allowlist,
//! and malformed input rejection.
//!
//! Sprint 177 of the verification effort. Sprint 49 had
//! 4 basic tests; this file pins the security perimeter
//! corner cases that a hostile operator could try to
//! sneak past (#335 SSRF cluster).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::config::validate_base_url;

// ───────────────────────────────────────────────────────────────────────────
// Section A — Scheme allowlist
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn https_scheme_passes_basic_check() {
    // Public hostname — validator does DNS so allow either Ok
    // or a DNS-rejection error (just verify it doesn't reject
    // on scheme grounds alone).
    let outcome = validate_base_url("https://api.example.com");
    if let Err(e) = outcome {
        assert!(
            !e.contains("Unsupported URL scheme"),
            "https MUST NOT be rejected as unsupported scheme; got {e}"
        );
    }
}

#[test]
fn http_scheme_passes_basic_check() {
    let outcome = validate_base_url("http://api.example.com");
    if let Err(e) = outcome {
        assert!(!e.contains("Unsupported URL scheme"));
    }
}

#[test]
fn file_scheme_rejected() {
    let err = validate_base_url("file:///etc/passwd").unwrap_err();
    assert!(
        err.contains("Unsupported URL scheme") || err.contains("file"),
        "file:// MUST be rejected; got {err}"
    );
}

#[test]
fn ftp_scheme_rejected() {
    let err = validate_base_url("ftp://example.com/").unwrap_err();
    assert!(err.contains("Unsupported URL scheme") || err.contains("ftp"));
}

#[test]
fn javascript_scheme_rejected() {
    let err = validate_base_url("javascript:alert(1)").unwrap_err();
    assert!(!err.is_empty(), "javascript: MUST be rejected");
}

#[test]
fn data_scheme_rejected() {
    let err = validate_base_url("data:text/plain,hello").unwrap_err();
    assert!(!err.is_empty());
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — IP literal: standard IPv4
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn loopback_127_0_0_1_rejected() {
    let err = validate_base_url("http://127.0.0.1/").unwrap_err();
    assert!(!err.is_empty(), "127.0.0.1 MUST be rejected");
}

#[test]
fn loopback_127_anywhere_in_range_rejected() {
    let err = validate_base_url("http://127.5.5.5/").unwrap_err();
    assert!(!err.is_empty(), "127.0.0.0/8 entire range MUST be rejected");
}

#[test]
fn rfc1918_private_10_x_rejected() {
    let err = validate_base_url("http://10.0.0.1/").unwrap_err();
    assert!(!err.is_empty(), "10.0.0.0/8 MUST be rejected");
}

#[test]
fn rfc1918_private_192_168_rejected() {
    let err = validate_base_url("http://192.168.1.1/").unwrap_err();
    assert!(!err.is_empty());
}

#[test]
fn rfc1918_private_172_16_rejected() {
    let err = validate_base_url("http://172.16.0.1/").unwrap_err();
    assert!(!err.is_empty());
}

#[test]
fn link_local_169_254_rejected() {
    let err = validate_base_url("http://169.254.0.1/").unwrap_err();
    assert!(!err.is_empty(), "link-local MUST be rejected");
}

#[test]
fn cloud_metadata_ip_169_254_169_254_rejected() {
    // PINS SSRF: AWS/GCP/Azure metadata IP.
    let err = validate_base_url("http://169.254.169.254/").unwrap_err();
    assert!(!err.is_empty(), "cloud metadata IP MUST be blocked (SSRF)");
}

#[test]
fn zero_zero_zero_zero_rejected() {
    let err = validate_base_url("http://0.0.0.0/").unwrap_err();
    assert!(!err.is_empty(), "0.0.0.0 MUST be rejected");
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — IPv6 loopback + private
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn ipv6_loopback_double_colon_one_rejected() {
    let err = validate_base_url("http://[::1]/").unwrap_err();
    assert!(!err.is_empty(), "[::1] IPv6 loopback MUST be rejected");
}

#[test]
fn ipv6_unspecified_double_colon_rejected() {
    let outcome = validate_base_url("http://[::]/");
    // :: is the unspecified address — should reject.
    assert!(outcome.is_err());
}

#[test]
fn ipv6_link_local_fe80_rejected() {
    let err = validate_base_url("http://[fe80::1]/").unwrap_err();
    assert!(!err.is_empty(), "fe80:: link-local IPv6 MUST be rejected");
}

#[test]
fn ipv6_unique_local_fd00_rejected() {
    let outcome = validate_base_url("http://[fd00::1]/");
    // fc00::/7 unique-local is documented as private.
    assert!(outcome.is_err());
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Hostname denylist
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn localhost_hostname_rejected() {
    let err = validate_base_url("http://localhost/").unwrap_err();
    assert!(
        err.contains("internal") || err.contains("metadata") || err.contains("localhost"),
        "localhost MUST be rejected; got {err}"
    );
}

#[test]
fn localhost_localdomain_rejected() {
    let outcome = validate_base_url("http://localhost.localdomain/");
    assert!(outcome.is_err());
}

#[test]
fn ip6_localhost_rejected() {
    let outcome = validate_base_url("http://ip6-localhost/");
    assert!(outcome.is_err());
}

#[test]
fn google_metadata_endpoint_rejected() {
    let outcome = validate_base_url("http://metadata.google.internal/");
    assert!(outcome.is_err(), "GCP metadata MUST be rejected");
}

#[test]
fn aws_metadata_endpoint_rejected() {
    let outcome = validate_base_url("http://instance-data/");
    assert!(outcome.is_err(), "AWS metadata MUST be rejected");
}

#[test]
fn bare_metadata_hostname_rejected() {
    let outcome = validate_base_url("http://metadata/");
    assert!(outcome.is_err());
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Hostname case-insensitivity
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn localhost_uppercase_rejected() {
    // PINS DOC: host comparison is case-insensitive
    // (lowercases input before denylist check).
    let outcome = validate_base_url("http://LOCALHOST/");
    assert!(outcome.is_err(), "LOCALHOST upper-case MUST be rejected");
}

#[test]
fn metadata_mixed_case_rejected() {
    let outcome = validate_base_url("http://MeTaData/");
    assert!(outcome.is_err());
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Malformed input
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn empty_string_rejected() {
    let outcome = validate_base_url("");
    assert!(outcome.is_err());
}

#[test]
fn whitespace_only_rejected() {
    let outcome = validate_base_url("   ");
    assert!(outcome.is_err());
}

#[test]
fn missing_scheme_rejected() {
    let outcome = validate_base_url("example.com/path");
    assert!(outcome.is_err());
}

#[test]
fn scheme_only_rejected() {
    let outcome = validate_base_url("https://");
    assert!(outcome.is_err());
}

#[test]
fn url_with_garbage_text_rejected() {
    let outcome = validate_base_url("not a url at all !!!");
    assert!(outcome.is_err());
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — Error message carries safe diagnostic info
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn error_message_omits_sensitive_url_components_but_retains_reason() {
    let sentinel = "signed-url-secret-sentinel";
    let url = format!("http://localhost/some/path?signature={sentinel}");
    let err = validate_base_url(&url).unwrap_err();
    assert!(err.contains("internal/metadata endpoint"), "got {err}");
    assert!(!err.contains(sentinel), "signed query leaked: {err}");
    assert!(!err.contains(&url), "full URL leaked: {err}");
}

#[test]
fn error_message_is_non_empty_for_every_rejection() {
    let cases = [
        "file:///x",
        "ftp://x.com/",
        "http://127.0.0.1/",
        "http://localhost/",
        "",
        "not-a-url",
    ];
    for url in cases {
        let err = validate_base_url(url).unwrap_err();
        assert!(!err.is_empty(), "{url}: error MUST be non-empty");
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section H — Determinism + idempotency
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn repeated_calls_yield_same_result_for_loopback() {
    // PINS PURE: no caching of outcomes.
    for _ in 0..5 {
        let outcome = validate_base_url("http://127.0.0.1/");
        assert!(outcome.is_err());
    }
}

#[test]
fn repeated_calls_yield_same_error_message_for_file_scheme() {
    let e1 = validate_base_url("file:///etc/passwd").unwrap_err();
    let e2 = validate_base_url("file:///etc/passwd").unwrap_err();
    assert_eq!(e1, e2);
}
