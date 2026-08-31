//! End-to-end tests for the `WebhookRegistry` URL-validation surface
//! and the MCP `HttpTransport` SSRF guard.
//!
//! Sprint 7 of the verification effort. `tests/mcp_integration.rs`
//! already pins 22 stdio-transport scenarios (handshake, tool refresh,
//! `call_tool`, rpc-error projection, disconnect, etc.) using a Python
//! echo-server fixture — this file fills the two gaps that the
//! existing suite intentionally leaves alone:
//!
//!   - **`WebhookRegistry` adversarial URL validation** —
//!     `validate_url` / `register` / `replace` against the documented
//!     attack catalog: `file://`, `javascript:`, `ftp://`, `data:`,
//!     plaintext-on-public-internet, malformed input, and the
//!     scheme-less-then-upgraded-to-https path.
//!   - **`HttpTransport::new` SSRF guard** — refusal of loopback,
//!     RFC 1918 addresses, `file://`, AWS cloud-metadata hostname,
//!     and acceptance only of `http(s)` schemes pointing at routable
//!     public hosts.
//!
//! Both surfaces are integration-critical: `WebhookRegistry` gates
//! outbound side-effects from the model, and `HttpTransport`'s SSRF
//! guard is the perimeter for MCP-server URLs read from
//! user-supplied configuration.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::mcp::{HttpTransport, McpError};
use openclaudia::tools::remote_trigger::{WebhookError, WebhookRegistry};
use std::collections::HashMap;

// ───────────────────────────────────────────────────────────────────────────
// Section A — WebhookRegistry adversarial URL validation
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn validate_url_accepts_explicit_https() {
    let reg = WebhookRegistry::new();
    let canon = reg
        .validate_url("https://example.com/hook")
        .expect("explicit https must pass");
    assert!(canon.matches("https://example.com/hook"));
}

#[test]
fn validate_url_upgrades_scheme_less_input_to_https() {
    let reg = WebhookRegistry::new();
    // No scheme → defaults to https (security-conservative).
    let canon = reg
        .validate_url("example.com/hook")
        .expect("scheme-less input must upgrade to https");
    assert!(canon.matches("https://example.com/hook"));
}

#[test]
fn validate_url_rejects_explicit_http_in_strict_registry() {
    let reg = WebhookRegistry::new();
    // Explicit http:// MUST be refused by the strict-default registry.
    let outcome = reg.validate_url("http://example.com/hook");
    assert!(
        matches!(outcome, Err(WebhookError::InsecureScheme { .. })),
        "explicit http:// must be refused as InsecureScheme; got {outcome:?}"
    );
}

#[test]
fn validate_url_accepts_explicit_http_in_plaintext_registry() {
    let reg = WebhookRegistry::new_allow_plaintext();
    let canon = reg
        .validate_url("http://localhost:8080/hook")
        .expect("http:// must be accepted when plaintext was opted in");
    assert!(canon.matches("http://localhost:8080/hook"));
}

/// Schemes that MUST be refused by both the strict registry AND the
/// plaintext-opt-in registry — neither variant should ever allow
/// `file://`, `javascript:`, `ftp://`, `data:`, etc. These bypass
/// outbound HTTP entirely and would let a model exfiltrate or load
/// local resources via the webhook surface.
const FORBIDDEN_SCHEMES: &[&str] = &[
    "file:///etc/passwd",
    "ftp://example.com/file",
    "data:text/plain,owned",
    "javascript:alert(1)",
    "ws://example.com/socket",
    "ldap://example.com/o=foo",
    "gopher://example.com/",
];

#[test]
fn forbidden_schemes_are_refused_by_strict_registry() {
    let reg = WebhookRegistry::new();
    for url in FORBIDDEN_SCHEMES {
        let outcome = reg.validate_url(url);
        assert!(
            matches!(
                outcome,
                Err(WebhookError::InvalidScheme { .. } | WebhookError::Malformed { .. })
            ),
            "{url:?} must be refused by strict registry; got {outcome:?}"
        );
    }
}

#[test]
fn forbidden_schemes_are_refused_even_with_plaintext_opt_in() {
    // The plaintext opt-in MUST NOT widen the allowlist to non-http(s).
    let reg = WebhookRegistry::new_allow_plaintext();
    for url in FORBIDDEN_SCHEMES {
        let outcome = reg.validate_url(url);
        assert!(
            matches!(
                outcome,
                Err(WebhookError::InvalidScheme { .. } | WebhookError::Malformed { .. })
            ),
            "{url:?} must be refused even with plaintext opt-in; got {outcome:?}"
        );
    }
}

/// Inputs that the URL validator MUST refuse as malformed. Note:
/// `https:/oops` is NOT in this list because the `url` crate's
/// parser happily treats `oops` as the host — that input would be
/// caught at DNS-resolution time, not at URL-validation time.
const MALFORMED_URLS: &[&str] = &[
    "",
    "   ",
    "://no-scheme-or-host",
    "https://", // empty host
];

#[test]
fn malformed_url_inputs_are_refused() {
    let reg = WebhookRegistry::new();
    for raw in MALFORMED_URLS {
        let outcome = reg.validate_url(raw);
        assert!(
            outcome.is_err(),
            "malformed input {raw:?} must be refused; got {outcome:?}"
        );
    }
}

#[test]
fn register_duplicate_name_is_rejected() {
    let mut reg = WebhookRegistry::new();
    reg.register("notify", "https://example.com/a", HashMap::new())
        .expect("first register");
    let outcome = reg.register("notify", "https://example.com/b", HashMap::new());
    assert!(
        matches!(outcome, Err(WebhookError::Duplicate { .. })),
        "duplicate name must be refused with Duplicate; got {outcome:?}"
    );
    // `replace` MUST overwrite without error.
    reg.replace("notify", "https://example.com/b", HashMap::new())
        .expect("replace must succeed where register would refuse");
    assert!(reg
        .get("notify")
        .unwrap()
        .url
        .matches("https://example.com/b"));
}

#[test]
fn headers_round_trip_byte_exact_including_hostile_values() {
    // Header values frequently carry tokens; the registry must not
    // mutate them in any way (case, trimming, encoding).
    let mut reg = WebhookRegistry::new();
    let mut headers = HashMap::new();
    headers.insert(
        "Authorization".to_string(),
        "Bearer SGVsbG8sIHdvcmxkIQ==".to_string(),
    );
    headers.insert("X-CustOM-Casing".to_string(), "  spaces  ".to_string());
    headers.insert("X-Quote".to_string(), "value with \"quotes\"".to_string());

    reg.register("hook", "https://example.com/h", headers.clone())
        .expect("register");
    let got = &reg.get("hook").expect("registered").headers;
    for (name, value) in &headers {
        assert!(
            got.matches_value(name, value),
            "header {name} must reach protected storage byte-exact"
        );
    }
    let debug = format!("{got:?}");
    for value in headers.values() {
        assert!(!debug.contains(value), "Debug must redact header values");
    }
}

#[test]
fn unknown_lookup_returns_none_not_panic() {
    let reg = WebhookRegistry::new();
    assert!(reg.get("does-not-exist").is_none());
    assert_eq!(reg.len(), 0);
    assert!(reg.is_empty());
    assert!(reg.names().next().is_none());
}

#[test]
fn register_persists_name_in_names_iter() {
    let mut reg = WebhookRegistry::new();
    reg.register("a", "https://a.example.com/", HashMap::new())
        .expect("a");
    reg.register("b", "https://b.example.com/", HashMap::new())
        .expect("b");
    let mut names: Vec<&str> = reg.names().collect();
    names.sort_unstable();
    assert_eq!(names, vec!["a", "b"]);
    assert_eq!(reg.len(), 2);
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — HttpTransport SSRF guard (perimeter)
// ───────────────────────────────────────────────────────────────────────────

/// URLs that the SSRF guard MUST refuse at construction time. Each
/// case represents a documented exfiltration / metadata-grab path.
const SSRF_BLOCKED_URLS: &[&str] = &[
    // Loopback in every common form.
    "http://127.0.0.1/mcp",
    "https://127.0.0.1:8443/mcp",
    "http://localhost/mcp",
    "http://[::1]/mcp",
    // RFC 1918 private space.
    "http://10.0.0.1/mcp",
    "http://192.168.1.1/mcp",
    "http://172.16.0.1/mcp",
    // Link-local + AWS/GCP metadata services.
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    // Non-http schemes.
    "file:///etc/passwd",
    "data:text/plain,owned",
    "ftp://example.com/",
];

#[test]
fn http_transport_new_refuses_ssrf_targets() {
    let mut leaked = Vec::new();
    for url in SSRF_BLOCKED_URLS {
        match HttpTransport::new(url) {
            Err(McpError::Transport(msg)) => {
                // The validator-error documented contract: message
                // starts with "SSRF guard rejected" so call sites
                // can distinguish it from a runtime error.
                assert!(
                    msg.contains("SSRF guard") || msg.to_lowercase().contains("ssrf"),
                    "SSRF rejection for {url:?} must mention 'SSRF guard'; got {msg:?}"
                );
            }
            Err(_other) => {
                // Any error is acceptable (better-safe-than-sorry).
            }
            Ok(_) => leaked.push((*url).to_string()),
        }
    }
    assert!(
        leaked.is_empty(),
        "SSRF guard let {} URLs through:\n  {}",
        leaked.len(),
        leaked.join("\n  ")
    );
}

#[test]
fn http_transport_new_does_not_refuse_routable_public_https_on_policy() {
    // The SSRF guard does live DNS resolution, so we can't assume
    // any specific public hostname will resolve in the test
    // environment (CI may have no network at all). What we CAN
    // pin: if `https://example.com/...` is refused, the refusal
    // MUST be a DNS-resolution failure — NOT an SSRF policy
    // rejection (loopback / RFC 1918 / metadata / non-http scheme).
    //
    // This catches the regression class where someone tightens the
    // policy and accidentally adds a public TLD to the denylist.
    let outcome = HttpTransport::new("https://example.com/v1");
    if let Err(McpError::Transport(msg)) = outcome {
        let lowered = msg.to_lowercase();
        let policy_words = [
            "loopback",
            "rfc 1918",
            "rfc1918",
            "private",
            "link-local",
            "metadata",
            "scheme",
        ];
        for word in policy_words {
            assert!(
                !lowered.contains(word),
                "rejection of public https URL must NOT mention policy term {word:?}; \
                 got msg={msg:?}"
            );
        }
    }
}
