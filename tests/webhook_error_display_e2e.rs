//! End-to-end tests for `tools::remote_trigger::WebhookError`
//! `Display` strings — pins all 5 variant message templates
//! exactly, plus `PartialEq`/`Eq` + `Clone` derives.
//!
//! Sprint 215 of the verification effort.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::tools::remote_trigger::WebhookError;

// ───────────────────────────────────────────────────────────────────────────
// Section A — InvalidScheme variant
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn invalid_scheme_display_uses_documented_template() {
    let err = WebhookError::InvalidScheme {};
    let s = err.to_string();
    assert_eq!(
        s,
        "webhook URL uses an unsupported scheme; \
         expected https (or http with explicit opt-in)"
    );
}

#[test]
fn invalid_scheme_display_does_not_include_untrusted_scheme() {
    let err = WebhookError::InvalidScheme {};
    let s = err.to_string();
    assert!(!s.contains("javascript-secret-sentinel"));
}

#[test]
fn invalid_scheme_with_empty_scheme_still_renders() {
    let err = WebhookError::InvalidScheme {};
    let s = err.to_string();
    assert!(s.contains("unsupported scheme"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — InsecureScheme variant
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn insecure_scheme_display_uses_documented_template() {
    let err = WebhookError::InsecureScheme {};
    let s = err.to_string();
    assert_eq!(
        s,
        "webhook URL uses insecure http://; \
         build the registry with new_allow_plaintext() to opt in"
    );
}

#[test]
fn insecure_scheme_display_mentions_new_allow_plaintext_opt_in() {
    // PINS DOC: the error guides operators to the opt-in builder.
    let err = WebhookError::InsecureScheme {};
    let s = err.to_string();
    assert!(s.contains("new_allow_plaintext()"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Malformed variant
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn malformed_display_uses_documented_template() {
    let err = WebhookError::Malformed {};
    let s = err.to_string();
    assert_eq!(s, "webhook URL is not a valid absolute URL with a host");
}

#[test]
fn malformed_with_empty_url_still_renders() {
    let err = WebhookError::Malformed {};
    let s = err.to_string();
    assert!(s.contains("not a valid absolute URL"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — UnknownWebhook variant
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn unknown_webhook_display_uses_documented_template() {
    let err = WebhookError::UnknownWebhook {
        name: "notify".to_string(),
    };
    let s = err.to_string();
    assert_eq!(s, "no webhook registered under name 'notify'");
}

#[test]
fn unknown_webhook_includes_name_in_quotes() {
    let err = WebhookError::UnknownWebhook {
        name: "marker-215".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("'marker-215'"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Duplicate variant
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn duplicate_display_uses_documented_template() {
    let err = WebhookError::Duplicate {
        name: "hook".to_string(),
    };
    let s = err.to_string();
    assert_eq!(s, "webhook name 'hook' is already registered");
}

#[test]
fn duplicate_includes_name_in_quotes() {
    let err = WebhookError::Duplicate {
        name: "x".to_string(),
    };
    let s = err.to_string();
    assert!(s.contains("'x'"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — Cross-variant distinctness
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn five_variants_have_distinct_display_strings() {
    let variants = vec![
        WebhookError::InvalidScheme {}.to_string(),
        WebhookError::InsecureScheme {}.to_string(),
        WebhookError::Malformed {}.to_string(),
        WebhookError::UnknownWebhook {
            name: "x".to_string(),
        }
        .to_string(),
        WebhookError::Duplicate {
            name: "x".to_string(),
        }
        .to_string(),
    ];
    let mut sorted = variants;
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), 5, "5 variants MUST have 5 distinct strings");
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — PartialEq + Eq + Clone
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn webhook_error_partial_eq_same_variant_same_payload() {
    let a = WebhookError::Duplicate {
        name: "hook".to_string(),
    };
    let b = WebhookError::Duplicate {
        name: "hook".to_string(),
    };
    assert_eq!(a, b);
}

#[test]
fn webhook_error_partial_eq_different_payload_distinct() {
    let a = WebhookError::Duplicate {
        name: "a".to_string(),
    };
    let b = WebhookError::Duplicate {
        name: "b".to_string(),
    };
    assert_ne!(a, b);
}

#[test]
fn webhook_error_clone_preserves_variant_and_payload() {
    let original = WebhookError::InvalidScheme {};
    let cloned = original.clone();
    assert_eq!(cloned, original);
}

// ───────────────────────────────────────────────────────────────────────────
// Section H — Error trait
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn webhook_error_implements_std_error_trait() {
    let err = WebhookError::Malformed {};
    let _: &dyn std::error::Error = &err;
}

#[test]
fn webhook_error_is_send_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<WebhookError>();
}

// ───────────────────────────────────────────────────────────────────────────
// Section I — Determinism
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn display_deterministic_across_repeated_calls() {
    let err = WebhookError::UnknownWebhook {
        name: "marker".to_string(),
    };
    let s1 = err.to_string();
    let s2 = err.to_string();
    let s3 = err.to_string();
    assert_eq!(s1, s2);
    assert_eq!(s2, s3);
}
