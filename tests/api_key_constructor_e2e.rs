//! End-to-end tests for `providers::api_key::ApiKey`
//! constructor validation paths + `MAX_API_KEY_LEN` cap +
//! `Deserialize` impl (mirrors `try_from_string`) +
//! `REDACTED_PLACEHOLDER` rejection semantics.
//!
//! Sprint 96 of the verification effort. Sprint 50
//! (`api_key_redaction_e2e`) covered the redaction Display /
//! Serialize / Debug paths; this file pins the constructor
//! validation matrix (Empty/NonAscii/ControlChar/TooLong),
//! the `MAX_API_KEY_LEN = 512` cap, and the Deserialize impl
//! that enforces the same validation at the serde boundary.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::providers::api_key::{
    redact_api_key, ApiKey, ApiKeyError, MAX_API_KEY_LEN, REDACTED_PLACEHOLDER,
};

// ───────────────────────────────────────────────────────────────────────────
// Section A — Constants
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn max_api_key_len_constant_matches_documented_value() {
    assert_eq!(MAX_API_KEY_LEN, 512);
}

#[test]
fn redacted_placeholder_is_documented_sentinel_string() {
    assert_eq!(REDACTED_PLACEHOLDER, "[REDACTED]");
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — try_from_string success path
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn try_from_string_accepts_typical_anthropic_format() {
    let raw = "sk-ant-api03-AAAAABBBBCCCCDDDD_EEEE-FFFF-GGGG-1234567890";
    let key = ApiKey::try_from_string(raw.to_string()).expect("valid");
    assert!(key.matches(raw));
}

#[test]
fn try_from_string_accepts_typical_openai_format() {
    let raw = "sk-proj-AAAAABBBBCCCCDDDD-EEEE-FFFF1234567890ABCDEF";
    let key = ApiKey::try_from_string(raw.to_string()).expect("valid");
    assert!(key.matches(raw));
}

#[test]
fn try_from_string_accepts_minimal_non_empty_input() {
    let key = ApiKey::try_from_string("a".to_string()).expect("valid");
    assert!(key.matches("a"));
}

#[test]
fn try_from_string_accepts_at_max_length() {
    let raw = "a".repeat(MAX_API_KEY_LEN);
    let key = ApiKey::try_from_string(raw.clone()).expect("at-max MUST validate");
    assert!(key.matches(&raw));
}

#[test]
fn try_from_string_accepts_ascii_special_characters() {
    // Documented contract: any ASCII non-control character is fine.
    let raw = "key-with_special.chars+slash/and=equals";
    let key = ApiKey::try_from_string(raw.to_string()).expect("valid");
    assert!(key.matches(raw));
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — try_from_string rejection paths (matrix)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn try_from_empty_string_returns_empty_variant() {
    let outcome = ApiKey::try_from_string(String::new());
    assert_eq!(outcome.unwrap_err(), ApiKeyError::Empty);
}

#[test]
fn try_from_whitespace_only_string_returns_empty_variant() {
    let outcome = ApiKey::try_from_string("   \t\n  ".to_string());
    // Whitespace-only → trim().is_empty() → Empty variant.
    assert!(matches!(outcome.unwrap_err(), ApiKeyError::Empty));
}

#[test]
fn try_from_non_ascii_string_returns_non_ascii_variant() {
    let outcome = ApiKey::try_from_string("key-日本語-suffix".to_string());
    assert_eq!(outcome.unwrap_err(), ApiKeyError::NonAscii);
}

#[test]
fn try_from_string_with_newline_returns_control_char_variant() {
    let outcome = ApiKey::try_from_string("key\ninjected".to_string());
    let err = outcome.unwrap_err();
    let ApiKeyError::ControlChar { codepoint } = err else {
        panic!("MUST be ControlChar variant; got {err:?}");
    };
    assert_eq!(codepoint, u32::from(b'\n'));
}

#[test]
fn try_from_string_with_carriage_return_returns_control_char_variant() {
    let outcome = ApiKey::try_from_string("key\r\nsmuggled".to_string());
    let err = outcome.unwrap_err();
    let ApiKeyError::ControlChar { codepoint } = err else {
        panic!("MUST be ControlChar variant; got {err:?}");
    };
    // The first control char encountered is \r (0x0D).
    assert_eq!(codepoint, u32::from(b'\r'));
}

#[test]
fn try_from_string_with_null_byte_returns_control_char_variant() {
    let outcome = ApiKey::try_from_string("key\0null".to_string());
    let err = outcome.unwrap_err();
    assert!(matches!(err, ApiKeyError::ControlChar { codepoint: 0 }));
}

#[test]
fn try_from_string_with_tab_returns_control_char_variant() {
    let outcome = ApiKey::try_from_string("key\twith\ttab".to_string());
    let err = outcome.unwrap_err();
    let ApiKeyError::ControlChar { codepoint } = err else {
        panic!("MUST be ControlChar variant; got {err:?}");
    };
    assert_eq!(codepoint, u32::from(b'\t'));
}

#[test]
fn try_from_string_just_over_max_length_returns_too_long_variant() {
    let raw = "a".repeat(MAX_API_KEY_LEN + 1);
    let outcome = ApiKey::try_from_string(raw);
    let err = outcome.unwrap_err();
    let ApiKeyError::TooLong { actual, max } = err else {
        panic!("MUST be TooLong variant; got {err:?}");
    };
    assert_eq!(actual, MAX_API_KEY_LEN + 1);
    assert_eq!(max, MAX_API_KEY_LEN);
}

#[test]
fn try_from_string_far_over_max_length_returns_too_long_variant() {
    // 8 KiB attack payload shape.
    let raw = "a".repeat(8 * 1024);
    let outcome = ApiKey::try_from_string(raw);
    assert!(matches!(outcome.unwrap_err(), ApiKeyError::TooLong { .. }));
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Error variant Display strings (CRLF-guard documentation)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn api_key_error_empty_has_descriptive_display() {
    let err = ApiKeyError::Empty;
    let msg = err.to_string();
    assert!(msg.contains("empty") || msg.contains("whitespace"));
}

#[test]
fn api_key_error_non_ascii_mentions_header_construction() {
    let err = ApiKeyError::NonAscii;
    let msg = err.to_string();
    assert!(msg.contains("non-ASCII"));
    assert!(msg.contains("header"));
}

#[test]
fn api_key_error_control_char_includes_codepoint_in_hex() {
    let err = ApiKeyError::ControlChar { codepoint: 0x0A };
    let msg = err.to_string();
    // PINS DOC: error message MUST include U+000A and CRLF guard.
    assert!(
        msg.contains("000A") || msg.contains("000a"),
        "MUST include hex codepoint; got {msg:?}"
    );
    assert!(
        msg.contains("CRLF injection") || msg.contains("CRLF"),
        "MUST mention CRLF guard; got {msg:?}"
    );
}

#[test]
fn api_key_error_too_long_carries_actual_and_max() {
    let err = ApiKeyError::TooLong {
        actual: 1024,
        max: 512,
    };
    let msg = err.to_string();
    assert!(msg.contains("1024"));
    assert!(msg.contains("512"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Deserialize impl validates at serde boundary
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn deserialize_accepts_valid_key_from_json_string() {
    let raw = "sk-test-key-12345abc";
    let json = format!("\"{raw}\"");
    let key: ApiKey = serde_json::from_str(&json).expect("valid");
    assert!(key.matches(raw));
}

#[test]
fn deserialize_rejects_empty_string_with_error_message() {
    let outcome: Result<ApiKey, _> = serde_json::from_str("\"\"");
    assert!(outcome.is_err());
    let msg = outcome.unwrap_err().to_string();
    assert!(msg.contains("empty") || msg.contains("whitespace"));
}

#[test]
fn deserialize_rejects_string_with_embedded_newline() {
    // PINS DESERIALIZE CRLF-GUARD: serde-deserialized key
    // goes through the same validator.
    let outcome: Result<ApiKey, _> = serde_json::from_str("\"key\\ninjection\"");
    assert!(outcome.is_err());
}

#[test]
fn deserialize_rejects_string_with_non_ascii_chars() {
    let outcome: Result<ApiKey, _> = serde_json::from_str("\"key-日本語\"");
    assert!(outcome.is_err());
}

#[test]
fn deserialize_rejects_string_over_max_length() {
    let raw = "a".repeat(MAX_API_KEY_LEN + 1);
    let json = format!("\"{raw}\"");
    let outcome: Result<ApiKey, _> = serde_json::from_str(&json);
    assert!(outcome.is_err());
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — REDACTED_PLACEHOLDER is output-only
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn serialize_then_deserialize_refuses_to_activate_redacted_placeholder() {
    let raw = "sk-real-secret-key";
    let original = ApiKey::try_from_string(raw.to_string()).expect("valid");
    let json = serde_json::to_string(&original).expect("ser");
    assert!(json.contains(REDACTED_PLACEHOLDER));
    let outcome = serde_json::from_str::<ApiKey>(&json);
    assert!(
        outcome.is_err(),
        "redacted output must never become a live key"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — redact_api_key boundary
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn redact_short_keys_collapse_to_redacted_marker() {
    for input in &["", "a", "short", "123456789"] {
        let r = redact_api_key(input);
        assert_eq!(r, REDACTED_PLACEHOLDER);
    }
}

#[test]
fn redact_keys_at_10_chars_reveals_no_fingerprint() {
    let input = "0123456789"; // exactly 10
    let r = redact_api_key(input);
    assert_eq!(r, REDACTED_PLACEHOLDER);
}

#[test]
fn redact_keys_long_form_reveals_no_fingerprint() {
    let input = "abcdefghijklmnopqrstuvwxyz1234567890";
    let r = redact_api_key(input);
    assert_eq!(r, REDACTED_PLACEHOLDER);
    assert!(!r.contains("abcd"));
    assert!(!r.contains("7890"));
}

#[test]
fn redact_non_ascii_input_still_reveals_nothing() {
    let input = "日本語キーprefix1234suffix";
    let r = redact_api_key(input);
    assert_eq!(r, REDACTED_PLACEHOLDER);
}
