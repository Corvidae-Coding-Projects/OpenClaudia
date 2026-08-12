//! End-to-end tests for `ApiKey` redaction across every
//! formatting path AND the `is_sensitive_env_pub` classifier
//! against the full attack catalog.
//!
//! Sprint 34 of the verification effort.
//!
//! `src/providers/api_key.rs` has 16 unit tests on the validator
//! side; this file pins the REDACTION contract (Display, Debug,
//! Serialize-to-JSON, Serialize-to-YAML) so a regression that
//! leaks raw keys into logs or persisted config fails loudly.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::providers::api_key::{
    redact_api_key, validate_api_key, ApiKey, REDACTED_PLACEHOLDER,
};
use openclaudia::tools::is_sensitive_env_pub as is_sensitive_env;

/// A realistic-shaped Anthropic key (40 chars) — long enough
/// that redaction shows head + tail rather than collapsing to
/// `<redacted>`.
const SAMPLE_KEY: &str = "sk-ant-api03-PRODUCTION-SECRET-VALUE_X1Y";

// ───────────────────────────────────────────────────────────────────────────
// Section A — redact_api_key shape
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn redact_api_key_collapses_short_inputs_to_redacted() {
    // Under 10 chars: the format `<head>…<tail>` would leave
    // too little obscured, so the impl collapses to a marker.
    for short in &["", "abc", "sk-ant", "123456789"] {
        let out = redact_api_key(short);
        assert_eq!(
            out, "<redacted>",
            "short input {short:?} must redact to the marker; got {out:?}"
        );
    }
}

#[test]
fn redact_api_key_keeps_head_and_tail_only() {
    let out = redact_api_key(SAMPLE_KEY);
    // The redaction shape is `<first-4-chars>…<last-4-chars>`.
    assert!(
        out.starts_with("sk-a"),
        "head 4 chars must survive: {out:?}"
    );
    assert!(
        out.ends_with("X1Y") || out.ends_with("1Y"),
        "tail 4 chars must survive: {out:?}"
    );
    // The ellipsis MUST be present.
    assert!(out.contains('…'), "must include the ellipsis: {out:?}");
    // The full secret MUST NOT appear in the redacted output.
    assert!(
        !out.contains("PRODUCTION-SECRET-VALUE"),
        "secret middle MUST NOT appear in redaction: {out:?}"
    );
}

#[test]
fn redact_api_key_does_not_carry_secret_in_any_substring() {
    // Even sliding-window substring matches of the middle must
    // not leak. Take a 16-char window from the middle and
    // assert it's NOT in the redacted output.
    let middle: String = SAMPLE_KEY.chars().skip(8).take(16).collect();
    let out = redact_api_key(SAMPLE_KEY);
    assert!(
        !out.contains(&middle),
        "16-char middle window {middle:?} MUST NOT leak; got {out:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — ApiKey Display + Debug
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn api_key_display_uses_redacted_form() {
    let key = ApiKey::try_from_string(SAMPLE_KEY.to_string()).expect("valid key");
    let display = format!("{key}");
    assert!(!display.contains("PRODUCTION-SECRET-VALUE"));
    assert!(display.contains('…'));
}

#[test]
fn api_key_debug_uses_redacted_form_with_wrapper() {
    let key = ApiKey::try_from_string(SAMPLE_KEY.to_string()).expect("valid key");
    let debug = format!("{key:?}");
    assert!(
        debug.starts_with("ApiKey("),
        "Debug must wrap in ApiKey(...); got {debug:?}"
    );
    assert!(!debug.contains("PRODUCTION-SECRET-VALUE"));
    assert!(debug.contains('…'));
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — ApiKey Serialize (JSON + YAML)
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn api_key_json_serialize_emits_exact_redacted_placeholder() {
    let key = ApiKey::try_from_string(SAMPLE_KEY.to_string()).expect("valid key");
    let json = serde_json::to_string(&key).expect("serialize");
    // The serialize impl emits the documented opaque marker —
    // NOT the ellipsis Display form. Tests pattern-match on
    // the public REDACTED_PLACEHOLDER constant so a future
    // marker rename surfaces here.
    assert!(
        !json.contains("PRODUCTION-SECRET-VALUE"),
        "raw secret MUST NOT appear; got {json}"
    );
    assert!(
        json.contains(REDACTED_PLACEHOLDER),
        "json MUST contain the REDACTED_PLACEHOLDER ({REDACTED_PLACEHOLDER:?}); got {json}"
    );
}

#[test]
fn api_key_yaml_serialize_emits_exact_redacted_placeholder() {
    let key = ApiKey::try_from_string(SAMPLE_KEY.to_string()).expect("valid key");
    let yaml = serde_yaml::to_string(&key).expect("yaml serialize");
    assert!(
        !yaml.contains("PRODUCTION-SECRET-VALUE"),
        "raw secret MUST NOT appear; got {yaml}"
    );
    assert!(
        yaml.contains(REDACTED_PLACEHOLDER),
        "yaml MUST contain the REDACTED_PLACEHOLDER ({REDACTED_PLACEHOLDER:?}); got {yaml}"
    );
}

#[test]
fn api_key_nested_in_struct_redacts_during_serialize() {
    // Common case: ApiKey lives inside ProviderConfig, which is
    // inside AppConfig. Serializing the wrapper MUST also
    // redact — otherwise a debug-dump of the whole config
    // leaks every key.
    #[derive(serde::Serialize)]
    struct Wrapper {
        provider: &'static str,
        api_key: ApiKey,
    }
    let w = Wrapper {
        provider: "anthropic",
        api_key: ApiKey::try_from_string(SAMPLE_KEY.to_string()).unwrap(),
    };
    let json = serde_json::to_string(&w).expect("wrapper serialize");
    assert!(
        !json.contains("PRODUCTION-SECRET-VALUE"),
        "raw secret MUST NOT appear in wrapper serialize; got {json}"
    );
    assert!(
        json.contains(REDACTED_PLACEHOLDER),
        "wrapper serialize MUST emit the placeholder for the nested key field; got {json}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — validate_api_key error messages
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn validate_api_key_rejects_empty_with_descriptive_message() {
    let outcome = validate_api_key("");
    let Err(msg) = outcome else {
        panic!("empty MUST be rejected")
    };
    assert!(
        msg.to_lowercase().contains("empty"),
        "msg must mention 'empty'; got {msg:?}"
    );
}

#[test]
fn validate_api_key_rejects_non_ascii_with_descriptive_message() {
    let outcome = validate_api_key("sk-ant-héllo");
    let Err(msg) = outcome else {
        panic!("non-ASCII MUST be rejected")
    };
    let lowered = msg.to_lowercase();
    assert!(
        lowered.contains("ascii") || lowered.contains("header"),
        "msg must mention ascii / header; got {msg:?}"
    );
}

#[test]
fn validate_api_key_rejects_control_char_with_descriptive_message() {
    let outcome = validate_api_key("sk-ant\ninjection");
    let Err(msg) = outcome else {
        panic!("control char MUST be rejected")
    };
    let lowered = msg.to_lowercase();
    assert!(
        lowered.contains("control") || lowered.contains("crlf") || lowered.contains("u+"),
        "msg must mention control/CRLF; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — is_sensitive_env classifier — exact matches
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn sensitive_env_canonical_provider_keys() {
    for key in &[
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "OPENAI_API_KEY",
        "OPENAI_ORG_ID",
        "OPENAI_PROJECT_ID",
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
        "DEEPSEEK_API_KEY",
        "QWEN_API_KEY",
        "DASHSCOPE_API_KEY",
        "ALIYUN_API_KEY",
        "ZAI_API_KEY",
        "GLM_API_KEY",
        "KIMI_API_KEY",
        "MOONSHOT_API_KEY",
        "MINIMAX_API_KEY",
        "OLLAMA_API_KEY",
        "OPENROUTER_API_KEY",
        "OPEN_ROUTER_API_KEY",
        "OPENCODE_API_KEY",
        "OPENCODE_GO_API_KEY",
        "OPENAI_COMPATIBLE_API_KEY",
        "API_KEY",
    ] {
        assert!(
            is_sensitive_env(key),
            "canonical provider key {key:?} MUST be sensitive"
        );
    }
}

#[test]
fn sensitive_env_ci_and_vcs_tokens() {
    for key in &[
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "GITLAB_TOKEN",
        "BITBUCKET_TOKEN",
        "NPM_TOKEN",
        "CARGO_REGISTRY_TOKEN",
        "PYPI_TOKEN",
        "DOCKER_PASSWORD",
        "DOCKER_AUTH_CONFIG",
        "KUBECONFIG",
        "VAULT_TOKEN",
    ] {
        assert!(
            is_sensitive_env(key),
            "CI/VCS token {key:?} MUST be sensitive"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — is_sensitive_env classifier — prefix matches
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn sensitive_env_cloud_provider_prefix_families() {
    for key in &[
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AZURE_CLIENT_SECRET",
        "AZURE_SUBSCRIPTION_ID",
        "GCP_PROJECT_ID",
        "GCP_SERVICE_ACCOUNT_KEY",
        "GCLOUD_PROJECT",
        "CLAUDE_CODE_USER_KEY",
    ] {
        assert!(
            is_sensitive_env(key),
            "cloud-provider prefix {key:?} MUST be sensitive"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — is_sensitive_env classifier — suffix matches
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn sensitive_env_suffix_catches_arbitrary_secret_envs() {
    for key in &[
        "MYAPP_API_KEY",
        "INTERNAL_TOKEN",
        "DATABASE_SECRET",
        "ADMIN_PASSWORD",
        "GPG_PASSPHRASE",
        "SSH_PRIVATE_KEY",
    ] {
        assert!(
            is_sensitive_env(key),
            "arbitrary suffix {key:?} MUST be sensitive"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section H — is_sensitive_env classifier — case-insensitivity
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn sensitive_env_classifier_is_case_insensitive() {
    // The impl uppercases the input before matching, so every
    // case variant of a sensitive key must classify the same.
    let canonical = "AWS_SECRET_ACCESS_KEY";
    assert!(is_sensitive_env(canonical));
    assert!(is_sensitive_env(&canonical.to_lowercase()));
    assert!(is_sensitive_env("aWs_SecreT_AcCess_KeY"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section I — is_sensitive_env classifier — negative cases
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn sensitive_env_does_not_classify_benign_env_vars() {
    // The classifier must not be overly aggressive — these
    // ordinary system vars MUST NOT be classified sensitive.
    for key in &[
        "HOME",
        "PATH",
        "USER",
        "SHELL",
        "PWD",
        "LANG",
        "TERM",
        "TZ",
        "EDITOR",
        "DISPLAY",
        "HOSTNAME",
        "OLDPWD",
        "LOGNAME",
        // Tricky cases — these LOOK sensitive but aren't.
        "TOKEN_LENGTH_INFO", // "TOKEN" appears but not as suffix
        "API_VERSION",       // ends in VERSION, not API_KEY
    ] {
        assert!(
            !is_sensitive_env(key),
            "{key:?} MUST NOT be classified sensitive (false positive)"
        );
    }
}

#[test]
fn sensitive_env_empty_input_returns_false() {
    assert!(!is_sensitive_env(""));
}
