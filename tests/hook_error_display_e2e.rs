//! End-to-end tests for `hooks::HookError` Display strings +
//! `HookEvent` `config_key` round-trip with `is_deny_intent`
//! semantics + `HookInput::match_tool`/`match_prompt`
//! accessor coherence.
//!
//! Sprint 111 of the verification effort. Sprint 73
//! (`hooks_event_input_e2e`) covered the `HookEvent` CC
//! parser plus builder pattern; this file pins the
//! `HookError` variant Display strings (operator-facing
//! error messages), `match_tool` / `match_prompt`
//! accessor semantics, and the `is_deny_intent` →
//! `config_key` cross-consistency check.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

mod support;

use openclaudia::hooks::{HookError, HookEvent, HookInput};
use openclaudia::runtime::{CapabilityGeneration, RunId};
use openclaudia::tools::{ToolCapabilityError, ToolResource};
use serde_json::json;

// ───────────────────────────────────────────────────────────────────────────
// Section A — HookError Display
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn hook_error_timeout_display_includes_seconds() {
    let err = HookError::Timeout(30);
    let msg = err.to_string();
    assert!(msg.contains("30"));
    assert!(msg.contains("timed out") || msg.contains("Timeout"));
}

#[test]
fn hook_error_command_failed_display_includes_reason() {
    let err = HookError::CommandFailed("exit code 1".to_string());
    let msg = err.to_string();
    assert!(msg.contains("Hook command failed"));
    assert!(msg.contains("exit code 1"));
}

#[test]
fn hook_error_parse_error_display_includes_reason() {
    let err = HookError::ParseError("malformed JSON".to_string());
    let msg = err.to_string();
    assert!(msg.contains("parse error"));
    assert!(msg.contains("malformed JSON"));
}

#[test]
fn hook_error_blocked_display_includes_reason() {
    let err = HookError::Blocked("policy violation".to_string());
    let msg = err.to_string();
    assert!(msg.contains("blocked"));
    assert!(msg.contains("policy violation"));
}

#[test]
fn hook_error_invalid_matcher_display_includes_pattern() {
    let err = HookError::InvalidMatcher("[unclosed".to_string());
    let msg = err.to_string();
    assert!(msg.contains("Invalid matcher"));
    assert!(msg.contains("[unclosed"));
}

#[test]
fn hook_error_denied_display_includes_binary_name() {
    // PINS DOC: allowlist enforcement error must surface the
    // binary name so operator can self-correct config.
    let err = HookError::Denied {
        binary: "evil-binary".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("evil-binary"));
    assert!(msg.contains("allowed_commands") || msg.contains("allowlist"));
}

#[test]
fn hook_error_variants_have_distinct_displays() {
    let errs: Vec<String> = vec![
        HookError::Capability(ToolCapabilityError::Unavailable {
            resource: ToolResource::Secrets,
            run_id: RunId::new(),
            generation: CapabilityGeneration::new(1).expect("non-zero generation"),
        })
        .to_string(),
        HookError::Timeout(5).to_string(),
        HookError::CommandFailed("x".to_string()).to_string(),
        HookError::ParseError("x".to_string()).to_string(),
        HookError::Blocked("x".to_string()).to_string(),
        HookError::InvalidMatcher("x".to_string()).to_string(),
        HookError::Denied {
            binary: "x".to_string(),
        }
        .to_string(),
    ];
    let mut sorted = errs.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        errs.len(),
        "all 7 HookError variants MUST produce distinct Display strings"
    );
}

#[test]
fn hook_error_clone_preserves_variant_data() {
    let original = HookError::Denied {
        binary: "name".to_string(),
    };
    let cloned = original.clone();
    assert_eq!(cloned.to_string(), original.to_string());
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — HookEvent::config_key matches serde
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn config_key_matches_serde_snake_case_form() {
    for event in &[
        HookEvent::SessionStart,
        HookEvent::PreToolUse,
        HookEvent::PostToolUse,
        HookEvent::Stop,
    ] {
        let serde_form = serde_json::to_string(event).expect("ser");
        let serde_form_unquoted = serde_form.trim_matches('"');
        assert_eq!(
            event.config_key(),
            serde_form_unquoted,
            "config_key MUST match serde rename_all form for {event:?}"
        );
    }
}

#[test]
fn config_key_is_distinct_for_every_documented_event() {
    let events = [
        HookEvent::SessionStart,
        HookEvent::SessionEnd,
        HookEvent::PreToolUse,
        HookEvent::PostToolUse,
        HookEvent::PostToolUseFailure,
        HookEvent::UserPromptSubmit,
        HookEvent::Stop,
        HookEvent::SubagentStart,
        HookEvent::SubagentStop,
        HookEvent::PreCompact,
        HookEvent::PermissionRequest,
        HookEvent::Notification,
        HookEvent::PreAdversaryReview,
        HookEvent::PostAdversaryReview,
        HookEvent::VddConflict,
        HookEvent::VddConverged,
    ];
    let mut keys: Vec<&'static str> = events.iter().map(HookEvent::config_key).collect();
    let n = keys.len();
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(
        keys.len(),
        n,
        "config_key MUST be 1:1 with HookEvent variants; got {} unique of {}",
        keys.len(),
        n
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — is_deny_intent semantics
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn is_deny_intent_pre_tool_use_is_true() {
    assert!(HookEvent::PreToolUse.is_deny_intent());
}

#[test]
fn is_deny_intent_permission_request_is_true() {
    assert!(HookEvent::PermissionRequest.is_deny_intent());
}

#[test]
fn is_deny_intent_observe_intent_events_are_false() {
    for event in &[
        HookEvent::SessionStart,
        HookEvent::SessionEnd,
        HookEvent::PostToolUse,
        HookEvent::PostToolUseFailure,
        HookEvent::UserPromptSubmit,
        HookEvent::Stop,
        HookEvent::SubagentStart,
        HookEvent::SubagentStop,
        HookEvent::PreCompact,
        HookEvent::Notification,
        HookEvent::PreAdversaryReview,
        HookEvent::PostAdversaryReview,
        HookEvent::VddConflict,
        HookEvent::VddConverged,
    ] {
        assert!(
            !event.is_deny_intent(),
            "{event:?} MUST be observe-intent (not deny)"
        );
    }
}

#[test]
fn deny_intent_events_count_matches_documented_2() {
    // PINS DOC: only PreToolUse + PermissionRequest are deny-intent.
    let events = [
        HookEvent::SessionStart,
        HookEvent::SessionEnd,
        HookEvent::PreToolUse,
        HookEvent::PostToolUse,
        HookEvent::PostToolUseFailure,
        HookEvent::UserPromptSubmit,
        HookEvent::Stop,
        HookEvent::SubagentStart,
        HookEvent::SubagentStop,
        HookEvent::PreCompact,
        HookEvent::PermissionRequest,
        HookEvent::Notification,
        HookEvent::PreAdversaryReview,
        HookEvent::PostAdversaryReview,
        HookEvent::VddConflict,
        HookEvent::VddConverged,
    ];
    let deny_count = events.iter().filter(|e| e.is_deny_intent()).count();
    assert_eq!(deny_count, 2, "exactly 2 events MUST be deny-intent");
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — HookInput::match_tool / match_prompt accessors
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn match_tool_returns_some_when_tool_name_set() {
    let input = HookInput::for_run(support::shared_run_context(), HookEvent::PreToolUse)
        .with_tool("bash", json!({"command": "ls"}));
    assert_eq!(input.match_tool(), Some("bash"));
}

#[test]
fn match_tool_returns_none_when_tool_name_absent() {
    let input = HookInput::for_run(support::shared_run_context(), HookEvent::SessionStart);
    assert!(input.match_tool().is_none());
}

#[test]
fn match_prompt_returns_some_when_prompt_set() {
    let input = HookInput::for_run(support::shared_run_context(), HookEvent::UserPromptSubmit)
        .with_prompt("hi there");
    assert_eq!(input.match_prompt(), Some("hi there"));
}

#[test]
fn match_prompt_returns_none_when_prompt_absent() {
    let input = HookInput::for_run(support::shared_run_context(), HookEvent::SessionStart);
    assert!(input.match_prompt().is_none());
}

#[test]
fn match_accessors_independent_tool_and_prompt_can_both_be_set() {
    let input = HookInput::for_run(support::shared_run_context(), HookEvent::PreToolUse)
        .with_tool("bash", json!({}))
        .with_prompt("context prompt");
    assert_eq!(input.match_tool(), Some("bash"));
    assert_eq!(input.match_prompt(), Some("context prompt"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — HookInput::with_session_id + with_extra
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn with_session_id_replaces_when_called_twice() {
    let input = HookInput::for_run(support::shared_run_context(), HookEvent::SessionStart)
        .with_session_id("first")
        .with_session_id("second");
    // Last write wins (builder pattern).
    assert_eq!(input.session_id.as_deref(), Some("second"));
}

#[test]
fn with_extra_multiple_keys_all_persist() {
    let input = HookInput::for_run(support::shared_run_context(), HookEvent::Notification)
        .with_extra("key1", json!("value1"))
        .with_extra("key2", json!(42))
        .with_extra("key3", json!({"nested": true}));
    assert_eq!(input.extra.len(), 3);
    assert_eq!(input.extra.get("key1"), Some(&json!("value1")));
    assert_eq!(input.extra.get("key2"), Some(&json!(42)));
    assert_eq!(input.extra.get("key3"), Some(&json!({"nested": true})));
}

#[test]
fn with_extra_same_key_twice_last_wins() {
    let input = HookInput::for_run(support::shared_run_context(), HookEvent::Notification)
        .with_extra("k", json!("first"))
        .with_extra("k", json!("second"));
    assert_eq!(input.extra.len(), 1);
    assert_eq!(input.extra.get("k"), Some(&json!("second")));
}
