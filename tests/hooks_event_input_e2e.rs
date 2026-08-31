//! End-to-end tests for `hooks::HookEvent` taxonomy +
//! `HookInput` builder + `HookResult` constructors +
//! `HookEngine::check_blocked` predicate + `is_deny_intent` /
//! `default_matcher_target` policies.
//!
//! Sprint 73 of the verification effort. Sprint 28's
//! `hooks_merge_e2e` covered the deep-merge layering; this
//! file pins the event-classification surface and the
//! input-builder API that downstream code depends on.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

mod support;

use openclaudia::hooks::{HookEngine, HookError, HookEvent, HookInput, HookOutput, HookResult};
use serde_json::json;

// ───────────────────────────────────────────────────────────────────────────
// Section A — HookEvent::config_key catalog
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn config_key_returns_snake_case_for_every_variant() {
    let cases = &[
        (HookEvent::SessionStart, "session_start"),
        (HookEvent::SessionEnd, "session_end"),
        (HookEvent::PreToolUse, "pre_tool_use"),
        (HookEvent::PostToolUse, "post_tool_use"),
        (HookEvent::PostToolUseFailure, "post_tool_use_failure"),
        (HookEvent::UserPromptSubmit, "user_prompt_submit"),
        (HookEvent::Stop, "stop"),
        (HookEvent::SubagentStart, "subagent_start"),
        (HookEvent::SubagentStop, "subagent_stop"),
        (HookEvent::PreCompact, "pre_compact"),
        (HookEvent::PermissionRequest, "permission_request"),
        (HookEvent::Notification, "notification"),
        (HookEvent::PreAdversaryReview, "pre_adversary_review"),
        (HookEvent::PostAdversaryReview, "post_adversary_review"),
        (HookEvent::VddConflict, "vdd_conflict"),
        (HookEvent::VddConverged, "vdd_converged"),
    ];
    for (event, expected) in cases {
        assert_eq!(
            event.config_key(),
            *expected,
            "{event:?} config_key MUST equal {expected:?}"
        );
    }
}

#[test]
fn config_key_values_are_pairwise_distinct() {
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
    let mut keys: Vec<&str> = events.iter().map(HookEvent::config_key).collect();
    let n = keys.len();
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), n, "config_keys MUST be pairwise distinct");
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — HookEvent::from_claude_code_name CC parity
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn from_claude_code_name_recovers_documented_cc_events() {
    // CC's PascalCase names → matching variants.
    let cases = &[
        ("PreToolUse", HookEvent::PreToolUse),
        ("PostToolUse", HookEvent::PostToolUse),
        ("PostToolUseFailure", HookEvent::PostToolUseFailure),
        ("UserPromptSubmit", HookEvent::UserPromptSubmit),
        ("Stop", HookEvent::Stop),
        ("SubagentStart", HookEvent::SubagentStart),
        ("SubagentStop", HookEvent::SubagentStop),
        ("PreCompact", HookEvent::PreCompact),
        ("Notification", HookEvent::Notification),
    ];
    for (cc, expected) in cases {
        let parsed = HookEvent::from_claude_code_name(cc)
            .unwrap_or_else(|| panic!("CC name {cc:?} MUST parse"));
        assert_eq!(parsed, *expected);
    }
}

#[test]
fn from_claude_code_name_recovers_oc_extension_events() {
    // OC-only events that don't exist in CC but we support.
    let cases = &[
        ("SessionStart", HookEvent::SessionStart),
        ("SessionEnd", HookEvent::SessionEnd),
        ("PermissionRequest", HookEvent::PermissionRequest),
        ("PreAdversaryReview", HookEvent::PreAdversaryReview),
        ("PostAdversaryReview", HookEvent::PostAdversaryReview),
        ("VddConflict", HookEvent::VddConflict),
        ("VddConverged", HookEvent::VddConverged),
    ];
    for (cc, expected) in cases {
        let parsed = HookEvent::from_claude_code_name(cc)
            .unwrap_or_else(|| panic!("OC ext name {cc:?} MUST parse"));
        assert_eq!(parsed, *expected);
    }
}

#[test]
fn from_claude_code_name_rejects_unknown_names() {
    for bad in &["", "TotallyUnknown", "preToolUse", "pre_tool_use"] {
        assert!(
            HookEvent::from_claude_code_name(bad).is_none(),
            "{bad:?} MUST NOT parse as CC name"
        );
    }
}

#[test]
fn from_claude_code_name_is_case_sensitive_by_design() {
    // CC uses PascalCase exactly; "pretooluse" MUST NOT
    // match (avoids accidental matches from typos).
    assert!(HookEvent::from_claude_code_name("pretooluse").is_none());
    assert!(HookEvent::from_claude_code_name("PRETOOLUSE").is_none());
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — is_deny_intent classification
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn deny_intent_events_are_pre_tool_use_and_permission_request_only() {
    // PINS CROSSLINK #758: only these 2 events fail-CLOSED on
    // malformed matcher regex; everything else fails-OPEN.
    assert!(HookEvent::PreToolUse.is_deny_intent());
    assert!(HookEvent::PermissionRequest.is_deny_intent());
    // Every other event MUST be observe-intent.
    for ev in &[
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
            !ev.is_deny_intent(),
            "{ev:?} MUST be observe-intent (fail-open)"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — HookInput builder methods
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn hook_input_for_run_initializes_bound_cwd_and_default_fields() {
    let input = HookInput::for_run(support::shared_run_context(), HookEvent::SessionStart);
    assert_eq!(input.event, HookEvent::SessionStart);
    assert_eq!(
        input.cwd,
        support::shared_run_context()
            .working_directory()
            .to_string_lossy()
    );
    // Optional fields: None by default.
    assert!(input.session_id.is_none());
    assert!(input.tool_name.is_none());
    assert!(input.tool_input.is_none());
    assert!(input.prompt.is_none());
    assert!(input.extra.is_empty());
}

#[test]
fn hook_input_with_session_id_sets_session() {
    let input = HookInput::for_run(support::shared_run_context(), HookEvent::SessionStart)
        .with_session_id("sess-123");
    assert_eq!(input.session_id.as_deref(), Some("sess-123"));
}

#[test]
fn hook_input_with_tool_sets_both_name_and_input() {
    let input = HookInput::for_run(support::shared_run_context(), HookEvent::PreToolUse)
        .with_tool("bash", json!({"command": "ls"}));
    assert_eq!(input.tool_name.as_deref(), Some("bash"));
    assert_eq!(input.tool_input, Some(json!({"command": "ls"})));
}

#[test]
fn hook_input_with_prompt_sets_prompt_field() {
    let input = HookInput::for_run(support::shared_run_context(), HookEvent::UserPromptSubmit)
        .with_prompt("hello world");
    assert_eq!(input.prompt.as_deref(), Some("hello world"));
}

#[test]
fn hook_input_with_extra_accumulates_into_extra_map() {
    let input = HookInput::for_run(support::shared_run_context(), HookEvent::Notification)
        .with_extra("type", json!("status"))
        .with_extra("level", json!("info"));
    assert_eq!(input.extra.get("type"), Some(&json!("status")));
    assert_eq!(input.extra.get("level"), Some(&json!("info")));
    assert_eq!(input.extra.len(), 2);
}

#[test]
fn hook_input_builder_methods_are_chainable() {
    let input = HookInput::for_run(support::shared_run_context(), HookEvent::PreToolUse)
        .with_session_id("s")
        .with_tool("bash", json!({}))
        .with_extra("k", json!("v"));
    assert!(input.session_id.is_some());
    assert!(input.tool_name.is_some());
    assert!(input.extra.contains_key("k"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — HookInput match accessors
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn match_tool_returns_tool_name_when_set() {
    let input = HookInput::for_run(support::shared_run_context(), HookEvent::PreToolUse)
        .with_tool("bash", json!({}));
    assert_eq!(input.match_tool(), Some("bash"));
}

#[test]
fn match_tool_returns_none_when_unset() {
    let input = HookInput::for_run(support::shared_run_context(), HookEvent::SessionStart);
    assert!(input.match_tool().is_none());
}

#[test]
fn match_prompt_returns_prompt_when_set() {
    let input = HookInput::for_run(support::shared_run_context(), HookEvent::UserPromptSubmit)
        .with_prompt("hello");
    assert_eq!(input.match_prompt(), Some("hello"));
}

#[test]
fn match_event_always_returns_event_config_key() {
    let input = HookInput::for_run(support::shared_run_context(), HookEvent::SessionStart);
    assert_eq!(input.match_event(), Some("session_start"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — HookResult constructors
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn hook_result_allowed_starts_with_allowed_true_and_empty_lists() {
    let r = HookResult::allowed();
    assert!(r.allowed);
    assert!(r.outputs.is_empty());
    assert!(r.errors.is_empty());
}

#[test]
fn hook_result_denied_sets_allowed_false_with_reason_in_outputs() {
    let r = HookResult::denied("policy violation");
    assert!(!r.allowed);
    assert_eq!(r.outputs.len(), 1);
    assert_eq!(r.outputs[0].decision.as_deref(), Some("deny"));
    assert_eq!(r.outputs[0].reason.as_deref(), Some("policy violation"));
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — legacy hook fields become typed reference context
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn legacy_system_fields_become_source_labeled_references_in_order() {
    let r = HookResult {
        allowed: true,
        outputs: vec![
            HookOutput {
                system_message: Some("first".to_string()),
                ..HookOutput::default()
            },
            HookOutput {
                system_message: None,
                ..HookOutput::default()
            },
            HookOutput {
                system_message: Some("third".to_string()),
                ..HookOutput::default()
            },
        ],
        errors: vec![],
    };
    let items = openclaudia::context::hook_result_reference_items(&r, "fixture", 10);
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].content(), "first");
    assert_eq!(items[1].content(), "third");
    assert!(items
        .iter()
        .all(|item| { item.authority() == openclaudia::context::ContextAuthority::Reference }));
}

#[test]
fn prompt_fields_are_all_preserved_as_reference_suggestions() {
    let r = HookResult {
        allowed: true,
        outputs: vec![
            HookOutput {
                prompt: None,
                ..HookOutput::default()
            },
            HookOutput {
                prompt: Some("modified".to_string()),
                ..HookOutput::default()
            },
            HookOutput {
                prompt: Some("ignored".to_string()),
                ..HookOutput::default()
            },
        ],
        errors: vec![],
    };
    let items = openclaudia::context::hook_result_reference_items(&r, "fixture", 10);
    assert_eq!(items.len(), 2);
    assert_eq!(items[0].content(), "modified");
    assert_eq!(items[1].content(), "ignored");
}

#[test]
fn no_hook_context_produces_no_reference_items() {
    let r = HookResult::allowed();
    assert!(openclaudia::context::hook_result_reference_items(&r, "fixture", 10).is_empty());
}

// ───────────────────────────────────────────────────────────────────────────
// Section H — HookEngine::check_blocked
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn check_blocked_returns_ok_when_result_allowed() {
    let r = HookResult::allowed();
    assert!(HookEngine::check_blocked(&r).is_ok());
}

#[test]
fn check_blocked_returns_error_when_result_denied() {
    let r = HookResult::denied("test reason");
    let outcome = HookEngine::check_blocked(&r);
    let Err(HookError::Blocked(msg)) = outcome else {
        panic!("MUST be Blocked; got {outcome:?}");
    };
    assert!(msg.contains("test reason"));
}

#[test]
fn check_blocked_uses_default_message_when_no_reason_provided() {
    let r = HookResult {
        allowed: false,
        outputs: vec![],
        errors: vec![],
    };
    let outcome = HookEngine::check_blocked(&r);
    let Err(HookError::Blocked(msg)) = outcome else {
        panic!("MUST be Blocked");
    };
    assert!(
        msg.contains("Action blocked"),
        "MUST surface default reason when none provided; got {msg:?}"
    );
}

#[test]
fn check_blocked_joins_multiple_reasons_with_semicolons() {
    let r = HookResult {
        allowed: false,
        outputs: vec![
            HookOutput {
                reason: Some("reason one".to_string()),
                ..HookOutput::default()
            },
            HookOutput {
                reason: Some("reason two".to_string()),
                ..HookOutput::default()
            },
        ],
        errors: vec![],
    };
    let outcome = HookEngine::check_blocked(&r);
    let Err(HookError::Blocked(msg)) = outcome else {
        panic!("MUST be Blocked");
    };
    assert!(msg.contains("reason one"));
    assert!(msg.contains("reason two"));
    assert!(
        msg.contains("; "),
        "multiple reasons MUST be joined by semicolon-space; got {msg:?}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section I — HookEvent serde
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn hook_event_serde_uses_snake_case_matching_config_key() {
    for ev in &[
        HookEvent::PreToolUse,
        HookEvent::Notification,
        HookEvent::SessionStart,
    ] {
        let json = serde_json::to_string(ev).expect("serialize");
        let unquoted = json.trim_matches('"');
        assert_eq!(
            unquoted,
            ev.config_key(),
            "serde encoding MUST equal config_key"
        );
    }
}
