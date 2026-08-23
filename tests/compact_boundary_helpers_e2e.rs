//! End-to-end tests for `compaction::COMPACT_BOUNDARY_MARKER`
//! and helpers — exact marker string, `build_compact_boundary_message`
//! envelope shape, `is_compact_boundary_message` predicate
//! across role/content variants, `extract_compact_boundary_metadata`
//! JSON round-trip, and the `Parts` content branch.
//!
//! Sprint 171 of the verification effort. Sprint 92
//! covered round-trip; this file pins the corner-case
//! predicate boundaries (Parts content, role check,
//! malformed JSON, multi-line message body).

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::compaction::{
    build_compact_boundary_message, extract_compact_boundary_metadata, is_compact_boundary_message,
    COMPACT_BOUNDARY_MARKER,
};
use openclaudia::proxy::{ChatMessage, ContentPart, MessageContent};

// ───────────────────────────────────────────────────────────────────────────
// Section A — The marker constant
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn marker_is_documented_namespaced_string() {
    // PINS WIRE: marker is "[openclaudia:compact_boundary]".
    assert_eq!(COMPACT_BOUNDARY_MARKER, "[openclaudia:compact_boundary]");
}

#[test]
fn marker_starts_with_bracket_namespace_prefix() {
    // PINS DOC: marker starts with "[openclaudia:" so it
    // can't be confused with user-emitted text.
    assert!(COMPACT_BOUNDARY_MARKER.starts_with("[openclaudia:"));
    assert!(COMPACT_BOUNDARY_MARKER.ends_with(']'));
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — build_compact_boundary_message envelope
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn build_message_uses_assistant_evidence_role() {
    let msg = build_compact_boundary_message(100, 5, Vec::new(), None);
    assert_eq!(msg.role, "assistant");
}

#[test]
fn build_message_uses_text_content_variant() {
    let msg = build_compact_boundary_message(100, 5, Vec::new(), None);
    assert!(matches!(msg.content, MessageContent::Text(_)));
}

#[test]
fn build_message_has_no_name_tool_calls_or_tool_call_id() {
    let msg = build_compact_boundary_message(100, 5, Vec::new(), None);
    assert!(msg.name.is_none());
    assert!(msg.tool_calls.is_none());
    assert!(msg.tool_call_id.is_none());
}

#[test]
fn build_message_content_starts_with_marker() {
    let msg = build_compact_boundary_message(50, 2, Vec::new(), None);
    match &msg.content {
        MessageContent::Text(t) => assert!(
            t.starts_with(COMPACT_BOUNDARY_MARKER),
            "content MUST start with marker; got {t:?}"
        ),
        MessageContent::Parts(_) => panic!("MUST be Text variant"),
    }
}

#[test]
fn build_message_content_includes_messages_summarized_in_human_text() {
    // PINS HUMAN: the trailing line is human-readable.
    let msg = build_compact_boundary_message(50, 42, Vec::new(), None);
    let MessageContent::Text(t) = &msg.content else {
        panic!()
    };
    assert!(
        t.contains("42 earlier message"),
        "MUST mention 42 in human line; got {t:?}"
    );
    assert!(t.contains("Conversation compacted"));
}

#[test]
fn build_message_json_metadata_is_well_formed() {
    // PINS WIRE: the metadata line is parseable JSON.
    let msg = build_compact_boundary_message(12345, 7, vec![1, 2, 3], Some("sess-171".to_string()));
    let extracted = extract_compact_boundary_metadata(&msg).expect("ok");
    assert_eq!(extracted.pre_tokens, 12345);
    assert_eq!(extracted.messages_summarized, 7);
    assert_eq!(extracted.archive_ids, vec![1, 2, 3]);
    assert_eq!(extracted.archive_session_id.as_deref(), Some("sess-171"));
    assert_eq!(extracted.trigger, "auto");
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — is_compact_boundary_message predicate
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn is_compact_boundary_recognises_marker_in_assistant_text_content() {
    let msg = build_compact_boundary_message(100, 1, Vec::new(), None);
    assert!(is_compact_boundary_message(&msg));
}

#[test]
fn is_compact_boundary_rejects_user_role_with_same_text() {
    // PINS ROLE: only assistant historical-evidence messages qualify.
    let mut msg = build_compact_boundary_message(100, 1, Vec::new(), None);
    msg.role = "user".to_string();
    assert!(
        !is_compact_boundary_message(&msg),
        "user role MUST NOT be recognised as compact boundary"
    );
}

#[test]
fn is_compact_boundary_accepts_legacy_system_role_for_compatibility() {
    let mut msg = build_compact_boundary_message(100, 1, Vec::new(), None);
    msg.role = "system".to_string();
    assert!(is_compact_boundary_message(&msg));
}

#[test]
fn is_compact_boundary_rejects_assistant_text_not_starting_with_marker() {
    let msg = ChatMessage {
        role: "assistant".to_string(),
        content: MessageContent::Text("not a boundary message".to_string()),
        name: None,
        tool_calls: None,
        tool_call_id: None,
        extra: std::collections::HashMap::new(),
    };
    assert!(!is_compact_boundary_message(&msg));
}

#[test]
fn is_compact_boundary_rejects_marker_embedded_mid_text() {
    // PINS PREFIX: marker MUST be at start, not embedded.
    let msg = ChatMessage {
        role: "assistant".to_string(),
        content: MessageContent::Text(format!("prefix {COMPACT_BOUNDARY_MARKER} body")),
        name: None,
        tool_calls: None,
        tool_call_id: None,
        extra: std::collections::HashMap::new(),
    };
    assert!(
        !is_compact_boundary_message(&msg),
        "embedded marker MUST NOT match (starts_with required)"
    );
}

#[test]
fn is_compact_boundary_recognises_parts_content_with_marker_text() {
    // PINS PARTS BRANCH: Parts variant with a text part
    // starting with the marker also qualifies.
    let msg = ChatMessage {
        role: "assistant".to_string(),
        content: MessageContent::Parts(vec![ContentPart {
            content_type: "text".to_string(),
            text: Some(format!("{COMPACT_BOUNDARY_MARKER} {{}}")),
            image_url: None,
        }]),
        name: None,
        tool_calls: None,
        tool_call_id: None,
        extra: std::collections::HashMap::new(),
    };
    assert!(is_compact_boundary_message(&msg));
}

#[test]
fn is_compact_boundary_recognises_parts_with_marker_in_any_text_part() {
    // PINS: .any() — marker text in ANY part qualifies.
    let msg = ChatMessage {
        role: "assistant".to_string(),
        content: MessageContent::Parts(vec![
            ContentPart {
                content_type: "text".to_string(),
                text: Some("not a marker".to_string()),
                image_url: None,
            },
            ContentPart {
                content_type: "text".to_string(),
                text: Some(format!("{COMPACT_BOUNDARY_MARKER} {{}}")),
                image_url: None,
            },
        ]),
        name: None,
        tool_calls: None,
        tool_call_id: None,
        extra: std::collections::HashMap::new(),
    };
    assert!(is_compact_boundary_message(&msg));
}

#[test]
fn is_compact_boundary_rejects_parts_with_no_text_at_all() {
    let msg = ChatMessage {
        role: "system".to_string(),
        content: MessageContent::Parts(vec![ContentPart {
            content_type: "image_url".to_string(),
            text: None,
            image_url: Some(serde_json::json!({"url": "x"})),
        }]),
        name: None,
        tool_calls: None,
        tool_call_id: None,
        extra: std::collections::HashMap::new(),
    };
    assert!(!is_compact_boundary_message(&msg));
}

#[test]
fn is_compact_boundary_rejects_empty_parts_array() {
    let msg = ChatMessage {
        role: "system".to_string(),
        content: MessageContent::Parts(Vec::new()),
        name: None,
        tool_calls: None,
        tool_call_id: None,
        extra: std::collections::HashMap::new(),
    };
    assert!(!is_compact_boundary_message(&msg));
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — extract_compact_boundary_metadata
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn extract_returns_none_for_non_boundary_message() {
    let msg = ChatMessage {
        role: "user".to_string(),
        content: MessageContent::Text("nothing".to_string()),
        name: None,
        tool_calls: None,
        tool_call_id: None,
        extra: std::collections::HashMap::new(),
    };
    assert!(extract_compact_boundary_metadata(&msg).is_none());
}

#[test]
fn extract_returns_none_when_marker_present_but_json_invalid() {
    let msg = ChatMessage {
        role: "system".to_string(),
        content: MessageContent::Text(format!(
            "{COMPACT_BOUNDARY_MARKER} not_valid_json_here\nbody"
        )),
        name: None,
        tool_calls: None,
        tool_call_id: None,
        extra: std::collections::HashMap::new(),
    };
    assert!(
        extract_compact_boundary_metadata(&msg).is_none(),
        "malformed JSON MUST surface as None"
    );
}

#[test]
fn extract_returns_metadata_from_parts_content_branch() {
    // PINS PARTS BRANCH: extract walks Parts too.
    let metadata_json = r#"{"trigger":"manual","pre_tokens":999,"messages_summarized":3,"archive_ids":[],"archive_session_id":null}"#;
    let msg = ChatMessage {
        role: "assistant".to_string(),
        content: MessageContent::Parts(vec![ContentPart {
            content_type: "text".to_string(),
            text: Some(format!("{COMPACT_BOUNDARY_MARKER} {metadata_json}\nbody")),
            image_url: None,
        }]),
        name: None,
        tool_calls: None,
        tool_call_id: None,
        extra: std::collections::HashMap::new(),
    };
    let m = extract_compact_boundary_metadata(&msg).expect("ok");
    assert_eq!(m.trigger, "manual");
    assert_eq!(m.pre_tokens, 999);
    assert_eq!(m.messages_summarized, 3);
}

#[test]
fn extract_picks_first_line_only_ignoring_body() {
    // PINS DOC: only first line carries the JSON. Subsequent
    // lines are human-readable.
    let msg = build_compact_boundary_message(100, 5, vec![10, 20], Some("xyz".to_string()));
    let m = extract_compact_boundary_metadata(&msg).expect("ok");
    assert_eq!(m.pre_tokens, 100);
    assert_eq!(m.archive_ids, vec![10, 20]);
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — Round-trip across construct/predicate/extract
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn build_then_is_then_extract_full_round_trip() {
    let original_pre = 54321_usize;
    let original_summarized = 17_usize;
    let original_ids = vec![100_i64, 200_i64];
    let original_session = Some("session-171-roundtrip".to_string());

    let msg = build_compact_boundary_message(
        original_pre,
        original_summarized,
        original_ids.clone(),
        original_session.clone(),
    );
    // Predicate recognises it.
    assert!(is_compact_boundary_message(&msg));
    // Extract returns the metadata.
    let extracted = extract_compact_boundary_metadata(&msg).expect("ok");
    assert_eq!(extracted.pre_tokens, original_pre);
    assert_eq!(extracted.messages_summarized, original_summarized);
    assert_eq!(extracted.archive_ids, original_ids);
    assert_eq!(extracted.archive_session_id, original_session);
}

#[test]
fn build_with_zero_pre_tokens_round_trips() {
    let msg = build_compact_boundary_message(0, 0, Vec::new(), None);
    assert!(is_compact_boundary_message(&msg));
    let m = extract_compact_boundary_metadata(&msg).expect("ok");
    assert_eq!(m.pre_tokens, 0);
    assert_eq!(m.messages_summarized, 0);
}

#[test]
fn build_with_huge_pre_tokens_does_not_truncate_or_panic() {
    let msg = build_compact_boundary_message(usize::MAX, usize::MAX, Vec::new(), None);
    assert!(is_compact_boundary_message(&msg));
    let m = extract_compact_boundary_metadata(&msg).expect("ok");
    assert_eq!(m.pre_tokens, usize::MAX);
    assert_eq!(m.messages_summarized, usize::MAX);
}
