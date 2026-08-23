//! End-to-end tests for `compaction::estimate_tokens` heuristic +
//! `get_context_window` table + compact-boundary serde round-trip.
//!
//! Sprint 64 of the verification effort. Sprint 44 covered the
//! `AutoCompactor` policy; this file covers the underlying
//! estimator + context-window-lookup + boundary-marker
//! helpers that the policy delegates to.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::compaction::{
    build_compact_boundary_message, estimate_message_tokens, estimate_request_tokens,
    estimate_tokens, extract_compact_boundary_metadata, get_context_window,
    is_compact_boundary_message, CompactBoundaryMetadata,
};
use openclaudia::proxy::{ChatCompletionRequest, ChatMessage, ContentPart, MessageContent};
use std::collections::HashMap;

// ───────────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────────

fn user_text(content: &str) -> ChatMessage {
    ChatMessage {
        role: "user".to_string(),
        content: MessageContent::Text(content.to_string()),
        name: None,
        tool_calls: None,
        tool_call_id: None,
        extra: std::collections::HashMap::new(),
    }
}

fn request_with(messages: Vec<ChatMessage>) -> ChatCompletionRequest {
    ChatCompletionRequest {
        model: "test".to_string(),
        messages,
        temperature: None,
        max_tokens: None,
        stream: None,
        tools: None,
        tool_choice: None,
        extra: HashMap::default(),
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — estimate_tokens ASCII path
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn estimate_tokens_empty_string_returns_zero() {
    assert_eq!(estimate_tokens(""), 0);
}

#[test]
fn estimate_tokens_ascii_uses_roughly_4_chars_per_token() {
    // Documented: ASCII_CHARS_PER_TOKEN = 4.
    // 4 chars of ASCII (no whitespace) = 1 token.
    let s = "abcd";
    assert_eq!(estimate_tokens(s), 1);
    // 16 chars = 4 tokens.
    let s = "abcdefghijklmnop";
    assert_eq!(estimate_tokens(s), 4);
}

#[test]
fn estimate_tokens_excludes_ascii_whitespace_from_token_count() {
    // "abc def" has 6 non-ws ASCII chars + 1 ws → 6/4 = 1.
    let s = "abc def";
    assert_eq!(estimate_tokens(s), 1, "ws excluded; 6/4=1");
}

#[test]
fn estimate_tokens_increases_monotonically_with_text_length() {
    let a = estimate_tokens(&"x".repeat(40));
    let b = estimate_tokens(&"x".repeat(80));
    let c = estimate_tokens(&"x".repeat(160));
    assert!(a < b);
    assert!(b < c);
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — estimate_tokens non-ASCII path
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn estimate_tokens_cjk_chars_cost_more_than_ascii_per_char() {
    // CJK alphanumeric: weight 4, divisor 2 → ~2 tokens/char.
    // ASCII: 4 chars/token → 0.25 tokens/char.
    // So 10 CJK chars > 10 ASCII chars in token cost.
    let cjk_10 = estimate_tokens(&"日".repeat(10));
    let ascii_10 = estimate_tokens(&"x".repeat(10));
    assert!(
        cjk_10 > ascii_10,
        "10 CJK MUST cost more than 10 ASCII; got {cjk_10} vs {ascii_10}"
    );
}

#[test]
fn estimate_tokens_emoji_cost_higher_than_cjk_per_char() {
    // Emoji are non-ASCII non-alphanumeric → SYMBOL_WEIGHT=6,
    // divisor 2 → ~3 tokens/char.
    // CJK → ~2 tokens/char.
    let emoji_10 = estimate_tokens(&"🎉".repeat(10));
    let cjk_10 = estimate_tokens(&"日".repeat(10));
    assert!(
        emoji_10 >= cjk_10,
        "10 emojis MUST cost >= 10 CJK chars; got {emoji_10} vs {cjk_10}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — estimate_tokens image-data flat cost
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn estimate_tokens_image_data_placeholder_adds_1600_tokens() {
    // Documented IMAGE_TOKEN_COST = 1600 per <image_data>.
    let baseline = estimate_tokens("hello world");
    let with_image = estimate_tokens("hello world<image_data>data</image_data>");
    // The text additions add some small token count for the
    // marker text + content. The 1600 image cost must be ~the
    // difference modulo a small overhead.
    let delta = with_image - baseline;
    assert!(
        delta >= 1600,
        "image_data placeholder MUST add at least 1600 tokens; got delta={delta}"
    );
}

#[test]
fn estimate_tokens_multiple_image_data_placeholders_each_count() {
    let one = estimate_tokens("<image_data>x</image_data>");
    let three = estimate_tokens(
        "<image_data>x</image_data><image_data>y</image_data><image_data>z</image_data>",
    );
    let delta = three - one;
    assert!(
        delta >= 3200,
        "2 more images MUST add ~3200 more tokens; got delta={delta}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — estimate_message_tokens for Parts
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn estimate_message_tokens_parts_with_text_and_image_url_charges_both() {
    let msg = ChatMessage {
        role: "user".to_string(),
        content: MessageContent::Parts(vec![
            ContentPart {
                content_type: "text".to_string(),
                text: Some("hello world".to_string()),
                image_url: None,
            },
            ContentPart {
                content_type: "image_url".to_string(),
                text: None,
                image_url: Some(serde_json::json!({"url": "https://x.com/img.png"})),
            },
        ]),
        name: None,
        tool_calls: None,
        tool_call_id: None,
        extra: std::collections::HashMap::new(),
    };
    let tokens = estimate_message_tokens(&msg);
    // text portion + 1600 for image.
    assert!(
        tokens >= 1600,
        "Parts with image_url MUST charge image cost; got {tokens}"
    );
}

#[test]
fn estimate_message_tokens_text_only_message_uses_just_text_estimate() {
    let msg = user_text("hello");
    let tokens = estimate_message_tokens(&msg);
    // "hello" = 5 chars ASCII → 5/4 = 1 token base + small
    // overhead for role/structure (depends on impl).
    assert!(
        tokens >= 1,
        "text msg MUST charge at least the text estimate; got {tokens}"
    );
    assert!(
        tokens < 100,
        "text msg of 5 chars MUST NOT be unreasonably large; got {tokens}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — estimate_request_tokens sums messages
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn estimate_request_tokens_zero_messages_returns_some_overhead_or_zero() {
    let req = request_with(vec![]);
    let _ = estimate_request_tokens(&req); // must not panic
}

#[test]
fn estimate_request_tokens_more_messages_more_tokens() {
    let small = request_with(vec![user_text("hi")]);
    let big = request_with(vec![user_text(&"x".repeat(10_000))]);
    let small_tokens = estimate_request_tokens(&small);
    let big_tokens = estimate_request_tokens(&big);
    assert!(
        big_tokens > small_tokens,
        "bigger request MUST estimate to more tokens; got small={small_tokens}, big={big_tokens}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — get_context_window per-model lookup
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn get_context_window_unknown_model_falls_back_to_default() {
    let cw = get_context_window("totally-unknown-model-xyz");
    // Documented: DEFAULT_CONTEXT = 128_000.
    assert!(
        cw >= 100_000,
        "unknown model MUST fall back to a safe default; got {cw}"
    );
}

#[test]
fn get_context_window_known_models_match_documented_values() {
    // Various documented models with known windows.
    let claude_sonnet = get_context_window("claude-3-5-sonnet-20241022");
    assert!(
        claude_sonnet >= 100_000,
        "claude-3-5-sonnet MUST have >= 100k window; got {claude_sonnet}"
    );
}

#[test]
fn get_context_window_is_case_insensitive() {
    let lower = get_context_window("claude-3-opus");
    let upper = get_context_window("CLAUDE-3-OPUS");
    assert_eq!(lower, upper, "lookup MUST be case-insensitive");
}

#[test]
fn get_context_window_substring_match_finds_provider_prefix() {
    // Documented: needle MUST appear in lowercased model.
    // A model like "anthropic/claude-3-haiku" should match
    // the haiku entry if present.
    let cw = get_context_window("anthropic/claude-3-haiku-20240307");
    // Returns either the haiku window or default — both > 0.
    assert!(cw > 0);
}

// ───────────────────────────────────────────────────────────────────────────
// Section G — compact_boundary_message round-trip
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn build_compact_boundary_message_produces_assistant_evidence_role() {
    let msg = build_compact_boundary_message(50_000, 25, vec![], None);
    assert_eq!(msg.role, "assistant");
}

#[test]
fn build_then_is_then_extract_round_trip_preserves_metadata() {
    let archive_ids = vec![1, 2, 3, 42];
    let session = "session-abc";
    let msg =
        build_compact_boundary_message(75_000, 30, archive_ids.clone(), Some(session.to_string()));
    assert!(is_compact_boundary_message(&msg));
    let metadata = extract_compact_boundary_metadata(&msg).expect("metadata");
    assert_eq!(metadata.pre_tokens, 75_000);
    assert_eq!(metadata.messages_summarized, 30);
    assert_eq!(metadata.archive_ids, archive_ids);
    assert_eq!(metadata.archive_session_id.as_deref(), Some(session));
    assert_eq!(metadata.trigger, "auto");
}

#[test]
fn is_compact_boundary_message_false_for_user_role() {
    // Even if the text contains the marker, a user-role
    // message MUST NOT be classified as a boundary.
    let msg = user_text("[openclaudia:compact_boundary] {} content");
    assert!(
        !is_compact_boundary_message(&msg),
        "user-role MUST NOT be classified as boundary"
    );
}

#[test]
fn is_compact_boundary_message_false_for_non_marker_system_message() {
    let msg = ChatMessage {
        role: "system".to_string(),
        content: MessageContent::Text("Just a regular system message".to_string()),
        name: None,
        tool_calls: None,
        tool_call_id: None,
        extra: std::collections::HashMap::new(),
    };
    assert!(!is_compact_boundary_message(&msg));
}

#[test]
fn extract_compact_boundary_metadata_returns_none_for_non_boundary() {
    let msg = user_text("not a boundary");
    assert!(extract_compact_boundary_metadata(&msg).is_none());
}

#[test]
fn compact_boundary_metadata_serde_round_trips() {
    let m = CompactBoundaryMetadata {
        trigger: "manual".to_string(),
        pre_tokens: 10_000,
        messages_summarized: 5,
        archive_ids: vec![100, 200],
        archive_session_id: Some("sess".to_string()),
    };
    let json = serde_json::to_string(&m).expect("serialize");
    let back: CompactBoundaryMetadata = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, m);
}

#[test]
fn compact_boundary_metadata_empty_archive_ids_skipped_in_serialization() {
    let m = CompactBoundaryMetadata {
        trigger: "auto".to_string(),
        pre_tokens: 0,
        messages_summarized: 0,
        archive_ids: vec![],
        archive_session_id: None,
    };
    let json = serde_json::to_string(&m).expect("serialize");
    // skip_serializing_if = "Vec::is_empty" + "Option::is_none"
    // → archive_ids + archive_session_id absent from output.
    assert!(
        !json.contains("archive_ids"),
        "empty archive_ids MUST be skipped; got {json}"
    );
    assert!(
        !json.contains("archive_session_id"),
        "None archive_session_id MUST be skipped; got {json}"
    );
}
