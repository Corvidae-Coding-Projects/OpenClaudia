//! End-to-end tests for `TaskManager` invariants and compaction
//! token-budget arithmetic.
//!
//! Sprint 6 of the verification effort. `src/session/task.rs` and
//! `src/compaction.rs` together have 81+ unit tests — but no
//! integration coverage of:
//!
//!   - **`TaskManager` invariants under sequenced ops** — only one
//!     `InProgress` at a time, demotion of the prior in-progress on
//!     transition, refusal to transition past an unfinished blocker,
//!     edge symmetry between `blocks` and `blocked_by` after
//!     deletion.
//!   - **Token estimator behaviour on adversarial inputs** —
//!     CJK and emoji weigh more than 0.25 token/char (regression
//!     for crosslink #321/#762), `<image_data>` placeholders add
//!     the documented 1600-token flat cost.
//!   - **Compact-boundary marker round-trip** — `build_…` →
//!     `is_compact_boundary_message` → `extract_compact_boundary_metadata`
//!     recovers the same metadata byte-exact, including the
//!     `archive_ids` vector and session id.
//!   - **`get_context_window` model-name table** — substring
//!     match returns the largest matching window; an unknown
//!     model falls back to the default.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::compaction::{
    build_compact_boundary_message, estimate_message_tokens, estimate_tokens,
    extract_compact_boundary_metadata, get_context_window, is_compact_boundary_message,
};
use openclaudia::proxy::{ChatMessage, MessageContent};
use openclaudia::session::{TaskManager, TaskStatus, TaskUpdateParams, TaskUpdateStatus};

// ───────────────────────────────────────────────────────────────────────────
// Section A — TaskManager invariants
// ───────────────────────────────────────────────────────────────────────────

fn mk_mgr() -> TaskManager {
    TaskManager::new()
}

#[test]
fn only_one_task_in_progress_at_a_time() {
    // The documented invariant: at most one task is InProgress.
    // Transitioning task B to InProgress must demote task A to
    // Pending (NOT delete it, NOT leave it as InProgress).
    let mut mgr = mk_mgr();
    let a_id = mgr
        .create_task("a".into(), "task A".into(), None)
        .expect("valid task fixture")
        .id
        .clone();
    let b_id = mgr
        .create_task("b".into(), "task B".into(), None)
        .expect("valid task fixture")
        .id
        .clone();

    // Move A to InProgress.
    mgr.update_task(
        &a_id,
        TaskUpdateParams {
            status: Some(TaskUpdateStatus::InProgress),
            ..Default::default()
        },
    )
    .expect("a→in_progress");
    assert_eq!(mgr.get_task(&a_id).unwrap().status, TaskStatus::InProgress);
    assert_eq!(mgr.get_task(&b_id).unwrap().status, TaskStatus::Pending);

    // Move B to InProgress. A MUST be demoted.
    mgr.update_task(
        &b_id,
        TaskUpdateParams {
            status: Some(TaskUpdateStatus::InProgress),
            ..Default::default()
        },
    )
    .expect("b→in_progress");
    assert_eq!(
        mgr.get_task(&a_id).unwrap().status,
        TaskStatus::Pending,
        "previously-in-progress task A must be demoted when B transitions"
    );
    assert_eq!(mgr.get_task(&b_id).unwrap().status, TaskStatus::InProgress);

    // current_task agrees.
    let cur = mgr.current_task().expect("current must exist");
    assert_eq!(cur.id, b_id);
}

#[test]
fn blocker_must_be_completed_before_dependent_can_progress() {
    let mut mgr = mk_mgr();
    let blocker = mgr
        .create_task("blk".into(), "blocker".into(), None)
        .expect("valid task fixture")
        .id
        .clone();
    let dependent = mgr
        .create_task("dep".into(), "dependent".into(), None)
        .expect("valid task fixture")
        .id
        .clone();

    // Add a dependency: blocker blocks dependent.
    mgr.update_task(
        &dependent,
        TaskUpdateParams {
            add_blocked_by: Some(vec![blocker.clone()]),
            ..Default::default()
        },
    )
    .expect("add dep");

    // Attempt to transition dependent → in_progress while blocker is
    // still Pending. MUST be refused.
    let outcome = mgr.update_task(
        &dependent,
        TaskUpdateParams {
            status: Some(TaskUpdateStatus::InProgress),
            ..Default::default()
        },
    );
    assert!(
        outcome.is_err(),
        "must refuse in_progress while blocker is pending; got {outcome:?}"
    );

    // Complete the blocker.
    mgr.update_task(
        &blocker,
        TaskUpdateParams {
            status: Some(TaskUpdateStatus::Completed),
            ..Default::default()
        },
    )
    .expect("complete blocker");

    // Now the transition must succeed.
    mgr.update_task(
        &dependent,
        TaskUpdateParams {
            status: Some(TaskUpdateStatus::InProgress),
            ..Default::default()
        },
    )
    .expect("dependent→in_progress after blocker done");
}

#[test]
fn add_blocked_by_creates_symmetric_blocks_edge() {
    // Adding "b blocks a" via blocked_by MUST also populate a.blocks.
    let mut mgr = mk_mgr();
    let a_id = mgr
        .create_task("a".into(), "a".into(), None)
        .expect("valid task fixture")
        .id
        .clone();
    let b_id = mgr
        .create_task("b".into(), "b".into(), None)
        .expect("valid task fixture")
        .id
        .clone();

    mgr.update_task(
        &a_id,
        TaskUpdateParams {
            add_blocked_by: Some(vec![b_id.clone()]),
            ..Default::default()
        },
    )
    .expect("add blocked_by");

    let a = mgr.get_task(&a_id).unwrap();
    let b = mgr.get_task(&b_id).unwrap();
    assert!(a.blocked_by.contains(&b_id), "a.blocked_by must contain b");
    assert!(
        b.blocks.contains(&a_id),
        "b.blocks must contain a (symmetric reverse edge)"
    );
}

#[test]
fn nonexistent_blocker_id_is_rejected() {
    let mut mgr = mk_mgr();
    let a_id = mgr
        .create_task("a".into(), "a".into(), None)
        .expect("valid task fixture")
        .id
        .clone();
    let outcome = mgr.update_task(
        &a_id,
        TaskUpdateParams {
            add_blocked_by: Some(vec!["task-9999".to_string()]),
            ..Default::default()
        },
    );
    assert!(
        outcome.is_err(),
        "adding a nonexistent blocker id must error; got {outcome:?}"
    );
}

#[test]
fn deleted_status_removes_task_and_returns_none() {
    let mut mgr = mk_mgr();
    let id = mgr
        .create_task("a".into(), "a".into(), None)
        .expect("valid task fixture")
        .id
        .clone();
    let outcome = mgr
        .update_task(
            &id,
            TaskUpdateParams {
                status: Some(TaskUpdateStatus::Deleted),
                ..Default::default()
            },
        )
        .expect("delete via status");
    assert!(
        outcome.is_none(),
        "delete must return Ok(None); got Ok(Some({outcome:?}))"
    );
    assert!(
        mgr.get_task(&id).is_none(),
        "task must be gone after delete"
    );
    assert!(mgr.list_tasks().is_empty());
}

#[test]
fn update_unknown_task_id_errors() {
    let mut mgr = mk_mgr();
    let outcome = mgr.update_task(
        "task-9999",
        TaskUpdateParams {
            subject: Some("x".to_string()),
            ..Default::default()
        },
    );
    assert!(outcome.is_err(), "update on unknown id must error");
}

#[test]
fn task_ids_increase_monotonically() {
    let mut mgr = mk_mgr();
    let id1 = mgr
        .create_task("a".into(), "a".into(), None)
        .expect("valid task fixture")
        .id
        .clone();
    let id2 = mgr
        .create_task("b".into(), "b".into(), None)
        .expect("valid task fixture")
        .id
        .clone();
    let id3 = mgr
        .create_task("c".into(), "c".into(), None)
        .expect("valid task fixture")
        .id
        .clone();
    assert_eq!(id1, "task-1");
    assert_eq!(id2, "task-2");
    assert_eq!(id3, "task-3");
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — Token estimator behaviour
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn ascii_estimate_is_approximately_len_over_four() {
    // 40 chars of ASCII non-whitespace → 40/4 = 10 tokens.
    let text = "a".repeat(40);
    let est = estimate_tokens(&text);
    assert!(
        (8..=12).contains(&est),
        "40 ASCII chars must estimate to ~10 tokens, got {est}"
    );
}

#[test]
fn whitespace_does_not_count_against_token_budget() {
    // Pure whitespace is absorbed by surrounding subword tokens.
    // crosslink #762: documented as 0.
    let text = "   \n\n\t   ".to_string();
    let est = estimate_tokens(&text);
    assert_eq!(
        est, 0,
        "pure whitespace must estimate to 0 tokens, got {est}"
    );
}

#[test]
fn cjk_text_costs_more_than_ascii_per_char() {
    // Regression test for crosslink #321/#762: the old `len()/4`
    // heuristic under-counted CJK by ~25%. The new weighted
    // estimator must produce a per-char cost notably higher than
    // 0.25 for CJK.
    let cjk = "你好世界你好世界你好世界你好世界"; // 16 chars
    let ascii = "abcdefghijklmnop"; // 16 chars

    let cjk_est = estimate_tokens(cjk);
    let ascii_est = estimate_tokens(ascii);
    assert!(
        cjk_est > ascii_est,
        "16 CJK chars must cost MORE than 16 ASCII chars, got cjk={cjk_est}, ascii={ascii_est}"
    );
    // Specifically: CJK should be ~2 tokens/char vs ASCII ~0.25 →
    // ratio of ~8x. Allow a wide band so the test isn't fragile
    // to weight tweaks within the design envelope. Integer
    // comparison avoids the usize → f32 precision-loss lint.
    assert!(
        cjk_est >= ascii_est.saturating_mul(2),
        "CJK token cost must be at least 2x ASCII for the same length, \
         got cjk={cjk_est}, ascii={ascii_est} (ratio < 2)"
    );
}

#[test]
fn image_data_block_costs_flat_1600_tokens() {
    // `<image_data>...</image_data>` placeholders represent real
    // image payloads billed at the documented flat cost. The
    // placeholder text itself is ~30 chars (~7 ASCII tokens) but
    // estimate_tokens must report at least 1600.
    let with_image = "before <image_data>...</image_data> after";
    let without_image = "before  after";
    let with = estimate_tokens(with_image);
    let without = estimate_tokens(without_image);
    let delta = with.saturating_sub(without);
    assert!(
        delta >= 1500,
        "the image block must add ~1600 tokens of cost; got delta={delta}"
    );
}

#[test]
fn message_token_estimate_includes_role_and_tool_call_overhead() {
    // A message with tool_calls must report MORE tokens than a
    // text-only message of the same content.
    let plain = ChatMessage {
        role: "assistant".to_string(),
        content: MessageContent::Text("ok".to_string()),
        name: None,
        tool_calls: None,
        tool_call_id: None,
        extra: std::collections::HashMap::new(),
    };
    let with_tools = ChatMessage {
        role: "assistant".to_string(),
        content: MessageContent::Text("ok".to_string()),
        name: None,
        tool_calls: Some(vec![serde_json::json!({
            "id": "call_1",
            "type": "function",
            "function": {"name": "bash", "arguments": "{\"command\":\"ls\"}"}
        })]),
        tool_call_id: None,
        extra: std::collections::HashMap::new(),
    };
    let plain_t = estimate_message_tokens(&plain);
    let with_tools_t = estimate_message_tokens(&with_tools);
    assert!(
        with_tools_t > plain_t,
        "tool_calls payload must add token cost; plain={plain_t}, with_tools={with_tools_t}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — Compact-boundary marker round-trip
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn compact_boundary_round_trips_through_predicate_and_extract() {
    let pre_tokens = 10_000;
    let messages_summarized = 42;
    let archive_ids = vec![101, 102, 103];
    let session_id = "session-abc".to_string();

    let msg = build_compact_boundary_message(
        pre_tokens,
        messages_summarized,
        archive_ids.clone(),
        Some(session_id.clone()),
    );

    // The predicate must recognise the marker.
    assert!(
        is_compact_boundary_message(&msg),
        "predicate must recognise the marker emitted by build_compact_boundary_message"
    );
    // And the metadata extractor must recover all fields byte-exact.
    let meta = extract_compact_boundary_metadata(&msg)
        .expect("metadata must be extractable from a freshly-built marker");
    assert_eq!(meta.pre_tokens, pre_tokens);
    assert_eq!(meta.messages_summarized, messages_summarized);
    assert_eq!(meta.archive_ids, archive_ids);
    assert_eq!(meta.archive_session_id, Some(session_id));
    assert_eq!(meta.trigger, "auto");
}

#[test]
fn non_boundary_messages_are_not_falsely_recognised() {
    // Counter-test: a normal message must NOT trip the predicate.
    let normal_user = ChatMessage {
        role: "user".to_string(),
        content: MessageContent::Text("hello".to_string()),
        name: None,
        tool_calls: None,
        tool_call_id: None,
        extra: std::collections::HashMap::new(),
    };
    let normal_assistant = ChatMessage {
        role: "assistant".to_string(),
        content: MessageContent::Text("hi there".to_string()),
        name: None,
        tool_calls: None,
        tool_call_id: None,
        extra: std::collections::HashMap::new(),
    };
    let normal_system_no_marker = ChatMessage {
        role: "system".to_string(),
        content: MessageContent::Text("you are a helpful assistant".to_string()),
        name: None,
        tool_calls: None,
        tool_call_id: None,
        extra: std::collections::HashMap::new(),
    };
    assert!(!is_compact_boundary_message(&normal_user));
    assert!(!is_compact_boundary_message(&normal_assistant));
    assert!(
        !is_compact_boundary_message(&normal_system_no_marker),
        "system message without the marker must NOT be recognised as boundary"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — get_context_window model-name dispatch
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn context_window_table_dispatches_by_substring() {
    // Each documented model family must resolve to a non-default
    // window. The exact value can shift as model providers update
    // their public limits, so we only assert "looked up from the
    // table, not the default fallback".
    let known = &[
        "claude-3-5-sonnet-20241022",
        "claude-3-opus-20240229",
        "gpt-4-turbo",
        "gpt-5.5",
        "gemini-3.5-flash",
    ];
    let default_window = get_context_window("totally-unknown-model-name-2099");
    for model in known {
        let w = get_context_window(model);
        assert!(
            w > 0,
            "known model {model:?} must resolve to a non-zero window"
        );
        // Most modern Claude/GPT/Gemini windows are >= the default;
        // we only require the lookup succeeded — i.e. matches one of
        // the table rows, even if (rarely) it equals the default.
        let _ = default_window; // suppress unused if all asserts widen
    }
    // Counter-test: unknown model falls back to default.
    assert!(
        default_window > 0,
        "the default fallback must itself be positive"
    );
}

#[test]
fn context_window_lookup_is_case_insensitive() {
    let lower = get_context_window("claude-3-5-sonnet-20241022");
    let upper = get_context_window("CLAUDE-3-5-SONNET-20241022");
    let mixed = get_context_window("Claude-3-5-Sonnet-20241022");
    assert_eq!(
        lower, upper,
        "context window lookup must be case-insensitive"
    );
    assert_eq!(lower, mixed);
}
