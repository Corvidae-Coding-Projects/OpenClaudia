//! End-to-end tests for `AutoCompactor` policy semantics.
//!
//! Sprint 44 of the verification effort.
//!
//! Covers the pure-predicate path (`should_compact`) under both
//! `AutoCompactPolicy::Auto` (defer to the analyzer's
//! preserve-recent window + 85%-threshold rule) and
//! `AutoCompactPolicy::AlwaysOverBudget` (strict
//! at-or-above-cap trigger). The `auto_compact` / `auto_microcompact`
//! async paths are exercised via `should_compact` since they
//! gate on the same predicate; covering the predicate
//! exhaustively is the cheaper + more meaningful regression
//! guard.

#![allow(clippy::missing_panics_doc)]
#![allow(clippy::expect_used)]
#![allow(clippy::unwrap_used)]

use openclaudia::compaction::{CompactionConfig, ContextCompactor, RequestTokenMeasurement};
use openclaudia::proxy::{ChatCompletionRequest, ChatMessage, MessageContent};
use openclaudia::services::{AutoCompactPolicy, AutoCompactor};

// ───────────────────────────────────────────────────────────────────────────
// Helpers
// ───────────────────────────────────────────────────────────────────────────

/// Build a request with N messages of `chars` characters each.
/// The estimator counts tokens at roughly 4 chars/token, so the
/// request's estimated token count is approximately
/// `(N * chars) / 4`.
fn make_request(n_messages: usize, chars_per_message: usize) -> ChatCompletionRequest {
    let body = "x".repeat(chars_per_message);
    let messages = (0..n_messages)
        .map(|_| ChatMessage {
            role: "user".to_string(),
            content: MessageContent::Text(body.clone()),
            name: None,
            tool_calls: None,
            tool_call_id: None,
            extra: std::collections::HashMap::new(),
        })
        .collect();
    ChatCompletionRequest {
        model: "test-model".to_string(),
        messages,
        temperature: None,
        max_tokens: None,
        stream: None,
        tools: None,
        tool_choice: None,
        extra: std::collections::HashMap::default(),
    }
}

/// Build a compactor with explicit `max_context_tokens` for
/// predictable threshold math.
fn compactor_with_cap(max_tokens: usize) -> ContextCompactor {
    let config = CompactionConfig {
        max_context_tokens: max_tokens,
        // Everything else at default.
        ..CompactionConfig::default()
    };
    ContextCompactor::new(config)
}

fn measured(request: &ChatCompletionRequest, tokens: usize) -> RequestTokenMeasurement {
    RequestTokenMeasurement::for_request(request, tokens)
}

// ───────────────────────────────────────────────────────────────────────────
// Section A — AutoCompactor::auto + ::new
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn auto_constructor_yields_auto_policy() {
    let compactor = compactor_with_cap(10_000);
    let auto = AutoCompactor::auto(compactor);
    // We can't read `.policy` directly (no accessor), but
    // we can verify behaviour: under Auto, a small request
    // MUST NOT compact.
    let small_req = make_request(2, 100); // tiny
    assert!(
        !auto.should_compact(&small_req, None),
        "tiny request under Auto MUST NOT trigger compaction"
    );
}

#[test]
fn compactor_accessor_returns_underlying_compactor() {
    let compactor = compactor_with_cap(50_000);
    let auto = AutoCompactor::auto(compactor);
    // The accessor returns a reference — same max_context_tokens.
    let analysis = auto
        .compactor()
        .analyze_with_measurement(&make_request(1, 10), None);
    assert_eq!(analysis.max_tokens, 50_000);
}

// ───────────────────────────────────────────────────────────────────────────
// Section B — AutoCompactPolicy::Auto — analyzer rule
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn auto_policy_does_not_compact_when_under_threshold() {
    let compactor = compactor_with_cap(100_000);
    let auto = AutoCompactor::new(compactor, AutoCompactPolicy::Auto);
    // Tiny request → under any reasonable threshold.
    let req = make_request(2, 100);
    assert!(!auto.should_compact(&req, None));
}

#[test]
fn auto_policy_compacts_when_actual_tokens_exceed_threshold() {
    // With max=10_000, threshold=0.85, RESPONSE_RESERVE=4096:
    //   threshold_tokens = 8500
    //   effective = 8500 - 4096 = 4404
    // So any actual_input_tokens > 4404 must trigger.
    let compactor = compactor_with_cap(10_000);
    let auto = AutoCompactor::new(compactor, AutoCompactPolicy::Auto);
    let req = make_request(1, 10);
    // Pass actual = 5000 (> 4404) → MUST trigger.
    assert!(
        auto.should_compact(&req, Some(measured(&req, 5000))),
        "actual=5000 > effective_threshold=4404 MUST trigger"
    );
    // Pass actual = 4404 (exactly at threshold) → MUST NOT
    // trigger (strict > comparison).
    assert!(
        !auto.should_compact(&req, Some(measured(&req, 4404))),
        "actual=4404 == effective_threshold MUST NOT trigger (strict >)"
    );
}

#[test]
fn auto_policy_uses_estimator_when_no_actual_hint_provided() {
    // Construct a request whose ESTIMATED tokens exceed the
    // effective threshold. With max=10_000, effective=4404,
    // estimator ~4 chars/token → need ~17,616 chars total.
    let compactor = compactor_with_cap(10_000);
    let auto = AutoCompactor::new(compactor, AutoCompactPolicy::Auto);
    let big_req = make_request(20, 2000); // 40_000 chars ~ 10_000 tokens
    assert!(
        auto.should_compact(&big_req, None),
        "big estimated-token request MUST trigger compaction under Auto"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section C — AutoCompactPolicy::AlwaysOverBudget — strict cap
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn always_over_budget_triggers_at_or_above_max_context() {
    let compactor = compactor_with_cap(10_000);
    let auto = AutoCompactor::new(compactor, AutoCompactPolicy::AlwaysOverBudget);
    let req = make_request(1, 10);
    // Under AlwaysOverBudget, only actual >= max triggers.
    // 9999 → NO trigger.
    assert!(
        !auto.should_compact(&req, Some(measured(&req, 9999))),
        "actual=9999 < max=10000 MUST NOT trigger under AlwaysOverBudget"
    );
    // 10000 → trigger (>= cap).
    assert!(
        auto.should_compact(&req, Some(measured(&req, 10_000))),
        "actual==max MUST trigger under AlwaysOverBudget"
    );
    // 15000 → trigger.
    assert!(auto.should_compact(&req, Some(measured(&req, 15_000))));
}

#[test]
fn always_over_budget_does_not_trigger_below_max_even_above_auto_threshold() {
    // Auto would trigger at >4404 (10k * 0.85 - 4096).
    // AlwaysOverBudget requires >=10000.
    // 7000 is above the Auto threshold but well below the
    // AlwaysOverBudget cap.
    let compactor = compactor_with_cap(10_000);
    let always = AutoCompactor::new(compactor.clone(), AutoCompactPolicy::AlwaysOverBudget);
    let auto = AutoCompactor::new(compactor, AutoCompactPolicy::Auto);
    let req = make_request(1, 10);

    // Auto: trigger at 7000.
    assert!(auto.should_compact(&req, Some(measured(&req, 7000))));
    // AlwaysOverBudget: do NOT trigger at 7000.
    assert!(
        !always.should_compact(&req, Some(measured(&req, 7000))),
        "AlwaysOverBudget MUST be STRICTER than Auto — 7000 is above Auto's effective threshold \
         but below AlwaysOverBudget's cap"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section D — Policy default
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn default_policy_is_auto() {
    let default = AutoCompactPolicy::default();
    assert_eq!(default, AutoCompactPolicy::Auto);
}

#[test]
fn policy_enum_equality_distinguishes_variants() {
    assert_ne!(AutoCompactPolicy::Auto, AutoCompactPolicy::AlwaysOverBudget);
    assert_eq!(AutoCompactPolicy::Auto, AutoCompactPolicy::Auto);
    assert_eq!(
        AutoCompactPolicy::AlwaysOverBudget,
        AutoCompactPolicy::AlwaysOverBudget
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Section E — empty / minimal-input edge cases
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn empty_request_never_compacts_under_either_policy() {
    let compactor = compactor_with_cap(10_000);
    let req = ChatCompletionRequest {
        model: "test-model".to_string(),
        messages: vec![],
        temperature: None,
        max_tokens: None,
        stream: None,
        tools: None,
        tool_choice: None,
        extra: std::collections::HashMap::default(),
    };
    let auto = AutoCompactor::new(compactor.clone(), AutoCompactPolicy::Auto);
    let always = AutoCompactor::new(compactor, AutoCompactPolicy::AlwaysOverBudget);
    assert!(
        !auto.should_compact(&req, None),
        "empty request under Auto MUST NOT compact"
    );
    assert!(
        !always.should_compact(&req, None),
        "empty request under AlwaysOverBudget MUST NOT compact"
    );
}

#[test]
fn actual_hint_zero_treated_as_zero_tokens() {
    // actual=Some(0) is the legitimate "fresh session, no
    // prior turn" case — MUST NOT trigger.
    let compactor = compactor_with_cap(10_000);
    let auto = AutoCompactor::new(compactor.clone(), AutoCompactPolicy::Auto);
    let always = AutoCompactor::new(compactor, AutoCompactPolicy::AlwaysOverBudget);
    let req = make_request(1, 10);
    assert!(!auto.should_compact(&req, Some(measured(&req, 0))));
    assert!(!always.should_compact(&req, Some(measured(&req, 0))));
}

// ───────────────────────────────────────────────────────────────────────────
// Section F — actual hint overrides estimator
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn actual_hint_overrides_estimator_when_provided() {
    // A small request whose ESTIMATE would be tiny, but with
    // an explicit actual count above the threshold, MUST
    // still trigger compaction.
    let compactor = compactor_with_cap(10_000);
    let auto = AutoCompactor::new(compactor, AutoCompactPolicy::Auto);
    let small_req = make_request(1, 10); // estimated ~3 tokens
                                         // Without hint: no compaction.
    assert!(!auto.should_compact(&small_req, None));
    // With hint above threshold: MUST compact.
    assert!(
        auto.should_compact(&small_req, Some(measured(&small_req, 9000))),
        "actual hint MUST override estimator"
    );
}

#[test]
fn estimator_drives_decision_when_hint_is_none_and_no_overrides() {
    let compactor = compactor_with_cap(10_000);
    let auto = AutoCompactor::new(compactor, AutoCompactPolicy::Auto);
    // A request guaranteed to exceed 4404 effective tokens
    // by estimator alone: 30 messages * 2000 chars = 60k chars
    // -> ~15k tokens.
    let big = make_request(30, 2000);
    assert!(
        auto.should_compact(&big, None),
        "estimator alone MUST trigger compaction on a sufficiently large request"
    );
}
