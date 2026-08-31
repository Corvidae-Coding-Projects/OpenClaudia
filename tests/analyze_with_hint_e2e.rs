//! End-to-end tests for request-bound compaction measurements.
//!
//! Provider counts are useful only for the exact request they measured. These
//! tests pin that binding as well as the input/output reserve decision.

#![allow(clippy::missing_panics_doc)]

use openclaudia::compaction::{CompactionConfig, ContextCompactor, RequestTokenMeasurement};
use openclaudia::proxy::{ChatCompletionRequest, ChatMessage, MessageContent};
use std::collections::HashMap;

fn request(content: &str) -> ChatCompletionRequest {
    ChatCompletionRequest {
        model: "test".to_string(),
        messages: vec![ChatMessage {
            role: "user".to_string(),
            content: MessageContent::Text(content.to_string()),
            name: None,
            tool_calls: None,
            tool_call_id: None,
            extra: HashMap::new(),
        }],
        temperature: None,
        max_tokens: None,
        stream: None,
        tools: None,
        tool_choice: None,
        extra: HashMap::new(),
    }
}

fn compactor(max_context_tokens: usize, threshold: f32) -> ContextCompactor {
    ContextCompactor::new(CompactionConfig {
        max_context_tokens,
        threshold,
        ..CompactionConfig::default()
    })
}

fn measured(request: &ChatCompletionRequest, tokens: usize) -> RequestTokenMeasurement {
    RequestTokenMeasurement::for_request(request, tokens)
}

#[test]
fn exact_request_measurement_overrides_estimate() {
    let request = request("hi");
    let analysis = compactor(100_000, 0.9)
        .analyze_with_measurement(&request, Some(measured(&request, 99_999)));
    assert_eq!(analysis.current_tokens, 99_999);
}

#[test]
fn measurement_for_another_request_is_rejected() {
    let original = request("first request");
    let changed = request("a different current request");
    let stale = RequestTokenMeasurement::for_request(&original, 99_999);
    let compactor = compactor(100_000, 0.9);
    let estimated = compactor.analyze(&changed);
    let analyzed = compactor.analyze_with_measurement(&changed, Some(stale));
    assert_eq!(analyzed.current_tokens, estimated.current_tokens);
    assert_eq!(analyzed.needs_compaction, estimated.needs_compaction);
}

#[test]
fn no_measurement_uses_current_request_estimate() {
    let request = request("hi");
    let analysis = compactor(100_000, 0.9).analyze_with_measurement(&request, None);
    assert!(analysis.current_tokens < 10_000);
}

#[test]
fn explicit_zero_measurement_is_preserved() {
    let request = request("hi");
    let analysis =
        compactor(100_000, 0.9).analyze_with_measurement(&request, Some(measured(&request, 0)));
    assert_eq!(analysis.current_tokens, 0);
}

#[test]
fn configured_context_and_output_reserve_define_target() {
    let mut request = request("hi");
    request.max_tokens = Some(8_000);
    let analysis = compactor(100_000, 0.9)
        .analyze_with_measurement(&request, Some(measured(&request, 82_001)));
    assert_eq!(analysis.max_tokens, 100_000);
    assert_eq!(analysis.target_tokens, 82_000);
    assert!(analysis.needs_compaction);
}

#[test]
fn default_response_reserve_threshold_is_exact() {
    let request = request("hi");
    let compactor = compactor(100_000, 0.9);
    let at = compactor.analyze_with_measurement(&request, Some(measured(&request, 85_904)));
    let above = compactor.analyze_with_measurement(&request, Some(measured(&request, 85_905)));
    assert!(!at.needs_compaction);
    assert!(above.needs_compaction);
}

#[test]
fn tokens_to_free_uses_half_threshold_recovery_target() {
    let request = request("hi");
    let analysis = compactor(100_000, 0.9)
        .analyze_with_measurement(&request, Some(measured(&request, 95_000)));
    assert_eq!(analysis.tokens_to_free, 50_000);
}

#[test]
fn repeated_bound_analysis_is_deterministic() {
    let request = request("hi");
    let compactor = compactor(100_000, 0.9);
    let first = compactor.analyze_with_measurement(&request, Some(measured(&request, 50_000)));
    let second = compactor.analyze_with_measurement(&request, Some(measured(&request, 50_000)));
    assert_eq!(first.current_tokens, second.current_tokens);
    assert_eq!(first.target_tokens, second.target_tokens);
    assert_eq!(first.needs_compaction, second.needs_compaction);
    assert_eq!(first.tokens_to_free, second.tokens_to_free);
}

#[test]
fn extreme_measurements_saturate_without_panicking() {
    let request = request("hi");
    let analysis = compactor(usize::MAX, 0.9)
        .analyze_with_measurement(&request, Some(measured(&request, usize::MAX)));
    assert_eq!(analysis.current_tokens, usize::MAX);
}

#[test]
fn zero_threshold_compacts_any_nonzero_measured_input() {
    let request = request("hi");
    let analysis =
        compactor(100_000, 0.0).analyze_with_measurement(&request, Some(measured(&request, 1)));
    assert!(analysis.needs_compaction);
}
