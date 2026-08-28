//! Response parsing utilities for VDD adversary output.
//!
//! Handles extraction of JSON from adversary text (raw JSON or Markdown code
//! blocks) and severity parsing. Natural-language clean inference is rejected.
//!
//! Response-text and token-usage extraction used to live here as free
//! functions but duplicated logic already owned by the
//! [`crate::providers::ProviderAdapter`] trait — see crosslink #479. The
//! free functions are gone; call `adapter.extract_response_text(..)` /
//! `adapter.extract_token_usage(..)` instead.

// ==========================================================================
// JSON Extraction
// ==========================================================================

/// Extract the substring between the first occurrence of `open` and the next
/// occurrence of `close` (after `open`). Returns `None` if either delimiter
/// is missing or `open`'s end lands on a non-char-boundary.
///
/// All slicing goes through [`str::get`] so multibyte content can never panic
/// (crosslink #337).
fn extract_between(text: &str, open: &str, close: &str) -> Option<String> {
    let start = text.find(open)? + open.len();
    let rest = text.get(start..)?;
    let end = rest.find(close)?;
    rest.get(..end).map(|s| s.trim().to_string())
}

/// Extract the body of a generic ``` ... ``` fence, skipping an optional
/// language identifier on the same line as the opening fence.
fn extract_after_fence_skip_lang(text: &str) -> Option<String> {
    let start = text.find("```")? + 3;
    let after_fence = text.get(start..)?;
    let line_end = after_fence.find('\n').unwrap_or(0);
    let after_lang = after_fence.get(line_end..)?;
    let end = after_lang.find("```")?;
    after_lang.get(..end).map(|s| s.trim().to_string())
}

/// Find the first occurrence of `anchor` in `text` and return the balanced
/// `{ ... }` block that *starts* at that anchor. Walks codepoints so
/// multibyte content stays sound.
fn extract_balanced_braces_after(text: &str, anchor: &str) -> Option<String> {
    let start = text.find(anchor)?;
    let tail = text.get(start..)?;
    let mut depth = 0i32;
    let mut end_rel: Option<usize> = None;
    for (i, c) in tail.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    end_rel = Some(i + c.len_utf8());
                    break;
                }
            }
            _ => {}
        }
    }
    let len = end_rel?;
    tail.get(..len).map(String::from)
}

/// Last-resort fallback: take everything from the first `{` to the last `}`.
fn extract_first_to_last_brace(text: &str) -> Option<String> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end <= start {
        return None;
    }
    // `}` is ASCII so `end + 1` is on a char boundary.
    text.get(start..=end).map(String::from)
}

/// Try to extract JSON from a response that may contain markdown code blocks.
///
/// Every slice into `text` goes through [`str::get`] so an offset that
/// somehow lands mid-codepoint returns `None` instead of panicking
/// (crosslink #337).
///
/// crosslink #941: the four extraction strategies used to be open-coded as
/// near-identical blocks of nested `if let Some(..) = ..` ladders. Each
/// strategy is now a focused helper with one responsibility and the
/// composing function reads as a declarative fallback chain.
pub(crate) fn extract_json_from_response(text: &str) -> Option<String> {
    extract_between(text, "```json", "```")
        .or_else(|| extract_after_fence_skip_lang(text))
        .or_else(|| extract_balanced_braces_after(text, r#"{"findings""#))
        .or_else(|| extract_first_to_last_brace(text))
}

// ==========================================================================
// Severity Parsing
// ==========================================================================

/// Parse a severity string into the Severity enum.
pub(crate) fn parse_severity(s: &str) -> super::finding::Severity {
    use super::finding::Severity;
    match s.to_uppercase().as_str() {
        "CRITICAL" => Severity::Critical,
        "HIGH" => Severity::High,
        "MEDIUM" | "MED" => Severity::Medium,
        "LOW" => Severity::Low,
        _ => Severity::Info,
    }
}

// Response-text and token-usage extraction moved to the
// `ProviderAdapter` trait — see crosslink #479. The free functions that
// used to live here duplicated logic owned by the provider adapters and
// silently returned defaults for any shape they did not hardcode.

// ==========================================================================
// Tests
// ==========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    // --- Regression tests for crosslink #337 (UTF-8 safety) ---
    #[test]
    fn extract_json_survives_leading_emoji() {
        // 4-byte UTF-8 codepoint immediately before the fence (🔥 = U+1F525).
        let text = "🔥```json\n{\"findings\": []}\n```";
        let json = extract_json_from_response(text).expect("parser should not panic");
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["findings"].is_array());
    }

    #[test]
    fn extract_json_survives_cjk_prose() {
        let text = "分析结果如下:\n```json\n{\"assessment\": \"NO_FINDINGS\"}\n```\n";
        let json = extract_json_from_response(text).expect("parser should not panic");
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["assessment"], "NO_FINDINGS");
    }

    #[test]
    fn extract_json_survives_smart_quotes_in_prose() {
        let text = "\u{201C}Note:\u{201D} nothing to report.\n```json\n{\"findings\": []}\n```";
        let json = extract_json_from_response(text).expect("parser should not panic");
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["findings"].is_array());
    }

    #[test]
    fn extract_json_survives_emoji_inside_json_string() {
        let text = r#"```json
{"findings": [{"desc": "contains 🚀 and 💥"}]}
```"#;
        let json = extract_json_from_response(text).expect("parser should not panic");
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["findings"][0]["desc"], "contains 🚀 and 💥");
    }

    #[test]
    fn extract_json_from_raw_findings_object_with_emoji() {
        let text = r#"preamble 🎯 {"findings": [{"desc": "hello"}]} trailing"#;
        let json = extract_json_from_response(text).expect("parser should not panic");
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["findings"][0]["desc"], "hello");
    }

    #[test]
    fn extract_json_returns_none_for_empty_input() {
        assert!(extract_json_from_response("").is_none());
        assert!(extract_json_from_response("no braces here").is_none());
    }

    #[test]
    fn extract_json_survives_unclosed_fence() {
        // Adversarial malformed output: opening fence but no closing fence.
        // Must not panic.
        let text = "```json\n{\"findings\": []"; // missing }
        let _ = extract_json_from_response(text);
    }

    #[test]
    fn test_parse_severity() {
        use super::super::finding::Severity;
        assert_eq!(parse_severity("CRITICAL"), Severity::Critical);
        assert_eq!(parse_severity("critical"), Severity::Critical);
        assert_eq!(parse_severity("HIGH"), Severity::High);
        assert_eq!(parse_severity("MEDIUM"), Severity::Medium);
        assert_eq!(parse_severity("MED"), Severity::Medium);
        assert_eq!(parse_severity("LOW"), Severity::Low);
        assert_eq!(parse_severity("INFO"), Severity::Info);
        assert_eq!(parse_severity("unknown"), Severity::Info);
    }

    #[test]
    fn test_extract_json_from_code_block() {
        let text = r#"Here is my analysis:
```json
{"findings": [], "assessment": "NO_FINDINGS"}
```
"#;
        let json = extract_json_from_response(text).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["assessment"], "NO_FINDINGS");
    }

    #[test]
    fn test_extract_json_from_raw() {
        let text = r#"Some preamble text {"findings": [{"severity": "HIGH"}], "assessment": "FINDINGS_PRESENT"} trailing text"#;
        let json = extract_json_from_response(text).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["assessment"], "FINDINGS_PRESENT");
    }

    // Response-text and token-usage tests moved with the functions —
    // see `src/providers/{mod,anthropic,google,ollama,openai}.rs`
    // (crosslink #479).
}
