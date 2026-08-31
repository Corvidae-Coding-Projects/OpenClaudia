//! Small VDD helper utilities: task extraction, truncation, advisory formatting.

use std::fmt::Write;

use crate::proxy::{ChatCompletionRequest, MessageContent};

use crate::vdd::finding::{Finding, FindingStatus};
use crate::vdd::static_analysis::StaticAnalysisResult;

/// Extract the user's task/request from the original conversation.
pub fn extract_user_task(request: &ChatCompletionRequest) -> String {
    // Find the last user message (the actual task)
    for message in request.messages.iter().rev() {
        if message.role == "user" {
            match &message.content {
                MessageContent::Text(text) => return text.clone(),
                MessageContent::Parts(parts) => {
                    let texts: Vec<&str> = parts.iter().filter_map(|p| p.text.as_deref()).collect();
                    return texts.join("\n");
                }
            }
        }
    }
    "No task description available".to_string()
}

/// Truncate output to a maximum length with an indicator.
///
/// UTF-8-safe: if `max_len` falls inside a multibyte codepoint, the cut
/// is moved back to the nearest char boundary. The previous
/// `text[..max_len]` indexing would panic on non-ASCII output at that
/// cut point.
pub fn truncate_output(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        return text.to_string();
    }
    let mut boundary = max_len;
    while boundary > 0 && !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    format!(
        "{}... [truncated, {} total chars]",
        &text[..boundary],
        text.len()
    )
}

/// Build a source-labeled reference observation for a later turn.
#[must_use]
pub fn findings_context_observation(
    findings: &[Finding],
    static_analysis: &[StaticAnalysisResult],
) -> Option<crate::context::ContextItem> {
    let content = format_findings_for_reference(findings, static_analysis);
    if content.is_empty() {
        return None;
    }
    Some(crate::context::ContextItem::reference(
        "vdd.advisory",
        crate::context::ReferenceSource::Vdd,
        "vdd:adversary-review",
        content,
        crate::context::ContextFreshness::Turn,
        700,
    ))
}

fn format_findings_for_reference(
    findings: &[Finding],
    static_analysis: &[StaticAnalysisResult],
) -> String {
    let genuine: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.status == FindingStatus::Genuine)
        .collect();

    if genuine.is_empty() && static_analysis.iter().all(|r| r.passed) {
        return String::new(); // No context needed
    }

    let mut output = String::from("<vdd-advisory>\n");

    if !genuine.is_empty() {
        output.push_str("Adversarial review observations about the previous response:\n\n");
        for (i, finding) in genuine.iter().enumerate() {
            let _ = writeln!(
                output,
                "{}. [{}] {}{}: {}",
                i + 1,
                finding.severity,
                finding
                    .cwe
                    .as_deref()
                    .map(|c| format!("{c} "))
                    .unwrap_or_default(),
                finding
                    .file_path
                    .as_deref()
                    .map(|f| format!(" in {f}"))
                    .unwrap_or_default(),
                finding.description
            );
        }
    }

    let failed_analysis: Vec<&StaticAnalysisResult> =
        static_analysis.iter().filter(|r| !r.passed).collect();
    if !failed_analysis.is_empty() {
        output.push_str("\nStatic analysis failures:\n");
        for result in failed_analysis {
            let _ = writeln!(
                output,
                "- `{}` (exit code {})",
                result.command, result.exit_code
            );
        }
    }

    output.push_str("</vdd-advisory>");
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vdd::finding::Severity;

    #[test]
    fn test_truncate_output_short() {
        assert_eq!(truncate_output("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_output_utf8_safe() {
        // 4-byte codepoint at the cut would have panicked under raw
        // byte indexing. Should cut back to a char boundary instead.
        let text = "aaa🔥bbbb"; // `aaa` + 4-byte emoji + `bbbb` = 3 + 4 + 4 = 11 bytes
        let result = truncate_output(text, 5);
        assert!(result.contains("aaa"), "unexpected: {result}");
        assert!(result.contains("truncated"));
    }

    #[test]
    fn test_truncate_output_long() {
        let result = truncate_output("hello world this is long", 10);
        assert!(result.starts_with("hello worl"));
        assert!(result.contains("truncated"));
    }

    #[test]
    fn test_format_findings_for_injection_empty() {
        let findings: Vec<Finding> = Vec::new();
        let analysis: Vec<StaticAnalysisResult> = Vec::new();
        assert!(findings_context_observation(&findings, &analysis).is_none());
    }

    #[test]
    fn test_format_findings_for_injection_with_genuine() {
        let findings = vec![Finding {
            id: "test-id".to_string(),
            severity: Severity::High,
            cwe: Some("CWE-89".to_string()),
            description: "SQL injection".to_string(),
            file_path: Some("src/db.rs".to_string()),
            line_range: Some((10, 20)),
            status: FindingStatus::Genuine,
            adversary_reasoning: "User input concatenated".to_string(),
            iteration: 1,
        }];
        let item = findings_context_observation(&findings, &[]).expect("reference observation");
        let result = item.content();
        assert!(result.contains("<vdd-advisory>"));
        assert!(result.contains("CWE-89"));
        assert!(result.contains("SQL injection"));
        assert!(result.contains("</vdd-advisory>"));
    }

    #[test]
    fn test_format_findings_skips_false_positives() {
        let findings = vec![Finding {
            id: "test-id".to_string(),
            severity: Severity::Low,
            cwe: None,
            description: "Not a real issue".to_string(),
            file_path: None,
            line_range: None,
            status: FindingStatus::FalsePositive,
            adversary_reasoning: String::new(),
            iteration: 1,
        }];
        assert!(findings_context_observation(&findings, &[]).is_none());
    }
}
