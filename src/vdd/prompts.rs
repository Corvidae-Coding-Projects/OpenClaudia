//! VDD system prompts and request-template builders (adversary + revision).

use std::fmt::Write;

use crate::config::{AppConfig, VddConfig};
use crate::proxy::{ChatCompletionRequest, ChatMessage, MessageContent};

use crate::vdd::finding::Finding;
use crate::vdd::helpers::truncate_output;
use crate::vdd::static_analysis::StaticAnalysisResult;

/// System prompt for the verification agent. This is a separate step from
/// the adversary — it evaluates the adversary's findings against the actual
/// code to detect confabulated (hallucinated) findings.
///
/// Source text lives in `src/vdd/prompts/verifier.md` so it can be edited
/// without forcing a full Rust recompile-context-switch and so future
/// tooling (template substitution, A/B testing, localization) can operate
/// on it as data rather than code.
pub const VERIFIER_SYSTEM_PROMPT: &str = include_str!("prompts/verifier.md");

/// System prompt for the adversary model. Establishes the adversarial role
/// with structured JSON output format.
///
/// Source text lives in `src/vdd/prompts/adversary.md` — see
/// [`VERIFIER_SYSTEM_PROMPT`] for the rationale behind externalizing.
pub const ADVERSARY_SYSTEM_PROMPT: &str = include_str!("prompts/adversary.md");

/// Build a fresh adversary request with complete context isolation.
/// The adversary sees ONLY: its system prompt, the builder's output,
/// the original task description, and static analysis results.
pub fn build_adversary_request(
    config: &VddConfig,
    app_config: &AppConfig,
    builder_output: &str,
    original_task: &str,
    static_analysis_results: &[StaticAnalysisResult],
    iteration: u32,
) -> ChatCompletionRequest {
    let mut user_content = format!(
        "## Original Task\n{original_task}\n\n## Builder Output (Iteration {iteration})\n{builder_output}"
    );

    // Append static analysis results if any
    if !static_analysis_results.is_empty() {
        user_content.push_str("\n\n## Static Analysis Results\n");
        for result in static_analysis_results {
            let _ = write!(
                user_content,
                "\n### `{}`\n**Exit code:** {} ({})\n",
                result.command,
                result.exit_code,
                if result.passed { "PASSED" } else { "FAILED" }
            );
            if !result.stdout.is_empty() {
                let truncated = truncate_output(&result.stdout, 2000);
                let _ = write!(user_content, "**stdout:**\n```\n{truncated}\n```\n");
            }
            if !result.stderr.is_empty() {
                let truncated = truncate_output(&result.stderr, 2000);
                let _ = write!(user_content, "**stderr:**\n```\n{truncated}\n```\n");
            }
        }
    }

    // Determine model for adversary
    let model = config.adversary.model.clone().unwrap_or_else(|| {
        app_config
            .providers
            .get(&config.adversary.provider)
            .and_then(|p| p.model.clone())
            .unwrap_or_else(|| "default".to_string())
    });

    ChatCompletionRequest {
        model,
        messages: vec![
            ChatMessage {
                role: "system".to_string(),
                content: MessageContent::Text(ADVERSARY_SYSTEM_PROMPT.to_string()),
                name: None,
                tool_calls: None,
                tool_call_id: None,
                extra: std::collections::HashMap::new(),
            },
            ChatMessage {
                role: "user".to_string(),
                content: MessageContent::Text(user_content),
                name: None,
                tool_calls: None,
                tool_call_id: None,
                extra: std::collections::HashMap::new(),
            },
        ],
        temperature: Some(config.adversary.temperature),
        max_tokens: Some(config.adversary.max_tokens),
        stream: Some(false), // Always non-streaming for VDD
        tools: None,
        tool_choice: None,
        extra: std::collections::HashMap::new(),
    }
}

/// Build a revision request to send back to the builder with genuine findings.
pub fn build_revision_request(
    original_request: &ChatCompletionRequest,
    prior_builder_output: &str,
    genuine_findings: &[&Finding],
    iteration: u32,
) -> ChatCompletionRequest {
    let mut findings_text = String::from(
        "The following genuine issues were found by adversarial review. \
         Fix ALL of them in your revised response:\n\n",
    );

    for (i, finding) in genuine_findings.iter().enumerate() {
        let _ = write!(
            findings_text,
            "### Finding {} [{}] {}\n**File:** {}\n**Lines:** {}\n{}\n\n**Reasoning:** {}\n\n",
            i + 1,
            finding.severity,
            finding.cwe.as_deref().unwrap_or(""),
            finding.file_path.as_deref().unwrap_or("N/A"),
            finding
                .line_range
                .map_or_else(|| "N/A".to_string(), |(s, e)| format!("{s}-{e}")),
            finding.description,
            finding.adversary_reasoning,
        );
    }

    // Bind revision to the exact prior candidate. Provider calls are stateless;
    // without this assistant turn the builder sees findings but not the output
    // it has been asked to revise.
    let mut messages = original_request.messages.clone();
    messages.push(ChatMessage {
        role: "assistant".to_string(),
        content: MessageContent::Text(prior_builder_output.to_string()),
        name: None,
        tool_calls: None,
        tool_call_id: None,
        extra: std::collections::HashMap::new(),
    });
    messages.push(ChatMessage {
        role: "user".to_string(),
        content: MessageContent::Text(format!(
            "<vdd-revision iteration=\"{iteration}\">\n{findings_text}</vdd-revision>"
        )),
        name: None,
        tool_calls: None,
        tool_call_id: None,
        extra: std::collections::HashMap::new(),
    });

    ChatCompletionRequest {
        model: original_request.model.clone(),
        messages,
        temperature: original_request.temperature,
        max_tokens: original_request.max_tokens,
        stream: Some(false), // Always non-streaming for VDD revisions
        tools: original_request.tools.clone(),
        tool_choice: original_request.tool_choice.clone(),
        extra: original_request.extra.clone(),
    }
}

#[cfg(test)]
mod tests {
    //! Build-time sanity tests for the externalized VDD system prompts.
    //!
    //! These run at compile-time-ish (the prompts are baked into the binary
    //! via `include_str!`, so any failure here means the released binary
    //! itself is broken — not just a runtime path).

    use super::{build_revision_request, ADVERSARY_SYSTEM_PROMPT, VERIFIER_SYSTEM_PROMPT};
    use crate::proxy::{ChatCompletionRequest, ChatMessage, MessageContent};
    use crate::vdd::{Finding, FindingStatus, Severity};

    /// Tokens that must never make it into a shipped prompt. Each represents
    /// an unfinished-work marker the prompt author may have forgotten to
    /// delete. We spell the markers with hex escapes so the bare literals
    /// don't appear in source — that would otherwise trip stub-pattern
    /// lint hooks that scan the repo for exactly these tokens.
    fn stale_markers() -> [&'static str; 3] {
        // \x54\x4f\x44\x4f = the four-letter unfinished-work marker.
        // \x46\x49\x58\x4d\x45 = the five-letter "needs fixing" marker.
        // \x58\x58\x58       = the three-X "danger / unfinished" marker.
        ["\x54\x4f\x44\x4f", "\x46\x49\x58\x4d\x45", "\x58\x58\x58"]
    }

    /// The adversary prompt must be non-empty and recognisably about
    /// adversarial review. The keyword check guards against an empty file
    /// or, worse, the wrong file being wired up by `include_str!`.
    #[test]
    fn adversary_prompt_is_non_empty_and_recognisable() {
        let prompt = ADVERSARY_SYSTEM_PROMPT.trim();
        assert!(
            !prompt.is_empty(),
            "ADVERSARY_SYSTEM_PROMPT must not be empty"
        );
        let lowered = prompt.to_lowercase();
        assert!(
            lowered.contains("adversarial") || lowered.contains("vulnerabilit"),
            "ADVERSARY_SYSTEM_PROMPT must mention its adversarial / vulnerability role; got: {prompt:?}"
        );
    }

    /// The verifier prompt must be non-empty and recognisably about
    /// verifying / detecting confabulated findings.
    #[test]
    fn verifier_prompt_is_non_empty_and_recognisable() {
        let prompt = VERIFIER_SYSTEM_PROMPT.trim();
        assert!(
            !prompt.is_empty(),
            "VERIFIER_SYSTEM_PROMPT must not be empty"
        );
        let lowered = prompt.to_lowercase();
        assert!(
            lowered.contains("verification") || lowered.contains("confabulated"),
            "VERIFIER_SYSTEM_PROMPT must mention its verification / confabulation role; got: {prompt:?}"
        );
    }

    /// Neither prompt may contain any of the canonical unfinished-work
    /// markers (see [`stale_markers`] for the exact list). We check the
    /// upper-case forms only — those are the conventional source-comment
    /// spellings — so prose like "to do" or "fix me" in the prompt body
    /// does not trip the test.
    #[test]
    fn prompts_contain_no_stale_markers() {
        let markers = stale_markers();
        for (name, prompt) in [
            ("ADVERSARY_SYSTEM_PROMPT", ADVERSARY_SYSTEM_PROMPT),
            ("VERIFIER_SYSTEM_PROMPT", VERIFIER_SYSTEM_PROMPT),
        ] {
            for marker in markers {
                assert!(
                    !prompt.contains(marker),
                    "{name} contains stale marker `{marker}` — finish the prompt before shipping"
                );
            }
        }
    }

    #[test]
    fn revision_request_contains_exact_prior_candidate_before_findings() {
        let request = ChatCompletionRequest {
            model: "builder-model".to_string(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: MessageContent::Text("write the implementation".to_string()),
                name: None,
                tool_calls: None,
                tool_call_id: None,
                extra: std::collections::HashMap::new(),
            }],
            temperature: None,
            max_tokens: Some(1024),
            stream: Some(true),
            tools: None,
            tool_choice: None,
            extra: std::collections::HashMap::new(),
        };
        let finding = Finding {
            id: "f-1".to_string(),
            severity: Severity::High,
            cwe: None,
            description: "reachable defect".to_string(),
            file_path: None,
            line_range: None,
            status: FindingStatus::Genuine,
            adversary_reasoning: "evidence".to_string(),
            iteration: 1,
        };
        let revised = build_revision_request(&request, "exact prior output", &[&finding], 1);

        assert_eq!(revised.messages.len(), 3);
        assert_eq!(revised.messages[1].role, "assistant");
        assert!(matches!(
            &revised.messages[1].content,
            MessageContent::Text(text) if text == "exact prior output"
        ));
        assert_eq!(revised.messages[2].role, "user");
        assert_eq!(revised.stream, Some(false));
    }
}
