//! Three-layer finding triage: duplicate detection, pattern heuristics, AI verification.

use std::collections::{HashMap, HashSet};
use std::fmt::Write;

use reqwest::Client;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use crate::config::{AppConfig, VddConfig};
use crate::providers::ApiKey;
use crate::proxy::{ChatCompletionRequest, ChatMessage, MessageContent};

use crate::vdd::confabulation::{
    finding_signature, is_common_false_positive, weak_finding_signature, FindingIdentity,
};
use crate::vdd::error::VddError;
use crate::vdd::finding::{Finding, FindingStatus};
use crate::vdd::helpers::truncate_output;
use crate::vdd::parsing::{extract_json_from_response, parse_severity};
use crate::vdd::prompts::VERIFIER_SYSTEM_PROMPT;
use crate::vdd::review::AdversaryResponse;
use crate::vdd::transport::send_to_builder_for_verification;

/// Disposition of a parsed adversary response.
///
/// Replaces the original "everything collapses to `Vec::new()`" return shape
/// that conflated three distinct signals — `NO_FINDINGS` (adversary intentionally
/// found nothing), parse failure (we couldn't read the response), and "JSON
/// parsed but the `findings` array was missing/empty". Callers can now
/// distinguish these for metrics / logging; the legacy [`parse_findings`]
/// wrapper still returns the flat `Vec<Finding>` for back-compat.
///
/// See crosslink #879.
#[derive(Debug)]
pub enum ParseFindingsOutcome {
    /// JSON parsed and the adversary explicitly reported `NO_FINDINGS`.
    NoFindings,
    /// JSON parsed and explicitly reported one or more findings.
    Findings(Vec<Finding>),
    /// We could not parse the response as a terminal JSON report. The
    /// raw response is intentionally NOT carried in the variant — the
    /// caller has already been logged a truncated preview by the parser
    /// and we don't want a giant unparseable blob travelling through
    /// metrics or audit channels.
    ParseError {
        /// Stable, short tag for downstream metric labels.
        kind: ParseErrorKind,
    },
}

/// Why parsing failed. Stable strings; do not rename without a metrics
/// migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// The response was not JSON in either accepted form (raw or fenced).
    NotJson,
    /// The response was syntactically JSON but did not match the expected
    /// adversary-response schema.
    InvalidSchema,
    /// The response parsed as JSON but had no `findings` field.
    MissingFindingsField,
}

impl ParseErrorKind {
    /// Stable label for tracing fields.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotJson => "not_json",
            Self::InvalidSchema => "invalid_schema",
            Self::MissingFindingsField => "missing_findings_field",
        }
    }
}

fn validate_adversary_response_shape(value: &Value) -> Result<(), ParseErrorKind> {
    let Some(obj) = value.as_object() else {
        return Err(ParseErrorKind::InvalidSchema);
    };

    // Preserve the public discriminator before evaluating the rest of the
    // object: absence of the mandatory findings field is more specific than
    // any unknown sibling key.
    let findings = obj
        .get("findings")
        .ok_or(ParseErrorKind::MissingFindingsField)?
        .as_array()
        .ok_or(ParseErrorKind::InvalidSchema)?;
    if obj
        .keys()
        .any(|key| !matches!(key.as_str(), "findings" | "assessment"))
    {
        return Err(ParseErrorKind::InvalidSchema);
    }
    for finding in findings {
        let Some(finding) = finding.as_object() else {
            return Err(ParseErrorKind::InvalidSchema);
        };
        if finding.keys().any(|key| {
            !matches!(
                key.as_str(),
                "severity" | "cwe" | "description" | "file" | "lines" | "reasoning"
            )
        }) {
            return Err(ParseErrorKind::InvalidSchema);
        }
    }
    let assessment = obj
        .get("assessment")
        .and_then(Value::as_str)
        .ok_or(ParseErrorKind::InvalidSchema)?;

    match (assessment, findings.is_empty()) {
        ("NO_FINDINGS", true) | ("FINDINGS_PRESENT", false) => Ok(()),
        _ => Err(ParseErrorKind::InvalidSchema),
    }
}

fn parse_adversary_response_json(candidate: &str) -> Result<AdversaryResponse, ParseErrorKind> {
    let value: Value = serde_json::from_str(candidate).map_err(|_| ParseErrorKind::NotJson)?;
    validate_adversary_response_shape(&value)?;
    serde_json::from_value(value).map_err(|_| ParseErrorKind::InvalidSchema)
}

/// Parse adversary response text into a discriminated outcome.
///
/// Use this when the caller wants to distinguish "adversary said no findings"
/// from "we couldn't read what the adversary said". Live engine paths use
/// this discriminated result so malformed output cannot become a clean pass.
pub fn parse_findings_detailed(adversary_response: &str, iteration: u32) -> ParseFindingsOutcome {
    let parsed = match parse_adversary_response_json(adversary_response) {
        Ok(response) => Ok(response),
        Err(ParseErrorKind::NotJson) => extract_json_from_response(adversary_response)
            .ok_or(ParseErrorKind::NotJson)
            .and_then(|json| parse_adversary_response_json(&json)),
        Err(kind) => Err(kind),
    };

    let response = match parsed {
        Ok(response) => response,
        Err(kind) => {
            warn!(
                outcome = "parse_error",
                kind = kind.as_str(),
                "VDD: Adversary response does not match the terminal findings schema"
            );
            info!(
                kind = kind.as_str(),
                "VDD: Unparseable response preview: {}",
                truncate_output(adversary_response, 500)
            );
            return ParseFindingsOutcome::ParseError { kind };
        }
    };

    let (Some(raw_findings), Some(assessment)) = (response.findings, response.assessment) else {
        warn!(
            outcome = "parse_error",
            kind = ParseErrorKind::InvalidSchema.as_str(),
            "VDD: Validated adversary response lost a required terminal field"
        );
        return ParseFindingsOutcome::ParseError {
            kind: ParseErrorKind::InvalidSchema,
        };
    };

    if assessment == "NO_FINDINGS" {
        info!(
            outcome = "no_findings",
            "VDD: Adversary reported no findings"
        );
        ParseFindingsOutcome::NoFindings
    } else {
        ParseFindingsOutcome::Findings(build_findings_from_raw(raw_findings, iteration))
    }
}

/// Parse adversary response text into structured findings (legacy shape).
///
/// Returns `Vec::new()` for both `NO_FINDINGS` and parse-failure outcomes,
/// matching the pre-#879 contract. Use [`parse_findings_detailed`] when the
/// caller needs to distinguish these.
///
/// The legacy wrapper still observes the discriminator in a trace span so
/// upstream dashboards can count parse failures vs. intentional
/// `NO_FINDINGS` without changing the function signature. crosslink #879.
pub fn parse_findings(adversary_response: &str, iteration: u32) -> Vec<Finding> {
    let outcome = parse_findings_detailed(adversary_response, iteration);
    match outcome {
        ParseFindingsOutcome::Findings(f) => f,
        ParseFindingsOutcome::NoFindings => Vec::new(),
        ParseFindingsOutcome::ParseError { kind } => {
            // Re-emit the discriminator at debug level so the legacy
            // wrapper has the same metric surface as the detailed API.
            // The original warn! at the failure site already covered
            // operator-visible logging; this is purely for downstream
            // counters that key off `parse_error_kind`.
            tracing::debug!(
                parse_error_kind = kind.as_str(),
                "parse_findings: returning Vec::new() due to parse error"
            );
            Vec::new()
        }
    }
}

/// Convert raw adversary-supplied finding rows into the canonical
/// [`Finding`] shape. Extracted so [`parse_findings`] and
/// [`parse_findings_detailed`] share the exact same construction logic.
fn build_findings_from_raw(
    raw_findings: Vec<crate::vdd::finding::RawFinding>,
    iteration: u32,
) -> Vec<Finding> {
    raw_findings
        .into_iter()
        .enumerate()
        .map(|(idx, raw)| {
            let severity = parse_severity(raw.severity.as_deref().unwrap_or("INFO"));
            let line_range = raw.lines.and_then(|lines| {
                if lines.len() >= 2 {
                    Some((lines[0], lines[1]))
                } else if lines.len() == 1 {
                    Some((lines[0], lines[0]))
                } else {
                    None
                }
            });

            let description = raw
                .description
                .unwrap_or_else(|| "No description".to_string());

            // Deterministic id: SHA-256 over (iteration, ordinal, file, line_range,
            // severity, cwe, description). Replaces the previous per-call
            // `Uuid::new_v4()` which made tests non-deterministic and broke
            // cross-iteration verdict lookup (crosslink #478).
            let id = deterministic_finding_id(
                iteration,
                idx,
                raw.file.as_deref(),
                line_range,
                &severity,
                raw.cwe.as_deref(),
                &description,
            );

            Finding {
                id,
                severity,
                cwe: raw.cwe,
                description,
                file_path: raw.file,
                line_range,
                status: FindingStatus::Genuine, // Default; triage will reclassify
                adversary_reasoning: raw.reasoning.unwrap_or_default(),
                iteration,
            }
        })
        .collect()
}

/// Build a stable, content-derived id for a finding.
///
/// The id is a short hex prefix of SHA-256 over the iteration, the ordinal
/// position of the finding inside the adversary response, and the finding's
/// natural-key fields (file, line range, severity, CWE, description). The
/// iteration + ordinal guarantee uniqueness when the same description is
/// re-reported within a single response, while the natural-key fields keep
/// the id stable across re-parses of the same input — which is what tests
/// (and Chainlink) need for assertable, cross-iteration identity.
fn deterministic_finding_id(
    iteration: u32,
    ordinal: usize,
    file_path: Option<&str>,
    line_range: Option<(usize, usize)>,
    severity: &crate::vdd::finding::Severity,
    cwe: Option<&str>,
    description: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(iteration.to_le_bytes());
    hasher.update(b"|");
    hasher.update((ordinal as u64).to_le_bytes());
    hasher.update(b"|");
    hasher.update(file_path.unwrap_or("").as_bytes());
    hasher.update(b"|");
    let (lo, hi) = line_range.unwrap_or((0, 0));
    hasher.update((lo as u64).to_le_bytes());
    hasher.update(b":");
    hasher.update((hi as u64).to_le_bytes());
    hasher.update(b"|");
    hasher.update(format!("{severity:?}").as_bytes());
    hasher.update(b"|");
    hasher.update(cwe.unwrap_or("").as_bytes());
    hasher.update(b"|");
    hasher.update(description.as_bytes());
    let digest = hasher.finalize();
    // 16 hex chars (64 bits) — collision probability negligible for the
    // per-iteration finding population (small N).
    let mut s = String::with_capacity(16);
    for byte in &digest[..8] {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

/// Inputs needed by the triage pipeline. Bundled into a struct so the
/// `triage_findings` API stays under the `too_many_arguments` lint threshold.
pub struct TriageContext<'a> {
    pub run: &'a crate::tools::ToolRunContext,
    pub client: &'a Client,
    pub config: &'a VddConfig,
    pub app_config: &'a AppConfig,
    /// Identities of confirmed false positives seen in earlier iterations.
    /// Used by Layer 1 to mark re-reports as `FalsePositive` via tuple-hash
    /// dedup (see crosslink #349 — replaces the prior Jaccard-on-words
    /// similarity, which was both false-negative and false-positive).
    pub previous_fps: &'a [FindingIdentity],
    pub builder_code: &'a str,
    pub builder_provider: &'a str,
    pub builder_api_key: Option<&'a ApiKey>,
    pub builder_auth: Option<&'a crate::vdd::transport::VddProviderAuth>,
}

/// Triage findings using three layers:
/// 1. Duplicate detection (string similarity against previous FPs)
/// 2. Common false positive patterns (hardcoded Rust patterns)
/// 3. AI-powered verification agent (sends findings + code to the
///    **builder's** provider to check each claim against actual code)
///
/// The verifier deliberately uses the builder's provider (not the
/// adversary's) to avoid correlated confabulation — if the adversary
/// hallucinates, asking the same model to verify would produce the
/// same hallucination.
pub async fn triage_findings(findings: &mut [Finding], ctx: &TriageContext<'_>) {
    // Historical duplicate and prose-pattern signals are useful review hints,
    // but neither is evidence that a finding is false. Keep them observable
    // without granting them status-transition authority.
    apply_duplicate_layer(findings, ctx.previous_fps);
    apply_pattern_layer(findings);

    // Layer 3: AI-powered verification — expensive but catches novel confabulations.
    // Hints never remove findings from this evidence-backed verification set.
    let surviving_genuine: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.status == FindingStatus::Genuine)
        .collect();

    if surviving_genuine.is_empty() {
        return;
    }

    match verify_findings(ctx, &surviving_genuine).await {
        Ok(verdicts) => apply_verdicts(findings, &verdicts),
        Err(e) => {
            // Verification is optional triage assistance. If it cannot run,
            // preserve the conservative Genuine status for every finding.
            eprintln!("\x1b[33m⚠ VDD verification agent failed: {e}\x1b[0m");
            eprintln!(
                "\x1b[33m  Findings remain genuine; duplicate and pattern signals are hints only.\x1b[0m"
            );
            warn!("VDD verifier request failed: {e}");
        }
    }
}

/// Layer 1: surface findings whose `(file_path, severity, cwe, line_range)`
/// tuple resembles a previously confirmed false positive.
///
/// Crosslink #349: this replaces the prior Jaccard-on-whitespace similarity
/// with a deterministic tuple-hash hint. Possible re-reports that cite the
/// same code at the same severity are surfaced for the verifier;
/// findings whose only signal is a free-text description fall through to a
/// weaker description-prefix signature (with a warn log) so we still
/// identify obvious re-reports without depending on word-overlap heuristics.
/// A match is only a hint: tuple and prefix signatures cannot prove that two
/// findings have the same cause, so this layer never changes finding status.
fn apply_duplicate_layer(findings: &[Finding], previous_fps: &[FindingIdentity]) {
    if previous_fps.is_empty() {
        return;
    }

    // Pre-compute the seen sets once per call.
    let mut strong_seen: HashSet<u64> = HashSet::with_capacity(previous_fps.len());
    let mut weak_seen: HashSet<u64> = HashSet::new();

    for id in previous_fps {
        if id.is_weak() {
            weak_seen.insert(id.weak_signature());
        } else {
            strong_seen.insert(id.signature());
        }
    }

    for finding in findings {
        let id = FindingIdentity::from_finding(finding);
        if id.is_weak() {
            // Weak finding — both cwe and line_range absent. Fall back to
            // the description-prefix signature and warn the operator that
            // dedup quality is reduced for this finding (per #349 mandate).
            warn!(
                file = ?finding.file_path,
                severity = %finding.severity,
                "VDD dedup: finding has no CWE and no line range — \
                 using weak description-prefix signature for duplicate \
                 detection. Adversary output quality should be improved \
                 upstream."
            );
            if weak_seen.contains(&weak_finding_signature(finding)) {
                warn!(
                    finding_id = %finding.id,
                    "VDD dedup hint: possible weak re-report; retaining finding as genuine pending evidence-backed verification"
                );
            }
        } else if strong_seen.contains(&finding_signature(finding)) {
            warn!(
                finding_id = %finding.id,
                "VDD dedup hint: possible tuple re-report; retaining finding as genuine pending evidence-backed verification"
            );
        }
    }
}

/// Layer 2: surface findings that match historical false-positive patterns.
/// Prose matching is not evidence and therefore cannot demote a finding.
fn apply_pattern_layer(findings: &[Finding]) {
    for finding in findings {
        if finding.status == FindingStatus::Genuine {
            let desc = &finding.description.to_lowercase();
            if is_common_false_positive(desc, &finding.adversary_reasoning.to_lowercase()) {
                warn!(
                    finding_id = %finding.id,
                    "VDD pattern hint: finding resembles a historical false positive; retaining it as genuine pending evidence-backed verification"
                );
            }
        }
    }
}

/// Apply verifier verdicts to the remaining Genuine findings (layer 3).
fn apply_verdicts(findings: &mut [Finding], verdicts: &HashMap<String, String>) {
    for finding in findings.iter_mut() {
        if finding.status != FindingStatus::Genuine {
            continue; // Preserve any host-owned status set before this pass.
        }
        if let Some(verdict) = verdicts.get(&finding.id) {
            if verdict == "confabulated" {
                eprintln!(
                    "\x1b[33m⚠ VDD verifier: adversary finding is confabulated — \"{}\"\x1b[0m",
                    truncate_output(&finding.description, 80)
                );
                finding.status = FindingStatus::FalsePositive;
            }
        }
    }
}

/// Send findings to a verification agent that checks each adversary claim
/// against the actual code.  Uses the **builder's** provider (not the
/// adversary's) to get an independent second opinion.
///
/// Returns a map of `finding_id` → "genuine" | "confabulated".
async fn verify_findings(
    ctx: &TriageContext<'_>,
    findings: &[&Finding],
) -> Result<HashMap<String, String>, VddError> {
    if findings.is_empty() {
        return Ok(HashMap::new());
    }

    eprintln!(
        "\x1b[36m🔍 VDD verifier: checking {} finding(s) against code via {}\x1b[0m",
        findings.len(),
        ctx.builder_provider
    );

    // Build a code view centered on the findings' cited line ranges
    // rather than blindly truncating to a prefix — a finding that
    // cited lines past byte 12_000 used to be demoted to
    // FalsePositive simply because the verifier could not see the
    // code. See crosslink #498.
    let (code_view, code_truncated) =
        build_verification_code_view(ctx.builder_code, findings, 12_000);
    if code_truncated {
        return Err(VddError::ParseError(
            "verification code view is truncated or contains an invalid cited range; \
             findings remain genuine"
                .to_string(),
        ));
    }
    let mut user_content =
        format!("## Code Under Review\n```\n{code_view}\n```\n\n## Adversary Findings to Verify\n");

    for (i, finding) in findings.iter().enumerate() {
        let _ = write!(
            user_content,
            "\n### Finding {} (ID: {})\n\
             - **Severity:** {:?}\n\
             - **CWE:** {}\n\
             - **File:** {}\n\
             - **Lines:** {}\n\
             - **Description:** {}\n\
             - **Adversary reasoning:** {}\n",
            i + 1,
            finding.id,
            finding.severity,
            finding.cwe.as_deref().unwrap_or("none"),
            finding.file_path.as_deref().unwrap_or("unknown"),
            finding
                .line_range
                .map_or_else(|| "unknown".to_string(), |(a, b)| format!("{a}-{b}")),
            finding.description,
            finding.adversary_reasoning,
        );
    }

    // Use the builder's provider model for verification — independent
    // from the adversary to avoid correlated confabulation.
    let model = ctx
        .app_config
        .providers
        .get(ctx.builder_provider)
        .and_then(|p| p.model.clone())
        .unwrap_or_else(|| "default".to_string());

    let request = ChatCompletionRequest {
        model,
        messages: vec![
            ChatMessage {
                role: "system".to_string(),
                content: MessageContent::Text(VERIFIER_SYSTEM_PROMPT.to_string()),
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
        temperature: Some(0.0), // Maximally deterministic for verification
        max_tokens: Some(ctx.config.adversary.max_tokens),
        stream: Some(false),
        tools: None,
        tool_choice: None,
        extra: std::collections::HashMap::new(),
    };

    // Route through the builder's provider, not the adversary's
    let (response_text, tokens) = send_to_builder_for_verification(
        ctx.run,
        ctx.client,
        ctx.config,
        ctx.app_config,
        &request,
        ctx.builder_provider,
        ctx.builder_api_key,
        ctx.builder_auth,
    )
    .await?;

    eprintln!(
        "\x1b[36m  Verifier used {} input + {} output tokens\x1b[0m",
        tokens.input_tokens, tokens.output_tokens
    );

    // Parse verdicts from the response
    Ok(parse_verification_verdicts(&response_text))
}

/// Parse the verification agent's response into a `finding_id` → verdict map.
fn parse_verification_verdicts(response: &str) -> HashMap<String, String> {
    let mut verdicts = HashMap::new();

    // Try to extract JSON from the response
    let json_str = extract_json_from_response(response).unwrap_or_else(|| response.to_string());

    if let Ok(value) = serde_json::from_str::<Value>(&json_str) {
        if let Some(arr) = value.get("verdicts").and_then(|v| v.as_array()) {
            for item in arr {
                if let (Some(id), Some(verdict)) = (
                    item.get("finding_id").and_then(|v| v.as_str()),
                    item.get("verdict").and_then(|v| v.as_str()),
                ) {
                    let normalized = verdict.to_lowercase();
                    if normalized == "genuine" || normalized == "confabulated" {
                        verdicts.insert(id.to_string(), normalized);
                    }
                }
            }
        }
    }

    if verdicts.is_empty() && !response.is_empty() {
        // Fallback: try to extract verdicts from natural language
        // If the verifier says something like "all findings are confabulated"
        let lower = response.to_lowercase();
        if lower.contains("all") && lower.contains("confabulated") {
            debug!("VDD verifier: bulk confabulation detected in natural language response");
            // Can't map to specific IDs without parsing, so return empty
            // and let the convergence math handle it next iteration
        }
        warn!(
            "VDD verifier: could not parse structured verdicts from response ({} chars)",
            response.len()
        );
    }

    verdicts
}

/// Build the code view shown to the verification LLM, centered around
/// the cited line ranges of each finding.
///
/// The previous implementation truncated `builder_code` to the first
/// `max_chars` bytes regardless of where the cited code lived, which
/// systematically demoted findings past the cutoff to `FalsePositive`
/// ("I can't find this code") even though they were genuine. This
/// helper:
///
///  1. For every finding with `file_path + line_range`, extracts a
///     ±`CONTEXT_LINES`-line window around that range.
///  2. Merges overlapping / adjacent windows.
///  3. Emits the windows in order with `...` separators between them
///     and with `<line_number>: ` prefixes so the verifier can match
///     the adversary's cited lines directly.
///  4. Falls back to raw truncation when no finding has line info OR
///     when the merged window view itself exceeds `max_chars` (in
///     that case we also log at warn! — the fail-safe from #498c is
///     enforced by the caller treating truncated windows as reason
///     to keep findings Genuine rather than demoted).
///
/// Returns the rendered view plus a boolean indicating whether any
/// truncation occurred; callers use the flag to decide whether to
/// fail-safe the affected findings. See crosslink #498.
fn build_verification_code_view(
    builder_code: &str,
    findings: &[&Finding],
    max_chars: usize,
) -> (String, bool) {
    const CONTEXT_LINES: usize = 20;

    // If the whole code fits, no truncation is needed.
    if builder_code.len() <= max_chars {
        return (builder_code.to_string(), false);
    }

    let lines: Vec<&str> = builder_code.lines().collect();

    // Collect only ordered, one-indexed ranges fully inside the supplied
    // code. A model-supplied invalid range makes the view incomplete; the
    // caller then keeps every affected finding genuine instead of asking the
    // verifier to classify against missing evidence.
    let mut invalid_range = false;
    let mut ranges = Vec::new();
    for finding in findings {
        let Some((start, end)) = finding.line_range else {
            continue;
        };
        if start == 0 || end < start || start > lines.len() || end > lines.len() {
            invalid_range = true;
            continue;
        }
        let zero_indexed_start = start - 1;
        ranges.push((
            zero_indexed_start.saturating_sub(CONTEXT_LINES),
            end.saturating_add(CONTEXT_LINES).min(lines.len()),
        ));
    }

    if invalid_range {
        return (truncate_output(builder_code, max_chars), true);
    }

    if ranges.is_empty() {
        // No line info — fall back to raw truncation.
        return (truncate_output(builder_code, max_chars), true);
    }

    // Merge overlapping windows.
    let mut sorted = ranges;
    sorted.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in sorted {
        if let Some(last) = merged.last_mut() {
            if start <= last.1 {
                last.1 = last.1.max(end);
                continue;
            }
        }
        merged.push((start, end));
    }

    let mut out = String::new();
    let mut any_truncated = false;
    for (i, (start, end)) in merged.iter().enumerate() {
        if i > 0 {
            out.push_str("\n...\n");
        }
        for (rel, line) in lines[*start..*end].iter().enumerate() {
            let line_num = *start + rel + 1;
            if out.len() + line.len() + 16 > max_chars {
                out.push_str("\n... [window truncated]");
                any_truncated = true;
                break;
            }
            let _ = writeln!(out, "{line_num}: {line}");
        }
        if out.len() >= max_chars {
            any_truncated = true;
            break;
        }
    }

    if out.is_empty() {
        return (truncate_output(builder_code, max_chars), true);
    }

    (out, any_truncated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppConfig;
    use crate::vdd::finding::Severity;

    fn test_app_config() -> AppConfig {
        AppConfig {
            proxy: crate::config::ProxyConfig::default(),
            providers: std::collections::HashMap::new(),
            hooks: crate::config::HooksConfig::default(),
            session: crate::config::SessionConfig::default(),
            keybindings: crate::config::KeybindingsConfig::default(),
            vdd: VddConfig::default(),
            guardrails: crate::config::GuardrailsConfig::default(),
            permissions: crate::config::PermissionsConfig::default(),
            memory: crate::config::MemoryConfig::default(),
            web_fetch: crate::config::WebFetchConfig::default(),
            remote_actions: crate::config::RemoteActionsConfig::default(),
            policy: crate::services::policy::EnterprisePolicy::default(),
            managed_settings_path: None,
        }
    }

    #[test]
    fn test_parse_findings_valid_json() {
        let response = r#"{"findings": [{"severity": "HIGH", "cwe": "CWE-89", "description": "SQL injection", "file": "src/db.rs", "lines": [10, 20], "reasoning": "User input concatenated"}], "assessment": "FINDINGS_PRESENT"}"#;
        let findings = parse_findings(response, 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].cwe, Some("CWE-89".to_string()));
        assert_eq!(findings[0].description, "SQL injection");
        assert_eq!(findings[0].file_path, Some("src/db.rs".to_string()));
        assert_eq!(findings[0].line_range, Some((10, 20)));
    }

    #[test]
    fn test_parse_findings_no_findings() {
        let response = r#"{"findings": [], "assessment": "NO_FINDINGS"}"#;
        let findings = parse_findings(response, 1);
        assert!(findings.is_empty());
    }

    /// crosslink #879: parse-failure and intentional `NO_FINDINGS` are
    /// distinct conditions and the detailed parser MUST surface them
    /// with different `ParseFindingsOutcome` variants. The old flat
    /// `Vec<Finding>` shape conflated both into "empty".
    #[test]
    fn parse_findings_detailed_distinguishes_no_findings_from_parse_error() {
        let no_findings = r#"{"findings": [], "assessment": "NO_FINDINGS"}"#;
        match parse_findings_detailed(no_findings, 1) {
            ParseFindingsOutcome::NoFindings => {}
            other => panic!("expected NoFindings, got {other:?}"),
        }

        // Pure garbage: not JSON in any form.
        let garbage = "<<<not json at all>>>";
        match parse_findings_detailed(garbage, 1) {
            ParseFindingsOutcome::ParseError { kind } => {
                assert_eq!(kind, ParseErrorKind::NotJson);
                assert_eq!(kind.as_str(), "not_json");
            }
            other => panic!("expected ParseError(NotJson), got {other:?}"),
        }

        // JSON object but no `findings` field, no NO_FINDINGS assessment.
        let no_field = r#"{"assessment": "OTHER"}"#;
        match parse_findings_detailed(no_field, 1) {
            ParseFindingsOutcome::ParseError { kind } => {
                assert_eq!(kind, ParseErrorKind::MissingFindingsField);
                assert_eq!(kind.as_str(), "missing_findings_field");
            }
            other => panic!("expected ParseError(MissingFindingsField), got {other:?}"),
        }
    }

    #[test]
    fn detailed_parser_rejects_partial_contradictory_and_prose_clean_outputs() {
        for invalid in [
            r#"{"findings": []}"#,
            r#"{"findings": [], "assessment": "FINDINGS_PRESENT"}"#,
            r#"{"findings": [], "assessment": "NO_FINDINGS", "truncated": true}"#,
            r#"{"findings": [{"description": "reachable defect"}], "assessment": "NO_FINDINGS"}"#,
            "The code looks good and has no issues.",
            "",
        ] {
            assert!(
                matches!(
                    parse_findings_detailed(invalid, 1),
                    ParseFindingsOutcome::ParseError { .. }
                ),
                "accepted non-terminal adversary output: {invalid:?}"
            );
        }
    }

    /// Regression test for crosslink #478: `parse_findings` used `Uuid::new_v4`
    /// per finding, which made finding ids non-deterministic and broke
    /// `HashMap`-keyed verdict lookup in tests. The replacement derives the id
    /// from (`iteration`, `ordinal_index`, `file_path`, `line_range`,
    /// `severity`, `cwe`, `description`), so repeated parses of the same
    /// input yield equal ids.
    #[test]
    fn test_parse_findings_ids_are_deterministic() {
        let response = r#"{"findings": [
            {"severity": "HIGH", "cwe": "CWE-89", "description": "SQL injection", "file": "src/db.rs", "lines": [10, 20], "reasoning": "User input concatenated"},
            {"severity": "MEDIUM", "cwe": "CWE-79", "description": "XSS in renderer", "file": "src/web.rs", "lines": [5, 7]}
        ], "assessment": "FINDINGS_PRESENT"}"#;

        let a = parse_findings(response, 1);
        let b = parse_findings(response, 1);
        assert_eq!(a.len(), 2);
        assert_eq!(b.len(), 2);
        for (fa, fb) in a.iter().zip(b.iter()) {
            assert_eq!(fa.id, fb.id, "finding ids must be stable across calls");
        }
        // Different ordinals must yield different ids — guards against a
        // bug where two findings inside the same response collapse onto the
        // same id and the second one's verdict overwrites the first.
        assert_ne!(a[0].id, a[1].id);
        // Iteration must be part of the key: same payload at iteration 2
        // should not collide with iteration 1 (so verdicts from a prior
        // iteration can't silently rebind to a new finding).
        let c = parse_findings(response, 2);
        assert_ne!(a[0].id, c[0].id);
    }

    /// Tuple matches are review hints, not authority to demote a finding.
    #[tokio::test]
    async fn test_triage_keeps_tuple_duplicate_genuine_without_verification() {
        let config = VddConfig::default();
        let app_config = test_app_config();
        let client = Client::new();

        let mut findings = vec![Finding {
            id: "1".to_string(),
            severity: Severity::High,
            cwe: Some("CWE-89".to_string()),
            description: "SQL injection in query builder module".to_string(),
            file_path: Some("src/db.rs".to_string()),
            line_range: Some((10, 20)),
            status: FindingStatus::Genuine,
            adversary_reasoning: String::new(),
            iteration: 2,
        }];

        // Previously confirmed FP at the same tuple. Synonym-worded causes
        // may still be distinct, so this remains only a review hint.
        let previous_fps = vec![FindingIdentity {
            file_path: Some("src/db.rs".to_string()),
            severity: Severity::High,
            cwe: Some("CWE-89".to_string()),
            line_range: Some((10, 20)),
            description: "String concatenation vulnerability in users table".to_string(),
        }];
        let ctx = TriageContext {
            run: crate::tools::security::test_run_context(),
            client: &client,
            config: &config,
            app_config: &app_config,
            previous_fps: &previous_fps,
            builder_code: "let q = format!(\"SELECT * FROM users WHERE id = {}\", x);",
            builder_provider: "test",
            builder_api_key: None,
            builder_auth: None,
        };
        triage_findings(&mut findings, &ctx).await;
        assert_eq!(findings[0].status, FindingStatus::Genuine);
    }

    /// Two findings with the same (file, severity) but different CWE must
    /// both survive Layer 1. Regression test for crosslink #349 — the old
    /// Jaccard impl could collapse them via stop-word overlap.
    #[tokio::test]
    async fn test_triage_keeps_distinct_cwe_on_same_file() {
        let config = VddConfig::default();
        let app_config = test_app_config();
        let client = Client::new();

        let mut findings = vec![Finding {
            id: "1".to_string(),
            severity: Severity::High,
            cwe: Some("CWE-79".to_string()),
            description: "XSS in template renderer".to_string(),
            file_path: Some("src/web.rs".to_string()),
            line_range: Some((100, 110)),
            status: FindingStatus::Genuine,
            adversary_reasoning: String::new(),
            iteration: 2,
        }];

        let previous_fps = vec![FindingIdentity {
            file_path: Some("src/web.rs".to_string()),
            severity: Severity::High,
            cwe: Some("CWE-89".to_string()), // different CWE
            line_range: Some((100, 110)),
            description: "SQL injection in template renderer".to_string(),
        }];
        let ctx = TriageContext {
            run: crate::tools::security::test_run_context(),
            client: &client,
            config: &config,
            app_config: &app_config,
            previous_fps: &previous_fps,
            builder_code: "let html = format!(\"<div>{}</div>\", user_input);",
            builder_provider: "nonexistent-provider", // AI layer will fail; we expect Genuine
            builder_api_key: None,
            builder_auth: None,
        };
        triage_findings(&mut findings, &ctx).await;
        assert_eq!(
            findings[0].status,
            FindingStatus::Genuine,
            "different CWE must not be treated as duplicate"
        );
    }

    /// Same file+cwe+severity but different line ranges → not duplicates.
    /// Two genuinely different findings in the same file must both survive.
    #[tokio::test]
    async fn test_triage_keeps_distinct_line_ranges() {
        let config = VddConfig::default();
        let app_config = test_app_config();
        let client = Client::new();

        let mut findings = vec![Finding {
            id: "1".to_string(),
            severity: Severity::High,
            cwe: Some("CWE-89".to_string()),
            description: "SQL injection at second call site".to_string(),
            file_path: Some("src/db.rs".to_string()),
            line_range: Some((200, 210)),
            status: FindingStatus::Genuine,
            adversary_reasoning: String::new(),
            iteration: 2,
        }];

        let previous_fps = vec![FindingIdentity {
            file_path: Some("src/db.rs".to_string()),
            severity: Severity::High,
            cwe: Some("CWE-89".to_string()),
            line_range: Some((10, 20)), // different range
            description: "SQL injection at first call site".to_string(),
        }];
        let ctx = TriageContext {
            run: crate::tools::security::test_run_context(),
            client: &client,
            config: &config,
            app_config: &app_config,
            previous_fps: &previous_fps,
            builder_code: "fn x() {} fn y() {}",
            builder_provider: "nonexistent-provider",
            builder_api_key: None,
            builder_auth: None,
        };
        triage_findings(&mut findings, &ctx).await;
        assert_eq!(
            findings[0].status,
            FindingStatus::Genuine,
            "different line range must not be treated as duplicate"
        );
    }

    /// Stop-word-heavy descriptions with DIFFERENT tuples must not collapse.
    /// Regression test for the prior Jaccard-on-whitespace false positive:
    /// "the issue is in the helper" shares enough stop words with itself
    /// across two files to trip the 0.7 threshold, yet the findings target
    /// completely different code.
    #[tokio::test]
    async fn test_triage_does_not_collapse_stopword_heavy_unrelated_findings() {
        let config = VddConfig::default();
        let app_config = test_app_config();
        let client = Client::new();

        let mut findings = vec![Finding {
            id: "1".to_string(),
            severity: Severity::Medium,
            cwe: Some("CWE-20".to_string()),
            description: "the issue is that the value in the helper is not checked properly"
                .to_string(),
            file_path: Some("src/auth.rs".to_string()),
            line_range: Some((30, 35)),
            status: FindingStatus::Genuine,
            adversary_reasoning: String::new(),
            iteration: 2,
        }];

        let previous_fps = vec![FindingIdentity {
            file_path: Some("src/db.rs".to_string()), // different file
            severity: Severity::Medium,
            cwe: Some("CWE-20".to_string()),
            line_range: Some((30, 35)),
            description: "the issue is that the value in the helper is not checked properly"
                .to_string(),
        }];
        let ctx = TriageContext {
            run: crate::tools::security::test_run_context(),
            client: &client,
            config: &config,
            app_config: &app_config,
            previous_fps: &previous_fps,
            builder_code: "fn auth_helper() {} fn db_helper() {}",
            builder_provider: "nonexistent-provider",
            builder_api_key: None,
            builder_auth: None,
        };
        triage_findings(&mut findings, &ctx).await;
        assert_eq!(
            findings[0].status,
            FindingStatus::Genuine,
            "stop-word-heavy descriptions at different files must NOT collapse"
        );
    }

    /// A weak description-prefix match is also only a review hint.
    #[tokio::test]
    async fn test_triage_weak_fallback_keeps_reissue_genuine() {
        let config = VddConfig::default();
        let app_config = test_app_config();
        let client = Client::new();

        let mut findings = vec![Finding {
            id: "1".to_string(),
            severity: Severity::Low,
            cwe: None,
            description: "Possible panic in helper if input is malformed".to_string(),
            file_path: Some("src/x.rs".to_string()),
            line_range: None,
            status: FindingStatus::Genuine,
            adversary_reasoning: String::new(),
            iteration: 2,
        }];

        let previous_fps = vec![FindingIdentity {
            file_path: Some("src/x.rs".to_string()),
            severity: Severity::Low,
            cwe: None,
            line_range: None,
            description: "Possible panic in helper if input is malformed (re-reported)".to_string(),
        }];
        let ctx = TriageContext {
            run: crate::tools::security::test_run_context(),
            client: &client,
            config: &config,
            app_config: &app_config,
            previous_fps: &previous_fps,
            builder_code: "fn helper(s: &str) {}",
            builder_provider: "nonexistent-provider",
            builder_api_key: None,
            builder_auth: None,
        };
        triage_findings(&mut findings, &ctx).await;
        assert_eq!(findings[0].status, FindingStatus::Genuine);
    }

    /// Historical prose patterns are hints, not proof of a false positive.
    #[tokio::test]
    async fn test_triage_keeps_common_pattern_genuine_without_verification() {
        let config = VddConfig::default();
        let app_config = test_app_config();
        let client = Client::new();

        let mut findings = vec![Finding {
            id: "1".to_string(),
            severity: Severity::High,
            cwe: Some("CWE-362".to_string()),
            description: "Panic on poisoned mutex — unwrap() on mutex can crash".to_string(),
            file_path: Some("src/main.rs".to_string()),
            line_range: Some((10, 10)),
            status: FindingStatus::Genuine,
            adversary_reasoning: "The code calls unwrap() on mutex which panics if poisoned"
                .to_string(),
            iteration: 1,
        }];

        // The historical pattern is visible to triage but cannot demote it.
        let ctx = TriageContext {
            run: crate::tools::security::test_run_context(),
            client: &client,
            config: &config,
            app_config: &app_config,
            previous_fps: &[],
            builder_code: "let guard = mutex.lock().unwrap();",
            builder_provider: "test",
            builder_api_key: None,
            builder_auth: None,
        };
        triage_findings(&mut findings, &ctx).await;
        assert_eq!(findings[0].status, FindingStatus::Genuine);
    }

    /// Test that findings surviving layers 1-2 remain Genuine when
    /// AI verification fails (non-blocking fallback).
    #[tokio::test]
    async fn test_triage_ai_failure_is_nonblocking() {
        let config = VddConfig::default();
        let app_config = test_app_config(); // No provider = AI call will fail
        let client = Client::new();

        let mut findings = vec![Finding {
            id: "novel-issue".to_string(),
            severity: Severity::High,
            cwe: Some("CWE-89".to_string()),
            description: "Novel SQL injection that no pattern catches".to_string(),
            file_path: Some("src/db.rs".to_string()),
            line_range: Some((45, 52)),
            status: FindingStatus::Genuine,
            adversary_reasoning: "User input concatenated into query".to_string(),
            iteration: 1,
        }];

        // AI verification will fail (no provider configured) but should
        // warn the user and keep the finding as Genuine (safe fallback).
        let ctx = TriageContext {
            run: crate::tools::security::test_run_context(),
            client: &client,
            config: &config,
            app_config: &app_config,
            previous_fps: &[],
            builder_code: "let query = format!(\"SELECT * FROM users WHERE id = {}\", user_input);",
            builder_provider: "nonexistent-provider",
            builder_api_key: None,
            builder_auth: None,
        };
        triage_findings(&mut findings, &ctx).await;
        assert_eq!(
            findings[0].status,
            FindingStatus::Genuine,
            "AI verification failure must not demote genuine findings"
        );
    }

    // --- Regression tests for crosslink #498 ---

    fn finding_with_lines(id: &str, start: usize, end: usize) -> Finding {
        Finding {
            id: id.to_string(),
            severity: Severity::Medium,
            cwe: None,
            file_path: Some("lib.rs".to_string()),
            line_range: Some((start, end)),
            description: format!("finding {id}"),
            adversary_reasoning: String::new(),
            status: FindingStatus::Genuine,
            iteration: 0,
        }
    }

    #[test]
    fn code_view_returns_whole_body_when_under_cap() {
        let code = "line1\nline2\nline3\n";
        let f = finding_with_lines("f1", 2, 2);
        let findings: Vec<&Finding> = vec![&f];
        let (view, truncated) = build_verification_code_view(code, &findings, 1000);
        assert_eq!(view, code);
        assert!(!truncated);
    }

    #[test]
    fn code_view_extracts_window_around_cited_lines() {
        // 200 lines, finding cites lines 150-152. Max bytes forces a
        // window view rather than the whole body.
        let code: String = (1..=200).fold(String::new(), |mut s, n| {
            let _ = writeln!(s, "line {n}");
            s
        });
        let f = finding_with_lines("f1", 150, 152);
        let findings: Vec<&Finding> = vec![&f];
        let (view, _) = build_verification_code_view(&code, &findings, 500);
        // Must contain the cited lines even though they're deep in the file.
        assert!(view.contains("line 150"), "missing cited line: {view}");
        assert!(view.contains("line 152"), "missing cited line: {view}");
        // Context lines above/below should also be present.
        assert!(view.contains("line 135") || view.contains("line 140"));
    }

    #[test]
    fn code_view_merges_overlapping_windows() {
        let code: String = (1..=200).fold(String::new(), |mut s, n| {
            let _ = writeln!(s, "line {n}");
            s
        });
        let f1 = finding_with_lines("f1", 50, 52);
        let f2 = finding_with_lines("f2", 55, 57); // overlaps f1's ±20 window
        let findings: Vec<&Finding> = vec![&f1, &f2];
        let (view, _) = build_verification_code_view(&code, &findings, 2000);
        // Should have exactly one `...` separator (none) because the
        // windows merged.
        assert!(
            !view.contains("\n...\n"),
            "overlapping windows not merged: {view}"
        );
        assert!(view.contains("line 50"));
        assert!(view.contains("line 57"));
    }

    #[test]
    fn code_view_falls_back_to_truncation_when_no_line_info() {
        let code: String = "x".repeat(5000);
        let f = Finding {
            id: "f1".to_string(),
            severity: Severity::Medium,
            cwe: None,
            file_path: None,
            line_range: None,
            description: "no lines".to_string(),
            adversary_reasoning: String::new(),
            status: FindingStatus::Genuine,
            iteration: 0,
        };
        let findings: Vec<&Finding> = vec![&f];
        let (view, truncated) = build_verification_code_view(&code, &findings, 1000);
        assert!(truncated);
        assert!(view.contains("truncated"));
    }

    #[test]
    fn code_view_rejects_hostile_ranges_without_panicking() {
        let code: String = (1..=200).fold(String::new(), |mut output, line| {
            let _ = writeln!(output, "line {line}");
            output
        });

        for (start, end) in [
            (0, 1),
            (80, 40),
            (201, 201),
            (1, 201),
            (usize::MAX, usize::MAX),
        ] {
            let finding = finding_with_lines("hostile", start, end);
            let findings = vec![&finding];
            let (_, incomplete) = build_verification_code_view(&code, &findings, 500);
            assert!(incomplete, "accepted hostile range {start}-{end}");
        }
    }
}
