//! Grounded loop data shapes that sit above provider adapters.
//!
//! Providers should only translate wire formats. This module describes the
//! packet the core loop should assemble before provider calls: authoritative
//! ledger entries first, lower-authority navigation aids later.

use crate::evidence::Denial;
use crate::ledger::{
    ActiveRealityLedgerGuard, Authority, LedgerError, ObservationKind, RealityLedger,
};
use crate::ledger::{ObsId, ObservationIndexEntry};
use crate::task_spec::TaskSpec;
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::path::Path;

pub const DEFAULT_GROUNDING_INDEX_LIMIT: usize = 64;
pub const TOOL_RESULT_LEDGER_CONTENT_MAX_BYTES: usize = 16 * 1024;
pub const LEDGER_VERIFICATION_OUTPUT_MAX_BYTES: usize = 20_000;
const MAX_RENDERED_TASK_CHARS: usize = 500;
const MAX_NAV_IDS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroundingPriority {
    RealityLedger = 0,
    TaskSpec = 1,
    CurrentDiff = 2,
    VerifierResults = 3,
    Summaries = 4,
    Memory = 5,
    ProviderChatHistory = 6,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundedPromptPacket {
    pub task: TaskSpec,
    pub ledger_index: Vec<ObservationIndexEntry>,
    pub current_diff: Option<ObsId>,
    pub verifier_results: Vec<ObsId>,
    pub summaries: Vec<ObsId>,
    pub memory: Vec<String>,
    pub provider_chat_history: Vec<serde_json::Value>,
}

impl GroundedPromptPacket {
    #[must_use]
    pub const fn new(task: TaskSpec, ledger_index: Vec<ObservationIndexEntry>) -> Self {
        Self {
            task,
            ledger_index,
            current_diff: None,
            verifier_results: Vec::new(),
            summaries: Vec::new(),
            memory: Vec::new(),
            provider_chat_history: Vec::new(),
        }
    }
}

/// Build the grounded prompt packet for a provider turn.
///
/// # Errors
///
/// Returns [`Denial`] when `task_obs` does not identify a user task
/// observation in the ledger.
pub fn build_prompt_packet(
    ledger: &RealityLedger,
    task_obs: ObsId,
    index_limit: usize,
    provider_chat_history: Vec<serde_json::Value>,
) -> Result<GroundedPromptPacket, Denial> {
    let task = TaskSpec::from_user_observation(ledger, task_obs)?;
    let mut packet = GroundedPromptPacket::new(task, ledger.observation_index(index_limit));
    packet.provider_chat_history = provider_chat_history;

    let observations = ledger.observations_chronological();
    packet.current_diff = observations
        .iter()
        .rev()
        .find(|obs| {
            matches!(obs.kind, ObservationKind::DiffObserved { .. }) && !ledger.is_stale(obs.id)
        })
        .map(|obs| obs.id);
    packet.verifier_results = observations
        .iter()
        .filter(|obs| {
            obs.authority == Authority::Verifier
                && matches!(obs.kind, ObservationKind::Verification { .. })
                && !ledger.is_stale(obs.id)
        })
        .rev()
        .take(MAX_NAV_IDS)
        .map(|obs| obs.id)
        .collect::<Vec<_>>();
    packet.verifier_results.reverse();
    packet.summaries = observations
        .iter()
        .filter(|obs| matches!(obs.kind, ObservationKind::Summary { .. }))
        .rev()
        .take(MAX_NAV_IDS)
        .map(|obs| obs.id)
        .collect::<Vec<_>>();
    packet.summaries.reverse();

    Ok(packet)
}

pub fn observe_session_user_task(session_id: &str, content: &str) -> Option<ObsId> {
    let mut ledger = match RealityLedger::open_project_session(session_id) {
        Ok(ledger) => ledger,
        Err(err) => {
            tracing::warn!(
                session_id,
                error = %err,
                "failed to open session reality ledger for user task"
            );
            return None;
        }
    };
    match ledger.observe_user_task(content.to_string()) {
        Ok(id) => Some(id),
        Err(err) => {
            tracing::warn!(
                session_id,
                error = %err,
                "failed to append user task observation to reality ledger"
            );
            None
        }
    }
}

#[must_use]
pub fn install_active_project_ledger_for_session(
    session_id: &str,
) -> Option<ActiveRealityLedgerGuard> {
    if crate::ledger::active_ledger_for_session(session_id).is_some() {
        return None;
    }
    let ledger = match RealityLedger::open_project_session(session_id) {
        Ok(ledger) => ledger,
        Err(err) => {
            tracing::warn!(
                session_id,
                error = %err,
                "failed to open session reality ledger; tool observations disabled"
            );
            return None;
        }
    };
    Some(crate::ledger::install_active_ledger_for_session(
        session_id,
        std::sync::Arc::new(std::sync::Mutex::new(ledger)),
    ))
}

pub fn observe_tool_result_for_session(
    session_id: &str,
    tool_name: &str,
    result: &crate::tools::ToolResult,
) -> Option<ObsId> {
    if let Some(shared) = crate::ledger::active_ledger_for_session(session_id) {
        let mut ledger = shared.lock().unwrap_or_else(|err| {
            tracing::error!("active reality ledger lock poisoned; recovering inner state");
            err.into_inner()
        });
        return match append_tool_result_observation(&mut ledger, tool_name, result) {
            Ok(id) => Some(id),
            Err(err) => {
                tracing::warn!(
                    session_id,
                    tool = tool_name,
                    error = %err,
                    "failed to append tool result observation to active reality ledger"
                );
                None
            }
        };
    }

    let mut ledger = match RealityLedger::open_project_session(session_id) {
        Ok(ledger) => ledger,
        Err(err) => {
            tracing::warn!(
                session_id,
                tool = tool_name,
                error = %err,
                "failed to open session reality ledger for tool result observation"
            );
            return None;
        }
    };
    match append_tool_result_observation(&mut ledger, tool_name, result) {
        Ok(id) => Some(id),
        Err(err) => {
            tracing::warn!(
                session_id,
                tool = tool_name,
                error = %err,
                "failed to append tool result observation to reality ledger"
            );
            None
        }
    }
}

pub fn observe_shell_command_for_session(
    session_id: &str,
    cwd: &Path,
    command: &str,
    exit_code: i32,
    stdout: &str,
    stderr: &str,
) {
    crate::tools::record_command_observation_for_session(
        session_id, cwd, command, exit_code, stdout, stderr,
    );
}

/// Append a bounded model-visible tool result observation.
///
/// # Errors
///
/// Returns [`LedgerError`] when ledger persistence fails.
pub fn append_tool_result_observation(
    ledger: &mut RealityLedger,
    tool_name: &str,
    result: &crate::tools::ToolResult,
) -> Result<ObsId, LedgerError> {
    let content =
        crate::tools::safe_truncate(result.content(), TOOL_RESULT_LEDGER_CONTENT_MAX_BYTES)
            .to_string();
    ledger.observe_tool_result(
        tool_name,
        serde_json::json!({
            "tool_call_id": result.tool_call_id(),
            "is_error": result.is_error(),
            "content": content,
            "truncated": result.content().len() > content.len(),
        }),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QualityGateObservationIds {
    pub command: ObsId,
    pub verification: ObsId,
}

/// Append command and verifier observations for a quality gate result.
///
/// # Errors
///
/// Returns [`LedgerError`] when either observation cannot be persisted.
pub fn append_quality_gate_observations(
    run: &crate::tools::ToolRunContext,
    ledger: &mut RealityLedger,
    gate: &crate::guardrails::QualityCheckResult,
) -> Result<QualityGateObservationIds, LedgerError> {
    let cwd = run.working_directory().to_string_lossy().to_string();
    let command = ledger.observe_command_run(
        cwd,
        quality_gate_argv(&gate.command),
        gate.exit_code,
        crate::tools::safe_truncate(&gate.stdout, LEDGER_VERIFICATION_OUTPUT_MAX_BYTES).to_string(),
        crate::tools::safe_truncate(&gate.stderr, LEDGER_VERIFICATION_OUTPUT_MAX_BYTES).to_string(),
    )?;

    let mut findings = Vec::new();
    if !gate.passed {
        findings.push(format!(
            "quality gate '{}' failed: exit_code={} required={}",
            gate.name, gate.exit_code, gate.required
        ));
        if !gate.stdout.trim().is_empty() {
            findings.push(format!(
                "stdout: {}",
                crate::tools::safe_truncate(&gate.stdout, LEDGER_VERIFICATION_OUTPUT_MAX_BYTES)
            ));
        }
        if !gate.stderr.trim().is_empty() {
            findings.push(format!(
                "stderr: {}",
                crate::tools::safe_truncate(&gate.stderr, LEDGER_VERIFICATION_OUTPUT_MAX_BYTES)
            ));
        }
    }
    let verification = ledger.append(
        Authority::Verifier,
        ObservationKind::Verification {
            passed: gate.passed,
            command: Some(gate.command.clone()),
            findings,
        },
    )?;

    Ok(QualityGateObservationIds {
        command,
        verification,
    })
}

fn quality_gate_argv(command: &str) -> Vec<String> {
    shlex::split(command)
        .filter(|argv| !argv.is_empty())
        .unwrap_or_else(|| vec![command.to_string()])
}

#[must_use]
pub fn session_grounding_system_content(session_id: &str, task_obs: ObsId) -> Option<String> {
    session_grounding_system_content_checked(session_id, task_obs).ok()
}

/// Render a grounding system message for an existing session ledger.
///
/// # Errors
///
/// Returns a string error when the session ledger cannot be opened or the
/// grounding packet cannot be built from the task observation.
pub fn session_grounding_system_content_checked(
    session_id: &str,
    task_obs: ObsId,
) -> Result<String, String> {
    let ledger = RealityLedger::open_project_session(session_id).map_err(|err| {
        tracing::warn!(
            session_id,
            error = %err,
            "failed to open session reality ledger for grounding packet"
        );
        format!("grounding requires reality ledger: {err}")
    })?;
    let packet = build_prompt_packet(&ledger, task_obs, DEFAULT_GROUNDING_INDEX_LIMIT, Vec::new())
        .map_err(|err| {
            tracing::warn!(
                session_id,
                reason = %err.reason(),
                "failed to build grounding packet"
            );
            format!("failed to build grounding packet: {}", err.reason())
        })?;
    Ok(render_grounding_system_message(&packet))
}

/// Insert a grounding system message into provider request messages.
///
/// # Errors
///
/// Returns a string error when no task observation is available, the ledger
/// cannot be opened, or the rendered grounding packet is empty.
pub fn request_messages_with_grounding(
    session_id: &str,
    task_obs: Option<ObsId>,
    session_messages: &[serde_json::Value],
) -> Result<Vec<serde_json::Value>, String> {
    let mut request_messages = session_messages.to_vec();
    let task_obs = task_obs.ok_or_else(|| {
        "grounding requires user task observation before provider request".to_string()
    })?;
    let content = session_grounding_system_content_checked(session_id, task_obs)?;
    if content.trim().is_empty() {
        return Err("grounding packet is empty".to_string());
    }
    let insert_at = request_messages
        .iter()
        .position(|message| message.get("role").and_then(|role| role.as_str()) != Some("system"))
        .unwrap_or(request_messages.len());
    request_messages.insert(
        insert_at,
        serde_json::json!({
            "role": "system",
            "content": content,
            "metadata": {
                "openclaudia_context_source": "reality"
            }
        }),
    );
    Ok(request_messages)
}

/// Validate a final model response against the persisted session ledger.
///
/// # Errors
///
/// Returns a string error when the ledger cannot be opened or the response is
/// denied by the final-answer gate.
pub fn validate_agentic_final_response(session_id: &str, content: &str) -> Result<(), String> {
    validate_and_render_agentic_final_response(session_id, content).map(|_| ())
}

/// Extract the user-facing summary from a structured final decision.
///
/// This intentionally does not validate cited evidence. Callers that are only
/// cleaning up live display can use it to avoid rendering the JSON envelope,
/// while history/persistence paths should still call
/// [`validate_and_render_agentic_final_response`].
///
/// # Errors
///
/// Returns a string error when a final-shaped JSON payload is malformed.
pub fn structured_final_summary(content: &str) -> Result<Option<String>, String> {
    match parse_structured_final_decision(content)? {
        Some(crate::decision::AgentDecision::Final { summary, .. }) => Ok(Some(summary)),
        Some(_) => Err("structured final decision validated as a non-final decision".to_string()),
        None => Ok(None),
    }
}

/// Validate a final model response and return the human-rendered final text.
///
/// Plain assistant text is accepted directly, matching Codex-style typed
/// message handling. Structured final decisions remain available when a turn
/// explicitly needs grounded evidence and verification IDs.
///
/// # Errors
///
/// Returns a string error when the ledger cannot be opened or the response is
/// denied by the final-answer gate.
pub fn validate_and_render_agentic_final_response(
    session_id: &str,
    content: &str,
) -> Result<String, String> {
    if content.trim().is_empty() {
        return Ok(String::new());
    }
    let mut ledger = match RealityLedger::open_project_session(session_id) {
        Ok(ledger) => ledger,
        Err(err) => {
            let reason = format!("final answer requires reality ledger: {err}");
            tracing::warn!(
                session_id,
                error = %err,
                "failed to open session reality ledger for final gate"
            );
            return Err(reason);
        }
    };
    validate_and_render_final_against_ledger(&mut ledger, content)
}

/// Validate final text against an already-open ledger and record the decision.
///
/// # Errors
///
/// Returns a string error when the final-answer gate denies the response.
pub fn validate_final_against_ledger(
    ledger: &mut RealityLedger,
    content: &str,
) -> Result<(), String> {
    validate_and_render_final_against_ledger(ledger, content).map(|_| ())
}

/// Validate final text against an already-open ledger and return rendered text.
///
/// `AgentDecision::Final` JSON is validated directly. Plain assistant text is
/// rendered as message text, matching Codex's typed message handling.
///
/// # Errors
///
/// Returns a string error when structured final validation denies the response.
pub fn validate_and_render_final_against_ledger(
    ledger: &mut RealityLedger,
    content: &str,
) -> Result<String, String> {
    match parse_structured_final_decision(content) {
        Ok(Some(decision)) => return validate_and_render_structured_final(ledger, &decision),
        Ok(None) => {}
        Err(reason) => {
            append_final_policy_decision(ledger, false, &reason);
            return Err(reason);
        }
    }

    append_final_policy_decision(ledger, true, "plain assistant final rendered");
    Ok(content.to_string())
}

fn validate_and_render_structured_final(
    ledger: &mut RealityLedger,
    decision: &crate::decision::AgentDecision,
) -> Result<String, String> {
    let crate::decision::AgentDecision::Final { summary, .. } = decision else {
        let reason = "structured final decision must have kind 'final'".to_string();
        append_final_policy_decision(ledger, false, &reason);
        return Err(reason);
    };

    match crate::decision::validate_decision(decision, ledger) {
        Ok(crate::decision::DecisionValidation::Final(_)) => {
            append_final_policy_decision(ledger, true, "structured final decision grounded");
            Ok(summary.clone())
        }
        Ok(_) => {
            let reason = "structured final decision validated as a non-final decision".to_string();
            append_final_policy_decision(ledger, false, &reason);
            Err(reason)
        }
        Err(denial) => {
            let reason = denial.reason().to_string();
            append_final_policy_decision(ledger, false, &reason);
            Err(reason)
        }
    }
}

fn parse_structured_final_decision(
    content: &str,
) -> Result<Option<crate::decision::AgentDecision>, String> {
    let Some(candidate) = structured_json_candidate(content) else {
        return Ok(None);
    };
    let value = serde_json::from_str::<serde_json::Value>(candidate)
        .map_err(|err| format!("Invalid structured final decision JSON: {err}"))?;
    let Some(kind) = value.get("kind").and_then(serde_json::Value::as_str) else {
        return Ok(None);
    };
    if kind != "final" {
        return Err("structured final decision must have kind 'final'".to_string());
    }
    serde_json::from_value::<crate::decision::AgentDecision>(value)
        .map(Some)
        .map_err(|err| format!("Invalid structured final decision: {err}"))
}

fn structured_json_candidate(content: &str) -> Option<&str> {
    let trimmed = content.trim();
    if trimmed.starts_with('{') {
        return Some(trimmed);
    }

    let fenced = trimmed.strip_prefix("```")?;
    let fenced = fenced
        .strip_prefix("json")
        .or_else(|| fenced.strip_prefix("JSON"))
        .unwrap_or(fenced)
        .trim_start();
    let end = fenced.rfind("```")?;
    Some(fenced[..end].trim())
}

pub fn append_final_policy_decision(ledger: &mut RealityLedger, allowed: bool, reason: &str) {
    if let Err(err) = ledger.append(
        Authority::Policy,
        ObservationKind::PolicyDecision {
            allowed,
            reason: reason.to_string(),
        },
    ) {
        tracing::warn!(
            allowed,
            reason,
            error = %err,
            "failed to append final-gate policy decision to reality ledger"
        );
    }
}

pub fn observe_policy_decision_for_session(
    session_id: &str,
    allowed: bool,
    reason: &str,
) -> Option<ObsId> {
    if let Some(shared) = crate::ledger::active_ledger_for_session(session_id) {
        let mut ledger = shared.lock().unwrap_or_else(|err| {
            tracing::error!("active reality ledger lock poisoned; recovering inner state");
            err.into_inner()
        });
        return append_policy_decision_observation(&mut ledger, allowed, reason, session_id);
    }

    let mut ledger = match RealityLedger::open_project_session(session_id) {
        Ok(ledger) => ledger,
        Err(err) => {
            tracing::warn!(
                session_id,
                error = %err,
                "failed to open session reality ledger for policy decision"
            );
            return None;
        }
    };
    append_policy_decision_observation(&mut ledger, allowed, reason, session_id)
}

fn append_policy_decision_observation(
    ledger: &mut RealityLedger,
    allowed: bool,
    reason: &str,
    session_id: &str,
) -> Option<ObsId> {
    match ledger.append(
        Authority::Policy,
        ObservationKind::PolicyDecision {
            allowed,
            reason: reason.to_string(),
        },
    ) {
        Ok(id) => Some(id),
        Err(err) => {
            tracing::warn!(
                session_id,
                allowed,
                reason,
                error = %err,
                "failed to append policy decision to reality ledger"
            );
            None
        }
    }
}

#[must_use]
pub fn render_grounding_system_message(packet: &GroundedPromptPacket) -> String {
    let mut out = String::new();
    out.push_str("Grounding hierarchy for this turn:\n");
    out.push_str(
        "Reality Ledger > TaskSpec > Current Diff > Verifier Results > Summaries > Memory > Provider Chat History\n\n",
    );
    let _ = writeln!(
        out,
        "TaskSpec [{}]: {}",
        packet.task.source_obs,
        truncate_for_prompt(&packet.task.content, MAX_RENDERED_TASK_CHARS)
    );
    if let Some(diff_id) = packet.current_diff {
        let _ = writeln!(out, "Current diff observation: [{diff_id}]");
    }
    if !packet.verifier_results.is_empty() {
        let ids = packet
            .verifier_results
            .iter()
            .map(|id| format!("[{id}]"))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(out, "Verifier observations: {ids}");
    }
    out.push_str("\nReality ledger index:\n");
    for entry in &packet.ledger_index {
        let stale = if entry.stale { " stale" } else { "" };
        let _ = writeln!(
            out,
            "- [{}] {:?}{stale}: {}",
            entry.id, entry.authority, entry.label
        );
    }
    out.push_str(
        "\nRules: Use memory, summaries, and provider chat history only as navigation aids. Treat facts as grounded only when backed by non-stale, non-summary ledger observations. Use grounding_context to hydrate selected observation IDs when detailed evidence is needed. Final answers should be plain assistant text. Use structured final JSON {\"kind\":\"final\",\"summary\":\"...\",\"evidence\":[\"obs-id\"],\"verification\":[\"obs-id\"]} only when an explicitly grounded decision is required.\n",
    );
    out
}

fn truncate_for_prompt(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut truncated = text.chars().take(max_chars).collect::<String>();
    truncated.push_str("...");
    truncated
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::Authority;
    use std::sync::{Arc, Mutex};

    #[test]
    fn prompt_packet_orders_authoritative_context_before_navigation() {
        let mut ledger = RealityLedger::new();
        let task = ledger
            .observe_user_task("Audit the binary commands.")
            .expect("task");
        let read = ledger
            .observe_file_read("src/main.rs", "fn main() {}", 1, 1, "fn main() {}")
            .expect("read");
        let diff = ledger
            .observe_diff(
                vec!["src/main.rs".to_string()],
                "diff --git a/src/main.rs b/src/main.rs",
            )
            .expect("diff");
        let verification = ledger
            .append(
                Authority::Verifier,
                ObservationKind::Verification {
                    passed: true,
                    command: Some("cargo check".to_string()),
                    findings: Vec::new(),
                },
            )
            .expect("verification");
        let forged_verification = ledger
            .append(
                Authority::Tool,
                ObservationKind::Verification {
                    passed: true,
                    command: Some("cargo check".to_string()),
                    findings: Vec::new(),
                },
            )
            .expect("forged verification");
        let summary = ledger
            .append(
                Authority::ModelSummary,
                ObservationKind::Summary {
                    text: "navigational only".to_string(),
                    source_obs: vec![read],
                },
            )
            .expect("summary");

        let packet = build_prompt_packet(&ledger, task, DEFAULT_GROUNDING_INDEX_LIMIT, Vec::new())
            .expect("packet");
        assert_eq!(packet.task.source_obs, task);
        assert_eq!(packet.current_diff, Some(diff));
        assert_eq!(packet.verifier_results, vec![verification]);
        assert!(!packet.verifier_results.contains(&forged_verification));
        assert_eq!(packet.summaries, vec![summary]);
        assert!(packet
            .ledger_index
            .iter()
            .any(|entry| entry.id == read && entry.stale));
    }

    #[test]
    fn grounding_message_states_summary_and_memory_are_not_evidence() {
        let mut ledger = RealityLedger::new();
        let task = ledger.observe_user_task("Run cargo test.").expect("task");
        let packet = build_prompt_packet(&ledger, task, DEFAULT_GROUNDING_INDEX_LIMIT, Vec::new())
            .expect("packet");

        let rendered = render_grounding_system_message(&packet);
        assert!(rendered.contains("Reality Ledger > TaskSpec"));
        assert!(rendered.contains(&format!("TaskSpec [{task}]")));
        assert!(rendered.contains("navigation aids"));
        assert!(rendered.contains("\"kind\":\"final\""));
        assert!(rendered.contains("Final answers should be plain assistant text"));
        assert!(rendered.contains("explicitly grounded decision"));
    }

    #[test]
    fn request_messages_with_grounding_fails_without_task_observation() {
        let err = request_messages_with_grounding("missing-task-observation", None, &[])
            .expect_err("provider request must not silently continue without a task observation");

        assert_eq!(
            err,
            "grounding requires user task observation before provider request"
        );
    }

    #[test]
    fn request_messages_with_grounding_fails_when_ledger_cannot_open() {
        let task = ObsId::new();
        let err = request_messages_with_grounding("invalid/session", Some(task), &[])
            .expect_err("provider request must not silently continue without the reality ledger");

        assert!(
            err.contains("grounding requires reality ledger"),
            "unexpected denial: {err}"
        );
    }

    #[test]
    fn shell_command_shortcut_records_command_and_verification() {
        let session_id = "legacy-repl-shell-shortcut-ledger-test";
        let ledger = Arc::new(Mutex::new(RealityLedger::new()));
        let _guard = crate::ledger::install_active_ledger_for_session(session_id, ledger.clone());

        observe_shell_command_for_session(
            session_id,
            Path::new("/tmp/project"),
            "cargo check --all-targets",
            0,
            "finished",
            "",
        );

        let observations = {
            let ledger = ledger.lock().expect("ledger lock");
            ledger
                .observations_chronological()
                .into_iter()
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(observations.len(), 2);
        assert!(observations.iter().any(|obs| {
            matches!(
                &obs.kind,
                ObservationKind::CommandRun {
                    cwd,
                    argv,
                    exit_code,
                    stdout,
                    stderr,
                } if cwd == "/tmp/project"
                    && argv == &vec![
                        "bash".to_string(),
                        "-c".to_string(),
                        "cargo check --all-targets".to_string(),
                    ]
                    && *exit_code == 0
                    && stdout == "finished"
                    && stderr.is_empty()
            )
        }));
        assert!(observations.iter().any(|obs| {
            matches!(
                &obs.kind,
                ObservationKind::Verification {
                    passed,
                    command,
                    findings,
                } if *passed
                    && command.as_deref() == Some("cargo check --all-targets")
                    && findings.iter().any(|finding| finding.contains("exited with code 0"))
            )
        }));
    }

    #[test]
    fn structured_final_decision_renders_summary_and_records_allow() {
        let mut ledger = RealityLedger::new();
        let task = ledger
            .observe_user_task("Verify the command path.")
            .expect("task");
        let command = ledger
            .observe_command_run(
                "/repo",
                vec!["cargo".to_string(), "test".to_string()],
                0,
                "ok",
                "",
            )
            .expect("command");
        let verification = ledger
            .append(
                Authority::Verifier,
                ObservationKind::Verification {
                    passed: true,
                    command: Some("cargo test".to_string()),
                    findings: Vec::new(),
                },
            )
            .expect("verification");
        let content = serde_json::json!({
            "kind": "final",
            "summary": "Verified the command path with cargo test.",
            "evidence": [task, command],
            "verification": [verification]
        })
        .to_string();

        let rendered = validate_and_render_final_against_ledger(&mut ledger, &content)
            .expect("structured final should pass");

        assert_eq!(rendered, "Verified the command path with cargo test.");
        assert!(
            ledger.observations_chronological().iter().any(|obs| {
                matches!(
                    &obs.kind,
                    ObservationKind::PolicyDecision { allowed: true, reason }
                        if reason == "structured final decision grounded"
                )
            }),
            "structured final allow decision must be recorded"
        );
    }

    #[test]
    fn structured_final_decision_rejects_missing_verification_and_records_denial() {
        let mut ledger = RealityLedger::new();
        let task = ledger.observe_user_task("Return final.").expect("task");
        let content = serde_json::json!({
            "kind": "final",
            "summary": "Done.",
            "evidence": [task],
            "verification": []
        })
        .to_string();

        let err = validate_and_render_final_against_ledger(&mut ledger, &content)
            .expect_err("missing verification must be denied");

        assert_eq!(err, "final answer requires verification observation");
        assert!(
            ledger.observations_chronological().iter().any(|obs| {
                matches!(
                    &obs.kind,
                    ObservationKind::PolicyDecision { allowed: false, reason }
                        if reason == "final answer requires verification observation"
                )
            }),
            "structured final denial must be recorded"
        );
    }

    #[test]
    fn structured_final_decision_accepts_json_fence() {
        let mut ledger = RealityLedger::new();
        let task = ledger.observe_user_task("Summarize work.").expect("task");
        let verification = ledger
            .append(
                Authority::Verifier,
                ObservationKind::Verification {
                    passed: false,
                    command: None,
                    findings: vec!["not run".to_string()],
                },
            )
            .expect("verification");
        let content = format!(
            "```json\n{}\n```",
            serde_json::json!({
                "kind": "final",
                "summary": "Work is summarized; verification was not run.",
                "evidence": [task],
                "verification": [verification]
            })
        );

        let rendered = validate_and_render_final_against_ledger(&mut ledger, &content)
            .expect("fenced structured final should pass");

        assert_eq!(rendered, "Work is summarized; verification was not run.");
    }

    #[test]
    fn plain_assistant_final_renders_without_citation_gate() {
        let mut ledger = RealityLedger::new();

        let rendered =
            validate_and_render_final_against_ledger(&mut ledger, "Verified with cargo check.")
                .expect("plain assistant final should render");

        assert_eq!(rendered, "Verified with cargo check.");
        assert!(
            ledger.observations_chronological().iter().any(|obs| {
                matches!(
                    &obs.kind,
                    ObservationKind::PolicyDecision { allowed: true, reason }
                        if reason == "plain assistant final rendered"
                )
            }),
            "plain assistant final allow decision must be recorded"
        );
    }

    #[test]
    fn agentic_final_fails_closed_when_ledger_cannot_open() {
        let err = validate_agentic_final_response("invalid/session", "Done.")
            .expect_err("ledger open failure must deny non-empty final");

        assert!(
            err.contains("final answer requires reality ledger"),
            "unexpected denial: {err}"
        );
    }
}
