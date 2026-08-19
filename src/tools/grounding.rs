use crate::ledger::{Authority, ObsId, Observation, ObservationKind, RealityLedger};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};

const MAX_GROUNDING_OBSERVATION_IDS: usize = 16;
const MAX_GROUNDING_TEXT_BYTES: usize = 12 * 1024;

pub fn execute_grounding_context(
    session_key: &str,
    args: &HashMap<String, Value>,
) -> (String, bool) {
    let ids = match parse_obs_ids(args) {
        Ok(ids) => ids,
        Err(err) => return (err, true),
    };
    let include_stale = match parse_include_stale(args) {
        Ok(include_stale) => include_stale,
        Err(err) => return (err, true),
    };

    let ledger = if let Some(shared) = crate::ledger::active_ledger_for_session(session_key) {
        let ledger = shared.lock().unwrap_or_else(|err| {
            tracing::error!("active reality ledger lock poisoned; recovering inner state");
            err.into_inner()
        });
        hydrate_from_ledger(session_key, &ledger, &ids, include_stale)
    } else {
        match RealityLedger::open_existing_project_session(session_key) {
            Ok(ledger) => hydrate_from_ledger(session_key, &ledger, &ids, include_stale),
            Err(
                crate::ledger::LedgerError::InvalidSessionKey { .. }
                | crate::ledger::LedgerError::MissingSessionLedger { .. },
            ) => {
                return (
                    "No active session reality ledger is available for grounding_context"
                        .to_string(),
                    true,
                );
            }
            Err(err) => {
                return (
                    format!("Failed to open session reality ledger for grounding_context: {err}"),
                    true,
                );
            }
        }
    };

    match serde_json::to_string_pretty(&ledger) {
        Ok(text) => (text, false),
        Err(err) => (
            format!("Failed to serialize grounding_context response: {err}"),
            true,
        ),
    }
}

fn parse_obs_ids(args: &HashMap<String, Value>) -> Result<Vec<ObsId>, String> {
    let Some(raw_ids) = args.get("ids") else {
        return Err("Missing 'ids' argument".to_string());
    };
    let Some(raw_ids) = raw_ids.as_array() else {
        return Err("Invalid 'ids' argument: expected array".to_string());
    };
    if raw_ids.is_empty() {
        return Err("'ids' must contain at least one observation ID".to_string());
    }
    if raw_ids.len() > MAX_GROUNDING_OBSERVATION_IDS {
        return Err(format!(
            "'ids' may contain at most {MAX_GROUNDING_OBSERVATION_IDS} observation IDs"
        ));
    }

    let mut seen = HashSet::new();
    let mut ids = Vec::with_capacity(raw_ids.len());
    for (index, raw_id) in raw_ids.iter().enumerate() {
        let Some(raw_id) = raw_id.as_str() else {
            return Err(format!("ids[{index}] must be a string"));
        };
        let id = raw_id
            .parse::<ObsId>()
            .map_err(|err| format!("ids[{index}] is not a valid observation ID: {err}"))?;
        if seen.insert(id) {
            ids.push(id);
        }
    }
    Ok(ids)
}

fn parse_include_stale(args: &HashMap<String, Value>) -> Result<bool, String> {
    args.get("include_stale").map_or(Ok(false), |value| {
        value
            .as_bool()
            .ok_or_else(|| "Invalid 'include_stale' argument: expected boolean".to_string())
    })
}

fn hydrate_from_ledger(
    session_key: &str,
    ledger: &RealityLedger,
    ids: &[ObsId],
    include_stale: bool,
) -> Value {
    let mut observations = Vec::new();
    let mut missing = Vec::new();
    let mut omitted_stale = Vec::new();

    for id in ids {
        let Some(observation) = ledger.get(*id) else {
            missing.push(id.to_string());
            continue;
        };
        let stale = ledger.is_stale(*id);
        if stale && !include_stale {
            omitted_stale.push(id.to_string());
            continue;
        }
        observations.push(render_observation(observation, stale));
    }

    json!({
        "session_id": session_key,
        "observations": observations,
        "missing": missing,
        "omitted_stale": omitted_stale,
        "rules": [
            "Use hydrated observations only as evidence when authoritative_evidence is true.",
            "Model summaries and stale observations are navigation aids, not evidence."
        ],
    })
}

fn render_observation(observation: &Observation, stale: bool) -> Value {
    json!({
        "id": observation.id.to_string(),
        "ts": observation.ts,
        "authority": observation.authority,
        "stale": stale,
        "authoritative_evidence": observation.authority != Authority::ModelSummary && !stale,
        "label": observation.kind.compact_label(),
        "kind": render_observation_kind(&observation.kind),
    })
}

fn render_observation_kind(kind: &ObservationKind) -> Value {
    match kind {
        ObservationKind::UserTask { content } => json!({
            "type": "user_task",
            "content": truncate_field(content),
        }),
        ObservationKind::FileRead {
            path,
            sha256,
            start_line,
            end_line,
            excerpt,
        } => json!({
            "type": "file_read",
            "path": path,
            "sha256": sha256,
            "start_line": start_line,
            "end_line": end_line,
            "excerpt": truncate_field(excerpt),
        }),
        ObservationKind::CommandRun {
            cwd,
            argv,
            exit_code,
            stdout,
            stderr,
        } => json!({
            "type": "command_run",
            "cwd": cwd,
            "argv": argv,
            "exit_code": exit_code,
            "stdout": truncate_field(stdout),
            "stderr": truncate_field(stderr),
        }),
        ObservationKind::DiffObserved { files, patch } => json!({
            "type": "diff_observed",
            "files": files,
            "patch": truncate_field(patch),
        }),
        ObservationKind::ToolResult { tool, result } => json!({
            "type": "tool_result",
            "tool": tool,
            "result": truncate_json_value(result),
        }),
        ObservationKind::PolicyDecision { allowed, reason } => json!({
            "type": "policy_decision",
            "allowed": allowed,
            "reason": truncate_field(reason),
        }),
        ObservationKind::Verification {
            passed,
            command,
            findings,
        } => json!({
            "type": "verification",
            "passed": passed,
            "command": command,
            "findings": findings.iter().map(|finding| truncate_field(finding)).collect::<Vec<_>>(),
        }),
        ObservationKind::Summary { text, source_obs } => json!({
            "type": "summary",
            "text": truncate_field(text),
            "source_obs": source_obs.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "non_authoritative": true,
        }),
    }
}

fn truncate_json_value(value: &Value) -> Value {
    let text = value.to_string();
    if text.len() <= MAX_GROUNDING_TEXT_BYTES {
        return value.clone();
    }
    json!({
        "truncated_json": truncate_field(&text),
    })
}

fn truncate_field(text: &str) -> String {
    let truncated = super::safe_truncate(text, MAX_GROUNDING_TEXT_BYTES);
    if truncated.len() == text.len() {
        return truncated.to_string();
    }
    format!("{truncated}\n... [truncated]")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::ObservationKind;
    use std::sync::{Arc, Mutex};

    #[test]
    fn grounding_context_hydrates_active_ledger_observation() {
        let session_id = "grounding-context-hydrates-active-ledger";
        let mut ledger = RealityLedger::new();
        let read = ledger
            .observe_file_read("src/lib.rs", "pub fn f() {}\n", 1, 1, "1| pub fn f() {}")
            .expect("file read");
        let shared = Arc::new(Mutex::new(ledger));
        let _ledger_guard = crate::ledger::install_active_ledger_for_session(session_id, shared);

        let args = HashMap::from([("ids".to_string(), json!([read.to_string()]))]);
        let (content, is_error) = execute_grounding_context(session_id, &args);

        assert!(!is_error, "{content}");
        let response: Value = serde_json::from_str(&content).expect("json");
        assert_eq!(response["observations"][0]["id"], read.to_string());
        assert_eq!(response["observations"][0]["authoritative_evidence"], true);
        assert_eq!(response["observations"][0]["kind"]["type"], "file_read");
    }

    #[test]
    fn grounding_context_omits_stale_unless_requested() {
        let session_id = "grounding-context-stale-filter";
        let mut ledger = RealityLedger::new();
        let read = ledger
            .observe_file_read("src/lib.rs", "old\n", 1, 1, "1| old")
            .expect("file read");
        ledger
            .observe_diff(
                vec!["src/lib.rs".to_string()],
                "diff --git a/src/lib.rs b/src/lib.rs\n",
            )
            .expect("diff");
        let shared = Arc::new(Mutex::new(ledger));
        let _ledger_guard = crate::ledger::install_active_ledger_for_session(session_id, shared);

        let args = HashMap::from([("ids".to_string(), json!([read.to_string()]))]);
        let (content, is_error) = execute_grounding_context(session_id, &args);
        assert!(!is_error, "{content}");
        let response: Value = serde_json::from_str(&content).expect("json");
        assert!(response["observations"]
            .as_array()
            .expect("array")
            .is_empty());
        assert_eq!(response["omitted_stale"][0], read.to_string());

        let args = HashMap::from([
            ("ids".to_string(), json!([read.to_string()])),
            ("include_stale".to_string(), json!(true)),
        ]);
        let (content, is_error) = execute_grounding_context(session_id, &args);
        assert!(!is_error, "{content}");
        let response: Value = serde_json::from_str(&content).expect("json");
        assert_eq!(response["observations"][0]["stale"], true);
        assert_eq!(response["observations"][0]["authoritative_evidence"], false);
    }

    #[test]
    fn grounding_context_marks_summaries_non_authoritative() {
        let session_id = "grounding-context-summary-non-authoritative";
        let mut ledger = RealityLedger::new();
        let summary = ledger
            .append(
                Authority::ModelSummary,
                ObservationKind::Summary {
                    text: "Navigation only".to_string(),
                    source_obs: Vec::new(),
                },
            )
            .expect("summary");
        let shared = Arc::new(Mutex::new(ledger));
        let _ledger_guard = crate::ledger::install_active_ledger_for_session(session_id, shared);

        let args = HashMap::from([("ids".to_string(), json!([summary.to_string()]))]);
        let (content, is_error) = execute_grounding_context(session_id, &args);

        assert!(!is_error, "{content}");
        let response: Value = serde_json::from_str(&content).expect("json");
        assert_eq!(response["observations"][0]["authoritative_evidence"], false);
        assert_eq!(
            response["observations"][0]["kind"]["non_authoritative"],
            true
        );
    }

    #[test]
    fn grounding_context_without_active_ledger_does_not_create_session_db() {
        let session_id = format!("grounding-context-missing-{}", uuid::Uuid::new_v4());
        let ledger_path =
            crate::ledger::project_session_ledger_path(&session_id).expect("ledger path");
        assert!(!ledger_path.exists(), "test session ledger must be absent");

        let args = HashMap::from([("ids".to_string(), json!([ObsId::new().to_string()]))]);
        let (content, is_error) = execute_grounding_context(&session_id, &args);

        assert!(is_error, "{content}");
        assert!(
            content.contains("No active session reality ledger"),
            "unexpected error: {content}"
        );
        assert!(
            !ledger_path.exists(),
            "grounding_context must not create a ledger while hydrating evidence"
        );
    }

    #[test]
    fn grounding_context_rejects_non_boolean_include_stale() {
        let session_id = "grounding-context-invalid-include-stale";
        let args = HashMap::from([
            ("ids".to_string(), json!([ObsId::new().to_string()])),
            ("include_stale".to_string(), json!("true")),
        ]);
        let (content, is_error) = execute_grounding_context(session_id, &args);

        assert!(is_error, "{content}");
        assert_eq!(
            content,
            "Invalid 'include_stale' argument: expected boolean"
        );
    }
}
