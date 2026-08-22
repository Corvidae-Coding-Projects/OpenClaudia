//! Typed agent decisions and validation against the reality ledger.

use crate::evidence::{evidence_for_requirement, Denial, EvidenceRequirement};
use crate::final_gate::{validate_final_answer, FinalGateReport};
use crate::ledger::{ObsId, ObservationKind, RealityLedger};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InspectTarget {
    File { path: String },
    Diff,
    Command { argv: Vec<String> },
    Observation { id: ObsId },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentDecision {
    Inspect {
        reason: String,
        target: InspectTarget,
    },
    Edit {
        reason: String,
        evidence: Vec<ObsId>,
        patch: String,
    },
    RunCommand {
        reason: String,
        evidence: Vec<ObsId>,
        argv: Vec<String>,
    },
    Final {
        claims: Vec<FinalClaim>,
    },
}

/// A final response is a set of typed claims. Supported claims cite exact
/// receipts; claims without proof must declare that state instead of being
/// promoted through free-form summary prose.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "claim_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum FinalClaim {
    FileChange {
        path: String,
        evidence: Vec<ObsId>,
    },
    CommandResult {
        argv: Vec<String>,
        exit_code: i32,
        evidence: Vec<ObsId>,
    },
    Verification {
        check: String,
        passed: bool,
        evidence: Vec<ObsId>,
    },
    Unsupported {
        statement: String,
        reason: String,
    },
    Unresolved {
        statement: String,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionValidation {
    Inspect,
    Edit { evidence: Vec<ObsId> },
    RunCommand { evidence: Vec<ObsId> },
    Final(FinalGateReport),
}

/// Validate a model decision against claim-specific, runtime-issued receipts.
///
/// # Errors
///
/// Returns [`Denial`] when the decision lacks required evidence, cites stale
/// or inapplicable observations, has an empty reason/patch, or makes a
/// final-answer claim that is not backed by ledger verification.
pub fn validate_decision(
    decision: &AgentDecision,
    ledger: &RealityLedger,
    run: &crate::tools::ToolRunContext,
) -> Result<DecisionValidation, Denial> {
    match decision {
        AgentDecision::Inspect { reason, .. } => {
            if reason.trim().is_empty() {
                return Err(Denial::new("inspect requires a reason"));
            }
            Ok(DecisionValidation::Inspect)
        }
        AgentDecision::Edit {
            reason,
            evidence,
            patch,
        } => {
            if reason.trim().is_empty() {
                return Err(Denial::new("edit requires a reason"));
            }
            if patch.trim().is_empty() {
                return Err(Denial::new("empty patch"));
            }

            let patch_paths = patch_paths_requiring_file_read(patch);
            if patch_paths.is_empty() {
                return Err(Denial::new("edit patch requires a concrete file target"));
            }
            for patch_path in patch_paths {
                let matching_ids = evidence
                    .iter()
                    .copied()
                    .filter(|id| {
                        ledger.get(*id).is_some_and(|obs| match &obs.kind {
                            ObservationKind::FileRead { path, .. } => {
                                observed_path_matches_patch_path(path, &patch_path)
                            }
                            _ => false,
                        })
                    })
                    .collect::<Vec<_>>();
                if matching_ids.is_empty() {
                    return Err(Denial::new(format!(
                        "edit patch requires fresh file observation: {patch_path}"
                    )));
                }
                evidence_for_requirement(
                    &matching_ids,
                    ledger,
                    run,
                    "edit requires evidence",
                    &EvidenceRequirement::FileRead { path: &patch_path },
                )?;
            }

            Ok(DecisionValidation::Edit {
                evidence: evidence.clone(),
            })
        }
        AgentDecision::RunCommand {
            reason,
            evidence,
            argv,
        } => {
            if reason.trim().is_empty() {
                return Err(Denial::new("command requires a reason"));
            }
            if argv.is_empty() {
                return Err(Denial::new("command argv cannot be empty"));
            }
            evidence_for_requirement(
                evidence,
                ledger,
                run,
                "command requires evidence",
                &EvidenceRequirement::TaskIntent,
            )?;
            Ok(DecisionValidation::RunCommand {
                evidence: evidence.clone(),
            })
        }
        AgentDecision::Final { claims } => {
            validate_final_answer(claims, ledger, run).map(DecisionValidation::Final)
        }
    }
}

fn patch_paths_requiring_file_read(patch: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut paths = Vec::new();
    for line in patch.lines() {
        if let Some(path) = line.strip_prefix("*** Update File: ") {
            push_patch_path(path, &mut seen, &mut paths);
            continue;
        }
        if let Some(path) = line.strip_prefix("*** Delete File: ") {
            push_patch_path(path, &mut seen, &mut paths);
            continue;
        }
        if let Some(path) = old_path_from_diff_git_line(line) {
            push_patch_path(path, &mut seen, &mut paths);
            continue;
        }
        if let Some(path) = line.strip_prefix("--- ") {
            push_patch_path(path, &mut seen, &mut paths);
        }
    }
    paths
}

fn old_path_from_diff_git_line(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("diff --git ")?;
    let mut parts = rest.split_whitespace();
    let old_path = parts.next()?;
    let _new_path = parts.next()?;
    if old_path == "/dev/null" {
        return None;
    }
    Some(old_path)
}

fn push_patch_path(path: &str, seen: &mut HashSet<String>, paths: &mut Vec<String>) {
    let Some(normalized) = normalize_patch_path(path) else {
        return;
    };
    if seen.insert(normalized.clone()) {
        paths.push(normalized);
    }
}

fn normalize_patch_path(path: &str) -> Option<String> {
    let mut path = path.trim();
    if path.is_empty() || path == "/dev/null" {
        return None;
    }
    if let Some((prefix, _timestamp)) = path.split_once('\t') {
        path = prefix;
    }
    if let Some(stripped) = path.strip_prefix("a/").or_else(|| path.strip_prefix("b/")) {
        path = stripped;
    }
    let path = path.trim_start_matches("./");
    (!path.is_empty()).then(|| path.to_string())
}

fn observed_path_matches_patch_path(observed: &str, patch_path: &str) -> bool {
    let observed = observed.trim_start_matches("./");
    let patch_path = patch_path.trim_start_matches("./");
    observed == patch_path
        || observed.ends_with(&format!("/{patch_path}"))
        || patch_path.ends_with(&format!("/{observed}"))
}
