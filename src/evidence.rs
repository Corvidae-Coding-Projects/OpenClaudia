//! Claim-specific evidence policy for decisions grounded in the reality ledger.

use crate::ledger::{EvidenceTrust, ObsId, Observation, ObservationKind, RealityLedger};
use thiserror::Error;

pub(crate) const MAX_EVIDENCE_RECEIPTS_PER_REQUIREMENT: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{reason}")]
pub struct Denial {
    reason: String,
}

impl Denial {
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }

    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

/// Exact use for which cited observations are being evaluated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceRequirement<'a> {
    TaskIntent,
    FileRead { path: &'a str },
    FileChange { path: &'a str },
    CommandResult { argv: &'a [String], exit_code: i32 },
    Verification { check: &'a str, passed: bool },
}

/// Hydrate receipt ids and enforce current-run, freshness, trust, and
/// claim-applicability policy for every cited record.
///
/// # Errors
///
/// Returns [`Denial`] when evidence is absent, unknown, stale, belongs to a
/// different run generation, is untrusted/legacy/derived content, or does not
/// satisfy the requested claim domain.
pub fn evidence_for_requirement<'a>(
    evidence: &[ObsId],
    ledger: &'a RealityLedger,
    run: &crate::tools::ToolRunContext,
    empty_reason: &str,
    requirement: &EvidenceRequirement<'_>,
) -> Result<Vec<&'a Observation>, Denial> {
    if evidence.is_empty() {
        return Err(Denial::new(empty_reason));
    }
    if evidence.len() > MAX_EVIDENCE_RECEIPTS_PER_REQUIREMENT {
        return Err(Denial::new(format!(
            "evidence exceeds the {MAX_EVIDENCE_RECEIPTS_PER_REQUIREMENT}-receipt limit"
        )));
    }

    evidence
        .iter()
        .map(|id| {
            let observation = ledger
                .get(*id)
                .ok_or_else(|| Denial::new(format!("unknown evidence receipt {id}")))?;
            if ledger.is_stale(*id) {
                return Err(Denial::new(format!(
                    "stale receipt {id} cannot support a claim"
                )));
            }
            if !observation.provenance.is_bound_to(run) {
                return Err(Denial::new(format!(
                    "receipt {id} does not belong to the current run generation"
                )));
            }
            match observation.provenance.trust {
                EvidenceTrust::UntrustedContent => {
                    return Err(Denial::new(format!(
                        "untrusted tool or model content receipt {id} cannot support a claim"
                    )))
                }
                EvidenceTrust::DerivedSummary => {
                    return Err(Denial::new("summary is navigation data, not evidence"))
                }
                EvidenceTrust::LegacyUnbound => {
                    return Err(Denial::new(format!(
                        "legacy unbound receipt {id} cannot support a claim"
                    )))
                }
                EvidenceTrust::UnverifiedPersisted => {
                    return Err(Denial::new(format!(
                        "unverified persisted receipt {id} cannot support a claim"
                    )))
                }
                EvidenceTrust::UserInput
                | EvidenceTrust::RuntimeObserved
                | EvidenceTrust::HostPolicy
                | EvidenceTrust::TrustedVerifier => {}
            }
            if !observation_satisfies(observation, requirement, run) {
                return Err(Denial::new(format!(
                    "receipt {id} is not applicable to {}",
                    requirement_label(requirement)
                )));
            }
            Ok(observation)
        })
        .collect()
}

fn observation_satisfies(
    observation: &Observation,
    requirement: &EvidenceRequirement<'_>,
    run: &crate::tools::ToolRunContext,
) -> bool {
    match requirement {
        EvidenceRequirement::TaskIntent => {
            observation.provenance.trust == EvidenceTrust::UserInput
                && matches!(observation.kind, ObservationKind::UserTask { .. })
        }
        EvidenceRequirement::FileRead { path } => {
            observation.provenance.trust == EvidenceTrust::RuntimeObserved
                && matches!(
                    &observation.kind,
                    ObservationKind::FileRead { path: observed, .. }
                        if evidence_paths_match(run, observed, path)
                )
        }
        EvidenceRequirement::FileChange { path } => {
            observation.provenance.trust == EvidenceTrust::RuntimeObserved
                && matches!(
                    &observation.kind,
                    ObservationKind::DiffObserved { files, .. }
                        if files.iter().any(|observed| evidence_paths_match(run, observed, path))
                )
        }
        EvidenceRequirement::CommandResult { argv, exit_code } => {
            observation.provenance.trust == EvidenceTrust::RuntimeObserved
                && matches!(
                    &observation.kind,
                    ObservationKind::CommandRun {
                        argv: observed,
                        exit_code: observed_exit,
                        ..
                    } if observed == argv && observed_exit == exit_code
                )
        }
        EvidenceRequirement::Verification { check, passed } => {
            observation.provenance.trust == EvidenceTrust::TrustedVerifier
                && observation.provenance.verification_method.is_some()
                && matches!(
                    &observation.provenance.source,
                    crate::ledger::EvidenceSource::QualityGate { check: observed }
                        if observed == check
                )
                && matches!(
                    observation.kind,
                    ObservationKind::Verification { passed: observed, .. }
                        if observed == *passed
                )
        }
    }
}

const fn requirement_label(requirement: &EvidenceRequirement<'_>) -> &'static str {
    match requirement {
        EvidenceRequirement::TaskIntent => "task intent",
        EvidenceRequirement::FileRead { .. } => "the exact file read",
        EvidenceRequirement::FileChange { .. } => "the exact file change",
        EvidenceRequirement::CommandResult { .. } => "the exact command result",
        EvidenceRequirement::Verification { .. } => "the exact quality-gate result",
    }
}

fn evidence_paths_match(run: &crate::tools::ToolRunContext, observed: &str, claimed: &str) -> bool {
    normalized_evidence_path(run, observed) == normalized_evidence_path(run, claimed)
}

fn normalized_evidence_path(run: &crate::tools::ToolRunContext, path: &str) -> std::path::PathBuf {
    let path = std::path::Path::new(path);
    let comparable = if path.is_absolute() {
        path.strip_prefix(run.project_root()).unwrap_or(path)
    } else {
        path
    };
    comparable
        .components()
        .filter(|component| !matches!(component, std::path::Component::CurDir))
        .collect()
}
