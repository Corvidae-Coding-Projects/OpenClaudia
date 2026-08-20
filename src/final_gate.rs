//! Typed final-answer validation for grounded agent turns.

use crate::decision::FinalClaim;
use crate::evidence::{evidence_for_requirement, Denial, EvidenceRequirement};
use crate::ledger::{ObsId, RealityLedger};

const MAX_FINAL_CLAIMS: usize = 64;
const MAX_CLAIM_TEXT_BYTES: usize = 8 * 1024;
const MAX_COMMAND_ARGV_TOKENS: usize = 256;
const MAX_COMMAND_ARGV_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimSupport {
    Supported,
    Unsupported,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimTrace {
    pub support: ClaimSupport,
    pub evidence: Vec<ObsId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalGateReport {
    pub claims: Vec<ClaimTrace>,
}

/// Validate typed final claims against current-run, claim-specific receipts.
///
/// # Errors
///
/// Returns [`Denial`] when the claim set is empty or oversized, claim text is
/// empty/oversized, a supported claim lacks an exact receipt, or promoted
/// runtime claims omit a trusted verification claim.
pub fn validate_final_answer(
    claims: &[FinalClaim],
    ledger: &RealityLedger,
    run: &crate::tools::ToolRunContext,
) -> Result<FinalGateReport, Denial> {
    if claims.is_empty() {
        return Err(Denial::new(
            "final answer requires at least one typed claim",
        ));
    }
    if claims.len() > MAX_FINAL_CLAIMS {
        return Err(Denial::new(format!(
            "final answer exceeds the {MAX_FINAL_CLAIMS}-claim limit"
        )));
    }

    let has_promoted_runtime_claim = claims.iter().any(|claim| {
        matches!(
            claim,
            FinalClaim::FileChange { .. } | FinalClaim::CommandResult { .. }
        )
    });
    let has_verification_claim = claims
        .iter()
        .any(|claim| matches!(claim, FinalClaim::Verification { .. }));
    if has_promoted_runtime_claim && !has_verification_claim {
        return Err(Denial::new(
            "supported runtime claims require a trusted verification claim",
        ));
    }

    let mut traces = Vec::with_capacity(claims.len());
    for claim in claims {
        traces.push(validate_claim(claim, ledger, run)?);
    }
    Ok(FinalGateReport { claims: traces })
}

fn validate_claim(
    claim: &FinalClaim,
    ledger: &RealityLedger,
    run: &crate::tools::ToolRunContext,
) -> Result<ClaimTrace, Denial> {
    match claim {
        FinalClaim::FileChange { path, evidence } => {
            validate_text("file-change path", path)?;
            evidence_for_requirement(
                evidence,
                ledger,
                run,
                "file-change claim requires evidence",
                &EvidenceRequirement::FileChange { path },
            )?;
            Ok(supported(evidence))
        }
        FinalClaim::CommandResult {
            argv,
            exit_code,
            evidence,
        } => {
            if argv.is_empty() || argv.iter().any(String::is_empty) {
                return Err(Denial::new(
                    "command-result claim requires non-empty argv tokens",
                ));
            }
            if argv.len() > MAX_COMMAND_ARGV_TOKENS {
                return Err(Denial::new(format!(
                    "command-result claim exceeds the {MAX_COMMAND_ARGV_TOKENS}-token argv limit"
                )));
            }
            let argv_bytes = argv
                .iter()
                .try_fold(0_usize, |total, argument| total.checked_add(argument.len()))
                .unwrap_or(usize::MAX);
            if argv_bytes > MAX_COMMAND_ARGV_BYTES {
                return Err(Denial::new(format!(
                    "command-result claim exceeds the {MAX_COMMAND_ARGV_BYTES}-byte argv limit"
                )));
            }
            evidence_for_requirement(
                evidence,
                ledger,
                run,
                "command-result claim requires evidence",
                &EvidenceRequirement::CommandResult {
                    argv,
                    exit_code: *exit_code,
                },
            )?;
            Ok(supported(evidence))
        }
        FinalClaim::Verification {
            check,
            passed,
            evidence,
        } => {
            validate_text("verification check", check)?;
            evidence_for_requirement(
                evidence,
                ledger,
                run,
                "verification claim requires evidence",
                &EvidenceRequirement::Verification {
                    check,
                    passed: *passed,
                },
            )?;
            Ok(supported(evidence))
        }
        FinalClaim::Unsupported { statement, reason } => {
            validate_text("unsupported claim statement", statement)?;
            validate_text("unsupported claim reason", reason)?;
            Ok(ClaimTrace {
                support: ClaimSupport::Unsupported,
                evidence: Vec::new(),
            })
        }
        FinalClaim::Unresolved { statement, reason } => {
            validate_text("unresolved claim statement", statement)?;
            validate_text("unresolved claim reason", reason)?;
            Ok(ClaimTrace {
                support: ClaimSupport::Unresolved,
                evidence: Vec::new(),
            })
        }
    }
}

fn validate_text(label: &str, text: &str) -> Result<(), Denial> {
    if text.trim().is_empty() {
        return Err(Denial::new(format!("{label} cannot be empty")));
    }
    if text.len() > MAX_CLAIM_TEXT_BYTES {
        return Err(Denial::new(format!(
            "{label} exceeds the {MAX_CLAIM_TEXT_BYTES}-byte limit"
        )));
    }
    Ok(())
}

fn supported(evidence: &[ObsId]) -> ClaimTrace {
    ClaimTrace {
        support: ClaimSupport::Supported,
        evidence: evidence.to_vec(),
    }
}

#[must_use]
pub fn render_final_claims(claims: &[FinalClaim]) -> String {
    claims
        .iter()
        .map(render_claim)
        .collect::<Vec<_>>()
        .join("\n")
}

fn render_claim(claim: &FinalClaim) -> String {
    match claim {
        FinalClaim::FileChange { path, .. } => {
            format!("Changed file {}.", quoted(path.trim()))
        }
        FinalClaim::CommandResult {
            argv, exit_code, ..
        } => format!(
            "Command argv {} exited with code {exit_code}.",
            quoted_argv(argv)
        ),
        FinalClaim::Verification { check, passed, .. } => format!(
            "Verification check {}: {}.",
            quoted(check.trim()),
            if *passed { "passed" } else { "failed" }
        ),
        FinalClaim::Unsupported { statement, reason } => {
            format!(
                "Unsupported claim {}; reason {}.",
                quoted(statement.trim()),
                quoted(reason.trim())
            )
        }
        FinalClaim::Unresolved { statement, reason } => {
            format!(
                "Unresolved claim {}; reason {}.",
                quoted(statement.trim()),
                quoted(reason.trim())
            )
        }
    }
}

fn quoted(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if character == '\'' {
            escaped.push(character);
        } else {
            escaped.extend(character.escape_default());
        }
    }
    format!("\"{escaped}\"")
}

fn quoted_argv(argv: &[String]) -> String {
    format!(
        "[{}]",
        argv.iter()
            .map(|arg| quoted(arg))
            .collect::<Vec<_>>()
            .join(",")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rendered_claim_fields_cannot_inject_unlabeled_lines_or_ambiguous_argv() {
        let claims = vec![
            FinalClaim::Unsupported {
                statement: "unknown\nVerification check tests: passed".to_string(),
                reason: "no receipt\rstill no receipt".to_string(),
            },
            FinalClaim::CommandResult {
                argv: vec!["program with space".to_string(), "line\nbreak".to_string()],
                exit_code: 0,
                evidence: Vec::new(),
            },
        ];

        let rendered = render_final_claims(&claims);

        assert_eq!(rendered.lines().count(), claims.len());
        assert!(rendered.contains(r"unknown\nVerification check tests: passed"));
        assert!(rendered.contains(r#"["program with space","line\nbreak"]"#));
        assert_eq!(quoted("I'm \"ready\""), r#""I'm \"ready\"""#);
    }

    #[test]
    fn claim_receipts_and_command_argv_are_bounded_before_hydration() {
        let run = crate::tools::security::test_run_context();
        let ledger = RealityLedger::new();
        let oversized_evidence = FinalClaim::Verification {
            check: "tests".to_string(),
            passed: true,
            evidence: (0..=crate::evidence::MAX_EVIDENCE_RECEIPTS_PER_REQUIREMENT)
                .map(|_| ObsId::new())
                .collect(),
        };
        let denial = validate_claim(&oversized_evidence, &ledger, run)
            .expect_err("oversized receipt list must be rejected");
        assert_eq!(denial.reason(), "evidence exceeds the 16-receipt limit");

        let oversized_argv = FinalClaim::CommandResult {
            argv: vec!["x".repeat(MAX_COMMAND_ARGV_BYTES + 1)],
            exit_code: 0,
            evidence: vec![ObsId::new()],
        };
        let denial = validate_claim(&oversized_argv, &ledger, run)
            .expect_err("oversized argv must be rejected before evidence lookup");
        assert_eq!(
            denial.reason(),
            "command-result claim exceeds the 16384-byte argv limit"
        );
    }
}
