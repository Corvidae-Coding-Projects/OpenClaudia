//! Persistence sinks for VDD findings: Crosslink issues + on-disk session JSON.

use std::path::Path;

use tracing::{info, warn};

use crate::vdd::error::VddError;
use crate::vdd::finding::Finding;
use crate::vdd::helpers::truncate_output;
use crate::vdd::review::VddSession;
use crate::vdd::static_analysis::create_crosslink_issue;

/// Create Crosslink issues for genuine findings.
///
/// Library-backed (no subprocess): each finding lands in
/// `.crosslink/issues.db` via `crosslink::db::Database`, matching the
/// store the agent-facing `crosslink` tool writes to. The previous
/// `chainlink` shell-out has been removed entirely.
pub async fn create_crosslink_issues(
    run: &std::sync::Arc<crate::tools::ToolRunContext>,
    findings: &[&Finding],
) -> Result<Vec<String>, VddError> {
    let mut issue_ids = Vec::new();

    for finding in findings {
        let label = if finding.cwe.is_some() {
            "security"
        } else {
            "bug"
        };

        let title = format!(
            "Fix {} VDD finding: {}",
            finding.severity,
            truncate_output(&finding.description, 60)
        );

        let comment = format!(
            "**Severity:** {}\n**CWE:** {}\n**File:** {}\n**Lines:** {}\n\n**Description:**\n{}\n\n**Reasoning:**\n{}",
            finding.severity,
            finding.cwe.as_deref().unwrap_or("N/A"),
            finding.file_path.as_deref().unwrap_or("N/A"),
            finding
                .line_range
                .map_or_else(|| "N/A".to_string(), |(s, e)| format!("{s}-{e}")),
            finding.description,
            finding.adversary_reasoning,
        );

        match create_crosslink_issue(run, &title, label, &comment).await {
            Ok(id) => {
                info!(issue_id = %id, severity = %finding.severity, "VDD: Created Crosslink issue");
                issue_ids.push(id);
            }
            Err(e) => {
                warn!(error = %e, "VDD: Failed to create Crosslink issue");
            }
        }
    }

    Ok(issue_ids)
}

/// Persist VDD session to disk.
pub fn persist_session(path: &Path, session: &VddSession) -> Result<(), VddError> {
    std::fs::create_dir_all(path)?;

    let filename = format!("vdd-session-{}.json", session.id);
    let filepath = path.join(filename);

    let json = serde_json::to_string_pretty(session)?;
    std::fs::write(&filepath, json)?;

    info!(path = %filepath.display(), "VDD: Session persisted");
    Ok(())
}
