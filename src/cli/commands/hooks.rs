//! User-visible review and approval commands for repository hook imports.

use openclaudia::hooks::{
    approve_repository_hook_import, inspect_repository_hook_imports, revoke_repository_hook_import,
    HookImportProposal, HookImportState,
};

/// Display every recognized repository hook proposal and its exact trust
/// binding. Discovery is read-only and never activates a proposal.
pub fn cmd_hooks_status() {
    let report = inspect_repository_hook_imports();
    println!("Repository hook imports\n");
    if report.proposals.is_empty() {
        println!("No repository hook imports discovered.");
    } else {
        for proposal in &report.proposals {
            print_proposal(proposal);
        }
    }
    if !report.diagnostics.is_empty() {
        println!("Diagnostics:");
        for diagnostic in &report.diagnostics {
            let source = diagnostic.source.as_deref().map_or_else(
                || "host approval store".to_string(),
                |path| path.display().to_string(),
            );
            println!("  - {source}: {}", diagnostic.message);
        }
    }
}

/// Persist an exact host-owned approval for a proposal currently present in
/// this canonical workspace.
pub fn cmd_hooks_approve(proposal_digest: &str) -> anyhow::Result<()> {
    let proposal = approve_repository_hook_import(proposal_digest)?;
    println!("Approved repository hook import:");
    print_proposal(&proposal);
    println!("The approval is bound to this workspace, source, content, events, and effects.");
    Ok(())
}

/// Revoke one exact approval receipt.
pub fn cmd_hooks_revoke(proposal_digest: &str) -> anyhow::Result<()> {
    revoke_repository_hook_import(proposal_digest)?;
    println!("Revoked repository hook import {proposal_digest}");
    Ok(())
}

fn print_proposal(proposal: &HookImportProposal) {
    let state = match proposal.state {
        HookImportState::Pending => "pending review",
        HookImportState::Changed => "changed; reapproval required",
        HookImportState::Approved => "approved",
    };
    println!("Source: {}", proposal.source.display());
    println!("  Kind: {}", proposal.kind);
    println!("  State: {state}");
    println!("  Workspace: {}", proposal.workspace.display());
    println!("  Source digest: {}", proposal.source_digest);
    println!("  Proposal digest: {}", proposal.proposal_digest);
    println!("  Events: {}", join_or_none(&proposal.requested_events));
    println!("  Effects: {}", join_or_none(&proposal.requested_effects));
    println!("  Hook actions: {}", proposal.hook_count);
    println!("  Commands: {}", join_or_none(&proposal.commands));
    if proposal.bound_files.is_empty() {
        println!("  Bound repository files: none");
    } else {
        println!("  Bound repository files:");
        for file in &proposal.bound_files {
            println!(
                "    - {} ({} bytes, {})",
                file.path.display(),
                file.bytes,
                file.digest
            );
        }
    }
    if proposal.state != HookImportState::Approved {
        println!(
            "  Approve exactly: openclaudia hooks approve {}",
            proposal.proposal_digest
        );
    }
    println!();
}

fn join_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values.join(", ")
    }
}
