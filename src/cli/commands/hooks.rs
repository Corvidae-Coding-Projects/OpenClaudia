//! User-visible review and approval commands for compatibility hook imports.

use openclaudia::hooks::{
    approve_repository_hook_import, inspect_repository_hook_imports, revoke_repository_hook_import,
    HookImportProposal, HookImportState,
};

/// Display every recognized repository hook proposal and its exact trust
/// binding. Discovery is read-only and never activates a proposal.
pub fn cmd_hooks_status() {
    let report = inspect_repository_hook_imports();
    println!("Compatibility hook imports\n");
    if report.proposals.is_empty() {
        println!("No compatibility hook imports discovered.");
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
    println!("Approved compatibility hook import:");
    print_proposal(&proposal);
    println!("The approval is bound to this workspace, source, content, events, and effects.");
    Ok(())
}

/// Revoke one exact approval receipt.
pub fn cmd_hooks_revoke(proposal_digest: &str) -> anyhow::Result<()> {
    revoke_repository_hook_import(proposal_digest)?;
    println!("Revoked compatibility hook import {proposal_digest}");
    Ok(())
}

fn print_proposal(proposal: &HookImportProposal) {
    let state = match proposal.state {
        HookImportState::Pending => "pending review",
        HookImportState::Changed => "changed; reapproval required",
        HookImportState::Rejected => "rejected; import set remains inert",
        HookImportState::Approved => "approved",
    };
    println!("Source: {}", proposal.source.display());
    println!("  Kind: {}", proposal.kind);
    println!("  Source scope: {}", proposal.source_scope);
    println!("  State: {state}");
    println!("  Workspace: {}", proposal.workspace.display());
    println!("  Workspace owner: {}", proposal.workspace_owner);
    println!("  Source root: {}", proposal.source_root.display());
    println!("  Source-root owner: {}", proposal.source_root_owner);
    println!("  Source owner: {}", proposal.source_owner);
    println!("  Source digest: {}", proposal.source_digest);
    println!("  Proposal digest: {}", proposal.proposal_digest);
    println!("  Events: {}", join_or_none(&proposal.requested_events));
    println!("  Effects: {}", join_or_none(&proposal.requested_effects));
    println!(
        "  Requested capabilities: {}",
        join_display_or_none(&proposal.requested_capabilities)
    );
    if proposal.output_authority.is_empty() {
        println!("  Output authority: none");
    } else {
        println!("  Output authority:");
        for authority in &proposal.output_authority {
            println!(
                "    - {}: {}",
                authority.event,
                join_display_or_none(&authority.fields)
            );
        }
    }
    println!("  Hook actions: {}", proposal.hook_count);
    println!("  Commands: {}", join_or_none(&proposal.commands));
    if proposal.executables.is_empty() {
        println!("  Executable identities: none");
    } else {
        println!("  Executable identities:");
        for executable in &proposal.executables {
            println!("    - argv: {}", join_or_none(&executable.argv));
            println!("      resolved: {}", executable.resolved_path.display());
            println!("      owner: {}", executable.owner);
            println!("      digest: {}", executable.digest);
        }
    }
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

fn join_display_or_none<T: std::fmt::Display>(values: &[T]) -> String {
    if values.is_empty() {
        "none".to_string()
    } else {
        values
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}
