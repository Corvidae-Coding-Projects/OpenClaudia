//! Bounded canonical child-run admission for local side questions.

use std::sync::Arc;
use std::time::Duration;

use crate::tools::{ToolRunContext, WorkspaceAccess};

use super::{ActorRole, BudgetLimits};

/// Wall-clock deadline for a side-question child provider attempt.
pub const SIDE_QUESTION_TIMEOUT: Duration = Duration::from_secs(30);

/// Output ceiling retained by the child even when its parent is broader.
pub const SIDE_QUESTION_MAX_OUTPUT_TOKENS: u64 = 4_096;

/// Derive a read-only, tool-less child run from exact parent authority.
///
/// The child participates in the parent's hierarchical budget, receives a
/// fresh run/cancellation identity, cannot execute processes or tools, and
/// cannot access secrets or model-facing memory services. Provider transport
/// is performed by the existing pipeline using host-resolved credentials;
/// credentials are never copied into this run.
///
/// # Errors
///
/// Returns an admission error when the parent budget cannot admit another
/// child or the narrowed capability set cannot be pinned.
pub fn derive_side_question_run(parent: &ToolRunContext) -> Result<Arc<ToolRunContext>, String> {
    let parent_limits = &parent.runtime().descriptor().budget.limits;
    let input_tokens = parent_limits.input_tokens.min(128 * 1_024);
    let output_tokens = parent_limits
        .output_tokens
        .min(SIDE_QUESTION_MAX_OUTPUT_TOKENS);
    let total_tokens = parent_limits
        .total_tokens
        .min(input_tokens.saturating_add(output_tokens));
    let limits = BudgetLimits {
        input_tokens,
        output_tokens,
        total_tokens,
        turns: parent_limits.turns.min(1),
        provider_calls: parent_limits.provider_calls.min(3),
        tool_calls: 0,
        elapsed_millis: parent_limits
            .elapsed_millis
            .min(u64::try_from(SIDE_QUESTION_TIMEOUT.as_millis()).unwrap_or(u64::MAX)),
        retries: parent_limits.retries.min(2),
        concurrent_calls: parent_limits.concurrent_calls.min(1),
        child_runs: 0,
        cost_microusd: parent_limits.cost_microusd.min(50_000_000),
        trace_bytes: parent_limits.trace_bytes.min(64 * 1_024),
    };
    let session_id = parent.runtime().descriptor().session_id.clone();
    ToolRunContext::builder(session_id, parent.project_root())
        .working_directory(parent.working_directory())
        .read_only_roots(Vec::new())
        .read_write_roots(Vec::new())
        .project_secret_masks(parent.project_secret_masks().to_vec())
        .environment_grants(std::collections::HashMap::new())
        .mcp_environment_grants(std::collections::HashMap::new())
        .executable_search_path(parent.executable_search_path())
        .workspace_access(WorkspaceAccess::ReadOnly)
        .process(false)
        .network(true)
        .secrets(false)
        .process_owner(format!("btw-{}", super::RunId::new()))
        .actor_role(ActorRole::Worker)
        .provider(parent.provider_id())
        .budget_limits(limits)
        .parent_budget(parent.budget().clone())
        .parent_cancellation(parent.runtime().cancellation())
        .runtime_mode(crate::modes::RuntimeMode::Behavioral(
            crate::modes::BehaviorMode::default(),
        ))
        .behavior_scope_targets(crate::modes::BehaviorScopeTargets::workspace_root())
        .bounded_inference_profile()
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn side_question_child_is_narrow_and_hierarchically_budgeted() {
        let root = tempfile::tempdir().expect("root");
        let parent = ToolRunContext::builder(crate::state::SessionId::new(), root.path())
            .working_directory(root.path())
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(std::collections::HashMap::new())
            .workspace_access(WorkspaceAccess::ReadWrite)
            .process(true)
            .network(true)
            .secrets(false)
            .provider("openai")
            .build()
            .expect("parent");

        let child = derive_side_question_run(&parent).expect("child");
        let grants = &child.runtime().descriptor().capabilities.grants;
        assert_ne!(child.run_id(), parent.run_id());
        assert_eq!(child.session_id(), parent.session_id());
        assert!(!child.permits_read(root.path()));
        assert!(!child.permits_write(root.path()));
        assert!(!grants.contains(&crate::runtime::CapabilityKind::WorkspaceRead));
        assert!(!grants.contains(&crate::runtime::CapabilityKind::Memory));
        assert!(!grants.contains(&crate::runtime::CapabilityKind::Mcp));
        assert!(grants.contains(&crate::runtime::CapabilityKind::Network));
        assert_eq!(
            child.runtime().descriptor().cancellation_root,
            parent.runtime().descriptor().cancellation_root
        );
        assert_eq!(child.runtime().descriptor().budget.limits.tool_calls, 0);
        assert_eq!(
            parent
                .budget()
                .snapshot()
                .expect("parent budget")
                .used
                .child_runs,
            1
        );

        let receipt = parent
            .runtime()
            .cancellation()
            .cancel(crate::runtime::CancellationReason::User);
        let child_receipt = child
            .runtime()
            .cancellation()
            .receipt()
            .expect("child cancellation receipt");
        assert_eq!(child_receipt.root, receipt.root);
        assert_eq!(child_receipt.source, receipt.source);
        assert_eq!(
            child_receipt.reason,
            crate::runtime::CancellationReason::User
        );
    }
}
