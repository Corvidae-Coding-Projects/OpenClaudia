use std::collections::HashMap;

use openclaudia::state::SessionId;
use openclaudia::tools::{
    commit_project_initialization, plan_project_initialization, ProjectInitCommitState,
    ProjectInitPolicy, ToolRunContext, WorkspaceAccess,
};
use tracing::info;

/// Initialize `OpenClaudia` configuration through a previewed transaction.
pub fn cmd_init(force: bool) -> anyhow::Result<()> {
    let project_root = std::env::current_dir()
        .map_err(|error| anyhow::anyhow!("cannot resolve current project directory: {error}"))?;
    let run = ToolRunContext::builder(SessionId::new(), project_root)
        .read_only_roots(Vec::new())
        .read_write_roots(Vec::new())
        .environment_grants(HashMap::new())
        .workspace_access(WorkspaceAccess::ReadWrite)
        .process(false)
        .network(false)
        .secrets(false)
        .provider("local")
        .build()
        .map_err(anyhow::Error::msg)?;
    let policy = if force {
        ProjectInitPolicy::ForceWithBackup
    } else {
        ProjectInitPolicy::RefuseCollisions
    };
    let plan = plan_project_initialization(&run, policy)?;

    info!(
        generation = plan.generation(),
        schema_version = plan.schema_version(),
        "Project initialization preview"
    );
    for effect in plan.effects() {
        if let Some(backup) = effect.backup_path() {
            info!(
                action = %effect.action(),
                path = %effect.path().display(),
                observed = ?effect.observed(),
                backup = %backup.display(),
                "Initialization effect"
            );
        } else {
            info!(
                action = %effect.action(),
                path = %effect.path().display(),
                observed = ?effect.observed(),
                "Initialization effect"
            );
        }
    }

    let receipt = commit_project_initialization(&run, &plan)?;
    match receipt.state() {
        ProjectInitCommitState::AlreadyCurrent => {
            info!("OpenClaudia project configuration is already current");
        }
        ProjectInitCommitState::Created => {
            info!("Initialized OpenClaudia configuration in .openclaudia/");
        }
        ProjectInitCommitState::ReplacedWithBackup => {
            let backup = receipt.backup_root().ok_or_else(|| {
                anyhow::anyhow!("force initialization completed without a recovery path")
            })?;
            info!(backup = %backup.display(), "Initialized OpenClaudia and retained replaced state");
        }
    }
    info!("  config.yaml  - Minimal project configuration");
    info!("  skills/      - Project skill packages");
    Ok(())
}
