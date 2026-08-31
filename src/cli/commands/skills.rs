//! Host-owned repository skill trust commands.

use openclaudia::skills::{
    inspect_project_skill_trust, revoke_project_skills, trust_project_skills,
    SkillCapabilityPolicy, SkillTrustStatus,
};

pub fn cmd_skills_status() -> anyhow::Result<()> {
    print_status(&inspect_project_skill_trust()?);
    Ok(())
}

pub fn cmd_skills_trust(
    allowed_tools: Vec<String>,
    allow_model: bool,
    allow_effort: bool,
    allow_hooks: bool,
) -> anyhow::Result<()> {
    let policy =
        SkillCapabilityPolicy::project(allowed_tools, allow_model, allow_effort, allow_hooks)?;
    let status = trust_project_skills(policy)?;
    println!("Trusted repository skill text for this exact workspace.");
    print_status(&status);
    Ok(())
}

pub fn cmd_skills_revoke() -> anyhow::Result<()> {
    let status = revoke_project_skills()?;
    println!("Revoked repository skill trust for this exact workspace.");
    print_status(&status);
    Ok(())
}

fn print_status(status: &SkillTrustStatus) {
    println!("Repository skills");
    println!("  Workspace: {}", status.workspace.display());
    println!("  Host trust store: {}", status.store_path.display());
    if let Some(policy) = status.policy.as_ref() {
        let allowed_tools = policy.allowed_tools().collect::<Vec<_>>();
        println!("  State: trusted");
        println!(
            "  Allowed tools: {}",
            if allowed_tools.is_empty() {
                "none".to_string()
            } else {
                allowed_tools.join(", ")
            }
        );
        println!("  Model hint: {}", yes_no(policy.allows_model()));
        println!("  Effort hint: {}", yes_no(policy.allows_effort()));
        println!("  Hooks: {}", yes_no(policy.allows_hooks()));
    } else {
        println!("  State: inert (no host trust receipt)");
    }
}

const fn yes_no(value: bool) -> &'static str {
    if value {
        "allowed"
    } else {
        "denied"
    }
}
