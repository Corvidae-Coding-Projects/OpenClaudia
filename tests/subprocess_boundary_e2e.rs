//! Structural guard for agent-reachable subprocess creation.
//!
//! Runtime escape tests prove the launcher works. This test complements them
//! by making a newly introduced direct process constructor in an agent module
//! fail review even before an escape payload is written.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]

fn production_source(path: &str) -> String {
    let source = std::fs::read_to_string(path).expect("source file");
    source
        .split("#[cfg(test)]\nmod tests")
        .next()
        .unwrap_or(&source)
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//") && !trimmed.starts_with("///") && !trimmed.starts_with("//!")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn agent_modules_do_not_construct_host_processes_directly() {
    let guarded = [
        "src/acp.rs",
        "src/guardrails.rs",
        "src/mcp.rs",
        "src/subagent.rs",
        "src/tools/file/read.rs",
        "src/tools/lsp.rs",
        "src/tools/worktree.rs",
        "src/vdd/static_analysis.rs",
    ];
    for path in guarded {
        let source = production_source(path);
        assert!(
            !source.contains("Command::new(")
                && !source.contains("std::process::Command::new(")
                && !source.contains("tokio::process::Command::new("),
            "{path} introduced a direct subprocess constructor; select a named SandboxProfile \
             and use the common sandbox launcher"
        );
    }
}

#[test]
fn hook_process_construction_remains_followed_by_enforced_sandboxing() {
    let source = production_source("src/hooks/mod.rs");
    let direct_constructors = source
        .lines()
        .filter(|line| line.contains("Command::new("))
        .count();
    assert_eq!(
        direct_constructors, 2,
        "hook command parsing has exactly two constructors (direct argv and explicit shell); \
         any new constructor needs a sandbox-boundary review"
    );
    assert!(source.contains("sandboxed_hook_command("));
    assert!(source.contains("TRUST_UNSANDBOXED_HOOKS_ENV"));
    assert!(source.contains("sandbox_mode == SandboxMode::FullSandbox"));
}

#[test]
fn unsandboxed_runner_is_test_only_and_agent_git_uses_named_profiles() {
    let command = std::fs::read_to_string("src/tools/command.rs").expect("command source");
    let marker = "#[cfg(test)]\npub fn run_with_timeout(";
    assert!(
        command.contains(marker),
        "the host subprocess helper must remain unavailable in production builds"
    );
    for path in ["src/tools/worktree.rs", "src/subagent.rs"] {
        let source = production_source(path);
        assert!(source.contains("SandboxProfile::GitWorktree"));
        assert!(!source.contains("run_with_timeout("));
    }
}
