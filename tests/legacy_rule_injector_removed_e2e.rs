//! Deterministic negative coverage for S-007.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]

use openclaudia::config::{Hook, HookEntry, HooksConfig};
use openclaudia::hooks::HookEngine;
use openclaudia::modes::BehaviorMode;
use openclaudia::prompt::build_prompt_context;
use openclaudia::services::tool_executor::ToolExecutor;
use std::path::{Path, PathBuf};

const SENTINEL: &str = "REPOSITORY_RULE_MUST_NOT_ENTER_CONTEXT_90A59FBF";

fn rust_files_below(directory: &Path, files: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).expect("read source directory") {
        let path = entry.expect("source entry").path();
        if path.is_dir() {
            rust_files_below(&path, files);
        } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
            files.push(path);
        }
    }
}

#[test]
fn repository_rule_file_cannot_enter_the_system_prompt() {
    let project = tempfile::tempdir().expect("project fixture");
    let legacy_directory = project.path().join(".openclaudia/rules");
    std::fs::create_dir_all(&legacy_directory).expect("legacy directory fixture");
    std::fs::write(legacy_directory.join("global.md"), SENTINEL).expect("legacy file fixture");

    let cwd = project.path().to_string_lossy();
    let blocks = build_prompt_context(&BehaviorMode::default(), None, Some(&cwd));
    let prompt = blocks.to_combined();

    assert!(!prompt.contains(SENTINEL));
    assert!(!prompt.contains("global.md"));
}

#[test]
fn production_sources_and_active_config_have_no_legacy_loader_or_activator() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut production_sources = Vec::new();
    rust_files_below(&root.join("src"), &mut production_sources);

    let forbidden_source_tokens = [
        "RulesEngine",
        "rules_engine",
        "rules_content",
        "inject_system_prefix",
        "init_project_rules",
        "generate_project_rules",
        "extract_extensions_from_messages",
        ".openclaudia/rules",
        ".chainlink/rules",
        ".crosslink/rules",
    ];
    for path in production_sources {
        let source = std::fs::read_to_string(&path).expect("read production source");
        for forbidden in forbidden_source_tokens {
            assert!(
                !source.contains(forbidden),
                "{} still contains legacy token {forbidden:?}",
                path.display()
            );
        }
    }

    for relative in [
        ".claude/settings.json",
        ".openclaudia/config.yaml",
        ".gitignore",
    ] {
        let path = root.join(relative);
        let content = std::fs::read_to_string(&path).expect("read active config");
        for forbidden in [
            "prompt-guard",
            "pre-web-check",
            "rules.local",
            "guard-full-sent",
            "guard-state",
        ] {
            assert!(
                !content.contains(forbidden),
                "{} still activates or advertises {forbidden:?}",
                path.display()
            );
        }
    }

    for relative in [
        "src/rules.rs",
        ".claude/hooks/prompt-guard.py",
        ".claude/hooks/pre-web-check.py",
        "tests/rules_context_e2e.rs",
        "tests/rules_accessors_e2e.rs",
        "tests/rules_engine_deep_e2e.rs",
        "tests/extract_extensions_matrix_e2e.rs",
    ] {
        assert!(!root.join(relative).exists(), "{relative} must be removed");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn pre_tool_hook_trace_keeps_only_neutral_extension_metadata() {
    let fixture = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).expect("trace fixture");
    let trace_path = fixture.path().join("hook-input.json");
    let trace_path_text = trace_path.to_string_lossy();
    let quoted_path = shlex::try_quote(trace_path_text.as_ref()).expect("quote path");

    let mut config = HooksConfig::default();
    config.pre_tool_use.push(HookEntry {
        matcher: Some("write_file".to_string()),
        hooks: vec![Hook::Command {
            command: format!("cat > {quoted_path}"),
            shell: true,
            timeout: 5,
        }],
    });
    let engine = HookEngine::new(config);

    ToolExecutor::run_pre_tool_use(
        support::shared_run_context(),
        &engine,
        Some("s-007-trace"),
        "write_file",
        &serde_json::json!({"path": "/workspace/src/main.rs"}),
    )
    .await
    .expect("neutral metadata hook should allow");

    let trace: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(trace_path).expect("captured hook trace"))
            .expect("hook trace JSON");
    assert_eq!(trace["extensions"], serde_json::json!(["rs"]));
    assert!(!trace.to_string().contains(SENTINEL));
    assert!(trace.get("instructions").is_none());
}

mod support;
