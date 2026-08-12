use std::{
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};
use tracing::info;

fn config_path_metadata(path: &Path) -> anyhow::Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(anyhow::anyhow!(
            "failed to inspect configuration path {}: {err}",
            path.display()
        )),
    }
}

fn write_new_regular_file(path: &Path, contents: &str) -> anyhow::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|err| {
            anyhow::anyhow!(
                "failed to create configuration file {}: {err}",
                path.display()
            )
        })?;
    file.write_all(contents.as_bytes()).map_err(|err| {
        anyhow::anyhow!(
            "failed to write configuration file {}: {err}",
            path.display()
        )
    })
}

#[allow(clippy::too_many_lines)]
/// Initialize `OpenClaudia` configuration
pub fn cmd_init(force: bool) -> anyhow::Result<()> {
    let config_dir = PathBuf::from(".openclaudia");
    let config_file = config_dir.join("config.yaml");

    if let Some(metadata) = config_path_metadata(&config_file)? {
        if !force {
            tracing::error!("Configuration already exists. Use --force to overwrite.");
            // Refuse-to-overwrite MUST exit non-zero so scripts checking $?
            // can detect the failure. Previously this returned Ok(()) and
            // exited 0, silently hiding the no-op from callers.
            anyhow::bail!(
                "Configuration already exists at .openclaudia/config.yaml. \
                 Re-run with --force to overwrite."
            );
        }

        if metadata.file_type().is_dir() {
            anyhow::bail!("Cannot overwrite .openclaudia/config.yaml because it is a directory.");
        }

        fs::remove_file(&config_file).map_err(|err| {
            anyhow::anyhow!(
                "failed to remove existing configuration path {}: {err}",
                config_file.display()
            )
        })?;
    }

    // Create directories
    fs::create_dir_all(&config_dir)?;
    fs::create_dir_all(config_dir.join("hooks"))?;
    fs::create_dir_all(config_dir.join("rules"))?;
    fs::create_dir_all(config_dir.join("plugins"))?;

    // Write default config
    let default_config = r#"# OpenClaudia Configuration
# https://github.com/dollspace-gay/OpenClaudia

proxy:
  port: 8080
  host: "127.0.0.1"
  # Provider: anthropic, openai, google/gemini, deepseek, qwen/alibaba,
  # zai/glm/zhipu, kimi/moonshot, minimax, ollama, local, lmstudio,
  # localai, text-generation-webui, openrouter, opencode/opencode-go,
  # openai-compatible
  target: anthropic

providers:
  # Anthropic - Models: claude-fable-5, claude-opus-4-8, claude-opus-4-7, claude-sonnet-4-6
  anthropic:
    base_url: https://api.anthropic.com
    # api_key: ${ANTHROPIC_API_KEY}  # Set via environment variable
  # OpenAI - Models: gpt-5.5, gpt-5.5-pro, gpt-5.4-mini
  openai:
    base_url: https://api.openai.com
    # api_key: ${OPENAI_API_KEY}
  # Google Gemini - Models: gemini-3.5-flash, gemini-3.1-pro-preview-customtools
  google:
    base_url: https://generativelanguage.googleapis.com
    # api_key: ${GOOGLE_API_KEY}  # or ${GEMINI_API_KEY}
  # Z.AI/GLM (OpenAI-compatible) - Models: glm-5.2, glm-5v-turbo, glm-5-turbo
  zai:
    base_url: https://api.z.ai/api/paas/v4
    # Coding Plan users: https://api.z.ai/api/coding/paas/v4
    # api_key: ${ZAI_API_KEY}
  # DeepSeek (OpenAI-compatible) - Models: deepseek-v4-pro, deepseek-v4-flash
  deepseek:
    base_url: https://api.deepseek.com
    # api_key: ${DEEPSEEK_API_KEY}
  # Qwen/Alibaba (OpenAI-compatible) - Models: qwen3.7-plus, qwen3.7-max
  qwen:
    base_url: https://dashscope.aliyuncs.com/compatible-mode
    # api_key: ${QWEN_API_KEY}  # or ${DASHSCOPE_API_KEY} / ${ALIYUN_API_KEY}
  # Kimi/Moonshot (OpenAI-compatible) - Models: kimi-k2.7-code, kimi-k2.6
  kimi:
    base_url: https://api.moonshot.ai/v1
    # api_key: ${KIMI_API_KEY}  # or ${MOONSHOT_API_KEY}
  # MiniMax (OpenAI-compatible) - Models: MiniMax-M3, MiniMax-M2.7
  minimax:
    base_url: https://api.minimax.io/v1
    # api_key: ${MINIMAX_API_KEY}
  # OpenRouter (OpenAI-compatible aggregator) - /model list fetches /v1/models
  openrouter:
    base_url: https://openrouter.ai/api/v1
    # api_key: ${OPENROUTER_API_KEY}  # or ${OPEN_ROUTER_API_KEY}
    # headers:
    #   HTTP-Referer: https://example.com
    #   X-OpenRouter-Title: OpenClaudia
  # OpenCode Go OpenAI-compatible endpoint subset
  opencode:
    base_url: https://opencode.ai/zen/go/v1
    # api_key: ${OPENCODE_API_KEY}  # or ${OPENCODE_GO_API_KEY}
  # Generic remote OpenAI-compatible endpoint
  openai-compatible:
    base_url: https://api.example.com/v1
    # api_key: ${OPENAI_COMPATIBLE_API_KEY}
    # model: my-model-name
  # Ollama for local LLM inference
  ollama:
    base_url: http://localhost:11434
  # Any OpenAI-compatible local server (LM Studio, LocalAI, text-generation-webui)
  local:
    base_url: http://localhost:1234/v1
  lmstudio:
    base_url: http://localhost:1234/v1
  localai:
    base_url: http://localhost:8080/v1
  text-generation-webui:
    base_url: http://localhost:5000/v1

# Hooks run at key moments in the agent lifecycle
# See the hooks configuration examples below.
# hooks:
#   session_start:
#     - hooks:
#         - type: command
#           command: python .openclaudia/hooks/session-start.py
#           timeout: 30
#   pre_tool_use:
#     - matcher: "Write|Edit"
#       hooks:
#         - type: command
#           command: python .openclaudia/hooks/validate-write.py
#   user_prompt_submit:
#     - hooks:
#         - type: command
#           command: python .openclaudia/hooks/prompt-guard.py

session:
  timeout_minutes: 30
  persist_path: .openclaudia/session

# Legacy line REPL keybindings (`openclaudia --tui-mode`)
# Map key combinations to actions. The default full-screen TUI currently
# uses its built-in shortcuts; type /help there to view them.
# Available actions: new_session, list_sessions, export, copy_response,
#   editor, models, toggle_mode, cancel, status, help, clear, exit, undo, redo, compact
# Set any key to "none" to disable it
# keybindings:
#   ctrl-x n: new_session
#   ctrl-x l: list_sessions
#   ctrl-x x: export
#   ctrl-x y: copy_response
#   ctrl-x e: editor
#   ctrl-x m: models
#   ctrl-x s: status
#   ctrl-x h: help
#   f2: models
#   tab: toggle_mode
#   escape: cancel

# Verification-Driven Development (VDD) - Adversarial code review
# Uses a DIFFERENT model to review the builder's output for bugs/issues
# vdd:
#   enabled: false
#   mode: advisory  # advisory = inject findings into next turn, blocking = loop until clean
#   adversary:
#     provider: google           # MUST differ from proxy.target
#     model: gemini-3.1-pro-preview
#     # model is optional; omitted uses the provider default
#     # api_key: ${GOOGLE_API_KEY}  # or ${GEMINI_API_KEY}; optional
#     temperature: 0.3           # Lower = more deterministic critique
#     max_tokens: 4096
#   thresholds:
#     max_iterations: 5          # Max adversary loops (blocking mode)
#     false_positive_rate: 0.75  # Confabulation threshold to stop loop
#     min_iterations: 2          # Minimum before checking confabulation
#   static_analysis:
#     enabled: true
#     commands:                  # Shell commands that must pass (exit 0)
#       - "cargo clippy -- -D warnings"
#       - "cargo test --no-fail-fast"
#     timeout_seconds: 120
#   tracking:
#     persist: true
#     path: .openclaudia/vdd
#     log_adversary_responses: true

# Guardrails - Constrain agent behavior and monitor changes
# guardrails:
#   blast_radius:
#     enabled: true
#     mode: advisory           # strict = block, advisory = warn
#     allowed_paths:           # Glob patterns (empty = all allowed)
#       - "src/**"
#       - "tests/**"
#     denied_paths:            # Glob patterns (takes priority over allowed)
#       - ".env"
#       - "secrets/**"
#       - "*.pem"
#     max_files_per_turn: 10   # 0 = unlimited
#   diff_monitor:
#     enabled: true
#     max_lines_changed: 500   # 0 = unlimited
#     max_files_changed: 10    # 0 = unlimited
#     action: warn             # warn, block, or inject_findings
#   quality_gates:
#     enabled: true
#     run_after: every_turn    # every_edit, every_turn, or on_commit
#     fail_action: warn        # warn, block, or inject_findings
#     timeout_seconds: 120
#     checks:
#       - name: clippy
#         command: "cargo clippy -- -D warnings"
#         required: true
#       - name: tests
#         command: "cargo test --no-fail-fast"
#         required: true
"#;

    write_new_regular_file(&config_file, default_config)?;

    // Write example hook
    let example_hook = r#"#!/usr/bin/env python3
"""Example SessionStart hook for OpenClaudia.

This hook runs when a new session starts.
Output JSON to stdout to inject context into the conversation.
"""

import json
import sys
import os

def main():
    # Read hook input from stdin
    input_data = json.load(sys.stdin)

    # Get project information
    cwd = input_data.get("cwd", os.getcwd())

    # Output context to inject
    output = {
        "systemMessage": f"Working directory: {cwd}"
    }

    print(json.dumps(output))

if __name__ == "__main__":
    main()
"#;

    fs::write(config_dir.join("hooks/session-start.py"), example_hook)?;

    // Write example rule
    let example_rule = r"# Global Rules

These rules are injected into every conversation.

## Code Quality
- Write clean, readable code
- Include error handling
- No hardcoded secrets

## Security
- Validate all user input
- Use parameterized queries
- Follow OWASP guidelines
";

    fs::write(config_dir.join("rules/global.md"), example_rule)?;

    info!("Initialized OpenClaudia configuration in .openclaudia/");
    info!("  config.yaml  - Main configuration");
    info!("  hooks/       - Hook scripts");
    info!("  rules/       - Markdown rules");
    info!("  plugins/     - Plugin directory");
    info!("");
    info!("Set your API key:");
    info!("  export ANTHROPIC_API_KEY=your-key-here");
    info!("");
    info!("Start the chat:");
    info!("  openclaudia");

    Ok(())
}

/// Detect project type from current directory
pub fn detect_project_type() -> Vec<(&'static str, &'static str)> {
    let mut detected = Vec::new();

    // Check for various project indicators
    if std::path::Path::new("Cargo.toml").exists() {
        detected.push(("rust", "Rust project detected (Cargo.toml)"));
    }
    if std::path::Path::new("package.json").exists() {
        detected.push(("node", "Node.js project detected (package.json)"));
    }
    if std::path::Path::new("pyproject.toml").exists() || std::path::Path::new("setup.py").exists()
    {
        detected.push(("python", "Python project detected"));
    }
    if std::path::Path::new("go.mod").exists() {
        detected.push(("go", "Go project detected (go.mod)"));
    }
    if std::path::Path::new("pom.xml").exists() || std::path::Path::new("build.gradle").exists() {
        detected.push(("java", "Java project detected"));
    }
    if std::path::Path::new(".git").exists() {
        detected.push(("git", "Git repository detected"));
    }

    detected
}

/// Generate project rules based on detected type
pub fn generate_project_rules(project_types: &[(&str, &str)]) -> String {
    let mut rules = String::new();
    rules.push_str("# Project Rules\n\n");
    rules.push_str("Auto-generated rules based on project structure.\n\n");

    for (ptype, _) in project_types {
        match *ptype {
            "rust" => {
                rules.push_str("## Rust Guidelines\n\n");
                rules.push_str("- Use `cargo fmt` before committing\n");
                rules.push_str("- Run `cargo clippy` to check for common mistakes\n");
                rules.push_str("- Prefer `?` operator over `.unwrap()` for error handling\n");
                rules.push_str("- Use `anyhow::Result` for application errors\n");
                rules.push_str("- Run `cargo test` before pushing changes\n\n");
            }
            "node" => {
                rules.push_str("## Node.js Guidelines\n\n");
                rules.push_str("- Use consistent code style (prettier/eslint)\n");
                rules.push_str("- Run `npm test` before committing\n");
                rules.push_str("- Keep dependencies up to date\n");
                rules.push_str("- Use async/await over callbacks\n\n");
            }
            "python" => {
                rules.push_str("## Python Guidelines\n\n");
                rules.push_str("- Follow PEP 8 style guide\n");
                rules.push_str("- Use type hints where possible\n");
                rules.push_str("- Run tests with pytest before committing\n");
                rules.push_str("- Use virtual environments\n\n");
            }
            "go" => {
                rules.push_str("## Go Guidelines\n\n");
                rules.push_str("- Run `go fmt` before committing\n");
                rules.push_str("- Use `go vet` to check for issues\n");
                rules.push_str("- Handle all errors explicitly\n");
                rules.push_str("- Run `go test ./...` before pushing\n\n");
            }
            "java" => {
                rules.push_str("## Java Guidelines\n\n");
                rules.push_str("- Follow Java naming conventions\n");
                rules.push_str("- Run tests before committing\n");
                rules.push_str("- Use dependency injection where appropriate\n\n");
            }
            "git" => {
                rules.push_str("## Git Guidelines\n\n");
                rules.push_str("- Write clear, descriptive commit messages\n");
                rules.push_str("- Keep commits atomic and focused\n");
                rules.push_str("- Don't commit secrets or API keys\n\n");
            }
            _ => {}
        }
    }

    rules
}

/// Initialize project rules from codebase analysis
pub fn init_project_rules() {
    let detected = detect_project_type();

    if detected.is_empty() {
        println!("\nNo recognized project type detected.");
        println!("Creating generic rules file.\n");
    } else {
        println!("\nDetected project types:");
        for (_, desc) in &detected {
            println!("  - {desc}");
        }
    }

    let rules_dir = std::path::Path::new(".openclaudia/rules");
    if let Err(e) = fs::create_dir_all(rules_dir) {
        eprintln!("\nFailed to create rules directory: {e}\n");
        return;
    }

    let rules_content = generate_project_rules(&detected);
    let rules_path = rules_dir.join("project.md");

    if rules_path.exists() {
        println!("\nRules file already exists at {}", rules_path.display());
        println!("Use a text editor to modify it.\n");
        return;
    }

    match fs::write(&rules_path, &rules_content) {
        Ok(()) => {
            println!("\nGenerated rules at: {}", rules_path.display());
            println!("Edit this file to customize rules for your project.\n");
        }
        Err(e) => eprintln!("\nFailed to write rules: {e}\n"),
    }
}
