use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::LazyLock;

/// Absolute, PATH-independent location of `git` for review helpers.
static GIT_BIN: LazyLock<Result<PathBuf, String>> =
    LazyLock::new(|| which::which("git").map_err(|e| format!("git binary not found on PATH: {e}")));

fn git_bin() -> Result<&'static Path, String> {
    match &*GIT_BIN {
        Ok(path) => Ok(path.as_path()),
        Err(msg) => Err(msg.clone()),
    }
}

fn git_output(args: &[&str]) -> Result<Output, String> {
    Command::new(git_bin()?)
        .args(args)
        .output()
        .map_err(|e| e.to_string())
}

fn git_failure_message(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let message = stderr.trim();
    if message.is_empty() {
        format!("git exited with {}", output.status)
    } else {
        message.to_string()
    }
}

/// Review uncommitted git changes or compare against a branch
pub fn review_git_changes(args: &str) {
    match git_output(&["rev-parse", "--git-dir"]) {
        Ok(output) if output.status.success() => {}
        Ok(_) => {
            println!("\nNot a git repository.\n");
            return;
        }
        Err(e) => {
            eprintln!("\nFailed to run git: {e}\n");
            return;
        }
    }

    println!();

    if args.is_empty() {
        review_uncommitted_changes();
    } else {
        review_branch_comparison(args.trim());
    }
}

fn review_uncommitted_changes() {
    println!("=== Git Status ===\n");
    let status = git_output(&["status", "--short"]);

    match status {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.is_empty() {
                println!("No changes detected.\n");
                return;
            }
            println!("{stdout}");
        }
        Ok(output) => {
            eprintln!(
                "Failed to run git status: {}\n",
                git_failure_message(&output)
            );
            return;
        }
        Err(e) => {
            eprintln!("Failed to run git status: {e}\n");
            return;
        }
    }

    println!("=== Uncommitted Changes ===\n");
    let diff = git_output(&["diff", "HEAD"]);

    match diff {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.is_empty() {
                println!("No diff to show (changes may be staged).\n");
            } else {
                let lines: Vec<&str> = stdout.lines().collect();
                if lines.len() > 100 {
                    for line in lines.iter().take(100) {
                        println!("{line}");
                    }
                    println!(
                        "\n... ({} more lines, use git diff directly for full output)\n",
                        lines.len() - 100
                    );
                } else {
                    println!("{stdout}");
                }
            }
        }
        Ok(output) => eprintln!("Failed to run git diff: {}\n", git_failure_message(&output)),
        Err(e) => eprintln!("Failed to run git diff: {e}\n"),
    }
}

fn review_branch_comparison(branch: &str) {
    println!("=== Comparing against '{branch}' ===\n");

    let verify_ref = format!("{branch}^{{commit}}");
    let branch_check = git_output(&[
        "rev-parse",
        "--verify",
        "--quiet",
        "--end-of-options",
        verify_ref.as_str(),
    ]);

    let base_commit = match branch_check {
        Ok(output) if output.status.success() => {
            let commit = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if commit.is_empty() {
                eprintln!("Branch '{branch}' not found.\n");
                return;
            }
            commit
        }
        Ok(_) => {
            eprintln!("Branch '{branch}' not found.\n");
            return;
        }
        Err(e) => {
            eprintln!("Failed to run git rev-parse: {e}\n");
            return;
        }
    };

    println!("Commits ahead of {branch}:\n");
    let range = format!("{base_commit}..HEAD");
    let log = git_output(&["log", "--oneline", range.as_str()]);

    match log {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.is_empty() {
                println!("  (no commits ahead)\n");
            } else {
                for line in stdout.lines() {
                    println!("  {line}");
                }
                println!();
            }
        }
        Ok(output) => eprintln!("Failed to run git log: {}\n", git_failure_message(&output)),
        Err(e) => eprintln!("Failed to run git log: {e}\n"),
    }

    println!("Changed files:\n");
    let diff_stat = git_output(&["diff", "--stat", base_commit.as_str()]);

    match diff_stat {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.is_empty() {
                println!("  (no changes)\n");
            } else {
                println!("{stdout}");
            }
        }
        Ok(output) => eprintln!(
            "Failed to run git diff --stat: {}\n",
            git_failure_message(&output)
        ),
        Err(e) => eprintln!("Failed to run git diff --stat: {e}\n"),
    }
}

/// Configure API key for a provider interactively
pub fn configure_provider_api_key() {
    use std::io::{self, Write};

    let providers = [
        ("anthropic", "Anthropic (Claude)", "ANTHROPIC_API_KEY"),
        ("openai", "OpenAI (GPT)", "OPENAI_API_KEY"),
        (
            "google",
            "Google (Gemini)",
            "GOOGLE_API_KEY or GEMINI_API_KEY",
        ),
        ("deepseek", "DeepSeek", "DEEPSEEK_API_KEY"),
        (
            "qwen",
            "Qwen (Alibaba)",
            "QWEN_API_KEY, DASHSCOPE_API_KEY, or ALIYUN_API_KEY",
        ),
        ("zai", "Z.AI (GLM)", "ZAI_API_KEY"),
        (
            "kimi",
            "Kimi (Moonshot)",
            "KIMI_API_KEY or MOONSHOT_API_KEY",
        ),
        ("minimax", "MiniMax", "MINIMAX_API_KEY"),
    ];

    println!("\n=== Configure API Provider ===\n");
    println!("Select a provider to configure:\n");

    for (i, (_, name, _)) in providers.iter().enumerate() {
        println!("  {}. {}", i + 1, name);
    }
    println!();

    print!("Enter choice (1-{}): ", providers.len());
    io::stdout().flush().ok();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        eprintln!("Failed to read input.\n");
        return;
    }

    let choice: usize = match input.trim().parse() {
        Ok(n) if n >= 1 && n <= providers.len() => n,
        _ => {
            eprintln!("Invalid choice.\n");
            return;
        }
    };

    let (provider_id, provider_name, env_var) = providers[choice - 1];

    println!("\nConfiguring {provider_name}...");
    println!("You can get an API key from the provider's website.\n");

    print!("Enter API key (or press Enter to skip): ");
    io::stdout().flush().ok();

    let mut api_key = String::new();
    if io::stdin().read_line(&mut api_key).is_err() {
        eprintln!("Failed to read input.\n");
        return;
    }

    let api_key = api_key.trim();
    if api_key.is_empty() {
        println!("Skipped. Set {env_var} environment variable instead.\n");
        return;
    }

    let config_path = provider_api_key_config_path();
    let Some(config_dir) = config_path.parent() else {
        eprintln!("Failed to resolve provider config directory.\n");
        return;
    };

    if let Err(e) = fs::create_dir_all(config_dir) {
        eprintln!("Failed to create config directory: {e}\n");
        return;
    }

    match upsert_provider_api_key_config(&config_path, provider_id, provider_name, api_key) {
        Ok(ProviderConfigUpdate::AlreadyConfigured) => {
            println!("\nProvider already configured in config file.");
            println!("Edit {} to update.\n", config_path.display());
        }
        Ok(ProviderConfigUpdate::Saved) => {
            println!("\nSaved API key to: {}", config_path.display());
            println!("Restart the chat to use the new configuration.\n");
        }
        Err(e) => eprintln!("\n{e}\n"),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ProviderConfigUpdate {
    AlreadyConfigured,
    Saved,
}

fn provider_api_key_config_path() -> PathBuf {
    dirs::home_dir().map_or_else(
        || PathBuf::from(".openclaudia/config.yaml"),
        |home| home.join(".openclaudia/config.yaml"),
    )
}

fn upsert_provider_api_key_config(
    config_path: &Path,
    provider_id: &str,
    _provider_name: &str,
    api_key: &str,
) -> Result<ProviderConfigUpdate, String> {
    let config_content = match fs::read_to_string(config_path) {
        Ok(content) => content,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => {
            return Err(format!(
                "Failed to read existing config {}: {e}",
                config_path.display()
            ));
        }
    };

    let mut root = if config_content.trim().is_empty() {
        serde_yaml::Value::Mapping(serde_yaml::Mapping::new())
    } else {
        serde_yaml::from_str::<serde_yaml::Value>(&config_content).map_err(|e| {
            format!(
                "Failed to parse existing config {}: {e}",
                config_path.display()
            )
        })?
    };

    let serde_yaml::Value::Mapping(root_map) = &mut root else {
        return Err(format!(
            "Failed to update config {}: root document must be a mapping",
            config_path.display()
        ));
    };

    let providers_yaml_key = serde_yaml::Value::String("providers".to_string());
    let selected_provider_yaml_key = serde_yaml::Value::String(provider_id.to_string());
    let api_key_yaml_key = serde_yaml::Value::String("api_key".to_string());

    if !root_map.contains_key(&providers_yaml_key) {
        root_map.insert(
            providers_yaml_key.clone(),
            serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        );
    }

    let providers = root_map.get_mut(&providers_yaml_key).ok_or_else(|| {
        format!(
            "Failed to update config {}: providers block missing after initialization",
            config_path.display()
        )
    })?;
    let serde_yaml::Value::Mapping(providers_map) = providers else {
        return Err(format!(
            "Failed to update config {}: providers must be a mapping",
            config_path.display()
        ));
    };

    if !providers_map.contains_key(&selected_provider_yaml_key) {
        providers_map.insert(
            selected_provider_yaml_key.clone(),
            serde_yaml::Value::Mapping(serde_yaml::Mapping::new()),
        );
    }

    let selected_provider = providers_map
        .get_mut(&selected_provider_yaml_key)
        .ok_or_else(|| {
            format!(
                "Failed to update config {}: provider block missing after initialization",
                config_path.display()
            )
        })?;
    let serde_yaml::Value::Mapping(selected_provider_map) = selected_provider else {
        return Err(format!(
            "Failed to update config {}: providers.{provider_id} must be a mapping",
            config_path.display()
        ));
    };

    if selected_provider_map.contains_key(&api_key_yaml_key) {
        return Ok(ProviderConfigUpdate::AlreadyConfigured);
    }

    selected_provider_map.insert(
        api_key_yaml_key,
        serde_yaml::Value::String(api_key.to_string()),
    );

    let rendered = serde_yaml::to_string(&root).map_err(|e| {
        format!(
            "Failed to encode API key for config {}: {e}",
            config_path.display()
        )
    })?;

    fs::write(config_path, rendered)
        .map_err(|e| format!("Failed to save config {}: {e}", config_path.display()))?;

    Ok(ProviderConfigUpdate::Saved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_yaml::Value as YamlValue;

    #[test]
    fn review_git_helpers_use_resolved_binary_path() {
        let git = git_bin().expect("review tests require git on PATH");
        assert!(
            git.is_absolute(),
            "git_bin must resolve git to an absolute path, got {}",
            git.display()
        );

        let src = include_str!("review.rs");
        let cfg_test = src
            .find("#[cfg(test)]")
            .expect("test module marker must be present");
        let production = &src[..cfg_test];

        assert!(
            production.contains("\"--end-of-options\""),
            "branch verification must terminate git option parsing"
        );

        for (idx, raw_line) in production.lines().enumerate() {
            let code = raw_line.split("//").next().unwrap_or("");
            assert!(
                !code.contains("Command::new(\"git\")")
                    && !code.contains("std::process::Command::new(\"git\")"),
                "production review code must not invoke bare git; line {n}: {raw_line}",
                n = idx + 1,
            );
            assert!(
                !code.contains(".unwrap().status.success()"),
                "production review code must not unwrap git probes; line {n}: {raw_line}",
                n = idx + 1,
            );
        }
    }

    #[test]
    fn upsert_provider_api_key_config_rejects_unreadable_utf8_without_overwrite() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.yaml");
        fs::write(&config_path, [0xff, 0xfe, 0xfd]).unwrap();

        let err = upsert_provider_api_key_config(&config_path, "openai", "OpenAI", "sk-new-key")
            .expect_err("invalid UTF-8 config must not be treated as empty");

        assert!(err.contains("Failed to read existing config"), "{err}");
        assert_eq!(fs::read(&config_path).unwrap(), vec![0xff, 0xfe, 0xfd]);
    }

    #[test]
    fn upsert_provider_api_key_config_writes_nested_provider_key() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.yaml");
        let api_key = "sk-quote\"and\\slash";

        let update = upsert_provider_api_key_config(&config_path, "openai", "OpenAI", api_key)
            .expect("new config should be written");

        assert_eq!(update, ProviderConfigUpdate::Saved);
        let config = fs::read_to_string(&config_path).unwrap();
        let parsed: YamlValue = serde_yaml::from_str(&config).unwrap();
        assert_eq!(
            parsed["providers"]["openai"]["api_key"].as_str(),
            Some(api_key)
        );
    }

    #[test]
    fn upsert_provider_api_key_config_preserves_existing_provider_key() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.yaml");
        let original = "providers:\n  openai:\n    api_key: \"sk-existing\"\n";
        fs::write(&config_path, original).unwrap();

        let update = upsert_provider_api_key_config(&config_path, "openai", "OpenAI", "sk-new")
            .expect("existing readable config should load");

        assert_eq!(update, ProviderConfigUpdate::AlreadyConfigured);
        assert_eq!(fs::read_to_string(&config_path).unwrap(), original);
    }

    #[test]
    fn upsert_provider_api_key_config_does_not_treat_legacy_key_as_configured() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.yaml");
        fs::write(&config_path, "openai_api_key: \"sk-legacy\"\n").unwrap();

        let update = upsert_provider_api_key_config(&config_path, "openai", "OpenAI", "sk-new")
            .expect("legacy top-level key should not block current schema");

        assert_eq!(update, ProviderConfigUpdate::Saved);
        let config = fs::read_to_string(&config_path).unwrap();
        let parsed: YamlValue = serde_yaml::from_str(&config).unwrap();
        assert_eq!(
            parsed["providers"]["openai"]["api_key"].as_str(),
            Some("sk-new")
        );
        assert_eq!(parsed["openai_api_key"].as_str(), Some("sk-legacy"));
    }

    #[test]
    fn upsert_provider_api_key_config_rejects_invalid_yaml_without_overwrite() {
        let tmp = tempfile::tempdir().unwrap();
        let config_path = tmp.path().join("config.yaml");
        let original = "providers:\n  openai: [unterminated\n";
        fs::write(&config_path, original).unwrap();

        let err = upsert_provider_api_key_config(&config_path, "openai", "OpenAI", "sk-new")
            .expect_err("invalid YAML config must not be overwritten");

        assert!(err.contains("Failed to parse existing config"), "{err}");
        assert_eq!(fs::read_to_string(&config_path).unwrap(), original);
    }
}
