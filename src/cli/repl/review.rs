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

/// Save a provider API key to the protected user credential store.
pub fn configure_provider_api_key(app_config: Option<&openclaudia::config::AppConfig>) {
    use std::io::{self, Write};

    if !openclaudia::provider_credentials::protected_persistence_supported() {
        eprintln!("\nProtected API-key persistence is unavailable on this platform.\n");
        return;
    }

    let loaded_config = if app_config.is_none() {
        match openclaudia::config::load_config() {
            Ok(config) => Some(config),
            Err(error) => {
                eprintln!("\nFailed to load provider configuration: {error}\n");
                return;
            }
        }
    } else {
        None
    };
    let config = app_config
        .or(loaded_config.as_ref())
        .expect("configuration is loaded when the caller does not supply it");
    let providers = openclaudia::provider_credentials::api_key_targets(config);
    if providers.is_empty() {
        eprintln!("\nNo remote API-key providers are configured.\n");
        return;
    }

    println!("\n=== Configure API Provider ===\n");
    println!("Select a provider to configure:\n");

    for (index, provider) in providers.iter().enumerate() {
        println!("  {}. {provider}", index + 1);
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

    let provider = &providers[choice - 1];
    let store_path = match openclaudia::provider_credentials::user_store_path() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("\n{error}\n");
            return;
        }
    };

    println!("\nProvider: {provider}");
    println!("Scope: this user account");
    println!("Destination: {}", store_path.display());
    println!("Effect: available to new OpenClaudia chats; project files are unchanged.\n");
    if !prompt_confirmation("Save to this destination? [y/N]: ") {
        println!("Cancelled; no credentials were changed.\n");
        return;
    }

    let overwrite = match openclaudia::provider_credentials::has_saved_user_api_key(provider) {
        Ok(false) => false,
        Ok(true) => {
            println!("A protected key is already saved for {provider}.");
            if !prompt_confirmation("Replace the existing saved key? [y/N]: ") {
                println!("Cancelled; the existing credential is unchanged.\n");
                return;
            }
            true
        }
        Err(error) => {
            eprintln!("\nFailed to inspect protected credentials: {error}\n");
            return;
        }
    };

    let api_key = match openclaudia::provider_credentials::prompt_hidden_api_key(provider) {
        Ok(api_key) => api_key,
        Err(error) => {
            eprintln!("\n{error}\n");
            return;
        }
    };
    match openclaudia::provider_credentials::save_user_api_key(provider, api_key, overwrite) {
        Ok(_) => {
            println!("\nSaved protected API key to: {}", store_path.display());
            println!("Start a new chat to use it.\n");
        }
        Err(error) => eprintln!("\nFailed to save protected API key: {error}\n"),
    }
}

fn prompt_confirmation(prompt: &str) -> bool {
    use std::io::{self, Write as _};

    print!("{prompt}");
    if io::stdout().flush().is_err() {
        return false;
    }
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn legacy_connect_source_has_no_yaml_secret_writer_or_echoed_key_read() {
        let source = include_str!("review.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production section");

        assert!(!production.contains(".openclaudia/config.yaml"));
        assert!(!production.contains("upsert_provider_api_key_config"));
        assert!(production.contains("prompt_hidden_api_key"));
    }
}
