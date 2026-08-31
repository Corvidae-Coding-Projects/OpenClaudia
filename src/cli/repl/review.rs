/// Review uncommitted changes or compare two exact commit identities through
/// the run-bound, helper-disabled Git profile.
pub fn review_git_changes(run: Option<&openclaudia::tools::ToolRunContext>, args: &str) {
    let Some(run) = run else {
        eprintln!("\nGit review is unavailable without an active run capability.\n");
        return;
    };
    if !args.trim().is_empty() {
        match openclaudia::git_transaction::review_branch(run, args.trim()) {
            Ok(review) => println!("\n{}\n", review.rendered),
            Err(error) => eprintln!("\nGit review failed: {error}\n"),
        }
        return;
    }
    match openclaudia::git_transaction::prepare_commit_review(run) {
        Ok(review) => {
            println!("\n=== Exact Uncommitted Git Review ===\n");
            println!("HEAD: {}", review.generation().head);
            println!("Destination: {}", review.destination());
            println!("Candidate tree: {}", review.candidate_tree());
            println!("Paths:");
            for path in review.rendered_paths() {
                println!("  - {path}");
            }
            println!("\n{}\n", review.rendered_diff());
        }
        Err(openclaudia::git_transaction::GitTransactionError::NothingToCommit { head }) => {
            println!("\nNo non-ignored changes at HEAD {head}.\n");
        }
        Err(error) => eprintln!("\nGit review failed: {error}\n"),
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
    #[test]
    fn review_routes_through_generation_bound_git_api() {
        let src = include_str!("review.rs");
        let cfg_test = src
            .find("#[cfg(test)]")
            .expect("test module marker must be present");
        let production = &src[..cfg_test];
        assert!(
            production.contains("git_transaction::review_branch")
                && production.contains("git_transaction::prepare_commit_review"),
            "both review modes must use the run-bound transaction API"
        );
        assert!(!production.contains("std::process::Command"));
        assert!(!production.contains(".output()"));

        let transaction = include_str!("../../git_transaction.rs");
        assert!(transaction.contains("\"--end-of-options\""));
        assert!(transaction.contains("run_prepared_run_owned_sync"));
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
