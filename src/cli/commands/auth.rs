use openclaudia::tools::safe_truncate;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
enum NativeOAuthSessionStoreStatus {
    Missing,
    SessionCount(usize),
    Unreadable(String),
}

fn spawn_browser_opener(auth_url: &str) {
    #[cfg(target_os = "windows")]
    {
        if let Ok(opener) = which::which("rundll32") {
            let _ = std::process::Command::new(opener)
                .args(["url.dll,FileProtocolHandler", auth_url])
                .spawn();
        }
    }
    #[cfg(target_os = "macos")]
    {
        if let Ok(opener) = which::which("open") {
            let _ = std::process::Command::new(opener).arg(auth_url).spawn();
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(opener) = which::which("xdg-open") {
            let _ = std::process::Command::new(opener).arg(auth_url).spawn();
        }
    }
}

fn native_oauth_session_store_path() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("openclaudia").join("oauth_sessions.json"))
}

fn native_oauth_session_store_path_exists(path: &Path) -> Result<bool, String> {
    match path.symlink_metadata() {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(format!("failed to inspect {}: {err}", path.display())),
    }
}

fn native_oauth_session_store_status() -> NativeOAuthSessionStoreStatus {
    let Some(path) = native_oauth_session_store_path() else {
        return NativeOAuthSessionStoreStatus::Missing;
    };

    let file = match open_native_oauth_session_file(&path) {
        Ok(Some(file)) => file,
        Ok(None) => return NativeOAuthSessionStoreStatus::Missing,
        Err(reason) => return NativeOAuthSessionStoreStatus::Unreadable(reason),
    };

    let content = match std::io::read_to_string(file) {
        Ok(content) => zeroize::Zeroizing::new(content),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return NativeOAuthSessionStoreStatus::Missing;
        }
        Err(err) => {
            return NativeOAuthSessionStoreStatus::Unreadable(format!(
                "failed to read {}: {err}",
                path.display()
            ));
        }
    };

    match serde_json::from_str::<std::collections::HashMap<String, serde_json::Value>>(&content) {
        Ok(sessions) => NativeOAuthSessionStoreStatus::SessionCount(sessions.len()),
        Err(err) => NativeOAuthSessionStoreStatus::Unreadable(format!(
            "failed to parse {}: {err}",
            path.display()
        )),
    }
}

fn open_native_oauth_session_file(path: &Path) -> Result<Option<std::fs::File>, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => Ok(Some(file)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) if err.raw_os_error() == Some(libc::ELOOP) => {
                Err(format!("{} is a symlink; refusing to read", path.display()))
            }
            Err(err) => Err(format!("failed to open {}: {err}", path.display())),
        }
    }

    #[cfg(not(unix))]
    {
        match std::fs::File::open(path) {
            Ok(file) => {
                if path
                    .symlink_metadata()
                    .is_ok_and(|metadata| metadata.file_type().is_symlink())
                {
                    return Err(format!("{} is a symlink; refusing to read", path.display()));
                }
                Ok(Some(file))
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(format!("failed to open {}: {err}", path.display())),
        }
    }
}

#[allow(clippy::too_many_lines)]
/// Authenticate with Claude Max subscription via OAuth
pub async fn cmd_auth(status: bool, logout: bool) -> anyhow::Result<()> {
    use openclaudia::oauth::{parse_auth_code, OAuthClient, OAuthStore, PkceParams};
    use std::io::{self, IsTerminal, Write};

    if status && logout {
        anyhow::bail!("auth --status and --logout cannot be used together");
    }

    let store = OAuthStore::new();

    // Handle --status flag
    if status {
        let credentials_path = openclaudia::claude_credentials::credentials_path().map_or_else(
            || "~/.claude/.credentials.json".to_string(),
            |path| path.display().to_string(),
        );
        match openclaudia::claude_credentials::peek_credentials() {
            Ok(Some(status)) => {
                let now_ms = chrono::Utc::now().timestamp_millis();
                let remaining_secs = (status.expires_at_ms - now_ms).max(0) / 1000;
                println!("Claude credentials ({credentials_path}):");
                println!(
                    "  subscription : {}",
                    status.subscription_type.as_deref().unwrap_or("unknown")
                );
                println!(
                    "  inference    : {}",
                    if status.has_inference_scope {
                        "yes"
                    } else {
                        "no (chat will fail)"
                    }
                );
                if status.expired {
                    println!("  status       : expired (auto-refreshes on next use)");
                } else if status.expires_soon {
                    println!("  status       : valid, expiring soon (auto-refreshes on next use)");
                } else {
                    println!(
                        "  status       : valid (~{}h{}m remaining)",
                        remaining_secs / 3600,
                        (remaining_secs % 3600) / 60
                    );
                }
            }
            Ok(None) => {
                println!("No Claude credentials at {credentials_path}.");
                println!("Run 'openclaudia auth', or log in with Claude Code / openclaude.");
            }
            Err(e) => {
                eprintln!("Could not read {credentials_path}: {e}");
                anyhow::bail!("could not read Claude credentials: {e}");
            }
        }

        println!();
        match native_oauth_session_store_status() {
            NativeOAuthSessionStoreStatus::Missing
            | NativeOAuthSessionStoreStatus::SessionCount(0) => {
                println!("Native OAuth session store: empty.");
            }
            NativeOAuthSessionStoreStatus::SessionCount(session_count) => {
                println!("Native OAuth session store: {session_count} session(s).");
            }
            NativeOAuthSessionStoreStatus::Unreadable(reason) => {
                eprintln!("Native OAuth session store unreadable: {reason}");
                anyhow::bail!("could not read native OAuth session store: {reason}");
            }
        }
        return Ok(());
    }

    // Handle --logout flag
    if logout {
        let persist_path = native_oauth_session_store_path();

        if let Some(path) = persist_path {
            if native_oauth_session_store_path_exists(&path)
                .map_err(|e| anyhow::anyhow!("could not inspect native OAuth session store: {e}"))?
            {
                std::fs::remove_file(&path).map_err(|e| {
                    anyhow::anyhow!(
                        "could not remove native OAuth session store {}: {e}",
                        path.display()
                    )
                })?;
                println!("Native OAuth sessions cleared.");
            } else {
                println!("No native OAuth sessions to clear.");
            }
        }
        println!("Shared Claude credentials were not deleted.");
        return Ok(());
    }

    // Start OAuth device flow
    println!("=== Claude Max OAuth Authentication ===\n");

    let pkce = PkceParams::generate();
    let auth_url = pkce.build_auth_url();

    println!("Step 1: Open this URL in your browser:\n");
    println!("  {auth_url}\n");

    let stdin = io::stdin();
    if stdin.is_terminal() {
        // Try to open browser automatically only for interactive use.
        spawn_browser_opener(&auth_url);
    }

    println!("Step 2: Sign in to Claude and authorize the application.");
    println!("Step 3: Copy the code shown (format: CODE#STATE)\n");

    print!("Paste the authorization code here: ");
    io::stdout().flush()?;

    let mut code_input = String::new();
    stdin.read_line(&mut code_input)?;
    let code_input = code_input.trim();

    if code_input.is_empty() {
        eprintln!("No code provided. Authentication cancelled.");
        anyhow::bail!("authentication cancelled: no code provided");
    }

    let (code, parsed_state) = parse_auth_code(code_input);

    let expected_state = &pkce.state;
    if let Some(ref state) = parsed_state {
        if !expected_state.matches(state) {
            eprintln!("State mismatch! This could be a CSRF attack. Authentication cancelled.");
            anyhow::bail!("authentication cancelled: OAuth state mismatch");
        }
    }

    println!("\nExchanging code for tokens...");

    let client = OAuthClient::new()?;
    let token_response = client.exchange_code(code, &pkce).await?;

    let mut session = openclaudia::oauth::OAuthSession::from_token_response(token_response);

    if session.can_create_api_key() {
        println!("Creating API key from OAuth token...");
        match client
            .create_api_key(&session.credentials.access_token)
            .await
        {
            Ok(api_key) => {
                session.api_key = Some(api_key);
                println!("API key created successfully");
            }
            Err(e) => {
                eprintln!("Warning: Failed to create API key: {e}");
                eprintln!("Falling back to Bearer token authentication.");
                session.auth_mode = openclaudia::oauth::AuthMode::BearerToken;
            }
        }
    } else {
        println!("Using Bearer token authentication (personal Claude Max account)");
        println!("  Granted scopes: {}", session.granted_scopes.join(", "));
    }

    if session
        .granted_scopes
        .iter()
        .any(|scope| scope == "user:inference")
    {
        match openclaudia::claude_credentials::store_credentials(
            &session.credentials.access_token,
            session.credentials.refresh_token.as_ref(),
            session.credentials.expires_at.timestamp_millis(),
            session.granted_scopes.clone(),
            None,
            None,
        ) {
            Ok(()) => {
                let path = openclaudia::claude_credentials::credentials_path().map_or_else(
                    || "~/.claude/.credentials.json".into(),
                    |p| p.display().to_string(),
                );
                println!("Saved Claude credentials to {path}");
            }
            Err(e) => eprintln!("Warning: could not write Claude credentials: {e}"),
        }
    } else {
        eprintln!("Note: granted scopes lack 'user:inference'; skipped writing Claude credentials");
    }

    let session_id = session.id.clone();
    let auth_mode = session.auth_mode.clone();
    store
        .try_store_session(session)
        .map_err(|e| anyhow::anyhow!("failed to save native OAuth session: {e:#}"))?;

    println!("\nAuthentication successful!");
    println!("  Session ID: {}", safe_truncate(&session_id, 8));
    match auth_mode {
        openclaudia::oauth::AuthMode::ApiKey => {
            println!("  Auth mode: API key (organization account)");
        }
        openclaudia::oauth::AuthMode::BearerToken => {
            println!("  Auth mode: Bearer token (personal account)");
        }
        openclaudia::oauth::AuthMode::ProxyMode => {
            println!("  Auth mode: Proxy (via anthropic-proxy)");
        }
    }
    println!("\nYour session has been saved. OpenClaudia will now use your");
    println!("Claude Max subscription automatically when target is 'anthropic'.");

    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn auth_browser_openers_use_resolved_binaries() {
        let source = include_str!("auth.rs");
        let cfg_test = source
            .find("#[cfg(test)]")
            .expect("test marker must be present");
        let production = &source[..cfg_test];

        for bare in [
            "Command::new(\"rundll32\")",
            "Command::new(\"open\")",
            "Command::new(\"xdg-open\")",
            "std::process::Command::new(\"rundll32\")",
            "std::process::Command::new(\"open\")",
            "std::process::Command::new(\"xdg-open\")",
        ] {
            assert!(
                !production.contains(bare),
                "auth opener must not invoke bare platform command: {bare}"
            );
        }

        for resolver in [
            "which::which(\"rundll32\")",
            "which::which(\"open\")",
            "which::which(\"xdg-open\")",
        ] {
            assert!(
                production.contains(resolver),
                "auth opener must resolve platform command with {resolver}"
            );
        }
    }

    #[test]
    fn auth_success_message_depends_on_fallible_session_persist() {
        let source = include_str!("auth.rs");
        let cfg_test = source
            .find("#[cfg(test)]")
            .expect("test marker must be present");
        let production = &source[..cfg_test];
        let persist_call = production
            .find(".try_store_session(session)")
            .expect("auth must use the fallible OAuth session persist path");
        let success_message = production
            .find("Your session has been saved")
            .expect("auth success message must be present");

        assert!(
            persist_call < success_message,
            "auth must persist the OAuth session before claiming it was saved"
        );
        assert!(
            !production.contains("store.store_session(session);"),
            "auth must not use the best-effort OAuth session persist wrapper"
        );
    }
}
