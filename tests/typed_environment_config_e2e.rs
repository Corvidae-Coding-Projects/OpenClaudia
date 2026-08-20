//! Runtime acceptance tests for the explicit typed environment schema.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]

use std::net::TcpListener;
use std::process::{Command, Output};

fn write_config(root: &tempfile::TempDir, yaml: &str) {
    let directory = root.path().join(".openclaudia");
    std::fs::create_dir_all(&directory).expect("config directory");
    std::fs::write(directory.join("config.yaml"), yaml).expect("config file");
}

fn write_home_config(home: &tempfile::TempDir, yaml: &str) {
    let directory = home.path().join(".openclaudia");
    std::fs::create_dir_all(&directory).expect("home config directory");
    std::fs::write(directory.join("config.yaml"), yaml).expect("home config file");
}

fn isolated_command(root: &tempfile::TempDir, home: &tempfile::TempDir) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_openclaudia"));
    command
        .env_clear()
        .current_dir(root.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("XDG_DATA_HOME", home.path().join(".local/share"));
    command
}

fn combined_output(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn default_file_and_environment_precedence_reaches_runtime_config_output() {
    let root = tempfile::tempdir().expect("project root");
    let home = tempfile::tempdir().expect("home root");
    write_config(&root, "{}\n");

    let defaults = isolated_command(&root, &home)
        .arg("config")
        .output()
        .expect("config command");
    assert!(defaults.status.success(), "{}", combined_output(&defaults));
    let defaults_text = combined_output(&defaults);
    assert!(defaults_text.contains("Port: 8080"));
    assert!(defaults_text.contains("Timeout: 30 minutes"));
    assert!(defaults_text.contains("Persist path: "));

    write_config(
        &root,
        r"
proxy:
  port: 8100
session:
  timeout_minutes: 41
  persist_path: file-sessions
",
    );
    let file = isolated_command(&root, &home)
        .arg("config")
        .output()
        .expect("config command");
    assert!(file.status.success(), "{}", combined_output(&file));
    let file_text = combined_output(&file);
    assert!(file_text.contains("Port: 8100"));
    assert!(file_text.contains("Timeout: 41 minutes"));
    assert!(file_text.contains("file-sessions"));

    write_home_config(
        &home,
        r"
proxy:
  port: 8150
session:
  timeout_minutes: 46
  persist_path: home-sessions
",
    );
    let trusted_home = isolated_command(&root, &home)
        .arg("config")
        .output()
        .expect("config command");
    assert!(
        trusted_home.status.success(),
        "{}",
        combined_output(&trusted_home)
    );
    let trusted_home_text = combined_output(&trusted_home);
    assert!(trusted_home_text.contains("Port: 8150"));
    assert!(trusted_home_text.contains("Timeout: 46 minutes"));
    assert!(trusted_home_text.contains("home-sessions"));

    let environment = isolated_command(&root, &home)
        .arg("config")
        .env("OPENCLAUDIA_PROXY__PORT", "8200")
        .env("OPENCLAUDIA_SESSION__TIMEOUT_MINUTES", "52")
        .env("OPENCLAUDIA_SESSION__PERSIST_PATH", "environment-sessions")
        .env(
            "OPENCLAUDIA_PROVIDERS__OPENAI_COMPATIBLE__BASE_URL",
            "https://example.com/typed-environment-v1",
        )
        .output()
        .expect("config command");
    assert!(
        environment.status.success(),
        "{}",
        combined_output(&environment)
    );
    let environment_text = combined_output(&environment);
    assert!(environment_text.contains("Port: 8200"));
    assert!(environment_text.contains("Timeout: 52 minutes"));
    assert!(environment_text.contains("environment-sessions"));
    assert!(environment_text.contains("https://example.com/typed-environment-v1"));
}

#[test]
fn explicit_cli_target_overrides_file_and_environment_before_startup_preflight() {
    let root = tempfile::tempdir().expect("project root");
    let home = tempfile::tempdir().expect("home root");
    write_config(
        &root,
        r"
proxy:
  target: anthropic
providers:
  local:
    base_url: http://localhost:1234/v1
",
    );
    let listener = TcpListener::bind("127.0.0.1:0").expect("held listener");
    let port = listener
        .local_addr()
        .expect("held address")
        .port()
        .to_string();

    let output = isolated_command(&root, &home)
        .args(["start", "--target", "local", "--port", &port])
        .env("OPENCLAUDIA_PROXY__TARGET", "openai")
        .output()
        .expect("start command");
    assert!(!output.status.success());
    let text = combined_output(&output);
    assert!(
        text.to_ascii_lowercase().contains("address already in use"),
        "CLI target must win and reach the held local bind: {text:?}"
    );
    assert!(
        !text.contains("OPENAI_API_KEY"),
        "environment target must not survive explicit CLI target: {text:?}"
    );
}

#[test]
fn valid_environment_value_replaces_invalid_lower_precedence_file_before_validation() {
    let root = tempfile::tempdir().expect("project root");
    let home = tempfile::tempdir().expect("home root");
    write_config(
        &root,
        r#"
proxy:
  port: not-an-integer
providers:
  anthropic:
    api_key: ""
"#,
    );

    let output = isolated_command(&root, &home)
        .arg("config")
        .env("OPENCLAUDIA_PROXY__PORT", "8300")
        .env(
            "OPENCLAUDIA_PROVIDERS__ANTHROPIC__API_KEY",
            "typed-environment-api-key",
        )
        .output()
        .expect("config command");
    assert!(output.status.success(), "{}", combined_output(&output));
    let text = combined_output(&output);
    assert!(text.contains("Port: 8300"));
    assert!(text.contains("anthropic") && text.contains("API key: configured"));
}

#[test]
fn unknown_and_ambiguous_environment_keys_fail_at_the_process_boundary() {
    let root = tempfile::tempdir().expect("project root");
    let home = tempfile::tempdir().expect("home root");
    write_config(&root, "{}\n");

    let unknown = isolated_command(&root, &home)
        .arg("config")
        .env("OPENCLAUDIA_PERMISSIONS__ENABELD", "false")
        .output()
        .expect("config command");
    assert!(!unknown.status.success());
    let unknown_text = combined_output(&unknown);
    assert!(unknown_text.contains("unknown OpenClaudia environment variable"));
    assert!(unknown_text.contains("OPENCLAUDIA_PERMISSIONS__ENABELD"));

    let ambiguous = isolated_command(&root, &home)
        .arg("config")
        .env("OPENCLAUDIA_SESSION__PERSIST_PATH", "canonical")
        .env("OPENCLAUDIA_SESSION_PERSIST_PATH", "legacy")
        .output()
        .expect("config command");
    assert!(!ambiguous.status.success());
    let ambiguous_text = combined_output(&ambiguous);
    assert!(ambiguous_text.contains("ambiguously configure session.persist_path"));
}

#[test]
fn malformed_security_value_fails_without_disclosing_secret_bytes() {
    let root = tempfile::tempdir().expect("project root");
    let home = tempfile::tempdir().expect("home root");
    write_config(&root, "{}\n");
    let secret = "typed-secret\r\ninjected-header";

    let output = isolated_command(&root, &home)
        .arg("config")
        .env("OPENCLAUDIA_PROVIDERS__ANTHROPIC__API_KEY", secret)
        .output()
        .expect("config command");
    assert!(!output.status.success());
    let text = combined_output(&output);
    assert!(text.contains("OPENCLAUDIA_PROVIDERS__ANTHROPIC__API_KEY"));
    assert!(text.contains("CRLF injection guard"));
    assert!(!text.contains(secret));
    assert!(!text.contains("typed-secret"));
}
