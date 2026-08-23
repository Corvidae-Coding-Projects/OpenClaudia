use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    process::{Command, Output, Stdio},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const CONFIG_ENV_VARS: &[&str] = &[
    "OPENCLAUDIA_PROXY_PORT",
    "OPENCLAUDIA_PROXY_HOST",
    "OPENCLAUDIA_PROXY_TARGET",
    "OPENCLAUDIA_SESSION_TIMEOUT_MINUTES",
    "OPENCLAUDIA_SESSION_PERSIST_PATH",
    "OPENCLAUDIA_PROVIDERS_ANTHROPIC_API_KEY",
    "OPENCLAUDIA_PROVIDERS_OPENAI_API_KEY",
    "OPENCLAUDIA_PROVIDERS_GOOGLE_API_KEY",
    "OPENCLAUDIA_PROVIDERS_ZAI_API_KEY",
    "OPENCLAUDIA_PROVIDERS_DEEPSEEK_API_KEY",
    "OPENCLAUDIA_PROVIDERS_QWEN_API_KEY",
    "OPENCLAUDIA_PROVIDERS_KIMI_API_KEY",
    "OPENCLAUDIA_PROVIDERS_MINIMAX_API_KEY",
    "OPENCLAUDIA_PROVIDERS_OPENROUTER_API_KEY",
    "OPENCLAUDIA_PROVIDERS_OPENCODE_API_KEY",
    "OPENCLAUDIA_PROVIDERS_OPENAI_COMPATIBLE_API_KEY",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "ZAI_API_KEY",
    "DEEPSEEK_API_KEY",
    "QWEN_API_KEY",
    "DASHSCOPE_API_KEY",
    "ALIYUN_API_KEY",
    "KIMI_API_KEY",
    "MOONSHOT_API_KEY",
    "MINIMAX_API_KEY",
    "OPENROUTER_API_KEY",
    "OPEN_ROUTER_API_KEY",
    "OPENCODE_API_KEY",
    "OPENCODE_GO_API_KEY",
    "OPENAI_COMPATIBLE_API_KEY",
    "API_KEY",
    "CLAUDE_CONFIG_HOME_DIR",
    "CLAUDE_CONFIG_DIR",
    "OPENCLAUDIA_HOOK_APPROVALS_PATH",
];

fn assert_missing_config_is_failure(args: &[&str]) {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let mut command = Command::new(env!("CARGO_BIN_EXE_openclaudia"));
    command
        .args(args)
        .current_dir(cwd.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("XDG_DATA_HOME", home.path().join(".local/share"));
    for var in CONFIG_ENV_VARS {
        command.env_remove(var);
    }

    let output = command.output().expect("openclaudia command must run");

    assert!(
        !output.status.success(),
        "openclaudia {args:?} must fail without config; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("No configuration found")
            || combined.contains("no configuration found")
            || combined.contains("No configuration source exists"),
        "missing-config failure should explain the problem; got {combined:?}"
    );
}

#[test]
fn default_tui_auth_failure_does_not_create_project_state_without_config() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");

    let output = isolated_command(&cwd, &home)
        .output()
        .expect("openclaudia default startup must run");

    assert!(
        !output.status.success(),
        "default startup without config must fail; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("No API key configured for Anthropic")
            && combined.contains("could not resolve authentication for target 'anthropic'"),
        "default startup should surface the auth failure from the default provider; got {combined:?}"
    );
    let state_dir = cwd.path().join(".openclaudia");
    if state_dir.exists() {
        let entries = fs::read_dir(&state_dir)
            .expect("project state dir should be readable")
            .map(|entry| {
                entry
                    .expect("project state entry should be readable")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            entries,
            vec!["logs".to_string()],
            "default startup without config must only create TUI logs, not project state"
        );

        let log_entries = fs::read_dir(state_dir.join("logs"))
            .expect("project logs dir should be readable")
            .map(|entry| {
                entry
                    .expect("project log entry should be readable")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();
        assert!(
            !log_entries.is_empty()
                && log_entries.iter().all(|name| {
                    name.starts_with("tui-")
                        && std::path::Path::new(name)
                            .extension()
                            .is_some_and(|ext| ext.eq_ignore_ascii_case("log"))
                }),
            "default startup without config must only create TUI log files; got {log_entries:?}"
        );
    }
}

fn isolated_command(cwd: &tempfile::TempDir, home: &tempfile::TempDir) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_openclaudia"));
    command
        .current_dir(cwd.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("XDG_DATA_HOME", home.path().join(".local/share"));
    for var in CONFIG_ENV_VARS {
        command.env_remove(var);
    }
    command
}

fn snapshot_tree(root: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    fn payload(metadata: &fs::Metadata, contents: &[u8]) -> Vec<u8> {
        let modified = metadata
            .modified()
            .expect("snapshot modification time")
            .duration_since(std::time::UNIX_EPOCH)
            .expect("snapshot time after epoch")
            .as_nanos();
        let mut payload = Vec::with_capacity(25 + contents.len());
        payload.extend_from_slice(&modified.to_le_bytes());
        payload.extend_from_slice(&metadata.len().to_le_bytes());
        payload.push(u8::from(metadata.permissions().readonly()));
        payload.extend_from_slice(contents);
        payload
    }

    fn visit(
        base: &std::path::Path,
        current: &std::path::Path,
        entries: &mut Vec<(String, Vec<u8>)>,
    ) {
        if !current.exists() {
            return;
        }
        let mut children = fs::read_dir(current)
            .expect("snapshot directory must be readable")
            .map(|entry| entry.expect("snapshot entry must be readable"))
            .collect::<Vec<_>>();
        children.sort_by_key(std::fs::DirEntry::file_name);
        for entry in children {
            let path = entry.path();
            let relative = path
                .strip_prefix(base)
                .expect("snapshot path remains beneath root")
                .to_string_lossy()
                .into_owned();
            let file_type = entry.file_type().expect("snapshot file type");
            let metadata = fs::symlink_metadata(&path).expect("snapshot metadata");
            if file_type.is_dir() {
                entries.push((format!("directory:{relative}"), payload(&metadata, &[])));
                visit(base, &path, entries);
            } else if file_type.is_symlink() {
                let target = fs::read_link(&path).expect("snapshot symlink target");
                entries.push((
                    format!("symlink:{relative}"),
                    payload(&metadata, target.to_string_lossy().as_bytes()),
                ));
            } else {
                entries.push((
                    format!("file:{relative}"),
                    payload(&metadata, &fs::read(&path).expect("snapshot file contents")),
                ));
            }
        }
    }

    let mut entries = Vec::new();
    visit(root, root, &mut entries);
    entries
}

fn approve_first_repository_hook_proposal(cwd: &tempfile::TempDir, home: &tempfile::TempDir) {
    let status = isolated_command(cwd, home)
        .args(["hooks", "status"])
        .output()
        .expect("hook proposal status must run");
    assert!(
        status.status.success(),
        "hook proposal status failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
    let stdout = String::from_utf8(status.stdout).expect("hook status must be UTF-8");
    let digest = stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("Proposal digest: "))
        .expect("hook status must display a proposal digest");
    let approval = isolated_command(cwd, home)
        .args(["hooks", "approve", digest])
        .output()
        .expect("hook proposal approval must run");
    assert!(
        approval.status.success(),
        "hook proposal approval failed: {}",
        String::from_utf8_lossy(&approval.stderr)
    );
}

fn run_auth_with_stdin(input: &str) -> Output {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let mut child = isolated_command(&cwd, &home)
        .arg("auth")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("openclaudia auth must spawn");

    child
        .stdin
        .take()
        .expect("auth stdin should be piped")
        .write_all(input.as_bytes())
        .expect("auth stdin should accept input");

    child.wait_with_output().expect("openclaudia auth must run")
}

#[test]
fn legacy_repl_login_reads_status_without_nesting_a_runtime() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    write_local_provider_config(&cwd);
    write_claude_oauth_credentials(&home.path().join(".claude"));

    let mut child = isolated_command(&cwd, &home)
        .args([
            "--tui-mode",
            "--dangerously-skip-permissions",
            "--target",
            "local",
            "--model",
            "local-test-model",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("legacy REPL must spawn");
    child
        .stdin
        .take()
        .expect("legacy REPL stdin")
        .write_all(b"/login\n/exit\n")
        .expect("legacy REPL should accept slash commands");

    let output = child.wait_with_output().expect("legacy REPL must exit");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "legacy REPL should exit cleanly after /login; got {combined:?}"
    );
    assert!(
        combined.contains("Authenticated via Claude Code credentials")
            && combined.contains("Type: max")
            && combined.contains("Tier: max"),
        "/login should report synchronous credential status; got {combined:?}"
    );
    assert!(
        !combined.contains("panicked") && !combined.contains("Cannot start a runtime"),
        "/login must not attempt to nest a Tokio runtime; got {combined:?}"
    );
}

#[test]
fn auth_status_and_logout_are_mutually_exclusive() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");

    let output = isolated_command(&cwd, &home)
        .args(["auth", "--status", "--logout"])
        .output()
        .expect("openclaudia auth must run");

    assert!(
        !output.status.success(),
        "auth --status --logout must fail; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("auth --status and --logout cannot be used together"),
        "mutually exclusive auth flags should explain the conflict; got {combined:?}"
    );
}

#[test]
fn config_without_config_exits_nonzero() {
    assert_missing_config_is_failure(&["config"]);
}

#[test]
fn config_accepts_documented_local_provider_loopback_url() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let config_dir = cwd.path().join(".openclaudia");
    fs::create_dir_all(&config_dir).expect("config dir");
    fs::write(
        config_dir.join("config.yaml"),
        r#"
proxy:
  port: 8080
  host: "127.0.0.1"
  target: local
providers:
  local:
    base_url: http://localhost:1234/v1
    model: local-test-model
"#,
    )
    .expect("config file");

    let output = isolated_command(&cwd, &home)
        .arg("config")
        .output()
        .expect("openclaudia config must run");

    assert!(
        output.status.success(),
        "documented local provider localhost base_url must load; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Target: local"),
        "config output should show active local target; got {stdout:?}"
    );
}

#[test]
fn config_loads_home_provider_key_schema_used_by_connect() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let home_config_dir = home.path().join(".openclaudia");
    fs::create_dir_all(&home_config_dir).expect("home config dir");
    fs::write(
        home_config_dir.join("config.yaml"),
        r#"
proxy:
  port: 8080
  host: "127.0.0.1"
  target: openai
providers:
  openai:
    base_url: https://api.openai.com/v1
    api_key: sk-openai-home-test-key
"#,
    )
    .expect("home config file");

    let output = isolated_command(&cwd, &home)
        .arg("config")
        .output()
        .expect("openclaudia config must run");

    assert!(
        output.status.success(),
        "home provider key schema must load; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Target: openai") && stdout.contains("openai:"),
        "config output should show the home OpenAI provider; got {stdout:?}"
    );
    assert!(
        stdout.contains("API key: configured") && !stdout.contains("sk-openai-home-test-key"),
        "config output should report key presence without leaking the key; got {stdout:?}"
    );
}

fn write_local_provider_config(cwd: &tempfile::TempDir) {
    write_local_provider_config_with_base_url(cwd, "http://localhost:1234/v1");
}

fn write_local_provider_config_with_host(cwd: &tempfile::TempDir, host: &str) {
    let config_dir = cwd.path().join(".openclaudia");
    fs::create_dir_all(&config_dir).expect("config dir");
    fs::write(
        config_dir.join("config.yaml"),
        format!(
            r#"
proxy:
  port: 8080
  host: "{host}"
  target: local
providers:
  local:
    base_url: http://localhost:1234/v1
"#,
        ),
    )
    .expect("config file");
}

fn write_local_provider_config_with_base_url(cwd: &tempfile::TempDir, base_url: &str) {
    let config_dir = cwd.path().join(".openclaudia");
    fs::create_dir_all(&config_dir).expect("config dir");
    fs::write(
        config_dir.join("config.yaml"),
        format!(
            r#"
proxy:
  port: 8080
  host: "127.0.0.1"
  target: local
providers:
  local:
    base_url: {base_url}
    model: local-test-model
"#,
        ),
    )
    .expect("config file");
}

fn write_lmstudio_provider_config_with_base_url(cwd: &tempfile::TempDir, base_url: &str) {
    let config_dir = cwd.path().join(".openclaudia");
    fs::create_dir_all(&config_dir).expect("config dir");
    fs::write(
        config_dir.join("config.yaml"),
        format!(
            r#"
proxy:
  port: 8080
  host: "127.0.0.1"
  target: local
providers:
  local:
    base_url: http://127.0.0.1:1
    model: unused-local-test-model
  lmstudio:
    base_url: {base_url}
    model: lmstudio-test-model
"#,
        ),
    )
    .expect("config file");
}

fn write_local_provider_config_with_stop_hook(cwd: &tempfile::TempDir, base_url: &str) {
    let config_dir = cwd.path().join(".openclaudia");
    fs::create_dir_all(&config_dir).expect("config dir");
    fs::write(
        config_dir.join("config.yaml"),
        format!(
            r#"
proxy:
  port: 8080
  host: "127.0.0.1"
  target: local
providers:
  local:
    base_url: {base_url}
    model: local-test-model
hooks:
  stop:
    - hooks:
        - type: command
          timeout: 2
          command: python3 .openclaudia/stop-hook.py
"#,
        ),
    )
    .expect("config file");
    fs::write(
        config_dir.join("stop-hook.py"),
        "import json\nprint(json.dumps({'decision': 'deny', 'reason': 'stop hook requested shutdown'}))\n",
    )
    .expect("stop hook script");
}

fn write_openai_provider_config(cwd: &tempfile::TempDir) {
    write_openai_provider_config_with_target(cwd, "openai");
}

fn write_openai_provider_config_with_target(cwd: &tempfile::TempDir, target: &str) {
    let config_dir = cwd.path().join(".openclaudia");
    fs::create_dir_all(&config_dir).expect("config dir");
    fs::write(
        config_dir.join("config.yaml"),
        format!(
            r#"
proxy:
  port: 8080
  host: "127.0.0.1"
  target: {target}
providers:
  openai:
    base_url: https://api.openai.com/v1
"#,
        ),
    )
    .expect("config file");
}

fn write_openai_provider_config_with_api_key(cwd: &tempfile::TempDir) {
    let config_dir = cwd.path().join(".openclaudia");
    fs::create_dir_all(&config_dir).expect("config dir");
    fs::write(
        config_dir.join("config.yaml"),
        r#"
proxy:
  port: 8080
  host: "127.0.0.1"
  target: openai
providers:
  openai:
    base_url: https://api.openai.com/v1
    api_key: sk-openai-test-key
"#,
    )
    .expect("config file");
}

fn write_doctor_adversarial_fixture(cwd: &tempfile::TempDir, home: &tempfile::TempDir) {
    let config_dir = cwd.path().join(".openclaudia");
    fs::create_dir_all(&config_dir).expect("config dir");
    fs::write(
        config_dir.join("config.yaml"),
        r"proxy:
  target: openai
providers:
  openai:
    base_url: https://example.com/doctor-origin-canary/v1
    api_key: doctor-api-key-canary
    headers:
      X-Doctor-Canary: doctor-custom-header-canary
",
    )
    .expect("config file");

    let claude_dir = home.path().join(".claude");
    fs::create_dir_all(&claude_dir).expect("Claude credential dir");
    fs::write(
        claude_dir.join(".credentials.json"),
        b"{foreign-credential-canary",
    )
    .expect("foreign credential canary");
    let plugin_dir = home.path().join(".openclaudia/plugins");
    fs::create_dir_all(&plugin_dir).expect("plugin tracker dir");
    fs::write(plugin_dir.join("installed.json"), b"{corrupt-plugin-canary")
        .expect("corrupt plugin tracker canary");
    let migration_dir = home.path().join(".local/share/openclaudia/chat_sessions");
    fs::create_dir_all(&migration_dir).expect("migration state dir");
    fs::write(
        migration_dir.join("malformed-session.json"),
        b"{migration-canary",
    )
    .expect("malformed migration canary");
}

fn assert_doctor_canaries_redacted(output: &Output) {
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for secret in [
        "doctor-api-key-canary",
        "doctor-custom-header-canary",
        "foreign-credential-canary",
        "corrupt-plugin-canary",
        "migration-canary",
        "doctor-origin-canary",
        "malformed-session.json",
    ] {
        assert!(
            !combined.contains(secret),
            "doctor output disclosed canary {secret:?}: {combined:?}"
        );
    }
}

fn write_anthropic_provider_config(cwd: &tempfile::TempDir) {
    write_anthropic_provider_config_with_target(cwd, "anthropic");
}

fn write_anthropic_provider_config_with_target(cwd: &tempfile::TempDir, target: &str) {
    let config_dir = cwd.path().join(".openclaudia");
    fs::create_dir_all(&config_dir).expect("config dir");
    fs::write(
        config_dir.join("config.yaml"),
        format!(
            r#"
proxy:
  port: 8080
  host: "127.0.0.1"
  target: {target}
providers:
  anthropic:
    base_url: https://api.anthropic.com
"#,
        ),
    )
    .expect("config file");
}

fn write_claude_oauth_credentials(claude_config: &std::path::Path) {
    fs::create_dir_all(claude_config).expect("claude config dir");
    fs::write(
        claude_config.join(".credentials.json"),
        r#"
{
  "claudeAiOauth": {
    "accessToken": "sk-ant-oat01-test-access-token",
    "refreshToken": "sk-ant-ort01-test-refresh-token",
    "expiresAt": 4102444800000,
    "scopes": ["user:inference"],
    "subscriptionType": "max",
    "rateLimitTier": "max"
  }
}
"#,
    )
    .expect("credentials fixture");
}

fn write_openai_target_with_local_fallback_config(cwd: &tempfile::TempDir) {
    let config_dir = cwd.path().join(".openclaudia");
    fs::create_dir_all(&config_dir).expect("config dir");
    fs::write(
        config_dir.join("config.yaml"),
        r#"
proxy:
  port: 8080
  host: "127.0.0.1"
  target: openai
providers:
  openai:
    base_url: https://api.openai.com/v1
  local:
    base_url: http://localhost:1234/v1
"#,
    )
    .expect("config file");
}

fn write_anthropic_target_with_openai_key_config(cwd: &tempfile::TempDir) {
    let config_dir = cwd.path().join(".openclaudia");
    fs::create_dir_all(&config_dir).expect("config dir");
    fs::write(
        config_dir.join("config.yaml"),
        r#"
proxy:
  port: 8080
  host: "127.0.0.1"
  target: anthropic
providers:
  anthropic:
    base_url: https://api.anthropic.com
  openai:
    base_url: https://api.openai.com/v1
    api_key: sk-openai-test-key
"#,
    )
    .expect("config file");
}

fn held_loopback_port() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind held port");
    let port = listener.local_addr().expect("local addr").port();
    (listener, port)
}

fn unused_loopback_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind free port");
    listener.local_addr().expect("local addr").port()
}

fn spawn_local_sse_server_rejecting_auth() -> (JoinHandle<Result<(), String>>, String) {
    spawn_local_sse_server_rejecting_auth_with_body(
        "data: {\"choices\":[{\"delta\":{\"content\":\"local ok\"}}]}\n\ndata: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n",
    )
}

fn spawn_local_sse_server_rejecting_auth_with_body(
    body: &'static str,
) -> (JoinHandle<Result<(), String>>, String) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local sse server");
    listener
        .set_nonblocking(true)
        .expect("set local sse listener nonblocking");
    let addr = listener.local_addr().expect("local sse addr");
    let base_url = format!("http://{addr}");

    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err("local SSE server timed out waiting for request".to_string());
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => return Err(format!("local SSE accept failed: {err}")),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|err| format!("set read timeout failed: {err}"))?;

        let mut reader = BufReader::new(
            stream
                .try_clone()
                .map_err(|err| format!("clone stream failed: {err}"))?,
        );
        let mut request_head = String::new();
        loop {
            let mut line = String::new();
            let bytes = reader
                .read_line(&mut line)
                .map_err(|err| format!("read request header failed: {err}"))?;
            if bytes == 0 {
                return Err("client closed before completing request headers".to_string());
            }
            if line == "\r\n" {
                break;
            }
            request_head.push_str(&line);
        }

        if !request_head.starts_with("POST /v1/chat/completions ") {
            return Err(format!(
                "unexpected local provider request: {request_head:?}"
            ));
        }
        if request_head
            .lines()
            .any(|line| line.to_ascii_lowercase().starts_with("authorization:"))
        {
            return Err(format!(
                "keyless local provider request must not send Authorization header: {request_head:?}"
            ));
        }

        let content_length = request_head
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
            })
            .unwrap_or(0);
        let mut request_body = vec![0; content_length];
        reader
            .read_exact(&mut request_body)
            .map_err(|err| format!("read request body failed: {err}"))?;
        if !String::from_utf8_lossy(&request_body).contains("\"stream\":true") {
            return Err("local --print request should ask for streaming".to_string());
        }

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .map_err(|err| format!("write local SSE response failed: {err}"))?;
        Ok(())
    });

    (handle, base_url)
}

fn spawn_local_chat_server_rejecting_auth() -> (JoinHandle<Result<(), String>>, String) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind local chat server");
    listener
        .set_nonblocking(true)
        .expect("set local chat listener nonblocking");
    let addr = listener.local_addr().expect("local chat addr");
    let base_url = format!("http://{addr}");

    let handle = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err("local chat server timed out waiting for request".to_string());
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => return Err(format!("local chat accept failed: {err}")),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(|err| format!("set read timeout failed: {err}"))?;

        let mut reader = BufReader::new(
            stream
                .try_clone()
                .map_err(|err| format!("clone stream failed: {err}"))?,
        );
        let mut request_head = String::new();
        loop {
            let mut line = String::new();
            let bytes = reader
                .read_line(&mut line)
                .map_err(|err| format!("read request header failed: {err}"))?;
            if bytes == 0 {
                return Err("client closed before completing request headers".to_string());
            }
            if line == "\r\n" {
                break;
            }
            request_head.push_str(&line);
        }

        if !request_head.starts_with("POST /v1/chat/completions ") {
            return Err(format!(
                "unexpected local provider request: {request_head:?}"
            ));
        }
        if request_head
            .lines()
            .any(|line| line.to_ascii_lowercase().starts_with("authorization:"))
        {
            return Err(format!(
                "keyless local provider request must not send Authorization header: {request_head:?}"
            ));
        }

        let content_length = request_head
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
            })
            .unwrap_or(0);
        let mut request_body = vec![0; content_length];
        reader
            .read_exact(&mut request_body)
            .map_err(|err| format!("read request body failed: {err}"))?;
        if !String::from_utf8_lossy(&request_body).contains("\"stream\":false") {
            return Err("local proxy request should preserve stream=false".to_string());
        }

        let body = r#"{"id":"chatcmpl-local","object":"chat.completion","created":0,"model":"local-test-model","choices":[{"index":0,"message":{"role":"assistant","content":"local proxy ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .map_err(|err| format!("write local chat response failed: {err}"))?;
        Ok(())
    });

    (handle, base_url)
}

fn spawn_doctor_network_probe_detector() -> (
    JoinHandle<Result<(), String>>,
    String,
    std::sync::mpsc::Sender<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind doctor network probe detector");
    listener
        .set_nonblocking(true)
        .expect("set doctor network probe listener nonblocking");
    let addr = listener.local_addr().expect("doctor network probe addr");
    let proxy_url = format!("http://{addr}");
    let (stop_tx, stop_rx) = std::sync::mpsc::channel();

    let handle = thread::spawn(move || loop {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .map_err(|err| {
                        format!("set doctor network probe read timeout failed: {err}")
                    })?;
                let mut reader =
                    BufReader::new(stream.try_clone().map_err(|err| {
                        format!("clone doctor network probe stream failed: {err}")
                    })?);
                let mut request_head = String::new();
                loop {
                    let mut line = String::new();
                    let bytes = reader.read_line(&mut line).map_err(|err| {
                        format!("read doctor network probe request failed: {err}")
                    })?;
                    if bytes == 0 || line == "\r\n" {
                        break;
                    }
                    request_head.push_str(&line);
                }

                let response = "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/redirect-canary\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(response.as_bytes());
                return Err(format!(
                    "doctor opened a network connection without a safe active probe: {request_head:?}"
                ));
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                if stop_rx.try_recv().is_ok() {
                    return Ok(());
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(err) => return Err(format!("doctor network probe accept failed: {err}")),
        }
    });

    (handle, proxy_url, stop_tx)
}

fn wait_for_loop_proxy(port: u16, child: &mut std::process::Child) -> Result<(), String> {
    let addr = format!("127.0.0.1:{port}");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if TcpStream::connect(&addr).is_ok() {
            return Ok(());
        }
        if let Some(status) = child
            .try_wait()
            .map_err(|err| format!("checking child status failed: {err}"))?
        {
            return Err(format!("loop proxy exited before listening: {status}"));
        }
        if Instant::now() >= deadline {
            return Err("timed out waiting for loop proxy to listen".to_string());
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn post_chat_completion_to_proxy(port: u16) -> Result<String, String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .map_err(|err| format!("connect to proxy failed: {err}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|err| format!("set read timeout failed: {err}"))?;
    let body = r#"{"model":"local-test-model","messages":[{"role":"user","content":"hello"}],"stream":false}"#;
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|err| format!("write proxy request failed: {err}"))?;
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|err| format!("read proxy response failed: {err}"))?;
    Ok(response)
}

fn wait_for_child_exit(mut child: std::process::Child) -> Output {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().expect("collect child output"),
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(25));
            }
            Ok(None) => {
                let _ = child.kill();
                return child
                    .wait_with_output()
                    .expect("collect killed child output");
            }
            Err(err) => panic!("checking child status failed: {err}"),
        }
    }
}

#[test]
fn start_allows_keyless_local_provider_until_bind_failure() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    write_local_provider_config(&cwd);
    let (_listener, port) = held_loopback_port();
    let port = port.to_string();

    let output = isolated_command(&cwd, &home)
        .args(["start", "--port", &port])
        .output()
        .expect("openclaudia start must run");

    assert!(
        !output.status.success(),
        "held port should make start fail after local auth preflight; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("No API key configured for provider")
            && !combined.contains("Set API_KEY"),
        "local provider must not be rejected for missing API key; got {combined:?}"
    );
    assert!(
        combined.to_lowercase().contains("address already in use"),
        "start should reach bind and report the held port; got {combined:?}"
    );
}

#[test]
fn start_mixed_case_anthropic_target_keeps_anthropic_auth_path() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    write_anthropic_provider_config_with_target(&cwd, "Anthropic");
    let (_listener, port) = held_loopback_port();
    let port = port.to_string();

    let output = isolated_command(&cwd, &home)
        .args(["start", "--port", &port])
        .output()
        .expect("openclaudia start must run");

    assert!(
        !output.status.success(),
        "held port should make start fail after mixed-case Anthropic auth preflight; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.to_lowercase().contains("address already in use"),
        "mixed-case Anthropic target should reach bind; got {combined:?}"
    );
    assert!(
        !combined.contains("Set API_KEY"),
        "mixed-case Anthropic target must not fall through to generic API_KEY diagnostics; got {combined:?}"
    );
}

#[test]
fn start_target_flag_overrides_config_before_auth_preflight() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    write_openai_target_with_local_fallback_config(&cwd);
    let (_listener, port) = held_loopback_port();
    let port = port.to_string();

    let output = isolated_command(&cwd, &home)
        .args(["start", "--target", "Local", "--port", &port])
        .output()
        .expect("openclaudia start must run");

    assert!(
        !output.status.success(),
        "held port should make start fail after applying target override; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("OPENAI_API_KEY")
            && !combined.contains("No API key configured for provider 'openai'"),
        "start --target Local must not auth-preflight the config's openai target; got {combined:?}"
    );
    assert!(
        combined.to_lowercase().contains("address already in use"),
        "start should reach bind after target override; got {combined:?}"
    );
}

#[test]
fn start_proxy_allows_keyless_local_provider_request() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let (server, base_url) = spawn_local_chat_server_rejecting_auth();
    write_local_provider_config_with_base_url(&cwd, &base_url);
    let proxy_port = unused_loopback_port();
    let proxy_port_arg = proxy_port.to_string();

    let mut child = isolated_command(&cwd, &home)
        .args(["start", "--port", &proxy_port_arg])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("openclaudia start must spawn");

    wait_for_loop_proxy(proxy_port, &mut child).expect("start proxy should listen");
    let response =
        post_chat_completion_to_proxy(proxy_port).expect("proxy request should complete");
    let _ = child.kill();
    let output = child
        .wait_with_output()
        .expect("collect killed start output");
    let server_result = server.join().expect("local chat server thread should join");

    assert!(
        server_result.is_ok(),
        "local chat server failed: {:?}",
        server_result.err()
    );
    assert!(
        response.starts_with("HTTP/1.1 200 OK") && response.contains("local proxy ok"),
        "start proxy should forward keyless local request and return upstream body; got {response:?}"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("No API key configured for provider")
            && !combined.contains("Set API_KEY"),
        "start proxy should not reject keyless local provider; got {combined:?}"
    );
}

#[test]
fn loop_allows_keyless_local_provider_and_reports_bind_failure() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    write_local_provider_config(&cwd);
    let (_listener, port) = held_loopback_port();
    let port = port.to_string();

    let output = isolated_command(&cwd, &home)
        .args(["loop", "--max-iterations", "1", "--port", &port])
        .output()
        .expect("openclaudia loop must run");

    assert!(
        !output.status.success(),
        "loop must return non-zero when its proxy server cannot bind; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("No API key configured for provider")
            && !combined.contains("Set API_KEY"),
        "local provider loop mode must not require an API key; got {combined:?}"
    );
    assert!(
        combined.to_lowercase().contains("address already in use"),
        "loop should surface the bind failure; got {combined:?}"
    );
}

#[test]
fn loop_root_target_flag_overrides_config_before_auth_preflight() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    write_openai_target_with_local_fallback_config(&cwd);
    let (_listener, port) = held_loopback_port();
    let port = port.to_string();

    let output = isolated_command(&cwd, &home)
        .args([
            "--target",
            "Local",
            "loop",
            "--max-iterations",
            "1",
            "--port",
            &port,
        ])
        .output()
        .expect("openclaudia loop must run");

    assert!(
        !output.status.success(),
        "held port should make loop fail after applying root target override; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("OPENAI_API_KEY") && !combined.contains("No API key configured"),
        "openclaudia --target Local loop must not auth-preflight the config's openai target; got {combined:?}"
    );
    assert!(
        combined.to_lowercase().contains("address already in use"),
        "loop should reach bind after root target override; got {combined:?}"
    );
}

#[test]
fn loop_host_flag_overrides_config_before_bind() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    write_local_provider_config_with_host(&cwd, "192.0.2.1");
    let (_listener, port) = held_loopback_port();
    let port = port.to_string();

    let output = isolated_command(&cwd, &home)
        .args([
            "loop",
            "--max-iterations",
            "1",
            "--host",
            "127.0.0.1",
            "--port",
            &port,
        ])
        .output()
        .expect("openclaudia loop must run");

    assert!(
        !output.status.success(),
        "loop should fail when the overridden bind address hits the held port; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.to_lowercase().contains("address already in use"),
        "loop --host should override the config host before binding; got {combined:?}"
    );
}

#[test]
fn loop_proxy_allows_keyless_local_provider_request_and_stops_after_one_iteration() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let (server, base_url) = spawn_local_chat_server_rejecting_auth();
    write_local_provider_config_with_base_url(&cwd, &base_url);
    let proxy_port = unused_loopback_port();
    let proxy_port_arg = proxy_port.to_string();

    let mut child = isolated_command(&cwd, &home)
        .args(["loop", "--max-iterations", "1", "--port", &proxy_port_arg])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("openclaudia loop must spawn");

    wait_for_loop_proxy(proxy_port, &mut child).expect("loop proxy should start");
    let response =
        post_chat_completion_to_proxy(proxy_port).expect("proxy request should complete");
    let output = wait_for_child_exit(child);
    let server_result = server.join().expect("local chat server thread should join");

    assert!(
        server_result.is_ok(),
        "local chat server failed: {:?}",
        server_result.err()
    );
    assert!(
        response.starts_with("HTTP/1.1 200 OK") && response.contains("local proxy ok"),
        "loop proxy should forward keyless local request and return upstream body; got {response:?}"
    );
    assert!(
        output.status.success(),
        "loop --max-iterations 1 should exit cleanly after one completed request; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn loop_stop_hook_denial_shuts_down_unlimited_loop_after_first_iteration() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let (server, base_url) = spawn_local_chat_server_rejecting_auth();
    write_local_provider_config_with_stop_hook(&cwd, &base_url);
    approve_first_repository_hook_proposal(&cwd, &home);
    let proxy_port = unused_loopback_port();
    let proxy_port_arg = proxy_port.to_string();

    let mut child = isolated_command(&cwd, &home)
        .args(["loop", "--max-iterations", "0", "--port", &proxy_port_arg])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("openclaudia loop must spawn");

    wait_for_loop_proxy(proxy_port, &mut child).expect("loop proxy should start");
    let response =
        post_chat_completion_to_proxy(proxy_port).expect("proxy request should complete");
    let output = wait_for_child_exit(child);
    let server_result = server.join().expect("local chat server thread should join");

    assert!(
        server_result.is_ok(),
        "local chat server failed: {:?}",
        server_result.err()
    );
    assert!(
        response.starts_with("HTTP/1.1 200 OK") && response.contains("local proxy ok"),
        "loop proxy should forward the request before Stop hook shutdown; got {response:?}"
    );
    assert!(
        output.status.success(),
        "loop --max-iterations 0 should exit cleanly when a Stop hook denies; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn start_without_config_exits_nonzero() {
    assert_missing_config_is_failure(&["start"]);
}

#[test]
fn loop_without_config_exits_nonzero() {
    assert_missing_config_is_failure(&["loop", "--max-iterations", "1"]);
}

#[test]
fn acp_without_config_exits_nonzero() {
    assert_missing_config_is_failure(&["acp"]);
}

#[test]
fn acp_accepts_keyless_local_provider_until_stdin_eof() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    write_local_provider_config(&cwd);

    let output = isolated_command(&cwd, &home)
        .arg("acp")
        .stdin(Stdio::null())
        .output()
        .expect("openclaudia acp must run");

    assert!(
        output.status.success(),
        "acp should start and exit cleanly on EOF for keyless local provider; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("No API key configured") && !combined.contains("Set API_KEY"),
        "local ACP mode must not require an API key; got {combined:?}"
    );
}

#[test]
fn acp_accepts_keyless_anthropic_with_claude_oauth_credentials_until_stdin_eof() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let claude_config = home.path().join("claude-config");
    write_anthropic_provider_config(&cwd);
    write_claude_oauth_credentials(&claude_config);

    let output = isolated_command(&cwd, &home)
        .arg("acp")
        .env("CLAUDE_CONFIG_HOME_DIR", &claude_config)
        .stdin(Stdio::null())
        .output()
        .expect("openclaudia acp must run");

    assert!(
        output.status.success(),
        "acp should start and exit cleanly on EOF for keyless Anthropic with Claude OAuth credentials; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("ANTHROPIC_API_KEY") && !combined.contains("No API key configured"),
        "Anthropic ACP OAuth mode must not ask for an API key; got {combined:?}"
    );
}

#[test]
fn acp_rejects_keyless_remote_provider_before_handshake() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    write_openai_provider_config(&cwd);

    let output = isolated_command(&cwd, &home)
        .arg("acp")
        .stdin(Stdio::null())
        .output()
        .expect("openclaudia acp must run");

    assert!(
        !output.status.success(),
        "acp should reject a remote provider with no API key; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("OPENAI_API_KEY"),
        "remote ACP auth failure should name the provider env var; got {combined:?}"
    );
}

#[test]
fn acp_model_override_autodetects_provider_when_target_not_explicit() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    write_anthropic_target_with_openai_key_config(&cwd);

    let output = isolated_command(&cwd, &home)
        .args(["acp", "--model", "gpt-5.5"])
        .stdin(Stdio::null())
        .output()
        .expect("openclaudia acp must run");

    assert!(
        output.status.success(),
        "acp should infer OpenAI from gpt model when no target override is supplied; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !combined.contains("ANTHROPIC_API_KEY"),
        "acp model autodetect should not ask for Anthropic credentials; got {combined:?}"
    );
}

#[test]
fn acp_explicit_target_takes_precedence_over_model_autodetect() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    write_anthropic_target_with_openai_key_config(&cwd);

    let output = isolated_command(&cwd, &home)
        .args(["acp", "--target", "anthropic", "--model", "gpt-5.5"])
        .stdin(Stdio::null())
        .output()
        .expect("openclaudia acp must run");

    assert!(
        !output.status.success(),
        "explicit anthropic target should win over gpt model autodetection; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("ANTHROPIC_API_KEY"),
        "explicit target auth failure should name Anthropic credentials; got {combined:?}"
    );
}

#[test]
fn acp_session_set_mode_updates_active_session_over_stdio() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    write_local_provider_config(&cwd);

    let mut child = isolated_command(&cwd, &home)
        .arg("acp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("openclaudia acp must spawn");

    {
        let mut stdin = child.stdin.take().expect("acp stdin should be piped");
        stdin
            .write_all(
                br#"{"jsonrpc":"2.0","id":1,"method":"session/new","params":{}}
{"jsonrpc":"2.0","id":2,"method":"session/set_mode","params":{"mode":"coding"}}
{"jsonrpc":"2.0","id":3,"method":"session/set_mode","params":{"mode":"auto"}}
"#,
            )
            .expect("acp stdin should accept JSON-RPC");
    }

    let output = child.wait_with_output().expect("openclaudia acp must run");
    assert!(
        output.status.success(),
        "acp stdio session/set_mode should succeed; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let responses = String::from_utf8(output.stdout).expect("stdout must be utf8");
    let response_values = responses
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("JSON-RPC response"))
        .collect::<Vec<_>>();

    let coding = response_values
        .iter()
        .find(|response| response["id"] == 2)
        .expect("coding response");
    assert_eq!(coding["result"]["mode"], "coding");
    assert_eq!(coding["result"]["activeMode"], "coding");

    let auto = response_values
        .iter()
        .find(|response| response["id"] == 3)
        .expect("auto response");
    assert_eq!(auto["result"]["mode"], "auto");
    assert_eq!(
        auto["result"]["activeMode"], "coding",
        "auto should report the active mode set by the previous request"
    );
}

#[test]
fn acp_session_set_config_option_updates_mode_and_model_over_stdio() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    write_openai_provider_config_with_api_key(&cwd);

    let mut child = isolated_command(&cwd, &home)
        .arg("acp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("openclaudia acp must spawn");

    let mut stdin = child.stdin.take().expect("acp stdin should be piped");
    let stdout = child.stdout.take().expect("acp stdout should be piped");
    let mut stderr = child.stderr.take().expect("acp stderr should be piped");
    let mut reader = BufReader::new(stdout);

    stdin
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"session/new\",\"params\":{}}\n")
        .expect("acp stdin should accept session/new");
    stdin.flush().expect("flush session/new");

    let mut created_line = String::new();
    reader
        .read_line(&mut created_line)
        .expect("read session/new response");
    let created =
        serde_json::from_str::<serde_json::Value>(&created_line).expect("session/new response");
    let session_id = created["result"]["sessionId"]
        .as_str()
        .expect("session id")
        .to_string();

    stdin
        .write_all(
            format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"session/set_config_option\",\"params\":{{\"sessionId\":\"{session_id}\",\"configId\":\"mode\",\"value\":\"coding\"}}}}\n"
            )
            .as_bytes(),
        )
        .expect("acp stdin should accept mode config");
    stdin.flush().expect("flush mode config");

    let mut mode_reply = String::new();
    reader
        .read_line(&mut mode_reply)
        .expect("read mode response");

    stdin
        .write_all(
            format!(
                "{{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"session/set_config_option\",\"params\":{{\"sessionId\":\"{session_id}\",\"configId\":\"model\",\"value\":\"future-model-2099\"}}}}\n"
            )
            .as_bytes(),
        )
        .expect("acp stdin should accept model config");
    stdin.flush().expect("flush model config");

    let mut selected_model_reply = String::new();
    reader
        .read_line(&mut selected_model_reply)
        .expect("read model response");

    drop(stdin);
    let status = child.wait().expect("openclaudia acp must run");
    let mut stderr_text = String::new();
    stderr
        .read_to_string(&mut stderr_text)
        .expect("stderr should be readable");
    assert!(
        status.success(),
        "acp stdio session/set_config_option should succeed; stdout={created_line:?}{mode_reply:?}{selected_model_reply:?} stderr={stderr_text:?}"
    );

    let mode = serde_json::from_str::<serde_json::Value>(&mode_reply).expect("mode response");
    let coding_mode_id = mode["result"]["configOptions"]
        .as_array()
        .expect("configOptions")
        .iter()
        .find(|option| option["id"] == "mode")
        .expect("mode config option")["currentValue"]
        .as_str();
    assert_eq!(coding_mode_id, Some("coding"));

    let model =
        serde_json::from_str::<serde_json::Value>(&selected_model_reply).expect("model response");
    let returned_model_id = model["result"]["configOptions"]
        .as_array()
        .expect("configOptions")
        .iter()
        .find(|option| option["id"] == "model")
        .expect("model config option")["currentValue"]
        .as_str();
    assert_eq!(returned_model_id, Some("future-model-2099"));
}

#[test]
fn print_accepts_keyless_local_provider_and_sends_no_auth_header() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let (server, base_url) = spawn_local_sse_server_rejecting_auth();
    write_local_provider_config_with_base_url(&cwd, &base_url);

    let output = isolated_command(&cwd, &home)
        .args(["--print", "hello"])
        .output()
        .expect("openclaudia --print must run");

    let server_result = server.join().expect("local SSE server thread should join");
    assert!(
        server_result.is_ok(),
        "local SSE server failed: {:?}",
        server_result.err()
    );
    assert!(
        output.status.success(),
        "print should succeed for keyless local provider; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "local ok\n");
}

#[test]
fn print_mixed_case_lmstudio_target_uses_lmstudio_config() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let (server, base_url) = spawn_local_sse_server_rejecting_auth();
    write_lmstudio_provider_config_with_base_url(&cwd, &base_url);

    let output = isolated_command(&cwd, &home)
        .args(["--target", "LMStudio", "--print", "hello"])
        .output()
        .expect("openclaudia --print must run");

    let server_result = server.join().expect("local SSE server thread should join");
    assert!(
        server_result.is_ok(),
        "LMStudio SSE server failed, which usually means --target LMStudio used the wrong provider config: {:?}",
        server_result.err()
    );
    assert!(
        output.status.success(),
        "print should succeed for mixed-case LMStudio using providers.lmstudio; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "local ok\n");
}

#[test]
fn print_rejects_malformed_sse_data_instead_of_succeeding_empty() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let (server, base_url) =
        spawn_local_sse_server_rejecting_auth_with_body("data: {not valid json}\n\n");
    write_local_provider_config_with_base_url(&cwd, &base_url);

    let output = isolated_command(&cwd, &home)
        .args(["--print", "hello"])
        .output()
        .expect("openclaudia --print must run");

    let server_result = server.join().expect("local SSE server thread should join");
    assert!(
        server_result.is_ok(),
        "local SSE server failed: {:?}",
        server_result.err()
    );
    assert!(
        !output.status.success(),
        "print must fail when provider SSE data is malformed; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("invalid SSE data JSON"),
        "print failure should identify malformed SSE data; got {combined:?}"
    );
}

#[test]
fn print_rejects_sse_stream_without_printable_text() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let (server, base_url) = spawn_local_sse_server_rejecting_auth_with_body(
        "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n",
    );
    write_local_provider_config_with_base_url(&cwd, &base_url);

    let output = isolated_command(&cwd, &home)
        .args(["--print", "hello"])
        .output()
        .expect("openclaudia --print must run");

    let server_result = server.join().expect("local SSE server thread should join");
    assert!(
        server_result.is_ok(),
        "local SSE server failed: {:?}",
        server_result.err()
    );
    assert!(
        !output.status.success(),
        "print must fail when provider SSE has no assistant text; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("provider stream did not contain printable assistant text"),
        "print failure should identify empty provider streams; got {combined:?}"
    );
    assert!(
        output.stdout.is_empty(),
        "print must not emit a blank successful-looking line before failing"
    );
}

#[test]
fn print_rejects_keyless_remote_provider_before_request() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    write_openai_provider_config(&cwd);

    let output = isolated_command(&cwd, &home)
        .args(["--print", "hello"])
        .output()
        .expect("openclaudia --print must run");

    assert!(
        !output.status.success(),
        "print should reject a remote provider with no API key; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("OPENAI_API_KEY"),
        "remote print auth failure should name the provider env var; got {combined:?}"
    );
}

#[test]
fn print_mixed_case_remote_provider_names_specific_env_var() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    write_openai_provider_config_with_target(&cwd, "OpenAI");

    let output = isolated_command(&cwd, &home)
        .args(["--print", "hello"])
        .output()
        .expect("openclaudia --print must run");

    assert!(
        !output.status.success(),
        "print should reject mixed-case OpenAI without an API key; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("OPENAI_API_KEY") && !combined.contains("Set API_KEY"),
        "mixed-case OpenAI target should keep the OpenAI env-var hint; got {combined:?}"
    );
}

#[test]
fn print_rejects_interactive_only_root_flags_instead_of_ignoring_them() {
    for (args, expected) in [
        (
            vec!["--print", "hello", "--resume"],
            "--resume/--continue cannot be used with --print",
        ),
        (
            vec!["--print", "hello", "--session-id", "abc123"],
            "--session-id cannot be used with --print",
        ),
        (
            vec!["--print", "hello", "--coordinator"],
            "--coordinator cannot be used with --print",
        ),
        (
            vec!["--print", "hello", "--dangerously-skip-permissions"],
            "--dangerously-skip-permissions cannot be used with --print",
        ),
        (
            vec!["--print", "hello", "--tui-mode"],
            "--tui-mode cannot be used with --print",
        ),
        (
            vec!["--print", "hello", "--mode", "debug"],
            "--mode cannot be used with --print",
        ),
    ] {
        let cwd = tempfile::tempdir().expect("cwd tempdir");
        let home = tempfile::tempdir().expect("home tempdir");
        let output = isolated_command(&cwd, &home)
            .args(&args)
            .output()
            .expect("openclaudia --print must run");

        assert!(
            !output.status.success(),
            "print with {args:?} must fail instead of ignoring the flag; stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            combined.contains(expected),
            "print with {args:?} should reject with {expected:?}; got {combined:?}"
        );
        assert!(
            !combined.contains("No configuration found"),
            "print with {args:?} should fail before config loading; got {combined:?}"
        );
    }
}

#[test]
fn subcommands_reject_unsupported_root_flags_before_config_loading() {
    for (args, expected) in [
        (
            vec!["--session-id", "abc123", "doctor"],
            "--session-id cannot be used with 'doctor'",
        ),
        (
            vec!["--coordinator", "config"],
            "--coordinator cannot be used with 'config'",
        ),
        (
            vec!["--dangerously-skip-permissions", "init"],
            "--dangerously-skip-permissions cannot be used with 'init'",
        ),
        (
            vec!["--tui-mode", "auth", "--status"],
            "--tui-mode cannot be used with 'auth'",
        ),
        (
            vec!["--mode", "debug", "loop", "--max-iterations", "1"],
            "--mode cannot be used with 'loop'",
        ),
        (
            vec!["--target", "OpenAI", "config"],
            "--target cannot be used with 'config'",
        ),
        (
            vec!["--model", "gpt-5.5", "loop", "--max-iterations", "1"],
            "--model cannot be used with 'loop'",
        ),
    ] {
        let cwd = tempfile::tempdir().expect("cwd tempdir");
        let home = tempfile::tempdir().expect("home tempdir");
        let output = isolated_command(&cwd, &home)
            .args(&args)
            .output()
            .expect("openclaudia subcommand must run");

        assert!(
            !output.status.success(),
            "subcommand with {args:?} must fail instead of ignoring the flag; stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            combined.contains(expected),
            "subcommand with {args:?} should reject with {expected:?}; got {combined:?}"
        );
        assert!(
            !combined.contains("No configuration found"),
            "subcommand with {args:?} should fail before config loading; got {combined:?}"
        );
    }
}

#[test]
fn doctor_without_config_exits_nonzero() {
    assert_missing_config_is_failure(&["doctor"]);
}

#[test]
fn legacy_repl_without_config_exits_nonzero() {
    assert_missing_config_is_failure(&["--tui-mode"]);
}

#[test]
fn doctor_default_is_offline_non_mutating_redacted_and_typed() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    write_doctor_adversarial_fixture(&cwd, &home);

    let (probe, proxy_url, stop_probe) = spawn_doctor_network_probe_detector();
    let cwd_before = snapshot_tree(cwd.path());
    let home_before = snapshot_tree(home.path());

    let output = isolated_command(&cwd, &home)
        .args(["doctor", "--json"])
        .env("HTTPS_PROXY", &proxy_url)
        .env("HTTP_PROXY", &proxy_url)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .expect("openclaudia doctor must run");
    let _ = stop_probe.send(());
    let probe_result = probe.join().expect("doctor probe thread should join");

    assert!(
        !output.status.success(),
        "standalone doctor must report degraded when no live composition is present; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        probe_result.is_ok(),
        "default doctor must not contact the network: {:?}",
        probe_result.err()
    );
    assert_eq!(snapshot_tree(cwd.path()), cwd_before);
    assert_eq!(snapshot_tree(home.path()), home_before);

    let report: openclaudia::doctor::DoctorReport = serde_json::from_slice(&output.stdout)
        .expect("doctor stdout must be one typed JSON report");
    report.validate().expect("doctor report must validate");
    assert_eq!(
        report.aggregate(),
        openclaudia::doctor::DoctorAggregate::Degraded
    );
    assert!(
        report.receipts().iter().all(|receipt| {
            receipt.observed_effects().iter().all(|effect| {
                matches!(
                    effect,
                    openclaudia::doctor::DoctorEffect::FilesystemRead
                        | openclaudia::doctor::DoctorEffect::CredentialRead
                )
            })
        }),
        "default doctor receipt claimed an active or mutating observed effect"
    );
    assert_doctor_canaries_redacted(&output);
    let active = report
        .receipts()
        .iter()
        .find(|receipt| receipt.check_id() == "provider.reachability")
        .expect("active provider receipt");
    assert_eq!(
        active.outcome(),
        openclaudia::doctor::DoctorOutcome::Skipped
    );
    assert_eq!(active.code(), "provider.reachability.not_granted");
    let migration = report
        .receipts()
        .iter()
        .find(|receipt| receipt.check_id() == "startup.migration_gate")
        .expect("migration receipt");
    assert_eq!(
        migration.outcome(),
        openclaudia::doctor::DoctorOutcome::Skipped
    );
}

#[test]
fn doctor_active_probe_accepts_only_exact_grant_and_remains_offline_without_broker() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    write_openai_provider_config_with_api_key(&cwd);

    let rejected_cwd_before = snapshot_tree(cwd.path());
    let rejected_home_before = snapshot_tree(home.path());
    let rejected = isolated_command(&cwd, &home)
        .args([
            "doctor",
            "--json",
            "--allow-active",
            "provider.reachability-canary-secret",
        ])
        .output()
        .expect("openclaudia doctor must reject unknown grant");
    assert!(!rejected.status.success());
    let rejected_text = format!(
        "{}{}",
        String::from_utf8_lossy(&rejected.stdout),
        String::from_utf8_lossy(&rejected.stderr)
    );
    assert!(rejected.stdout.is_empty());
    assert!(rejected_text.contains("unknown active diagnostic grant"));
    assert!(!rejected_text.contains("canary-secret"));
    assert_eq!(snapshot_tree(cwd.path()), rejected_cwd_before);
    assert_eq!(snapshot_tree(home.path()), rejected_home_before);

    let (probe, proxy_url, stop_probe) = spawn_doctor_network_probe_detector();
    let cwd_before = snapshot_tree(cwd.path());
    let home_before = snapshot_tree(home.path());
    let output = isolated_command(&cwd, &home)
        .args([
            "doctor",
            "--json",
            "--allow-active",
            "provider.reachability",
        ])
        .env("HTTPS_PROXY", &proxy_url)
        .env("HTTP_PROXY", &proxy_url)
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .expect("openclaudia doctor must run with exact grant");
    let _ = stop_probe.send(());
    let probe_result = probe.join().expect("doctor probe thread should join");

    assert!(!output.status.success());
    assert!(
        probe_result.is_ok(),
        "unsafe active network effect occurred"
    );
    assert_eq!(snapshot_tree(cwd.path()), cwd_before);
    assert_eq!(snapshot_tree(home.path()), home_before);
    let report: openclaudia::doctor::DoctorReport =
        serde_json::from_slice(&output.stdout).expect("typed doctor report");
    report.validate().expect("valid doctor report");
    let active = report
        .receipts()
        .iter()
        .find(|receipt| receipt.check_id() == "provider.reachability")
        .expect("active provider receipt");
    assert_eq!(
        active.outcome(),
        openclaudia::doctor::DoctorOutcome::Skipped
    );
    assert_eq!(active.code(), "provider.reachability.broker_unavailable");
    assert!(active.observed_effects().is_empty());
}

#[test]
fn doctor_mixed_case_remote_provider_returns_stable_redacted_receipt() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    write_openai_provider_config_with_target(&cwd, "OpenAI");

    let output = isolated_command(&cwd, &home)
        .args(["doctor", "--json"])
        .output()
        .expect("openclaudia doctor must run");

    assert!(
        !output.status.success(),
        "doctor should fail mixed-case OpenAI without an API key; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: openclaudia::doctor::DoctorReport =
        serde_json::from_slice(&output.stdout).expect("typed doctor report");
    let provider = report
        .receipts()
        .iter()
        .find(|receipt| receipt.check_id() == "provider.configuration")
        .expect("provider receipt");
    assert_eq!(provider.outcome(), openclaudia::doctor::DoctorOutcome::Fail);
    assert_eq!(provider.code(), "provider.configuration.credential_missing");
}

#[test]
fn auth_without_code_exits_nonzero() {
    let output = run_auth_with_stdin("");

    assert!(
        !output.status.success(),
        "auth with empty stdin must fail; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("No code provided. Authentication cancelled."),
        "cancelled auth should explain the failure; got {combined:?}"
    );
}

#[test]
fn auth_state_mismatch_exits_nonzero_before_token_exchange() {
    let output = run_auth_with_stdin("test-code#definitely-not-the-generated-state\n");

    assert!(
        !output.status.success(),
        "auth with mismatched state must fail; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("State mismatch! This could be a CSRF attack."),
        "state mismatch should explain the failure; got {combined:?}"
    );
    assert!(
        !combined.contains("Exchanging code for tokens"),
        "state mismatch must abort before network token exchange; got {combined:?}"
    );
}

#[test]
fn auth_status_with_malformed_credentials_exits_nonzero() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let claude_config = home.path().join("claude-config");
    fs::create_dir_all(&claude_config).expect("claude config dir");
    fs::write(claude_config.join(".credentials.json"), "{not valid json")
        .expect("malformed credentials fixture");

    let output = isolated_command(&cwd, &home)
        .args(["auth", "--status"])
        .env("CLAUDE_CONFIG_HOME_DIR", &claude_config)
        .output()
        .expect("openclaudia auth --status must run");

    assert!(
        !output.status.success(),
        "auth --status must fail when an existing credentials file is malformed; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Could not read") && combined.contains(".credentials.json"),
        "status failure should identify the unreadable credentials file; got {combined:?}"
    );
}

#[test]
fn auth_status_with_malformed_native_oauth_store_exits_nonzero() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let xdg_data = home.path().join(".local/share");
    let store_dir = xdg_data.join("openclaudia");
    fs::create_dir_all(&store_dir).expect("oauth store dir");
    fs::write(store_dir.join("oauth_sessions.json"), "{not valid json")
        .expect("malformed native oauth store");

    let output = isolated_command(&cwd, &home)
        .args(["auth", "--status"])
        .output()
        .expect("openclaudia auth --status must run");

    assert!(
        !output.status.success(),
        "auth --status must fail when native OAuth store is malformed; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Native OAuth session store unreadable")
            && combined.contains("oauth_sessions.json"),
        "status failure should identify the unreadable native OAuth store; got {combined:?}"
    );
}

#[test]
fn auth_logout_describes_native_session_scope() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let output = isolated_command(&cwd, &home)
        .args(["auth", "--logout"])
        .output()
        .expect("openclaudia auth --logout must run");

    assert!(
        output.status.success(),
        "auth --logout with no native sessions should still succeed; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("No native OAuth sessions to clear")
            && combined.contains("Shared Claude credentials were not deleted"),
        "logout output must describe what was and was not cleared; got {combined:?}"
    );
}

#[test]
fn auth_logout_removes_native_session_store_without_deleting_shared_credentials() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let xdg_data = home.path().join(".local/share");
    let store_dir = xdg_data.join("openclaudia");
    fs::create_dir_all(&store_dir).expect("oauth store dir");
    let native_store = store_dir.join("oauth_sessions.json");
    fs::write(
        &native_store,
        r#"{"native-session":{"access_token":"tok"}}"#,
    )
    .expect("native oauth store fixture");

    let claude_config = home.path().join("claude-config");
    write_claude_oauth_credentials(&claude_config);
    let credentials_path = claude_config.join(".credentials.json");
    let credentials_before =
        fs::read_to_string(&credentials_path).expect("credentials fixture should be readable");

    let output = isolated_command(&cwd, &home)
        .args(["auth", "--logout"])
        .env("CLAUDE_CONFIG_HOME_DIR", &claude_config)
        .output()
        .expect("openclaudia auth --logout must run");

    assert!(
        output.status.success(),
        "auth --logout should succeed with both native and shared stores; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Native OAuth sessions cleared")
            && combined.contains("Shared Claude credentials were not deleted"),
        "logout output must distinguish native sessions from shared credentials; got {combined:?}"
    );
    assert!(
        !native_store.exists(),
        "auth --logout must remove the native OAuth session cache"
    );
    assert!(
        credentials_path.exists(),
        "auth --logout must not delete shared Claude credentials"
    );
    assert_eq!(
        fs::read_to_string(&credentials_path).expect("credentials should remain readable"),
        credentials_before,
        "auth --logout must not rewrite shared Claude credentials"
    );
}

#[cfg(unix)]
#[test]
fn auth_logout_removes_broken_native_oauth_symlink() {
    use std::os::unix::fs::symlink;

    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let xdg_data = home.path().join(".local/share");
    let store_dir = xdg_data.join("openclaudia");
    fs::create_dir_all(&store_dir).expect("oauth store dir");
    let native_store = store_dir.join("oauth_sessions.json");
    symlink(store_dir.join("missing-target.json"), &native_store).expect("broken oauth symlink");
    assert!(
        !native_store.exists(),
        "fixture should be a broken symlink so Path::exists would miss it"
    );
    assert!(
        native_store.symlink_metadata().is_ok(),
        "broken symlink fixture should exist as a path entry"
    );

    let output = isolated_command(&cwd, &home)
        .args(["auth", "--logout"])
        .output()
        .expect("openclaudia auth --logout must run");

    assert!(
        output.status.success(),
        "auth --logout should remove a broken native OAuth symlink; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("Native OAuth sessions cleared")
            && combined.contains("Shared Claude credentials were not deleted"),
        "logout output should report the native cache cleanup; got {combined:?}"
    );
    assert!(
        native_store.symlink_metadata().is_err(),
        "auth --logout must remove the broken native OAuth symlink itself"
    );
}

#[test]
fn start_rejects_model_flag_instead_of_ignoring_it() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let output = isolated_command(&cwd, &home)
        .args(["start", "--model", "gpt-5.5"])
        .output()
        .expect("openclaudia start must run");

    assert!(
        !output.status.success(),
        "start --model must fail at CLI parsing instead of ignoring the model; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unexpected argument '--model'"),
        "start --model should be rejected by clap; got {stderr:?}"
    );
    assert!(
        !stderr.contains("No configuration found"),
        "start --model should fail before config loading; got {stderr:?}"
    );
}

#[test]
fn start_rejects_root_model_flag_instead_of_ignoring_it() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let output = isolated_command(&cwd, &home)
        .args(["--model", "gpt-5.5", "start"])
        .output()
        .expect("openclaudia start must run");

    assert!(
        !output.status.success(),
        "root --model with start must fail instead of being ignored; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("--model cannot be used with 'start'"),
        "root --model should be rejected by OpenClaudia preflight; got {combined:?}"
    );
    assert!(
        !combined.contains("No configuration found"),
        "root --model should fail before start config loading; got {combined:?}"
    );
}

#[test]
fn acp_accepts_its_own_model_flag() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let output = isolated_command(&cwd, &home)
        .args(["acp", "--model", "gpt-5.5"])
        .output()
        .expect("openclaudia acp must run");

    assert!(
        !output.status.success(),
        "acp without config still fails, but not because --model was rejected"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("No configuration found") || combined.contains("no configuration found"),
        "acp --model should parse and then fail on missing config; got {combined:?}"
    );
    assert!(
        !combined.contains("unexpected argument '--model'"),
        "acp owns --model and must not reject it; got {combined:?}"
    );
}

#[test]
fn acp_accepts_root_model_flag() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let output = isolated_command(&cwd, &home)
        .args(["--model", "gpt-5.5", "acp"])
        .output()
        .expect("openclaudia acp must run");

    assert!(
        !output.status.success(),
        "acp without config still fails, but not because root --model was rejected"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("No configuration found") || combined.contains("no configuration found"),
        "acp with root --model should parse and then fail on missing config; got {combined:?}"
    );
    assert!(
        !combined.contains("--model cannot be used"),
        "acp is allowed to inherit root --model; got {combined:?}"
    );
}

#[test]
fn acp_rejects_root_resume_flag_instead_of_ignoring_it() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let output = isolated_command(&cwd, &home)
        .args(["--resume", "acp"])
        .output()
        .expect("openclaudia acp must run");

    assert!(
        !output.status.success(),
        "root --resume with acp must fail instead of being ignored; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("--resume/--continue cannot be used with 'acp'"),
        "root --resume should be rejected by OpenClaudia preflight; got {combined:?}"
    );
    assert!(
        !combined.contains("No configuration found"),
        "root --resume should fail before acp config loading; got {combined:?}"
    );
}

#[test]
fn doctor_rejects_root_target_flag_instead_of_ignoring_it() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let output = isolated_command(&cwd, &home)
        .args(["--target", "OpenAI", "doctor"])
        .output()
        .expect("openclaudia doctor must run");

    assert!(
        !output.status.success(),
        "root --target with doctor must fail instead of being ignored; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("--target cannot be used with 'doctor'"),
        "root --target should be rejected by OpenClaudia preflight; got {combined:?}"
    );
    assert!(
        !combined.contains("No configuration found"),
        "root --target should fail before doctor config loading; got {combined:?}"
    );
}

#[test]
fn help_describes_tui_mode_as_legacy_repl_escape_hatch() {
    let output = Command::new(env!("CARGO_BIN_EXE_openclaudia"))
        .arg("--help")
        .output()
        .expect("openclaudia --help must run");

    assert!(output.status.success(), "--help should succeed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Launch legacy line-oriented REPL instead of the default full-screen TUI"),
        "--tui-mode help must describe the actual legacy REPL behavior; got {stdout:?}"
    );
    assert!(
        !stdout.contains("Launch full-screen interactive TUI"),
        "--tui-mode help must not claim to launch the default TUI"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn readme_cli_examples_do_not_advertise_stale_tui_or_coordinator_modes() {
    let readme = include_str!("../README.md");

    assert!(
        readme.contains("openclaudia --tui-mode         # Legacy line-oriented REPL"),
        "README must match the binary's --tui-mode behavior"
    );
    assert!(
        readme.contains("openclaudia --coordinator --tui-mode"),
        "README must show --coordinator with the required legacy REPL flag"
    );
    assert!(
        readme.contains(
            "openclaudia --print \"prompt\"   # Send one prompt, print the response, and exit"
        ),
        "README must document the binary's supported non-interactive --print mode"
    );
    assert!(
        readme.contains("openclaudia auth --logout      # Clear native OAuth session cache"),
        "README must not imply auth --logout deletes shared Claude credentials"
    );
    assert!(
        readme.contains(
            "**Thinking Mode** — Extended reasoning for Anthropic, OpenAI GPT-5/o1/o3/o4, Gemini 3.x/2.5, DeepSeek V4, Qwen QwQ, Z.AI/GLM, and MiniMax-M3"
        ),
        "README feature list must match the implemented provider thinking surface"
    );
    assert!(
        readme.contains(
            "reasoning_effort: \"medium\"  # OpenAI GPT-5/o1/o3/o4: none, low, medium, high, xhigh"
        ),
        "README config sample must mention every OpenAI reasoning family supported by the adapter"
    );
    assert!(
        readme.contains("budget_tokens: 10000        # Google Gemini thinking budget"),
        "README config sample must not pin Google thinking to an older Gemini family"
    );
    for alias_group in [
        "google/gemini",
        "qwen/alibaba",
        "zai/glm/zhipu",
        "kimi/moonshot",
    ] {
        assert!(
            readme.contains(alias_group),
            "README config sample must advertise supported provider alias group {alias_group}"
        );
    }
    assert!(
        readme.contains(
            "**Cron Scheduling** — Create, list, and delete cron schedule metadata for external schedulers"
        ),
        "README feature list must describe cron records as metadata for external schedulers"
    );
    assert!(
        readme.contains(
            "| `cron_create` | Create recurring cron metadata for an external scheduler |"
        ),
        "README tool table must describe cron_create without implying OpenClaudia runs schedules"
    );
    assert!(
        !readme.contains("openclaudia --coordinator      # Multi-agent coordinator mode"),
        "README must not advertise the Phase 1 coordinator as a working binary mode"
    );
    assert!(
        !readme.contains("**Cron Scheduling** — Create, list, and delete recurring scheduled jobs"),
        "README must not imply OpenClaudia executes stored cron records"
    );
    assert!(
        !readme.contains("| `cron_create` | Create a recurring scheduled job |"),
        "README tool table must not advertise cron_create as an internal job runner"
    );
    assert!(
        !readme.contains("OpenAI o1/o3, Gemini 2.5, DeepSeek R1"),
        "README must not retain stale thinking-provider wording"
    );
    assert!(
        !readme.contains("openclaudia --tui-mode         # Full-screen TUI"),
        "README must not claim --tui-mode launches the default full-screen TUI"
    );
    assert!(
        readme.contains("#   default_allow:"),
        "README permissions sample must use the supported config schema"
    );
    assert!(
        !readme.contains("denied_tools") && !readme.contains("denied_commands"),
        "README permissions sample must not advertise unsupported deny-list fields"
    );
    assert!(
        readme.contains("openclaudia loop -n 10         # Max 10 iterations"),
        "README loop example must use the loop subcommand's -n/--max-iterations flag"
    );
    assert!(
        !readme.contains("openclaudia loop -m 10"),
        "README must not claim global -m/--model controls loop iteration count"
    );
    assert!(
        readme.contains("## Slash Commands (Default TUI)"),
        "README slash-command docs must describe the default full-screen TUI"
    );
    assert!(
        readme.contains("## Keyboard Shortcuts (Default TUI)"),
        "README keyboard docs must describe the default full-screen TUI"
    );
    assert!(
        readme.contains("| `/provider [name]` | Show or switch provider |"),
        "README default-TUI slash docs must advertise the implemented provider switch command"
    );
    assert!(
        readme.contains("| `/model <name>` | Switch to a different model |"),
        "README default-TUI slash docs must advertise the implemented model switch command"
    );
    assert!(
        readme.contains("The `keybindings:` config map customizes the legacy line-oriented REPL"),
        "README must explain that configurable keybindings apply to the legacy REPL"
    );
    for stale_tui_shortcut in [
        "| `Ctrl-X N` | New session |",
        "| `Ctrl-X M` | Show models |",
        "| `F2` | Show models |",
    ] {
        assert!(
            !readme.contains(stale_tui_shortcut),
            "README default-TUI keyboard docs must not advertise legacy shortcut: {stale_tui_shortcut}"
        );
    }
    for stale_tui_claim in [
        "| `/connect`, `/auth` | Configure API keys |",
        "| `/config path` | Show config file locations |",
        "| `/continue <n>`, `/load <n>`, `/resume <n>` | Load session by number |",
    ] {
        assert!(
            !readme.contains(stale_tui_claim),
            "README default-TUI slash docs must not advertise unsupported/stale command: {stale_tui_claim}"
        );
    }
}

#[test]
fn architecture_cli_overview_lists_all_binary_subcommands() {
    let architecture = include_str!("../ARCHITECTURE.md");
    for command in [
        "init", "auth", "start", "acp", "config", "doctor", "hooks", "team", "loop",
    ] {
        assert!(
            architecture.contains(command),
            "ARCHITECTURE.md high-level CLI overview must mention `{command}`"
        );
    }
    assert!(
        architecture.contains("Subcommands: init, auth, start,")
            && architecture.contains("acp, config, doctor, hooks, team, loop"),
        "ARCHITECTURE.md must keep the command inventory in the high-level overview"
    );
}

#[test]
fn comparison_provider_counts_match_current_adapter_surface() {
    let comparison = include_str!("../COMPARISON.md");

    assert!(
        comparison.contains("8 cloud + Ollama/local"),
        "COMPARISON.md must include Kimi and MiniMax in OpenClaudia's provider count"
    );
    assert!(
        comparison
            .contains("8 cloud provider adapters plus Ollama/local OpenAI-compatible routing"),
        "COMPARISON.md must describe the current adapter surface precisely"
    );
    assert!(
        comparison.contains("Pass `-m gemini-3.5-flash` and the provider is auto-detected"),
        "COMPARISON.md provider auto-detection example should use a current catalog model"
    );
    for stale_claim in ["7 + Ollama", "7 native provider adapters"] {
        assert!(
            !comparison.contains(stale_claim),
            "COMPARISON.md must not retain stale provider claim: {stale_claim}"
        );
    }
}

#[test]
fn init_refuses_overwrite_unless_force_and_creates_documented_tree() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");

    let output = isolated_command(&cwd, &home)
        .arg("init")
        .output()
        .expect("openclaudia init must run");
    assert!(
        output.status.success(),
        "init should succeed in empty tempdir; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let config_dir = cwd.path().join(".openclaudia");
    for path in ["config.yaml", "hooks/session-start.py", "plugins"] {
        assert!(
            config_dir.join(path).exists(),
            "init should create documented path .openclaudia/{path}"
        );
    }
    assert!(
        !config_dir.join("rules").exists(),
        "init must not recreate the removed repository rule-injector path"
    );

    fs::write(config_dir.join("config.yaml"), "sentinel: true\n").expect("replace config");
    let output = isolated_command(&cwd, &home)
        .arg("init")
        .output()
        .expect("second openclaudia init must run");
    assert!(
        !output.status.success(),
        "second init without --force must refuse overwrite; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("already exists") && combined.contains("--force"),
        "init overwrite refusal should explain --force; got {combined:?}"
    );
    assert_eq!(
        fs::read_to_string(config_dir.join("config.yaml")).expect("config should remain"),
        "sentinel: true\n",
        "init without --force must not overwrite existing config"
    );

    let output = isolated_command(&cwd, &home)
        .args(["init", "--force"])
        .output()
        .expect("openclaudia init --force must run");
    assert!(
        output.status.success(),
        "init --force should overwrite existing config; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let config = fs::read_to_string(config_dir.join("config.yaml"))
        .expect("forced init should write config");
    assert!(
        config.contains("OpenClaudia Configuration") && !config.contains("sentinel"),
        "init --force must replace the previous config contents"
    );

    let output = isolated_command(&cwd, &home)
        .arg("config")
        .output()
        .expect("openclaudia config must run after init");
    assert!(
        output.status.success(),
        "the generated config must load without edits; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn init_refuses_broken_config_symlink_without_force() {
    use std::os::unix::fs::symlink;

    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let config_dir = cwd.path().join(".openclaudia");
    fs::create_dir_all(&config_dir).expect("config dir");
    let config_path = config_dir.join("config.yaml");
    let outside_target = home.path().join("outside-config.yaml");
    symlink(&outside_target, &config_path).expect("broken config symlink");
    assert!(
        !config_path.exists(),
        "fixture should be a broken symlink so Path::exists would miss it"
    );
    assert!(
        config_path.symlink_metadata().is_ok(),
        "broken config symlink should exist as a path entry"
    );

    let output = isolated_command(&cwd, &home)
        .arg("init")
        .output()
        .expect("openclaudia init must run");

    assert!(
        !output.status.success(),
        "init without --force must refuse a broken config symlink; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("already exists") && combined.contains("--force"),
        "init should report the existing config path entry; got {combined:?}"
    );
    assert!(
        outside_target.symlink_metadata().is_err(),
        "init must not follow the broken symlink and create its target"
    );
    assert!(
        config_path.symlink_metadata().is_ok(),
        "init without --force must leave the config symlink in place"
    );
}

#[cfg(unix)]
#[test]
fn init_force_replaces_broken_config_symlink_with_project_file() {
    use std::os::unix::fs::symlink;

    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let config_dir = cwd.path().join(".openclaudia");
    fs::create_dir_all(&config_dir).expect("config dir");
    let config_path = config_dir.join("config.yaml");
    let outside_target = home.path().join("outside-config.yaml");
    symlink(&outside_target, &config_path).expect("broken config symlink");

    let output = isolated_command(&cwd, &home)
        .args(["init", "--force"])
        .output()
        .expect("openclaudia init --force must run");

    assert!(
        output.status.success(),
        "init --force should replace a broken config symlink in-project; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        outside_target.symlink_metadata().is_err(),
        "init --force must not create the old symlink target"
    );
    let metadata = config_path
        .symlink_metadata()
        .expect("forced init should write project config path");
    assert!(
        metadata.file_type().is_file(),
        "forced init should replace the symlink with a regular project file"
    );
    let config = fs::read_to_string(&config_path).expect("config should be readable");
    assert!(
        config.contains("OpenClaudia Configuration"),
        "forced init should write the default config template"
    );
}

#[test]
fn init_template_marks_keybindings_as_legacy_repl_specific() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let output = isolated_command(&cwd, &home)
        .arg("init")
        .output()
        .expect("openclaudia init must run");

    assert!(
        output.status.success(),
        "init should succeed in empty tempdir; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let config = fs::read_to_string(cwd.path().join(".openclaudia/config.yaml"))
        .expect("init should write config.yaml");
    assert!(
        config.contains("https://github.com/dollspace-gay/OpenClaudia"),
        "init template must point at the real upstream repository"
    );
    assert!(
        !config.contains("github.com/yourusername/openclaudia"),
        "init template must not contain placeholder repository URLs"
    );
    for model in [
        "claude-opus-4-7",
        "gpt-5.5",
        "gemini-3.5-flash",
        "gemini-3.1-pro-preview-customtools",
        "MiniMax-M3",
    ] {
        assert!(
            config.contains(model),
            "init template should advertise representative current model {model}"
        );
    }
    for provider in openclaudia::providers::SUPPORTED_PROVIDERS {
        assert!(
            config.contains(provider),
            "init template provider inventory must mention supported target {provider}"
        );
    }
    for provider in [
        "ollama:",
        "local:",
        "lmstudio:",
        "localai:",
        "text-generation-webui:",
    ] {
        assert!(
            config.contains(provider),
            "init template must include advertised local provider {provider}"
        );
    }
    assert!(
        config.contains("Legacy line REPL keybindings (`openclaudia --tui-mode`)"),
        "init template must label keybindings as legacy REPL-specific"
    );
    assert!(
        config.contains("uses its built-in shortcuts; type /help there to view them"),
        "init template must point default-TUI users at /help"
    );
    assert!(
        !config.contains("# Keyboard shortcuts - map key combinations to actions"),
        "init template must not imply keybindings customize the default TUI"
    );
}

#[test]
fn coordinator_without_legacy_repl_exits_nonzero() {
    let cwd = tempfile::tempdir().expect("cwd tempdir");
    let home = tempfile::tempdir().expect("home tempdir");
    let output = isolated_command(&cwd, &home)
        .arg("--coordinator")
        .output()
        .expect("openclaudia --coordinator must run");

    assert!(
        !output.status.success(),
        "default TUI must not silently ignore --coordinator; stdout={:?} stderr={:?}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("--coordinator is only supported by the legacy REPL"),
        "coordinator failure should explain the required mode; got {combined:?}"
    );
}
