//! Process-boundary coverage for the S-103 host authority commands.

#![allow(clippy::expect_used)]

use std::process::{Command, Output};

fn command(home: &tempfile::TempDir, workspace: &tempfile::TempDir) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_openclaudia"));
    command
        .current_dir(workspace.path())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join(".config"))
        .env("XDG_DATA_HOME", home.path().join(".local/share"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("OPENCLAUDIA_") {
            command.env_remove(name);
        }
    }
    command
}

fn success(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "command failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("public JSON output")
}

#[test]
fn create_status_and_invite_are_reachable_and_never_print_private_material() {
    let home = tempfile::tempdir().expect("home");
    let workspace = tempfile::tempdir().expect("workspace");
    let created_output = command(&home, &workspace)
        .args([
            "team",
            "create",
            "--principal-id",
            "host-owner",
            "--membership-ttl-seconds",
            "3600",
        ])
        .output()
        .expect("team create");
    let created_text = String::from_utf8_lossy(&created_output.stdout);
    assert!(!created_text.contains("secret"));
    assert!(!created_text.contains(home.path().to_string_lossy().as_ref()));
    let created = success(&created_output);
    assert_eq!(created["status"], "active");
    assert_eq!(created["principal_id"], "host-owner");
    assert_eq!(created["role"], "owner");
    let team_id = created["team_id"].as_str().expect("team ID");

    let status = success(
        &command(&home, &workspace)
            .args(["team", "status", "--team-id", team_id])
            .output()
            .expect("team status"),
    );
    assert_eq!(status, created);

    let invite_output = command(&home, &workspace)
        .args([
            "team",
            "invite",
            "--team-id",
            team_id,
            "--ttl-seconds",
            "300",
        ])
        .output()
        .expect("team invite");
    let invite_text = String::from_utf8_lossy(&invite_output.stdout);
    assert!(!invite_text.contains("secret"));
    assert!(!invite_text.contains("private"));
    let invite = success(&invite_output);
    assert_eq!(invite["bundle"]["document"]["team_id"], team_id);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let workspaces = home.path().join(".openclaudia/memory/workspaces");
        let workspace_state = std::fs::read_dir(workspaces)
            .expect("workspace state")
            .next()
            .expect("one workspace")
            .expect("workspace entry")
            .path();
        let credential = workspace_state.join(format!("team-authority-{team_id}.json"));
        let mode = std::fs::metadata(credential)
            .expect("credential metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn repository_selector_names_a_team_but_never_creates_membership() {
    let home = tempfile::tempdir().expect("home");
    let workspace = tempfile::tempdir().expect("workspace");
    let team_id = "team-0123456789abcdef0123456789abcdef";
    let config_dir = workspace.path().join(".openclaudia");
    std::fs::create_dir_all(&config_dir).expect("config directory");
    std::fs::write(
        config_dir.join("config.yaml"),
        format!("memory:\n  team_id: {team_id}\n"),
    )
    .expect("team selector");

    let status = success(
        &command(&home, &workspace)
            .args(["team", "status"])
            .output()
            .expect("team status"),
    );
    assert_eq!(status["status"], "unenrolled");

    let authority_files = std::fs::read_dir(home.path().join(".openclaudia/memory/workspaces"))
        .expect("workspace state")
        .flat_map(Result::into_iter)
        .flat_map(|entry| std::fs::read_dir(entry.path()).into_iter().flatten())
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("team-authority-")
        })
        .count();
    assert_eq!(authority_files, 0, "selector must not create credentials");
}

#[test]
fn manual_public_artifact_enrollment_completes_across_two_host_stores() {
    let owner_home = tempfile::tempdir().expect("owner home");
    let member_home = tempfile::tempdir().expect("member home");
    let workspace = tempfile::tempdir().expect("workspace");
    let created = success(
        &command(&owner_home, &workspace)
            .args([
                "team",
                "create",
                "--principal-id",
                "owner",
                "--membership-ttl-seconds",
                "3600",
            ])
            .output()
            .expect("create team"),
    );
    let team_id = created["team_id"].as_str().expect("team ID");

    let invitation_output = command(&owner_home, &workspace)
        .args([
            "team",
            "invite",
            "--team-id",
            team_id,
            "--ttl-seconds",
            "300",
        ])
        .output()
        .expect("invitation");
    assert!(invitation_output.status.success());
    let invitation_path = workspace.path().join("invitation.json");
    std::fs::write(&invitation_path, invitation_output.stdout).expect("write invitation");

    let request_output = command(&member_home, &workspace)
        .arg("team")
        .arg("begin-enrollment")
        .arg("--invitation")
        .arg(&invitation_path)
        .args(["--principal-id", "member"])
        .output()
        .expect("begin enrollment");
    assert!(request_output.status.success());
    let request_path = workspace.path().join("request.json");
    std::fs::write(&request_path, request_output.stdout).expect("write request");

    let approval_output = command(&owner_home, &workspace)
        .arg("team")
        .arg("approve-enrollment")
        .arg("--invitation")
        .arg(&invitation_path)
        .arg("--request")
        .arg(&request_path)
        .args(["--role", "reader", "--membership-ttl-seconds", "3600"])
        .output()
        .expect("approve enrollment without redundant team flag");
    assert!(
        approval_output.status.success(),
        "approval stderr={}",
        String::from_utf8_lossy(&approval_output.stderr)
    );
    let approval_path = workspace.path().join("approval.json");
    std::fs::write(&approval_path, approval_output.stdout).expect("write approval");

    let accepted = success(
        &command(&member_home, &workspace)
            .arg("team")
            .arg("accept-enrollment")
            .arg("--approval")
            .arg(&approval_path)
            .output()
            .expect("accept enrollment without redundant team flag"),
    );
    assert_eq!(accepted["status"], "active");
    assert_eq!(accepted["principal_id"], "member");
    assert_eq!(accepted["role"], "reader");
    assert_eq!(accepted["team_id"], team_id);
}
