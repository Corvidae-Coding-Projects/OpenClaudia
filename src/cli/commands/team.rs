//! Host-only lifecycle commands for authenticated team-memory authority.
//!
//! These commands exchange signed public JSON artifacts manually. They never
//! print or accept private keys. Lesson transport remains the responsibility
//! of the S-104 replication service.

use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use openclaudia::team_memory::{
    PrincipalId, TeamAuthorityBundle, TeamAuthorityStore, TeamCredentialRotationRequest,
    TeamEnrollmentApproval, TeamEnrollmentInvitation, TeamEnrollmentRequest, TeamId, TeamRole,
    MAX_TEAM_AUTHORITY_ARTIFACT_BYTES,
};
use serde::Serialize;

pub fn cmd_team_create(principal_id: &str, membership_ttl_seconds: i64) -> anyhow::Result<()> {
    let (home, workspace) = authority_roots()?;
    let principal_id: PrincipalId = principal_id.parse().map_err(anyhow::Error::new)?;
    let store =
        TeamAuthorityStore::bootstrap(&home, &workspace, principal_id, membership_ttl_seconds)?;
    print_json(&store.status()?)
}

pub fn cmd_team_status(team_id: Option<&str>) -> anyhow::Result<()> {
    let (home, workspace) = authority_roots()?;
    let team_id = resolve_team_id(team_id)?;
    let store = TeamAuthorityStore::open_for_workspace(&home, &workspace, team_id)?;
    print_json(&store.status()?)
}

pub fn cmd_team_invite(team_id: Option<&str>, ttl_seconds: i64) -> anyhow::Result<()> {
    let store = open_store(team_id)?;
    print_json(&store.create_enrollment_invitation(ttl_seconds)?)
}

pub fn cmd_team_begin_enrollment(invitation_path: &Path, principal_id: &str) -> anyhow::Result<()> {
    let invitation = TeamEnrollmentInvitation::decode(&read_public_artifact(invitation_path)?)?;
    let principal_id: PrincipalId = principal_id.parse().map_err(anyhow::Error::new)?;
    let (home, workspace) = authority_roots()?;
    let (_, request) =
        TeamAuthorityStore::begin_enrollment(&home, &workspace, principal_id, invitation)?;
    print_json(&request)
}

pub fn cmd_team_approve_enrollment(
    team_id: Option<&str>,
    invitation_path: &Path,
    request_path: &Path,
    role: &str,
    membership_ttl_seconds: i64,
) -> anyhow::Result<()> {
    let invitation = TeamEnrollmentInvitation::decode(&read_public_artifact(invitation_path)?)?;
    let request = TeamEnrollmentRequest::decode(&read_public_artifact(request_path)?)?;
    let role: TeamRole = role.parse().map_err(anyhow::Error::new)?;
    let store = open_store_for_artifact(team_id, invitation.team_id())?;
    print_json(&store.approve_enrollment(&invitation, &request, role, membership_ttl_seconds)?)
}

pub fn cmd_team_accept_enrollment(
    team_id: Option<&str>,
    approval_path: &Path,
) -> anyhow::Result<()> {
    let approval = TeamEnrollmentApproval::decode(&read_public_artifact(approval_path)?)?;
    let store = open_store_for_artifact(team_id, approval.team_id())?;
    store.accept_enrollment(&approval)?;
    print_json(&store.status()?)
}

pub fn cmd_team_set_role(
    team_id: Option<&str>,
    principal_id: &str,
    role: &str,
) -> anyhow::Result<()> {
    let principal_id: PrincipalId = principal_id.parse().map_err(anyhow::Error::new)?;
    let role: TeamRole = role.parse().map_err(anyhow::Error::new)?;
    let store = open_store(team_id)?;
    print_json(&store.set_member_role(&principal_id, role)?)
}

pub fn cmd_team_revoke(team_id: Option<&str>, principal_id: &str) -> anyhow::Result<()> {
    let principal_id: PrincipalId = principal_id.parse().map_err(anyhow::Error::new)?;
    let store = open_store(team_id)?;
    print_json(&store.revoke_member(&principal_id)?)
}

pub fn cmd_team_renew(
    team_id: Option<&str>,
    principal_id: &str,
    membership_ttl_seconds: i64,
) -> anyhow::Result<()> {
    let principal_id: PrincipalId = principal_id.parse().map_err(anyhow::Error::new)?;
    let store = open_store(team_id)?;
    print_json(&store.renew_member(&principal_id, membership_ttl_seconds)?)
}

pub fn cmd_team_recover_expired_owner(
    team_id: Option<&str>,
    membership_ttl_seconds: i64,
) -> anyhow::Result<()> {
    let store = open_store(team_id)?;
    print_json(&store.recover_expired_local_owner(membership_ttl_seconds)?)
}

pub fn cmd_team_rotate_authority(team_id: Option<&str>) -> anyhow::Result<()> {
    let store = open_store(team_id)?;
    print_json(&store.rotate_authority_key()?)
}

pub fn cmd_team_begin_credential_rotation(team_id: Option<&str>) -> anyhow::Result<()> {
    let store = open_store(team_id)?;
    print_json(&store.begin_principal_key_rotation()?)
}

pub fn cmd_team_approve_credential_rotation(
    team_id: Option<&str>,
    request_path: &Path,
) -> anyhow::Result<()> {
    let request = TeamCredentialRotationRequest::decode(&read_public_artifact(request_path)?)?;
    let store = open_store_for_artifact(team_id, request.team_id())?;
    print_json(&store.approve_principal_key_rotation(&request)?)
}

pub fn cmd_team_apply_authority(team_id: Option<&str>, bundle_path: &Path) -> anyhow::Result<()> {
    let bundle = TeamAuthorityBundle::decode(&read_public_artifact(bundle_path)?)?;
    let store = open_store_for_artifact(team_id, bundle.team_id())?;
    store.apply_authority_bundle(&bundle)?;
    print_json(&store.status()?)
}

pub fn cmd_team_audit(team_id: Option<&str>) -> anyhow::Result<()> {
    let store = open_store(team_id)?;
    print_json(&store.audit_receipts()?)
}

fn open_store(team_id: Option<&str>) -> anyhow::Result<TeamAuthorityStore> {
    let (home, workspace) = authority_roots()?;
    TeamAuthorityStore::open_for_workspace(&home, &workspace, resolve_team_id(team_id)?)
        .map_err(Into::into)
}

fn open_store_for_artifact(
    selected_team_id: Option<&str>,
    artifact_team_id: &TeamId,
) -> anyhow::Result<TeamAuthorityStore> {
    let team_id = selected_team_id.map_or_else(
        || Ok(artifact_team_id.clone()),
        |selected| {
            let selected: TeamId = selected.parse().map_err(anyhow::Error::new)?;
            anyhow::ensure!(
                &selected == artifact_team_id,
                "selected team does not match the signed authority artifact"
            );
            Ok(selected)
        },
    )?;
    let (home, workspace) = authority_roots()?;
    TeamAuthorityStore::open_for_workspace(&home, &workspace, team_id).map_err(Into::into)
}

fn resolve_team_id(team_id: Option<&str>) -> anyhow::Result<TeamId> {
    if let Some(team_id) = team_id {
        return team_id.parse().map_err(anyhow::Error::new);
    }
    openclaudia::config::load_config()
        .context("loading team selection from configuration")?
        .memory
        .team_id
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no team selected; pass --team-id or set memory.team_id to a host-enrolled team"
            )
        })
}

fn authority_roots() -> anyhow::Result<(PathBuf, PathBuf)> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("host home is unavailable"))?;
    let workspace = std::env::current_dir().context("reading current workspace")?;
    Ok((home, workspace))
}

fn print_json(value: &impl Serialize) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn read_public_artifact(path: &Path) -> anyhow::Result<Vec<u8>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .with_context(|| format!("opening public authority artifact {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting public authority artifact {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_file(),
        "public authority artifact must be a regular file"
    );
    anyhow::ensure!(
        metadata.len() <= MAX_TEAM_AUTHORITY_ARTIFACT_BYTES as u64,
        "public authority artifact exceeds its byte limit"
    );
    let initial_capacity = usize::try_from(metadata.len())
        .unwrap_or(MAX_TEAM_AUTHORITY_ARTIFACT_BYTES)
        .min(MAX_TEAM_AUTHORITY_ARTIFACT_BYTES);
    let mut bytes = Vec::with_capacity(initial_capacity);
    file.take(MAX_TEAM_AUTHORITY_ARTIFACT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading public authority artifact {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() <= MAX_TEAM_AUTHORITY_ARTIFACT_BYTES,
        "public authority artifact changed beyond its byte limit while being read"
    );
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_artifact_reader_rejects_directory() {
        let directory = tempfile::tempdir().expect("temp directory");
        let error = read_public_artifact(directory.path()).expect_err("directory must fail");
        assert!(error.to_string().contains("regular file"));
    }

    #[test]
    fn status_type_is_public_json_only() {
        let status = openclaudia::team_memory::TeamAuthorityStatus::Unenrolled;
        assert_eq!(
            serde_json::to_string(&status).unwrap(),
            r#"{"status":"unenrolled"}"#
        );
    }
}
