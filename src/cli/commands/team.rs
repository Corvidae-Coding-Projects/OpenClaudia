//! Host-only lifecycle commands for authenticated team memory.
//!
//! Authority commands exchange signed public JSON artifacts manually and never
//! print or accept private keys. Replica commands configure a pinned service,
//! synchronize the encrypted local replica, or own the bounded TLS service.

use std::io::Read as _;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;
#[cfg(unix)]
use openclaudia::team_memory::MAX_TEAM_REPLICATION_PRIVATE_KEY_BYTES;
use openclaudia::team_memory::{
    PrincipalId, TeamAuthorityBundle, TeamAuthorityStore, TeamCredentialRotationRequest,
    TeamEnrollmentApproval, TeamEnrollmentInvitation, TeamEnrollmentRequest, TeamId, TeamRole,
    TeamServiceDescriptor, MAX_TEAM_AUTHORITY_ARTIFACT_BYTES,
    MAX_TEAM_REPLICATION_CERTIFICATE_BYTES,
};
use serde::Serialize;
use zeroize::Zeroizing;

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

pub fn cmd_team_replica_status(team_id: Option<&str>) -> anyhow::Result<()> {
    let store = open_store(team_id)?;
    let replica = openclaudia::team_memory::TeamReplica::open_client(store)?;
    print_json(&replica.status()?)
}

pub fn cmd_team_service_descriptor(
    team_id: Option<&str>,
    endpoint: &str,
    certificate_path: &Path,
) -> anyhow::Result<()> {
    let certificate = read_public_artifact_with_limit(
        certificate_path,
        MAX_TEAM_REPLICATION_CERTIFICATE_BYTES,
        "TLS certificate",
    )?;
    let replica = openclaudia::team_memory::TeamReplica::open_service(open_store(team_id)?)?;
    print_json(&replica.service_descriptor(endpoint, &certificate)?)
}

pub fn cmd_team_configure_service(
    team_id: Option<&str>,
    descriptor_path: &Path,
    allow_transport_rotation: bool,
) -> anyhow::Result<()> {
    let descriptor = TeamServiceDescriptor::decode(&read_public_artifact(descriptor_path)?)?;
    let store = open_store_for_artifact(team_id, descriptor.team_id())?;
    let replica = openclaudia::team_memory::TeamReplica::open_client(store)?;
    print_json(&replica.configure_service(&descriptor, allow_transport_rotation)?)
}

pub fn cmd_team_sync(team_id: Option<&str>) -> anyhow::Result<()> {
    let replica = Arc::new(openclaudia::team_memory::TeamReplica::open_client(
        open_store(team_id)?,
    )?);
    let supervisor =
        openclaudia::team_memory::TeamReplicationSupervisor::start_for_explicit_sync(replica)?;
    let report = supervisor.synchronize_now();
    let shutdown = supervisor.shutdown();
    let report = report?;
    shutdown?;
    print_json(&report)
}

pub async fn cmd_team_serve(
    team_id: Option<&str>,
    listen: SocketAddr,
    endpoint: &str,
    certificate_path: &Path,
    private_key_path: &Path,
) -> anyhow::Result<()> {
    let certificate = read_public_artifact_with_limit(
        certificate_path,
        MAX_TEAM_REPLICATION_CERTIFICATE_BYTES,
        "TLS certificate",
    )?;
    let private_key = read_private_key(private_key_path)?;
    let server = openclaudia::team_memory::TeamMemoryTlsServer::bind(
        listen,
        certificate.clone(),
        private_key,
    )
    .await?;
    let replica = Arc::new(openclaudia::team_memory::TeamReplica::open_service(
        open_store(team_id)?,
    )?);
    let descriptor = replica.service_descriptor(endpoint, &certificate)?;
    print_json(&descriptor)?;
    std::io::stdout().flush()?;
    server
        .serve(replica, async {
            if tokio::signal::ctrl_c().await.is_err() {
                tracing::warn!("team-memory service could not install its shutdown signal");
            }
        })
        .await
        .map_err(Into::into)
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
    read_public_artifact_with_limit(
        path,
        MAX_TEAM_AUTHORITY_ARTIFACT_BYTES,
        "public authority artifact",
    )
}

fn read_public_artifact_with_limit(
    path: &Path,
    maximum_bytes: usize,
    artifact_kind: &str,
) -> anyhow::Result<Vec<u8>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .with_context(|| format!("opening {artifact_kind} {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting {artifact_kind} {}", path.display()))?;
    anyhow::ensure!(metadata.is_file(), "{artifact_kind} must be a regular file");
    anyhow::ensure!(
        metadata.len() <= maximum_bytes as u64,
        "{artifact_kind} exceeds its byte limit"
    );
    let initial_capacity = usize::try_from(metadata.len())
        .unwrap_or(maximum_bytes)
        .min(maximum_bytes);
    let mut bytes = Vec::with_capacity(initial_capacity);
    file.take(maximum_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("reading {artifact_kind} {}", path.display()))?;
    anyhow::ensure!(
        bytes.len() <= maximum_bytes,
        "{artifact_kind} changed beyond its byte limit while being read"
    );
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_private_key(_path: &Path) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    anyhow::bail!(
        "private TLS key loading is unavailable because this platform cannot enforce the required owner-only descriptor policy"
    )
}

#[cfg(unix)]
fn read_private_key(path: &Path) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options
        .open(path)
        .with_context(|| format!("opening private TLS key {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspecting private TLS key {}", path.display()))?;
    anyhow::ensure!(metadata.is_file(), "private TLS key must be a regular file");
    anyhow::ensure!(
        metadata.len() <= MAX_TEAM_REPLICATION_PRIVATE_KEY_BYTES as u64,
        "private TLS key exceeds its byte limit"
    );
    // SAFETY: `geteuid` takes no pointers and has no preconditions.
    let effective_uid = unsafe { libc::geteuid() };
    anyhow::ensure!(
        metadata.uid() == effective_uid
            && metadata.nlink() == 1
            && metadata.mode() & 0o7777 == 0o600,
        "private TLS key must be owner-only, single-linked, and owned by this host user"
    );
    let initial_capacity = usize::try_from(metadata.len())
        .unwrap_or(MAX_TEAM_REPLICATION_PRIVATE_KEY_BYTES)
        .min(MAX_TEAM_REPLICATION_PRIVATE_KEY_BYTES);
    let mut bytes = Zeroizing::new(Vec::with_capacity(initial_capacity));
    file.take(MAX_TEAM_REPLICATION_PRIVATE_KEY_BYTES as u64 + 1)
        .read_to_end(bytes.as_mut())
        .with_context(|| format!("reading private TLS key {}", path.display()))?;
    anyhow::ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_TEAM_REPLICATION_PRIVATE_KEY_BYTES,
        "private TLS key is empty or changed beyond its byte limit while being read"
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

    #[cfg(unix)]
    #[test]
    fn private_key_reader_requires_exact_owner_only_regular_file() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let directory = tempfile::tempdir().expect("temp directory");
        let key_path = directory.path().join("service-key.der");
        std::fs::write(&key_path, b"private-key-fixture").expect("write key fixture");
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o644))
            .expect("set broad mode");
        assert!(read_private_key(&key_path).is_err());

        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("set private mode");
        assert_eq!(
            read_private_key(&key_path).expect("private key").as_slice(),
            b"private-key-fixture"
        );
        let link_path = directory.path().join("service-key-link.der");
        symlink(&key_path, &link_path).expect("key symlink");
        assert!(read_private_key(&link_path).is_err());
    }
}
