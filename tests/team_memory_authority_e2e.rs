//! End-to-end contracts for S-103 authenticated team-memory authority.

#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]

use std::sync::{Arc, Barrier};

use openclaudia::runtime::ContentDigest;
use openclaudia::team_memory::{
    PrincipalId, TeamAuditDecisionCode, TeamAuthorityError, TeamAuthorityStatus,
    TeamAuthorityStore, TeamAuthorizationDenial, TeamAuthorizationOutcome,
    TeamEnrollmentInvitation, TeamId, TeamMemoryOperation, TeamOperationGrant, TeamRole,
};

const START: i64 = 1_800_000_000;
const MEMBERSHIP_TTL: i64 = 100_000;

struct EnrolledPair {
    owner_home: tempfile::TempDir,
    member_home: tempfile::TempDir,
    workspace: tempfile::TempDir,
    owner: TeamAuthorityStore,
    member: TeamAuthorityStore,
    member_id: PrincipalId,
}

fn digest(label: &str) -> ContentDigest {
    ContentDigest::sha256(label.as_bytes())
}

fn principal(value: &str) -> PrincipalId {
    value.parse().expect("valid principal")
}

fn corrupt_signature(value: &mut serde_json::Value, field: &str) {
    let signature = value[field].as_str().expect("signature string");
    let replacement = if signature.starts_with('A') { 'B' } else { 'A' };
    let mut corrupted = signature.to_string();
    corrupted.replace_range(..1, &replacement.to_string());
    value[field] = serde_json::Value::String(corrupted);
}

fn bootstrap_owner(
    home: &tempfile::TempDir,
    workspace: &tempfile::TempDir,
    ttl_seconds: i64,
) -> TeamAuthorityStore {
    TeamAuthorityStore::bootstrap_at(
        home.path(),
        workspace.path(),
        principal("owner"),
        ttl_seconds,
        START,
    )
    .expect("bootstrap owner")
}

fn enroll_member(role: TeamRole) -> EnrolledPair {
    let owner_home = tempfile::tempdir().expect("owner home");
    let member_home = tempfile::tempdir().expect("member home");
    let workspace = tempfile::tempdir().expect("workspace");
    let owner = bootstrap_owner(&owner_home, &workspace, MEMBERSHIP_TTL);
    let invitation = owner
        .create_enrollment_invitation_at(3_600, START + 1)
        .expect("invitation");
    let member_id = principal("member");
    let (member, request) = TeamAuthorityStore::begin_enrollment_at(
        member_home.path(),
        workspace.path(),
        member_id.clone(),
        invitation.clone(),
        START + 2,
    )
    .expect("begin enrollment");
    let approval = owner
        .approve_enrollment_at(&invitation, &request, role, MEMBERSHIP_TTL, START + 3)
        .expect("approve enrollment");
    member
        .accept_enrollment_at(&approval, START + 4)
        .expect("accept enrollment");
    EnrolledPair {
        owner_home,
        member_home,
        workspace,
        owner,
        member,
        member_id,
    }
}

fn expect_authorized(outcome: TeamAuthorizationOutcome) {
    match outcome {
        TeamAuthorizationOutcome::Authorized(permit) => drop(permit),
        TeamAuthorizationOutcome::Denied { reason, .. } => {
            panic!("unexpected denial: {reason:?}")
        }
    }
}

fn expect_denied(outcome: TeamAuthorizationOutcome, expected: TeamAuthorizationDenial) {
    match outcome {
        TeamAuthorizationOutcome::Denied { receipt, reason } => {
            assert_eq!(reason, expected);
            assert!(!receipt.allowed);
        }
        TeamAuthorizationOutcome::Authorized(permit) => {
            panic!("unexpected authorization: {permit:?}")
        }
    }
}

#[test]
fn path_or_repository_selector_never_creates_membership() {
    let home = tempfile::tempdir().expect("host home");
    let workspace = tempfile::tempdir().expect("workspace");
    let team_id: TeamId = "team-0123456789abcdef0123456789abcdef"
        .parse()
        .expect("team ID");
    let store = TeamAuthorityStore::open_for_workspace(home.path(), workspace.path(), team_id)
        .expect("open absent authority");
    assert_eq!(
        store.status_at(START).expect("status"),
        TeamAuthorityStatus::Unenrolled
    );
    assert!(matches!(
        store.issue_grant_at(TeamMemoryOperation::Search, digest("request"), 30, START),
        Err(TeamAuthorityError::Unenrolled)
    ));
}

#[test]
fn enrollment_artifacts_are_public_bounded_and_restart_safe() {
    let pair = enroll_member(TeamRole::Contributor);
    let status = pair.member.status_at(START + 5).expect("status");
    assert!(matches!(
        status,
        TeamAuthorityStatus::Active {
            role: TeamRole::Contributor,
            ..
        }
    ));
    let bundle_json = pair
        .owner
        .public_bundle_at(START + 5)
        .expect("bundle")
        .encode_pretty()
        .expect("public JSON");
    let bundle_text = String::from_utf8(bundle_json).expect("UTF-8");
    assert!(!bundle_text.contains("secret"));
    assert!(!bundle_text.contains("private"));
    assert!(
        !format!("{:?}", pair.owner).contains(pair.owner_home.path().to_string_lossy().as_ref())
    );

    let reopened = TeamAuthorityStore::open_for_workspace(
        pair.member_home.path(),
        pair.workspace.path(),
        pair.owner.team_id().clone(),
    )
    .expect("reopen member");
    assert_eq!(reopened.status_at(START + 5).unwrap(), status);
}

#[test]
fn every_role_is_enforced_at_the_durable_authorization_boundary() {
    let pair = enroll_member(TeamRole::Reader);
    let operations = [
        TeamMemoryOperation::List,
        TeamMemoryOperation::Search,
        TeamMemoryOperation::Propose,
        TeamMemoryOperation::Correct,
        TeamMemoryOperation::Delete,
        TeamMemoryOperation::Review,
        TeamMemoryOperation::Export,
        TeamMemoryOperation::Import,
        TeamMemoryOperation::Admin,
        TeamMemoryOperation::ReplicatePull,
        TeamMemoryOperation::ReplicatePush,
        TeamMemoryOperation::ManageOwnCredential,
    ];
    let roles = [
        TeamRole::Reader,
        TeamRole::Contributor,
        TeamRole::Maintainer,
        TeamRole::Owner,
    ];
    let mut now = START + 10;
    for role in roles {
        let bundle = pair
            .owner
            .set_member_role_at(&pair.member_id, role, now)
            .expect("set role");
        pair.member
            .apply_authority_bundle_at(&bundle, now + 1)
            .expect("apply role");
        now += 2;
        for operation in operations {
            let request_digest = digest(&format!("{role}-{operation}-{now}"));
            let grant = pair
                .member
                .issue_grant_at(operation, request_digest, 30, now)
                .expect("signed request");
            let outcome = pair
                .member
                .authorize_grant_at(&grant, operation, request_digest, now)
                .expect("durable decision");
            if role.permits(operation) {
                expect_authorized(outcome);
                let replay = pair
                    .member
                    .authorize_grant_at(&grant, operation, request_digest, now)
                    .expect("durable replay decision");
                expect_denied(replay, TeamAuthorizationDenial::GrantReplay);
            } else {
                expect_denied(outcome, TeamAuthorizationDenial::RoleDenied);
            }
            now += 1;
        }
    }
    let receipts = pair.member.audit_receipts_at(now).expect("audit");
    assert!(receipts.iter().any(|receipt| receipt.allowed));
    assert!(receipts.iter().any(|receipt| {
        receipt.decision_code == TeamAuditDecisionCode::RoleDenied && !receipt.allowed
    }));
    assert!(receipts.iter().any(|receipt| {
        receipt.decision_code == TeamAuditDecisionCode::GrantReplay && !receipt.allowed
    }));
    let encoded = serde_json::to_string(&receipts).expect("receipts JSON");
    assert!(!encoded.contains("member"));
    assert!(!encoded.contains("owner"));
    assert!(!encoded.contains("public_key"));
}

#[test]
fn wrong_scope_expiry_request_and_restart_replay_fail_before_a_permit() {
    let home = tempfile::tempdir().expect("host home");
    let workspace = tempfile::tempdir().expect("workspace");
    let store = bootstrap_owner(&home, &workspace, MEMBERSHIP_TTL);

    let request_digest = digest("exact request");
    let grant = store
        .issue_grant_at(TeamMemoryOperation::Search, request_digest, 30, START + 1)
        .expect("grant");
    let wrong_request = store
        .authorize_grant_at(
            &grant,
            TeamMemoryOperation::Search,
            digest("other request"),
            START + 2,
        )
        .expect("wrong request decision");
    expect_denied(wrong_request, TeamAuthorizationDenial::GrantMismatch);

    let mut wrong_team_json: serde_json::Value =
        serde_json::from_slice(&grant.encode_pretty().unwrap()).unwrap();
    wrong_team_json["team_id"] =
        serde_json::Value::String("team-fedcba9876543210fedcba9876543210".to_string());
    let wrong_team = TeamOperationGrant::decode(&serde_json::to_vec(&wrong_team_json).unwrap())
        .expect("typed tampered grant");
    let outcome = store
        .authorize_grant_at(
            &wrong_team,
            TeamMemoryOperation::Search,
            request_digest,
            START + 2,
        )
        .expect("scope decision");
    expect_denied(outcome, TeamAuthorizationDenial::ScopeMismatch);

    let mut wrong_workspace_json: serde_json::Value =
        serde_json::from_slice(&grant.encode_pretty().unwrap()).unwrap();
    wrong_workspace_json["workspace_id"] =
        serde_json::Value::String(format!("workspace-sha256:{}", "0".repeat(64)));
    let wrong_workspace =
        TeamOperationGrant::decode(&serde_json::to_vec(&wrong_workspace_json).unwrap())
            .expect("typed tampered grant");
    let outcome = store
        .authorize_grant_at(
            &wrong_workspace,
            TeamMemoryOperation::Search,
            request_digest,
            START + 2,
        )
        .expect("workspace decision");
    expect_denied(outcome, TeamAuthorizationDenial::ScopeMismatch);

    let expired = store
        .issue_grant_at(
            TeamMemoryOperation::Search,
            digest("expired"),
            10,
            START + 3,
        )
        .expect("expiring grant");
    let outcome = store
        .authorize_grant_at(
            &expired,
            TeamMemoryOperation::Search,
            digest("expired"),
            START + 13,
        )
        .expect("expiry decision");
    expect_denied(outcome, TeamAuthorizationDenial::Expired);

    let replay_request = digest("restart replay");
    let replay_grant = store
        .issue_grant_at(TeamMemoryOperation::Search, replay_request, 30, START + 14)
        .expect("replay grant");
    expect_authorized(
        store
            .authorize_grant_at(
                &replay_grant,
                TeamMemoryOperation::Search,
                replay_request,
                START + 14,
            )
            .expect("first use"),
    );
    let reopened = TeamAuthorityStore::open_for_workspace(
        home.path(),
        workspace.path(),
        store.team_id().clone(),
    )
    .expect("restart");
    expect_denied(
        reopened
            .authorize_grant_at(
                &replay_grant,
                TeamMemoryOperation::Search,
                replay_request,
                START + 15,
            )
            .expect("replay after restart"),
        TeamAuthorizationDenial::GrantReplay,
    );
}

#[test]
fn downgrade_revocation_and_authority_rotation_invalidate_old_grants() {
    let pair = enroll_member(TeamRole::Owner);
    let admin_request = digest("old admin");
    let old_admin = pair
        .member
        .issue_grant_at(TeamMemoryOperation::Admin, admin_request, 60, START + 10)
        .expect("old admin grant");

    let reader_bundle = pair
        .owner
        .set_member_role_at(&pair.member_id, TeamRole::Reader, START + 11)
        .expect("downgrade");
    pair.member
        .apply_authority_bundle_at(&reader_bundle, START + 12)
        .expect("apply downgrade");
    expect_denied(
        pair.member
            .authorize_grant_at(
                &old_admin,
                TeamMemoryOperation::Admin,
                admin_request,
                START + 12,
            )
            .expect("stale role decision"),
        TeamAuthorizationDenial::MembershipInvalid,
    );
    let new_admin = pair
        .member
        .issue_grant_at(
            TeamMemoryOperation::Admin,
            digest("new admin"),
            30,
            START + 13,
        )
        .expect("reader can sign request");
    expect_denied(
        pair.member
            .authorize_grant_at(
                &new_admin,
                TeamMemoryOperation::Admin,
                digest("new admin"),
                START + 13,
            )
            .expect("role denial"),
        TeamAuthorizationDenial::RoleDenied,
    );

    let search_request = digest("pre-revoke search");
    let pre_revoke = pair
        .member
        .issue_grant_at(TeamMemoryOperation::Search, search_request, 60, START + 14)
        .expect("pre-revoke grant");
    let revoked_bundle = pair
        .owner
        .revoke_member_at(&pair.member_id, START + 15)
        .expect("revoke");
    pair.member
        .apply_authority_bundle_at(&revoked_bundle, START + 16)
        .expect("apply revocation");
    assert!(matches!(
        pair.member.status_at(START + 16).unwrap(),
        TeamAuthorityStatus::Revoked { .. }
    ));
    assert!(matches!(
        pair.member.public_bundle_at(START + 16),
        Err(TeamAuthorityError::MembershipInvalid)
    ));
    assert!(matches!(
        pair.member.audit_receipts_at(START + 16),
        Err(TeamAuthorityError::MembershipInvalid)
    ));
    expect_denied(
        pair.member
            .authorize_grant_at(
                &pre_revoke,
                TeamMemoryOperation::Search,
                search_request,
                START + 16,
            )
            .expect("revoked decision"),
        TeamAuthorizationDenial::MembershipInvalid,
    );

    let owner_request = digest("pre-root-rotation");
    let owner_grant = pair
        .owner
        .issue_grant_at(TeamMemoryOperation::Search, owner_request, 60, START + 17)
        .expect("owner grant");
    pair.owner
        .rotate_authority_key_at(START + 18)
        .expect("root rotation");
    expect_denied(
        pair.owner
            .authorize_grant_at(
                &owner_grant,
                TeamMemoryOperation::Search,
                owner_request,
                START + 19,
            )
            .expect("old root generation decision"),
        TeamAuthorizationDenial::MembershipInvalid,
    );
}

#[test]
fn expired_owner_does_not_satisfy_the_last_active_owner_invariant() {
    let owner_home = tempfile::tempdir().expect("owner home");
    let expired_home = tempfile::tempdir().expect("expired owner home");
    let workspace = tempfile::tempdir().expect("workspace");
    let owner = bootstrap_owner(&owner_home, &workspace, MEMBERSHIP_TTL);
    let invitation = owner
        .create_enrollment_invitation_at(60, START + 1)
        .expect("invitation");
    let (expiring_owner, request) = TeamAuthorityStore::begin_enrollment_at(
        expired_home.path(),
        workspace.path(),
        principal("expiring-owner"),
        invitation.clone(),
        START + 2,
    )
    .expect("begin enrollment");
    let approval = owner
        .approve_enrollment_at(&invitation, &request, TeamRole::Owner, 5, START + 3)
        .expect("approve second owner");
    expiring_owner
        .accept_enrollment_at(&approval, START + 4)
        .expect("accept second owner");
    assert!(matches!(
        expiring_owner.status_at(START + 8).expect("status"),
        TeamAuthorityStatus::Expired { .. }
    ));

    let original = owner.public_bundle_at(START + 10).expect("current bundle");
    assert!(matches!(
        owner.set_member_role_at(&principal("owner"), TeamRole::Reader, START + 10),
        Err(TeamAuthorityError::OwnerRequired)
    ));
    assert!(matches!(
        owner.revoke_member_at(&principal("owner"), START + 10),
        Err(TeamAuthorityError::OwnerRequired)
    ));
    assert_eq!(
        owner
            .public_bundle_at(START + 10)
            .expect("unchanged bundle"),
        original
    );
}

#[test]
fn principal_rotation_switches_secrets_atomically_and_survives_restart() {
    let home = tempfile::tempdir().expect("host home");
    let workspace = tempfile::tempdir().expect("workspace");
    let store = TeamAuthorityStore::bootstrap_at(
        home.path(),
        workspace.path(),
        principal("owner"),
        MEMBERSHIP_TTL,
        START,
    )
    .expect("bootstrap");
    let old_request = digest("old principal key");
    let old_grant = store
        .issue_grant_at(TeamMemoryOperation::Search, old_request, 60, START + 1)
        .expect("old grant");
    let rotation = store
        .begin_principal_key_rotation_at(START + 2)
        .expect("begin rotation");
    store
        .approve_principal_key_rotation_at(&rotation, START + 3)
        .expect("approve self rotation");
    expect_denied(
        store
            .authorize_grant_at(
                &old_grant,
                TeamMemoryOperation::Search,
                old_request,
                START + 4,
            )
            .expect("old key decision"),
        TeamAuthorizationDenial::MembershipInvalid,
    );
    let reopened = TeamAuthorityStore::open_for_workspace(
        home.path(),
        workspace.path(),
        store.team_id().clone(),
    )
    .expect("restart");
    let new_request = digest("new principal key");
    let new_grant = reopened
        .issue_grant_at(TeamMemoryOperation::Search, new_request, 30, START + 5)
        .expect("new key grant");
    expect_authorized(
        reopened
            .authorize_grant_at(
                &new_grant,
                TeamMemoryOperation::Search,
                new_request,
                START + 5,
            )
            .expect("new key authorization"),
    );
}

#[test]
fn concurrent_consumers_cannot_both_receive_one_permit() {
    let home = tempfile::tempdir().expect("host home");
    let workspace = tempfile::tempdir().expect("workspace");
    let store = TeamAuthorityStore::bootstrap_at(
        home.path(),
        workspace.path(),
        principal("owner"),
        MEMBERSHIP_TTL,
        START,
    )
    .expect("bootstrap");
    let request_digest = digest("concurrent grant");
    let grant = store
        .issue_grant_at(TeamMemoryOperation::Search, request_digest, 60, START + 1)
        .expect("grant");
    let barrier = Arc::new(Barrier::new(3));
    let mut workers = Vec::new();
    for _ in 0..2 {
        let store = store.clone();
        let grant = grant.clone();
        let barrier = Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            store
                .authorize_grant_at(
                    &grant,
                    TeamMemoryOperation::Search,
                    request_digest,
                    START + 2,
                )
                .expect("decision")
        }));
    }
    barrier.wait();
    let outcomes = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker"))
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, TeamAuthorizationOutcome::Authorized(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(
                outcome,
                TeamAuthorizationOutcome::Denied {
                    reason: TeamAuthorizationDenial::GrantReplay,
                    ..
                }
            ))
            .count(),
        1
    );
}

#[test]
fn audited_permit_is_invalidated_by_a_concurrent_authority_generation_change() {
    let pair = enroll_member(TeamRole::Owner);
    let request_digest = digest("generation-bound permit");
    let grant = pair
        .member
        .issue_grant_at(TeamMemoryOperation::Admin, request_digest, 60, START + 10)
        .expect("admin grant");
    let permit = match pair
        .member
        .authorize_grant_at(
            &grant,
            TeamMemoryOperation::Admin,
            request_digest,
            START + 10,
        )
        .expect("authorization")
    {
        TeamAuthorizationOutcome::Authorized(permit) => permit,
        TeamAuthorizationOutcome::Denied { reason, .. } => {
            panic!("unexpected denial: {reason:?}")
        }
    };
    pair.member
        .validate_permit_at(
            &permit,
            TeamMemoryOperation::Admin,
            request_digest,
            START + 10,
        )
        .expect("current permit");

    let downgraded = pair
        .owner
        .set_member_role_at(&pair.member_id, TeamRole::Reader, START + 11)
        .expect("downgrade");
    pair.member
        .apply_authority_bundle_at(&downgraded, START + 12)
        .expect("observe downgrade");
    assert!(matches!(
        pair.member.validate_permit_at(
            &permit,
            TeamMemoryOperation::Admin,
            request_digest,
            START + 12,
        ),
        Err(TeamAuthorityError::MembershipInvalid)
    ));
}

#[test]
fn pending_enrollment_can_restart_with_a_fresh_private_credential() {
    let owner_home = tempfile::tempdir().expect("owner home");
    let member_home = tempfile::tempdir().expect("member home");
    let workspace = tempfile::tempdir().expect("workspace");
    let owner = bootstrap_owner(&owner_home, &workspace, MEMBERSHIP_TTL);
    let first_invitation = owner
        .create_enrollment_invitation_at(3_600, START + 1)
        .expect("first invitation");
    let (_, abandoned_request) = TeamAuthorityStore::begin_enrollment_at(
        member_home.path(),
        workspace.path(),
        principal("member"),
        first_invitation,
        START + 2,
    )
    .expect("first pending enrollment");
    let replacement_invitation = owner
        .create_enrollment_invitation_at(3_600, START + 3)
        .expect("replacement invitation");
    let (member, replacement_request) = TeamAuthorityStore::begin_enrollment_at(
        member_home.path(),
        workspace.path(),
        principal("member"),
        replacement_invitation.clone(),
        START + 4,
    )
    .expect("replace pending enrollment");
    assert_ne!(abandoned_request, replacement_request);
    let approval = owner
        .approve_enrollment_at(
            &replacement_invitation,
            &replacement_request,
            TeamRole::Contributor,
            MEMBERSHIP_TTL,
            START + 5,
        )
        .expect("approve replacement");
    member
        .accept_enrollment_at(&approval, START + 6)
        .expect("accept replacement");
    assert!(matches!(
        member.status_at(START + 6).expect("status"),
        TeamAuthorityStatus::Active {
            role: TeamRole::Contributor,
            ..
        }
    ));
}

#[test]
fn revoked_identity_reenrolls_but_old_membership_never_revives() {
    let pair = enroll_member(TeamRole::Contributor);
    let old_grant = pair
        .member
        .issue_grant_at(
            TeamMemoryOperation::Search,
            digest("pre-revocation"),
            60,
            START + 7,
        )
        .expect("old grant");
    let revoked = pair
        .owner
        .revoke_member_at(&pair.member_id, START + 8)
        .expect("revoke member");
    pair.member
        .apply_authority_bundle_at(&revoked, START + 9)
        .expect("observe revocation");
    assert!(matches!(
        pair.member
            .recover_expired_local_owner_at(MEMBERSHIP_TTL, START + 10),
        Err(TeamAuthorityError::MembershipInvalid)
    ));

    let reenrollment_invitation = pair
        .owner
        .create_enrollment_invitation_at(3_600, START + 10)
        .expect("re-enrollment invitation");
    let (reenrolled, reenrollment_request) = TeamAuthorityStore::begin_enrollment_at(
        pair.member_home.path(),
        pair.workspace.path(),
        pair.member_id.clone(),
        reenrollment_invitation.clone(),
        START + 11,
    )
    .expect("revoked identity starts fresh enrollment");
    let reenrollment_approval = pair
        .owner
        .approve_enrollment_at(
            &reenrollment_invitation,
            &reenrollment_request,
            TeamRole::Maintainer,
            MEMBERSHIP_TTL,
            START + 12,
        )
        .expect("owner approves new membership");
    reenrolled
        .accept_enrollment_at(&reenrollment_approval, START + 13)
        .expect("accept new membership");
    assert!(matches!(
        reenrolled.status_at(START + 13).expect("status"),
        TeamAuthorityStatus::Active {
            role: TeamRole::Maintainer,
            ..
        }
    ));
    expect_denied(
        reenrolled
            .authorize_grant_at(
                &old_grant,
                TeamMemoryOperation::Search,
                digest("pre-revocation"),
                START + 14,
            )
            .expect("old membership decision"),
        TeamAuthorizationDenial::MembershipInvalid,
    );
}

#[test]
fn expired_root_owner_recovery_is_narrow_audited_and_restart_safe() {
    let home = tempfile::tempdir().expect("host home");
    let workspace = tempfile::tempdir().expect("workspace");
    let store = TeamAuthorityStore::bootstrap_at(
        home.path(),
        workspace.path(),
        principal("owner"),
        10,
        START,
    )
    .expect("bootstrap");
    assert!(matches!(
        store.status_at(START + 10).expect("expired status"),
        TeamAuthorityStatus::Expired { .. }
    ));
    let recovery = store
        .recover_expired_local_owner_at(1_000, START + 10)
        .expect("authority-key recovery");
    assert!(recovery.receipt.allowed);
    assert_eq!(
        recovery.receipt.decision_code,
        TeamAuditDecisionCode::RecoveryAllowed
    );
    let reopened = TeamAuthorityStore::open_for_workspace(
        home.path(),
        workspace.path(),
        store.team_id().clone(),
    )
    .expect("restart");
    assert!(matches!(
        reopened.status_at(START + 11).expect("active status"),
        TeamAuthorityStatus::Active { .. }
    ));
    assert!(reopened
        .audit_receipts_at(START + 11)
        .expect("audit")
        .iter()
        .any(|receipt| receipt.decision_code == TeamAuditDecisionCode::RecoveryAllowed));
    assert!(matches!(
        reopened.recover_expired_local_owner_at(1_000, START + 11),
        Err(TeamAuthorityError::MembershipInvalid)
    ));
    assert!(matches!(
        reopened.recover_expired_local_owner_at(1_000, START + 9),
        Err(TeamAuthorityError::ClockRollback)
    ));
    assert!(matches!(
        reopened.status_at(START + 9),
        Err(TeamAuthorityError::ClockRollback)
    ));
}

#[test]
fn tampered_credential_state_fails_as_recovery_not_unenrolled() {
    let home = tempfile::tempdir().expect("host home");
    let workspace = tempfile::tempdir().expect("workspace");
    let store = TeamAuthorityStore::bootstrap_at(
        home.path(),
        workspace.path(),
        principal("owner"),
        MEMBERSHIP_TTL,
        START,
    )
    .expect("bootstrap");
    let state_path = home
        .path()
        .join(".openclaudia/memory/workspaces")
        .join(store.workspace_id().path_component())
        .join(format!("team-authority-{}.json", store.team_id()));
    std::fs::write(&state_path, b"{}\n").expect("tamper state");
    assert!(matches!(
        store.status_at(START + 1),
        Err(TeamAuthorityError::RecoveryRequired { .. })
    ));
}

#[test]
fn malformed_and_oversized_public_artifacts_are_rejected_before_use() {
    assert!(matches!(
        TeamEnrollmentInvitation::decode(b"{}"),
        Err(TeamAuthorityError::InvalidArtifact)
    ));
    let oversized = vec![b'x'; openclaudia::team_memory::MAX_TEAM_AUTHORITY_ARTIFACT_BYTES + 1];
    assert!(matches!(
        TeamEnrollmentInvitation::decode(&oversized),
        Err(TeamAuthorityError::CapacityExceeded {
            resource: "public artifact"
        })
    ));
}

#[test]
fn forged_signed_artifacts_fail_before_authority_or_metadata_changes() {
    let owner_home = tempfile::tempdir().expect("owner home");
    let member_home = tempfile::tempdir().expect("member home");
    let workspace = tempfile::tempdir().expect("workspace");
    let owner = bootstrap_owner(&owner_home, &workspace, MEMBERSHIP_TTL);

    let request_digest = digest("forged grant");
    let grant = owner
        .issue_grant_at(TeamMemoryOperation::Search, request_digest, 30, START + 1)
        .expect("grant");
    let mut grant_json: serde_json::Value =
        serde_json::from_slice(&grant.encode_pretty().expect("grant JSON")).expect("JSON");
    corrupt_signature(&mut grant_json, "signature");
    let forged_grant =
        TeamOperationGrant::decode(&serde_json::to_vec(&grant_json).expect("forged grant JSON"))
            .expect("typed forged grant");
    expect_denied(
        owner
            .authorize_grant_at(
                &forged_grant,
                TeamMemoryOperation::Search,
                request_digest,
                START + 2,
            )
            .expect("durable invalid-signature decision"),
        TeamAuthorizationDenial::InvalidSignature,
    );

    let invitation = owner
        .create_enrollment_invitation_at(300, START + 3)
        .expect("invitation");
    let mut invitation_json: serde_json::Value =
        serde_json::from_slice(&invitation.encode_pretty().expect("invitation JSON"))
            .expect("JSON");
    corrupt_signature(&mut invitation_json, "signature");
    let forged_invitation = TeamEnrollmentInvitation::decode(
        &serde_json::to_vec(&invitation_json).expect("forged invitation JSON"),
    )
    .expect("typed forged invitation");
    assert!(matches!(
        TeamAuthorityStore::begin_enrollment_at(
            member_home.path(),
            workspace.path(),
            principal("member"),
            forged_invitation,
            START + 4,
        ),
        Err(TeamAuthorityError::InvalidSignature)
    ));

    let (_, request) = TeamAuthorityStore::begin_enrollment_at(
        member_home.path(),
        workspace.path(),
        principal("member"),
        invitation.clone(),
        START + 4,
    )
    .expect("valid request");
    let mut request_json: serde_json::Value =
        serde_json::from_slice(&request.encode_pretty().expect("request JSON")).expect("JSON");
    corrupt_signature(&mut request_json, "proof_signature");
    let forged_request = openclaudia::team_memory::TeamEnrollmentRequest::decode(
        &serde_json::to_vec(&request_json).expect("forged request JSON"),
    )
    .expect("typed forged request");
    assert!(matches!(
        owner.approve_enrollment_at(
            &invitation,
            &forged_request,
            TeamRole::Reader,
            MEMBERSHIP_TTL,
            START + 5,
        ),
        Err(TeamAuthorityError::InvalidSignature)
    ));

    let bundle = owner.public_bundle_at(START + 5).expect("public bundle");
    let mut bundle_json: serde_json::Value =
        serde_json::from_slice(&bundle.encode_pretty().expect("bundle JSON")).expect("JSON");
    corrupt_signature(&mut bundle_json, "document_signature");
    let forged_bundle = openclaudia::team_memory::TeamAuthorityBundle::decode(
        &serde_json::to_vec(&bundle_json).expect("forged bundle JSON"),
    )
    .expect("typed forged bundle");
    assert!(matches!(
        owner.apply_authority_bundle_at(&forged_bundle, START + 5),
        Err(TeamAuthorityError::InvalidSignature)
    ));
}
