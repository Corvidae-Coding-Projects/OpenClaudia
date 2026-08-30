//! Generation-bound local Git review and commit transactions.
//!
//! Review is prepared in a run-owned index and object quarantine under the
//! immutable run capability. The user's index and repository object database
//! remain untouched until an explicit approval binds the exact candidate
//! tree, diff, path set, destination, message, Git policy, and workspace
//! generations. Commit publication then re-stages the same paths in another
//! run-owned index, compares the resulting tree and diff, creates and verifies
//! the commit object, and advances only the approved ref from the reviewed
//! HEAD. Push and pull-request publication deliberately live outside this
//! module and require their own receipt.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::runtime::{CapabilityGeneration, ContentDigest, RunId, WorkspaceGeneration};
use crate::tools::command::{CommandError, ProcessLimits};
use crate::tools::{SandboxProfile, ToolResource, ToolRunContext};

const GIT_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_GIT_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_REVIEW_PATHS: usize = 4_096;
const MAX_REVIEW_PATH_BYTES: usize = 2 * 1024 * 1024;
const MAX_COMMIT_MESSAGE_BYTES: usize = 4_096;
const MAX_REPOSITORY_CONFIG_BYTES: usize = 1024 * 1024;
const EMPTY_TRUNCATION_MARKER: &[u8] = b"";
const PROFILE_GENERATION: &[u8] = b"openclaudia-git-review-v1";

static ACTIVE_REPOSITORY_REVIEWS: LazyLock<Mutex<BTreeSet<PathBuf>>> =
    LazyLock::new(|| Mutex::new(BTreeSet::new()));

/// Exact mutable generations and immutable capability identity shown to the
/// approving frontend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitReviewGeneration {
    pub run_id: RunId,
    pub capability_generation: CapabilityGeneration,
    pub workspace_generation: WorkspaceGeneration,
    pub workspace_binding: ContentDigest,
    pub head: String,
    pub destination: String,
    pub index: ContentDigest,
    pub path_set: ContentDigest,
    pub policy: ContentDigest,
    pub candidate_tree: String,
    pub candidate_index: ContentDigest,
    pub candidate_diff: ContentDigest,
}

impl GitReviewGeneration {
    fn digest(&self) -> ContentDigest {
        digest_frames(&[
            self.run_id.to_string().as_bytes(),
            self.capability_generation.to_string().as_bytes(),
            self.workspace_generation.to_string().as_bytes(),
            self.workspace_binding.as_bytes(),
            self.head.as_bytes(),
            self.destination.as_bytes(),
            self.index.as_bytes(),
            self.path_set.as_bytes(),
            self.policy.as_bytes(),
            self.candidate_tree.as_bytes(),
            self.candidate_index.as_bytes(),
            self.candidate_diff.as_bytes(),
        ])
    }
}

/// Host-held approval for exactly one prepared local commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitCommitApproval {
    generation: GitReviewGeneration,
    paths: Vec<PathBuf>,
    message: String,
    approval_digest: ContentDigest,
}

impl GitCommitApproval {
    #[must_use]
    pub const fn digest(&self) -> ContentDigest {
        self.approval_digest
    }
}

/// Verified receipt for a local commit only. It grants no push or pull-request
/// authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalCommitReceipt {
    pub commit_id: String,
    pub destination: String,
    pub repository_root: PathBuf,
    pub parent: String,
    pub tree: String,
    pub approved_paths: Vec<PathBuf>,
    pub approval_digest: ContentDigest,
    pub generation: GitReviewGeneration,
}

/// State retained when Git crossed an irreversible local boundary but the
/// complete postcondition could not be proven.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoverableCommitState {
    pub commit_id: String,
    pub destination: String,
    pub parent: String,
    pub tree: String,
    pub observed_destination: Option<String>,
    pub index_reconciled: bool,
}

/// Receipt returned when the user declines a prepared review.
///
/// Dropping a review has the same cleanup behavior, but this value lets
/// frontends render cancellation as a terminal state rather than an apparent
/// no-op success.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitReviewCancellation {
    pub review_digest: ContentDigest,
}

/// Bounded comparison of the exact observed HEAD against one resolved commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitBranchReview {
    pub head: String,
    pub base: String,
    pub branch: String,
    pub rendered: String,
}

/// Visible, typed failures for the review/commit lifecycle.
#[derive(Debug, Error)]
pub enum GitTransactionError {
    #[error("Git review requires an active workspace/process capability: {0}")]
    Capability(String),
    #[error("another Git review already owns repository {0:?}")]
    RepositoryBusy(PathBuf),
    #[error("not inside the run's canonical Git repository")]
    NotRepository,
    #[error("Git review requires an attached branch destination")]
    DetachedHead,
    #[error("there are no non-ignored changes to review at HEAD {head}")]
    NothingToCommit { head: String },
    #[error("Git review contains {count} paths; the bounded limit is {limit}")]
    TooManyPaths { count: usize, limit: usize },
    #[error("Git review path data exceeds the {limit}-byte bound")]
    PathSetTooLarge { limit: usize },
    #[error("Git {operation} output exceeded the {limit}-byte bound")]
    OutputLimit {
        operation: &'static str,
        limit: usize,
    },
    #[error("Git {operation} failed: {detail}")]
    GitFailed {
        operation: &'static str,
        detail: String,
    },
    #[error("Git review was cancelled: {reason}")]
    Cancelled { reason: String },
    #[error("repository-selected clean filter is active for {path:?}; explicit trusted filter support is required")]
    ActiveFilter { path: PathBuf },
    #[error("Git identity is unavailable: {0}")]
    IdentityUnavailable(String),
    #[error("the approved paths, destination, message, or review generation do not match the prepared review")]
    ApprovalMismatch,
    #[error("commit message must contain 1..={MAX_COMMIT_MESSAGE_BYTES} bytes and no NUL")]
    InvalidCommitMessage,
    #[error("the repository changed after approval; review the new generation")]
    ConcurrentMutation {
        expected: Box<GitReviewGeneration>,
        observed: Box<GitReviewGeneration>,
    },
    #[error(
        "Git created commit {state_commit} but did not publish the approved destination: {detail}"
    )]
    CommitNotPublished {
        state_commit: String,
        detail: String,
        state: Box<RecoverableCommitState>,
    },
    #[error("Git published a local commit but its complete postcondition is uncertain: {detail}")]
    CommitPublishedUncertain {
        detail: String,
        state: Box<RecoverableCommitState>,
    },
}

struct RepositoryReviewLease {
    root: PathBuf,
}

impl RepositoryReviewLease {
    fn acquire(root: &Path) -> Result<Self, GitTransactionError> {
        let mut active = ACTIVE_REPOSITORY_REVIEWS
            .lock()
            .map_err(|error| GitTransactionError::Capability(error.to_string()))?;
        if !active.insert(root.to_path_buf()) {
            return Err(GitTransactionError::RepositoryBusy(root.to_path_buf()));
        }
        drop(active);
        Ok(Self {
            root: root.to_path_buf(),
        })
    }
}

impl Drop for RepositoryReviewLease {
    fn drop(&mut self) {
        ACTIVE_REPOSITORY_REVIEWS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.root);
    }
}

struct CandidateIndex {
    _directory: tempfile::TempDir,
    index_path: PathBuf,
    tree: String,
    entries_digest: ContentDigest,
    diff: Vec<u8>,
    diff_digest: ContentDigest,
}

/// Prepared bounded review. Its private temporary index, workspace-operation
/// guard, and repository lease are released automatically on cancellation or
/// any error.
pub struct GitCommitReview {
    _workspace_operation: crate::tools::security::WorkspaceOperationGuard,
    _repository_lease: RepositoryReviewLease,
    repository_root: PathBuf,
    object_directory: PathBuf,
    paths: Vec<PathBuf>,
    candidate: CandidateIndex,
    generation: GitReviewGeneration,
}

impl GitCommitReview {
    #[must_use]
    pub const fn generation(&self) -> &GitReviewGeneration {
        &self.generation
    }

    #[must_use]
    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }

    /// Terminal-safe renderings of the exact NUL-safe path identities.
    #[must_use]
    pub fn rendered_paths(&self) -> Vec<String> {
        self.paths
            .iter()
            .map(|path| render_terminal_label_bytes(os_str_bytes(path.as_os_str()).as_ref()))
            .collect()
    }

    #[must_use]
    pub fn destination(&self) -> &str {
        &self.generation.destination
    }

    #[must_use]
    pub fn candidate_tree(&self) -> &str {
        &self.candidate.tree
    }

    /// Render untrusted diff bytes without passing terminal escape sequences
    /// or other control bytes through to the operator's terminal.
    #[must_use]
    pub fn rendered_diff(&self) -> String {
        render_terminal_bytes(&self.candidate.diff)
    }

    #[must_use]
    pub fn default_message(&self) -> String {
        if self.paths.len() == 1 {
            format!(
                "Update {}",
                render_terminal_label_bytes(os_str_bytes(self.paths[0].as_os_str()).as_ref())
            )
        } else {
            format!("Update {} files", self.paths.len())
        }
    }

    /// Bind an approval to the exact values displayed by the frontend.
    ///
    /// # Errors
    ///
    /// Returns an error when the message is invalid or an approved value
    /// differs from the prepared review.
    pub fn approve(
        &self,
        approved_paths: &[PathBuf],
        destination: &str,
        message: &str,
    ) -> Result<GitCommitApproval, GitTransactionError> {
        validate_message(message)?;
        if approved_paths != self.paths || destination != self.generation.destination {
            return Err(GitTransactionError::ApprovalMismatch);
        }
        let path_digest = digest_paths(approved_paths);
        let approval_digest = digest_frames(&[
            self.generation.digest().as_bytes(),
            path_digest.as_bytes(),
            destination.as_bytes(),
            message.as_bytes(),
        ]);
        Ok(GitCommitApproval {
            generation: self.generation.clone(),
            paths: approved_paths.to_vec(),
            message: message.to_string(),
            approval_digest,
        })
    }

    #[must_use]
    pub fn cancel(self) -> GitReviewCancellation {
        GitReviewCancellation {
            review_digest: self.generation.digest(),
        }
    }
}

#[derive(Clone)]
struct GitIdentity {
    name: String,
    email: String,
}

struct RepositoryObservation {
    head: String,
    destination: String,
    index: ContentDigest,
    paths: Vec<PathBuf>,
    path_set: ContentDigest,
    policy: ContentDigest,
}

/// Prepare one exact, bounded local-commit review without changing the user's
/// index, refs, or repository object database.
///
/// # Errors
///
/// Returns a typed capability, repository, policy, bound, cancellation, or
/// Git-process failure. A clean worktree is `NothingToCommit`.
pub fn prepare_commit_review(run: &ToolRunContext) -> Result<GitCommitReview, GitTransactionError> {
    run.require(ToolResource::WorkspaceRead)
        .and_then(|()| run.require(ToolResource::Process))
        .map_err(|error| GitTransactionError::Capability(error.to_string()))?;
    check_cancellation(run)?;
    let workspace_operation = run
        .begin_workspace_operation()
        .map_err(|error| GitTransactionError::Capability(error.to_string()))?;
    let repository_root = repository_root(run, SandboxProfile::GitReview)?;
    if repository_root != run.project_root() {
        return Err(GitTransactionError::NotRepository);
    }
    let repository_lease = RepositoryReviewLease::acquire(&repository_root)?;
    let object_directory = repository_object_directory(run, &repository_root)?;
    let observation = observe_repository(run, &repository_root, None)?;
    if observation.paths.is_empty() {
        return Err(GitTransactionError::NothingToCommit {
            head: observation.head,
        });
    }
    let candidate = stage_candidate(
        run,
        &repository_root,
        &object_directory,
        &observation.head,
        &observation.paths,
        true,
    )?;
    let generation = generation_from_observation(run, &observation, &candidate);
    Ok(GitCommitReview {
        _workspace_operation: workspace_operation,
        _repository_lease: repository_lease,
        repository_root,
        object_directory,
        paths: observation.paths,
        candidate,
        generation,
    })
}

/// Render a bounded, helper-disabled comparison against a branch or commit.
///
/// The requested ref is resolved to a full object identity before either the
/// log or diff runs, and HEAD is checked again before success is returned.
///
/// # Errors
///
/// Returns a typed capability, input, repository, cancellation, concurrent
/// HEAD, output-bound, or Git-process failure.
#[allow(clippy::too_many_lines)] // The ordered observe/render/revalidate lifecycle is one transaction.
pub fn review_branch(
    run: &ToolRunContext,
    branch: &str,
) -> Result<GitBranchReview, GitTransactionError> {
    run.require(ToolResource::WorkspaceRead)
        .and_then(|()| run.require(ToolResource::Process))
        .map_err(|error| GitTransactionError::Capability(error.to_string()))?;
    if branch.is_empty()
        || branch.len() > 255
        || branch.starts_with('-')
        || branch.chars().any(char::is_control)
    {
        return Err(GitTransactionError::GitFailed {
            operation: "validate comparison ref",
            detail: "comparison ref is empty, option-like, oversized, or contains control data"
                .to_string(),
        });
    }
    let _workspace_operation = run
        .begin_workspace_operation()
        .map_err(|error| GitTransactionError::Capability(error.to_string()))?;
    let root = repository_root(run, SandboxProfile::GitReview)?;
    if root != run.project_root() {
        return Err(GitTransactionError::NotRepository);
    }
    let head = git_text(
        run,
        SandboxProfile::GitReview,
        &root,
        "resolve comparison HEAD",
        &[
            OsString::from("rev-parse"),
            OsString::from("--verify"),
            OsString::from("HEAD"),
        ],
        &[],
    )?;
    let requested = format!("{branch}^{{commit}}");
    let base = git_text(
        run,
        SandboxProfile::GitReview,
        &root,
        "resolve comparison ref",
        &[
            OsString::from("rev-parse"),
            OsString::from("--verify"),
            OsString::from("--end-of-options"),
            OsString::from(requested),
        ],
        &[],
    )?;
    validate_object_id(&head, "comparison HEAD")?;
    validate_object_id(&base, "comparison base")?;
    let range = format!("{base}..{head}");
    let log = git_success(
        run,
        SandboxProfile::GitReview,
        &root,
        "render comparison log",
        &[
            OsString::from("log"),
            OsString::from("--oneline"),
            OsString::from("--no-decorate"),
            OsString::from(&range),
        ],
        &[],
    )?;
    let diff_range = format!("{base}..{head}");
    let diff = git_success(
        run,
        SandboxProfile::GitReview,
        &root,
        "render comparison diff",
        &[
            OsString::from("diff"),
            OsString::from("--stat"),
            OsString::from("--no-color"),
            OsString::from("--no-ext-diff"),
            OsString::from("--no-textconv"),
            OsString::from(diff_range),
            OsString::from("--"),
        ],
        &[],
    )?;
    let final_head = git_text(
        run,
        SandboxProfile::GitReview,
        &root,
        "revalidate comparison HEAD",
        &[
            OsString::from("rev-parse"),
            OsString::from("--verify"),
            OsString::from("HEAD"),
        ],
        &[],
    )?;
    if final_head != head {
        return Err(GitTransactionError::GitFailed {
            operation: "revalidate comparison HEAD",
            detail: "HEAD changed while the bounded comparison was being rendered".to_string(),
        });
    }
    let rendered = format!(
        "=== Comparing {} ({}) against HEAD {} ===\n\nCommits ahead:\n{}\nChanged files:\n{}",
        branch,
        base,
        head,
        render_terminal_bytes(&log),
        render_terminal_bytes(&diff),
    );
    Ok(GitBranchReview {
        head,
        base,
        branch: branch.to_string(),
        rendered,
    })
}

/// Revalidate and commit one exact approval. Local success is returned only
/// after the new object, destination ref, user index, and clean reviewed path
/// postcondition have all been verified.
///
/// # Errors
///
/// Returns a typed pre-publication failure or a recoverable partial state when
/// an irreversible local commit boundary was crossed without full proof.
pub fn commit_approved_review(
    run: &ToolRunContext,
    review: GitCommitReview,
    approval: GitCommitApproval,
) -> Result<LocalCommitReceipt, GitTransactionError> {
    run.require(ToolResource::WorkspaceWrite)
        .and_then(|()| run.require(ToolResource::Process))
        .map_err(|error| GitTransactionError::Capability(error.to_string()))?;
    check_cancellation(run)?;
    validate_approval(&review, &approval)?;

    let observation = observe_repository(run, &review.repository_root, Some(&review.paths))?;
    let candidate = stage_candidate(
        run,
        &review.repository_root,
        &review.object_directory,
        &observation.head,
        &observation.paths,
        false,
    )?;
    let observed_generation = generation_from_observation(run, &observation, &candidate);
    if observed_generation != review.generation {
        return Err(GitTransactionError::ConcurrentMutation {
            expected: Box::new(review.generation),
            observed: Box::new(observed_generation),
        });
    }

    let commit_id = create_commit(run, &review, &candidate, &approval)?;
    verify_commit_object(
        run,
        &review.repository_root,
        &commit_id,
        &review.generation.head,
        &candidate.tree,
    )?;

    let final_observation = observe_repository(run, &review.repository_root, Some(&review.paths))?;
    let final_candidate = stage_candidate(
        run,
        &review.repository_root,
        &review.object_directory,
        &final_observation.head,
        &final_observation.paths,
        false,
    )?;
    let final_generation = generation_from_observation(run, &final_observation, &final_candidate);
    if final_generation != review.generation {
        return Err(GitTransactionError::CommitNotPublished {
            state_commit: commit_id.clone(),
            detail: "repository changed after commit-object creation".to_string(),
            state: Box::new(recovery_state(&review, &commit_id, None, false)),
        });
    }

    publish_destination(run, &review, &commit_id)?;
    reconcile_user_index(run, &review, &commit_id)?;
    let receipt = verify_published_state(run, &review, &commit_id, &approval)?;
    drop(approval);
    Ok(receipt)
}

fn validate_approval(
    review: &GitCommitReview,
    approval: &GitCommitApproval,
) -> Result<(), GitTransactionError> {
    validate_message(&approval.message)?;
    let expected = review.approve(
        &approval.paths,
        &approval.generation.destination,
        &approval.message,
    )?;
    if approval.generation != review.generation
        || approval.approval_digest != expected.approval_digest
    {
        return Err(GitTransactionError::ApprovalMismatch);
    }
    Ok(())
}

fn observe_repository(
    run: &ToolRunContext,
    root: &Path,
    expected_paths: Option<&[PathBuf]>,
) -> Result<RepositoryObservation, GitTransactionError> {
    check_cancellation(run)?;
    let head = git_text(
        run,
        SandboxProfile::GitReview,
        root,
        "resolve HEAD",
        &[
            OsString::from("rev-parse"),
            OsString::from("--verify"),
            OsString::from("HEAD"),
        ],
        &[],
    )?;
    validate_object_id(&head, "HEAD")?;
    let destination = git_text(
        run,
        SandboxProfile::GitReview,
        root,
        "resolve destination",
        &[
            OsString::from("symbolic-ref"),
            OsString::from("--quiet"),
            OsString::from("HEAD"),
        ],
        &[],
    )
    .map_err(|error| match error {
        GitTransactionError::GitFailed { .. } => GitTransactionError::DetachedHead,
        other => other,
    })?;
    if !destination.starts_with("refs/heads/") {
        return Err(GitTransactionError::DetachedHead);
    }
    let index_bytes = git_success(
        run,
        SandboxProfile::GitReview,
        root,
        "inspect index",
        &[
            OsString::from("ls-files"),
            OsString::from("--stage"),
            OsString::from("-z"),
        ],
        &[],
    )?;
    let paths = discover_paths(run, root)?;
    if let Some(expected) = expected_paths {
        if paths != expected {
            return Ok(RepositoryObservation {
                head,
                destination,
                index: ContentDigest::sha256(index_bytes),
                path_set: digest_paths(&paths),
                policy: policy_digest(run, root, &paths)?,
                paths,
            });
        }
    }
    let policy = policy_digest(run, root, &paths)?;
    Ok(RepositoryObservation {
        head,
        destination,
        index: ContentDigest::sha256(index_bytes),
        path_set: digest_paths(&paths),
        policy,
        paths,
    })
}

fn generation_from_observation(
    run: &ToolRunContext,
    observation: &RepositoryObservation,
    candidate: &CandidateIndex,
) -> GitReviewGeneration {
    let descriptor = run.runtime().descriptor();
    GitReviewGeneration {
        run_id: run.run_id(),
        capability_generation: run.generation(),
        workspace_generation: descriptor.workspace.generation,
        workspace_binding: descriptor.workspace.digest,
        head: observation.head.clone(),
        destination: observation.destination.clone(),
        index: observation.index,
        path_set: observation.path_set,
        policy: observation.policy,
        candidate_tree: candidate.tree.clone(),
        candidate_index: candidate.entries_digest,
        candidate_diff: candidate.diff_digest,
    }
}

#[allow(clippy::too_many_lines)] // Each command contributes to one generation-bound candidate.
fn stage_candidate(
    run: &ToolRunContext,
    root: &Path,
    object_directory: &Path,
    head: &str,
    paths: &[PathBuf],
    quarantine_objects: bool,
) -> Result<CandidateIndex, GitTransactionError> {
    let directory = tempfile::Builder::new()
        .prefix("git-review-")
        .tempdir_in(run.private_temp_root())
        .map_err(|error| {
            GitTransactionError::Capability(format!("cannot create run-owned Git index: {error}"))
        })?;
    let index_path = directory.path().join("index");
    let mut environment = vec![(
        OsString::from("GIT_INDEX_FILE"),
        index_path.as_os_str().to_os_string(),
    )];
    if quarantine_objects {
        let quarantine = directory.path().join("objects");
        std::fs::create_dir(&quarantine).map_err(|error| {
            GitTransactionError::Capability(format!("cannot create Git object quarantine: {error}"))
        })?;
        environment.push((
            OsString::from("GIT_OBJECT_DIRECTORY"),
            quarantine.as_os_str().to_os_string(),
        ));
        environment.push((
            OsString::from("GIT_ALTERNATE_OBJECT_DIRECTORIES"),
            object_directory.as_os_str().to_os_string(),
        ));
    }
    git_success(
        run,
        if quarantine_objects {
            SandboxProfile::GitReview
        } else {
            SandboxProfile::GitCommit
        },
        root,
        "initialize run-owned index",
        &[OsString::from("read-tree"), OsString::from(head)],
        &environment,
    )?;
    let mut add_args = vec![
        OsString::from("add"),
        OsString::from("-A"),
        OsString::from("--"),
    ];
    add_args.extend(paths.iter().map(|path| path.as_os_str().to_os_string()));
    git_success(
        run,
        if quarantine_objects {
            SandboxProfile::GitReview
        } else {
            SandboxProfile::GitCommit
        },
        root,
        "stage approved paths in run-owned index",
        &add_args,
        &environment,
    )?;
    let tree = git_text(
        run,
        if quarantine_objects {
            SandboxProfile::GitReview
        } else {
            SandboxProfile::GitCommit
        },
        root,
        "write candidate tree",
        &[OsString::from("write-tree")],
        &environment,
    )?;
    validate_object_id(&tree, "candidate tree")?;
    let entries = git_success(
        run,
        if quarantine_objects {
            SandboxProfile::GitReview
        } else {
            SandboxProfile::GitCommit
        },
        root,
        "snapshot candidate index",
        &[
            OsString::from("ls-files"),
            OsString::from("--stage"),
            OsString::from("-z"),
        ],
        &environment,
    )?;
    let mut diff_args = vec![
        OsString::from("diff"),
        OsString::from("--cached"),
        OsString::from("--binary"),
        OsString::from("--full-index"),
        OsString::from("--no-color"),
        OsString::from("--no-ext-diff"),
        OsString::from("--no-textconv"),
        OsString::from(head),
        OsString::from("--"),
    ];
    diff_args.extend(paths.iter().map(|path| path.as_os_str().to_os_string()));
    let diff = git_success(
        run,
        if quarantine_objects {
            SandboxProfile::GitReview
        } else {
            SandboxProfile::GitCommit
        },
        root,
        "render candidate diff",
        &diff_args,
        &environment,
    )?;
    if diff.is_empty() {
        return Err(GitTransactionError::NothingToCommit {
            head: head.to_string(),
        });
    }
    let diff_digest = ContentDigest::sha256(&diff);
    Ok(CandidateIndex {
        _directory: directory,
        index_path,
        tree,
        entries_digest: ContentDigest::sha256(entries),
        diff,
        diff_digest,
    })
}

fn create_commit(
    run: &ToolRunContext,
    review: &GitCommitReview,
    candidate: &CandidateIndex,
    approval: &GitCommitApproval,
) -> Result<String, GitTransactionError> {
    check_cancellation(run)?;
    let identity = read_identity(run, &review.repository_root)?;
    let environment = vec![
        (
            OsString::from("GIT_INDEX_FILE"),
            candidate.index_path.as_os_str().to_os_string(),
        ),
        (
            OsString::from("GIT_AUTHOR_NAME"),
            OsString::from(&identity.name),
        ),
        (
            OsString::from("GIT_AUTHOR_EMAIL"),
            OsString::from(&identity.email),
        ),
        (
            OsString::from("GIT_COMMITTER_NAME"),
            OsString::from(&identity.name),
        ),
        (
            OsString::from("GIT_COMMITTER_EMAIL"),
            OsString::from(&identity.email),
        ),
    ];
    let commit = git_text(
        run,
        SandboxProfile::GitCommit,
        &review.repository_root,
        "create commit object",
        &[
            OsString::from("commit-tree"),
            OsString::from(&candidate.tree),
            OsString::from("-p"),
            OsString::from(&review.generation.head),
            OsString::from("-m"),
            OsString::from(&approval.message),
        ],
        &environment,
    )?;
    validate_object_id(&commit, "commit")?;
    Ok(commit)
}

fn publish_destination(
    run: &ToolRunContext,
    review: &GitCommitReview,
    commit_id: &str,
) -> Result<(), GitTransactionError> {
    let result = git_success(
        run,
        SandboxProfile::GitCommit,
        &review.repository_root,
        "publish approved destination",
        &[
            OsString::from("update-ref"),
            OsString::from(&review.generation.destination),
            OsString::from(commit_id),
            OsString::from(&review.generation.head),
        ],
        &[],
    );
    result
        .map(|_| ())
        .map_err(|error| GitTransactionError::CommitNotPublished {
            state_commit: commit_id.to_string(),
            detail: error.to_string(),
            state: Box::new(recovery_state(review, commit_id, None, false)),
        })
}

fn reconcile_user_index(
    run: &ToolRunContext,
    review: &GitCommitReview,
    commit_id: &str,
) -> Result<(), GitTransactionError> {
    let current_index = git_success(
        run,
        SandboxProfile::GitReview,
        &review.repository_root,
        "revalidate user index",
        &[
            OsString::from("ls-files"),
            OsString::from("--stage"),
            OsString::from("-z"),
        ],
        &[],
    )?;
    if ContentDigest::sha256(current_index) != review.generation.index {
        return Err(GitTransactionError::CommitPublishedUncertain {
            detail:
                "the user index changed before post-commit reconciliation; it was not overwritten"
                    .to_string(),
            state: Box::new(recovery_state(
                review,
                commit_id,
                Some(commit_id.to_string()),
                false,
            )),
        });
    }
    git_success(
        run,
        SandboxProfile::GitCommit,
        &review.repository_root,
        "reconcile user index",
        &[OsString::from("read-tree"), OsString::from(commit_id)],
        &[],
    )
    .map(|_| ())
    .map_err(|error| GitTransactionError::CommitPublishedUncertain {
        detail: format!("the commit ref advanced but the user index was not reconciled: {error}"),
        state: Box::new(recovery_state(
            review,
            commit_id,
            Some(commit_id.to_string()),
            false,
        )),
    })
}

fn verify_published_state(
    run: &ToolRunContext,
    review: &GitCommitReview,
    commit_id: &str,
    approval: &GitCommitApproval,
) -> Result<LocalCommitReceipt, GitTransactionError> {
    let observed = git_text(
        run,
        SandboxProfile::GitReview,
        &review.repository_root,
        "verify destination",
        &[
            OsString::from("rev-parse"),
            OsString::from("--verify"),
            OsString::from(&review.generation.destination),
        ],
        &[],
    )?;
    if observed != commit_id {
        return Err(GitTransactionError::CommitPublishedUncertain {
            detail: format!("approved destination now resolves to {observed}"),
            state: Box::new(recovery_state(review, commit_id, Some(observed), true)),
        });
    }
    let index_entries = git_success(
        run,
        SandboxProfile::GitReview,
        &review.repository_root,
        "verify reconciled index",
        &[
            OsString::from("ls-files"),
            OsString::from("--stage"),
            OsString::from("-z"),
        ],
        &[],
    )?;
    if ContentDigest::sha256(index_entries) != review.generation.candidate_index {
        return Err(GitTransactionError::CommitPublishedUncertain {
            detail: "the user index does not match the committed candidate tree".to_string(),
            state: Box::new(recovery_state(review, commit_id, Some(observed), false)),
        });
    }
    let remaining = discover_paths(run, &review.repository_root)?;
    if !remaining.is_empty() {
        return Err(GitTransactionError::CommitPublishedUncertain {
            detail: format!(
                "the local commit was published, but {} concurrent non-ignored path(s) remain",
                remaining.len()
            ),
            state: Box::new(recovery_state(review, commit_id, Some(observed), true)),
        });
    }
    Ok(LocalCommitReceipt {
        commit_id: commit_id.to_string(),
        destination: review.generation.destination.clone(),
        repository_root: review.repository_root.clone(),
        parent: review.generation.head.clone(),
        tree: review.generation.candidate_tree.clone(),
        approved_paths: review.paths.clone(),
        approval_digest: approval.approval_digest,
        generation: review.generation.clone(),
    })
}

fn verify_commit_object(
    run: &ToolRunContext,
    root: &Path,
    commit: &str,
    parent: &str,
    tree: &str,
) -> Result<(), GitTransactionError> {
    let actual_tree = git_text(
        run,
        SandboxProfile::GitReview,
        root,
        "verify commit tree",
        &[
            OsString::from("show"),
            OsString::from("-s"),
            OsString::from("--format=%T"),
            OsString::from(commit),
        ],
        &[],
    )?;
    let actual_parent = git_text(
        run,
        SandboxProfile::GitReview,
        root,
        "verify commit parent",
        &[
            OsString::from("show"),
            OsString::from("-s"),
            OsString::from("--format=%P"),
            OsString::from(commit),
        ],
        &[],
    )?;
    if actual_tree != tree || actual_parent != parent {
        return Err(GitTransactionError::GitFailed {
            operation: "verify commit identity",
            detail: "commit tree or parent differs from the reviewed candidate".to_string(),
        });
    }
    Ok(())
}

fn recovery_state(
    review: &GitCommitReview,
    commit_id: &str,
    observed_destination: Option<String>,
    index_reconciled: bool,
) -> RecoverableCommitState {
    RecoverableCommitState {
        commit_id: commit_id.to_string(),
        destination: review.generation.destination.clone(),
        parent: review.generation.head.clone(),
        tree: review.generation.candidate_tree.clone(),
        observed_destination,
        index_reconciled,
    }
}

fn discover_paths(run: &ToolRunContext, root: &Path) -> Result<Vec<PathBuf>, GitTransactionError> {
    let tracked = git_success(
        run,
        SandboxProfile::GitReview,
        root,
        "discover tracked changes",
        &[
            OsString::from("diff"),
            OsString::from("--name-only"),
            OsString::from("-z"),
            OsString::from("--no-renames"),
            OsString::from("HEAD"),
            OsString::from("--"),
        ],
        &[],
    )?;
    let untracked = git_success(
        run,
        SandboxProfile::GitReview,
        root,
        "discover untracked changes",
        &[
            OsString::from("ls-files"),
            OsString::from("--others"),
            OsString::from("--exclude-standard"),
            OsString::from("-z"),
        ],
        &[],
    )?;
    let mut paths = BTreeSet::new();
    let mut path_bytes = 0_usize;
    for raw in split_nul(&tracked).chain(split_nul(&untracked)) {
        if raw.is_empty() {
            continue;
        }
        path_bytes = path_bytes.saturating_add(raw.len());
        if path_bytes > MAX_REVIEW_PATH_BYTES {
            return Err(GitTransactionError::PathSetTooLarge {
                limit: MAX_REVIEW_PATH_BYTES,
            });
        }
        let path = path_from_git_bytes(raw)?;
        if path.is_absolute()
            || path
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
        {
            return Err(GitTransactionError::GitFailed {
                operation: "validate changed paths",
                detail: "Git returned a non-relative path".to_string(),
            });
        }
        paths.insert(path);
        if paths.len() > MAX_REVIEW_PATHS {
            return Err(GitTransactionError::TooManyPaths {
                count: paths.len(),
                limit: MAX_REVIEW_PATHS,
            });
        }
    }
    Ok(paths.into_iter().collect())
}

fn policy_digest(
    run: &ToolRunContext,
    root: &Path,
    paths: &[PathBuf],
) -> Result<ContentDigest, GitTransactionError> {
    let config = read_repository_config(root)?;
    let mut attribute_args = vec![
        OsString::from("check-attr"),
        OsString::from("-z"),
        OsString::from("--all"),
        OsString::from("--"),
    ];
    attribute_args.extend(paths.iter().map(|path| path.as_os_str().to_os_string()));
    let attributes = git_success(
        run,
        SandboxProfile::GitReview,
        root,
        "inspect path attributes",
        &attribute_args,
        &[],
    )?;
    reject_active_filters(&attributes)?;
    Ok(digest_frames(&[PROFILE_GENERATION, &config, &attributes]))
}

fn reject_active_filters(attributes: &[u8]) -> Result<(), GitTransactionError> {
    let fields = split_nul(attributes).collect::<Vec<_>>();
    for triple in fields.as_chunks::<3>().0 {
        if triple[1] == b"filter" && !matches!(triple[2], b"unspecified" | b"unset") {
            return Err(GitTransactionError::ActiveFilter {
                path: path_from_git_bytes(triple[0])?,
            });
        }
    }
    Ok(())
}

fn read_identity(run: &ToolRunContext, root: &Path) -> Result<GitIdentity, GitTransactionError> {
    let config = read_repository_config(root)?;
    let mut snapshot = tempfile::Builder::new()
        .prefix("git-config-")
        .tempfile_in(run.private_temp_root())
        .map_err(|error| {
            GitTransactionError::IdentityUnavailable(format!(
                "cannot create bounded repository-config snapshot: {error}"
            ))
        })?;
    snapshot.write_all(&config).map_err(|error| {
        GitTransactionError::IdentityUnavailable(format!(
            "cannot write bounded repository-config snapshot: {error}"
        ))
    })?;
    snapshot.flush().map_err(|error| {
        GitTransactionError::IdentityUnavailable(format!(
            "cannot flush bounded repository-config snapshot: {error}"
        ))
    })?;
    let name = read_local_identity_value(run, root, snapshot.path(), "user.name")?;
    let email = read_local_identity_value(run, root, snapshot.path(), "user.email")?;
    if name.is_empty()
        || email.is_empty()
        || name
            .chars()
            .any(|character| matches!(character, '\0' | '\n' | '\r'))
        || email
            .chars()
            .any(|character| matches!(character, '\0' | '\n' | '\r'))
    {
        return Err(GitTransactionError::IdentityUnavailable(
            "repository-local user.name/user.email is malformed".to_string(),
        ));
    }
    Ok(GitIdentity { name, email })
}

fn read_local_identity_value(
    run: &ToolRunContext,
    root: &Path,
    config_snapshot: &Path,
    key: &'static str,
) -> Result<String, GitTransactionError> {
    git_text(
        run,
        SandboxProfile::GitReview,
        root,
        "read commit identity",
        &[
            OsString::from("config"),
            OsString::from("--no-includes"),
            OsString::from("--file"),
            config_snapshot.as_os_str().to_os_string(),
            OsString::from("--get"),
            OsString::from(key),
        ],
        &[],
    )
    .map_err(|_| {
        GitTransactionError::IdentityUnavailable(format!(
            "set `{key}` in the repository-local Git config and retry"
        ))
    })
}

fn read_repository_config(root: &Path) -> Result<Vec<u8>, GitTransactionError> {
    let config_path = repository_config_path(root)?;
    let metadata = std::fs::symlink_metadata(&config_path).map_err(|error| {
        GitTransactionError::GitFailed {
            operation: "inspect repository config",
            detail: format!("cannot inspect '{}': {error}", config_path.display()),
        }
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(GitTransactionError::GitFailed {
            operation: "inspect repository config",
            detail: format!("'{}' is not a regular file", config_path.display()),
        });
    }
    if metadata.len() > u64::try_from(MAX_REPOSITORY_CONFIG_BYTES).unwrap_or(u64::MAX) {
        return Err(GitTransactionError::GitFailed {
            operation: "inspect repository config",
            detail: format!(
                "'{}' exceeds the {MAX_REPOSITORY_CONFIG_BYTES}-byte bound",
                config_path.display()
            ),
        });
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options
        .open(&config_path)
        .map_err(|error| GitTransactionError::GitFailed {
            operation: "inspect repository config",
            detail: format!("cannot open '{}': {error}", config_path.display()),
        })?;
    let mut bytes = Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(MAX_REPOSITORY_CONFIG_BYTES)
            .min(MAX_REPOSITORY_CONFIG_BYTES),
    );
    std::io::Read::by_ref(&mut file)
        .take(u64::try_from(MAX_REPOSITORY_CONFIG_BYTES + 1).unwrap_or(u64::MAX))
        .read_to_end(&mut bytes)
        .map_err(|error| GitTransactionError::GitFailed {
            operation: "inspect repository config",
            detail: format!("cannot read '{}': {error}", config_path.display()),
        })?;
    if bytes.len() > MAX_REPOSITORY_CONFIG_BYTES {
        return Err(GitTransactionError::GitFailed {
            operation: "inspect repository config",
            detail: format!(
                "'{}' grew beyond the {MAX_REPOSITORY_CONFIG_BYTES}-byte bound",
                config_path.display()
            ),
        });
    }
    Ok(bytes)
}

#[allow(clippy::too_many_lines)] // Linked-worktree ownership is validated as one fail-closed resolution.
fn repository_config_path(root: &Path) -> Result<PathBuf, GitTransactionError> {
    let git_entry = root.join(".git");
    let metadata =
        std::fs::symlink_metadata(&git_entry).map_err(|error| GitTransactionError::GitFailed {
            operation: "resolve repository config",
            detail: error.to_string(),
        })?;
    if metadata.file_type().is_symlink() {
        return Err(GitTransactionError::GitFailed {
            operation: "resolve repository config",
            detail: "symbolic-link .git metadata is refused".to_string(),
        });
    }
    if metadata.is_dir() {
        return Ok(git_entry.join("config"));
    }
    if !metadata.is_file() || metadata.len() > 4096 {
        return Err(GitTransactionError::GitFailed {
            operation: "resolve repository config",
            detail: "linked-worktree .git entry is not a bounded regular file".to_string(),
        });
    }
    let pointer =
        std::fs::read_to_string(&git_entry).map_err(|error| GitTransactionError::GitFailed {
            operation: "resolve repository config",
            detail: error.to_string(),
        })?;
    let target = pointer
        .trim()
        .strip_prefix("gitdir:")
        .map(str::trim)
        .filter(|target| !target.is_empty())
        .ok_or_else(|| GitTransactionError::GitFailed {
            operation: "resolve repository config",
            detail: "malformed linked-worktree .git entry".to_string(),
        })?;
    let target = Path::new(target);
    let admin_candidate = if target.is_absolute() {
        target.to_path_buf()
    } else {
        root.join(target)
    };
    let admin = admin_candidate
        .canonicalize()
        .map_err(|error| GitTransactionError::GitFailed {
            operation: "resolve repository config",
            detail: error.to_string(),
        })?;
    let common_pointer = std::fs::read_to_string(admin.join("commondir")).map_err(|error| {
        GitTransactionError::GitFailed {
            operation: "resolve repository config",
            detail: error.to_string(),
        }
    })?;
    let common_pointer = Path::new(common_pointer.trim());
    if common_pointer.as_os_str().is_empty() {
        return Err(GitTransactionError::GitFailed {
            operation: "resolve repository config",
            detail: "linked-worktree commondir is empty".to_string(),
        });
    }
    let common_candidate = if common_pointer.is_absolute() {
        common_pointer.to_path_buf()
    } else {
        admin.join(common_pointer)
    };
    let common =
        common_candidate
            .canonicalize()
            .map_err(|error| GitTransactionError::GitFailed {
                operation: "resolve repository config",
                detail: error.to_string(),
            })?;
    let worktrees = common.join("worktrees").canonicalize().map_err(|error| {
        GitTransactionError::GitFailed {
            operation: "resolve repository config",
            detail: error.to_string(),
        }
    })?;
    if admin.parent() != Some(worktrees.as_path()) {
        return Err(GitTransactionError::GitFailed {
            operation: "resolve repository config",
            detail: "linked-worktree admin directory is not owned by its common repository"
                .to_string(),
        });
    }
    let backlink = std::fs::read_to_string(admin.join("gitdir"))
        .and_then(|value| PathBuf::from(value.trim()).canonicalize())
        .map_err(|error| GitTransactionError::GitFailed {
            operation: "resolve repository config",
            detail: error.to_string(),
        })?;
    let expected = git_entry
        .canonicalize()
        .map_err(|error| GitTransactionError::GitFailed {
            operation: "resolve repository config",
            detail: error.to_string(),
        })?;
    if backlink != expected {
        return Err(GitTransactionError::GitFailed {
            operation: "resolve repository config",
            detail: "linked-worktree metadata backlink mismatch".to_string(),
        });
    }
    Ok(common.join("config"))
}

fn repository_root(
    run: &ToolRunContext,
    profile: SandboxProfile,
) -> Result<PathBuf, GitTransactionError> {
    let value = git_text(
        run,
        profile,
        run.working_directory(),
        "resolve repository root",
        &[
            OsString::from("rev-parse"),
            OsString::from("--show-toplevel"),
        ],
        &[],
    )?;
    PathBuf::from(value)
        .canonicalize()
        .map_err(|_| GitTransactionError::NotRepository)
}

fn repository_object_directory(
    run: &ToolRunContext,
    root: &Path,
) -> Result<PathBuf, GitTransactionError> {
    let value = git_text(
        run,
        SandboxProfile::GitReview,
        root,
        "resolve repository object directory",
        &[
            OsString::from("rev-parse"),
            OsString::from("--git-path"),
            OsString::from("objects"),
        ],
        &[],
    )?;
    let path = PathBuf::from(value);
    let absolute = if path.is_absolute() {
        path
    } else {
        root.join(path)
    };
    absolute
        .canonicalize()
        .map_err(|error| GitTransactionError::GitFailed {
            operation: "resolve repository object directory",
            detail: error.to_string(),
        })
}

fn git_text(
    run: &ToolRunContext,
    profile: SandboxProfile,
    root: &Path,
    operation: &'static str,
    args: &[OsString],
    environment: &[(OsString, OsString)],
) -> Result<String, GitTransactionError> {
    let bytes = git_success(run, profile, root, operation, args, environment)?;
    let text = String::from_utf8(bytes).map_err(|error| GitTransactionError::GitFailed {
        operation,
        detail: format!("Git returned non-UTF-8 identity data: {error}"),
    })?;
    Ok(text.trim().to_string())
}

fn git_success(
    run: &ToolRunContext,
    profile: SandboxProfile,
    root: &Path,
    operation: &'static str,
    args: &[OsString],
    environment: &[(OsString, OsString)],
) -> Result<Vec<u8>, GitTransactionError> {
    check_cancellation(run)?;
    let git = run
        .resolve_executable("git")
        .map_err(|error| GitTransactionError::Capability(error.to_string()))?;
    let mut hardened = vec![
        OsString::from("--literal-pathspecs"),
        OsString::from("--no-optional-locks"),
        OsString::from("-c"),
        OsString::from("core.hooksPath=/dev/null"),
        OsString::from("-c"),
        OsString::from("core.fsmonitor=false"),
        OsString::from("-c"),
        OsString::from("core.pager=cat"),
        OsString::from("-c"),
        OsString::from("color.ui=false"),
        OsString::from("-c"),
        OsString::from("diff.external="),
        OsString::from("-c"),
        OsString::from("credential.helper="),
        OsString::from("-c"),
        OsString::from("protocol.file.allow=never"),
        OsString::from("-c"),
        OsString::from("protocol.ext.allow=never"),
        OsString::from("-c"),
        OsString::from("commit.gpgSign=false"),
        OsString::from("-c"),
        OsString::from("tag.gpgSign=false"),
        OsString::from("-c"),
        OsString::from("core.logAllRefUpdates=false"),
        OsString::from("-c"),
        OsString::from("core.attributesfile=/dev/null"),
        OsString::from("-c"),
        OsString::from("core.excludesfile=/dev/null"),
    ];
    hardened.extend_from_slice(args);
    let mut child_environment = vec![
        (
            OsString::from("GIT_CONFIG_GLOBAL"),
            OsString::from("/dev/null"),
        ),
        (OsString::from("GIT_CONFIG_NOSYSTEM"), OsString::from("1")),
        (OsString::from("GIT_TERMINAL_PROMPT"), OsString::from("0")),
        (OsString::from("GIT_OPTIONAL_LOCKS"), OsString::from("0")),
        (OsString::from("GIT_LITERAL_PATHSPECS"), OsString::from("1")),
        (OsString::from("GIT_PAGER"), OsString::from("cat")),
        (OsString::from("LC_ALL"), OsString::from("C")),
    ];
    child_environment.extend_from_slice(environment);
    let prepared = crate::tools::sandboxed_process_command_with_env(
        run,
        profile,
        git.as_os_str(),
        &hardened,
        root,
        &child_environment,
    )
    .map_err(GitTransactionError::Capability)?;
    let output = crate::tools::command::run_prepared_run_owned_sync(
        run,
        prepared,
        "git",
        ProcessLimits::new(GIT_TIMEOUT)
            .with_output_limit(MAX_GIT_OUTPUT_BYTES, EMPTY_TRUNCATION_MARKER),
    )
    .map_err(|error| map_command_error(operation, error))?;
    if output.stdout.truncated || output.stderr.truncated {
        return Err(GitTransactionError::OutputLimit {
            operation,
            limit: MAX_GIT_OUTPUT_BYTES,
        });
    }
    if !output.status.success() {
        return Err(GitTransactionError::GitFailed {
            operation,
            detail: render_terminal_bytes(&output.stderr.bytes),
        });
    }
    Ok(output.stdout.bytes)
}

fn map_command_error(operation: &'static str, error: CommandError) -> GitTransactionError {
    match error {
        CommandError::Cancelled { reason, .. } => GitTransactionError::Cancelled {
            reason: format!("{reason:?}"),
        },
        other => GitTransactionError::GitFailed {
            operation,
            detail: other.to_string(),
        },
    }
}

fn check_cancellation(run: &ToolRunContext) -> Result<(), GitTransactionError> {
    run.runtime()
        .cancellation()
        .receipt()
        .map_or(Ok(()), |receipt| {
            Err(GitTransactionError::Cancelled {
                reason: format!("{:?}", receipt.reason),
            })
        })
}

fn validate_message(message: &str) -> Result<(), GitTransactionError> {
    if message.is_empty()
        || message.len() > MAX_COMMIT_MESSAGE_BYTES
        || message.as_bytes().contains(&0)
    {
        Err(GitTransactionError::InvalidCommitMessage)
    } else {
        Ok(())
    }
}

fn validate_object_id(value: &str, label: &'static str) -> Result<(), GitTransactionError> {
    if (40..=64).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(GitTransactionError::GitFailed {
            operation: "validate Git object identity",
            detail: format!("{label} is not a full hexadecimal object identity"),
        })
    }
}

fn digest_paths(paths: &[PathBuf]) -> ContentDigest {
    let mut hasher = Sha256::new();
    for path in paths {
        let bytes = os_str_bytes(path.as_os_str());
        hasher.update(bytes.len().to_le_bytes());
        hasher.update(bytes.as_ref());
    }
    ContentDigest::from_sha256_bytes(hasher.finalize().into())
}

fn digest_frames(frames: &[&[u8]]) -> ContentDigest {
    let mut hasher = Sha256::new();
    for frame in frames {
        hasher.update(frame.len().to_le_bytes());
        hasher.update(frame);
    }
    ContentDigest::from_sha256_bytes(hasher.finalize().into())
}

fn split_nul(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes.split(|byte| *byte == 0)
}

#[cfg(unix)]
#[allow(clippy::unnecessary_wraps)] // Keep one fallible signature across Unix and Windows callers.
fn path_from_git_bytes(bytes: &[u8]) -> Result<PathBuf, GitTransactionError> {
    use std::os::unix::ffi::OsStringExt as _;
    Ok(PathBuf::from(OsString::from_vec(bytes.to_vec())))
}

#[cfg(windows)]
fn path_from_git_bytes(bytes: &[u8]) -> Result<PathBuf, GitTransactionError> {
    String::from_utf8(bytes.to_vec())
        .map(PathBuf::from)
        .map_err(|error| GitTransactionError::GitFailed {
            operation: "decode Git path",
            detail: error.to_string(),
        })
}

#[cfg(not(any(unix, windows)))]
fn path_from_git_bytes(bytes: &[u8]) -> Result<PathBuf, GitTransactionError> {
    String::from_utf8(bytes.to_vec())
        .map(PathBuf::from)
        .map_err(|error| GitTransactionError::GitFailed {
            operation: "decode Git path",
            detail: error.to_string(),
        })
}

#[cfg(unix)]
fn os_str_bytes(value: &OsStr) -> std::borrow::Cow<'_, [u8]> {
    use std::os::unix::ffi::OsStrExt as _;
    std::borrow::Cow::Borrowed(value.as_bytes())
}

#[cfg(not(unix))]
fn os_str_bytes(value: &OsStr) -> std::borrow::Cow<'_, [u8]> {
    std::borrow::Cow::Owned(value.to_string_lossy().as_bytes().to_vec())
}

fn render_terminal_bytes(bytes: &[u8]) -> String {
    let mut rendered = String::with_capacity(bytes.len());
    for byte in bytes {
        match *byte {
            b'\n' => rendered.push('\n'),
            b'\t' => rendered.push('\t'),
            0x20..=0x7e => rendered.push(char::from(*byte)),
            _ => {
                use std::fmt::Write as _;
                let _ = write!(rendered, "\\x{byte:02x}");
            }
        }
    }
    rendered
}

fn render_terminal_label_bytes(bytes: &[u8]) -> String {
    let mut rendered = String::with_capacity(bytes.len());
    for byte in bytes {
        if let 0x20..=0x7e = *byte {
            rendered.push(char::from(*byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(rendered, "\\x{byte:02x}");
        }
    }
    rendered
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn git(root: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .current_dir(root)
            .args(args)
            .output()
            .expect("run test Git command");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    fn repository() -> (tempfile::TempDir, std::sync::Arc<ToolRunContext>, String) {
        let root = tempfile::tempdir().expect("temporary repository");
        git(root.path(), &["init", "-b", "main"]);
        git(
            root.path(),
            &["config", "--local", "user.name", "Test User"],
        );
        git(
            root.path(),
            &["config", "--local", "user.email", "test@example.invalid"],
        );
        std::fs::write(root.path().join("tracked.txt"), "base\n").expect("base file");
        git(root.path(), &["add", "--", "tracked.txt"]);
        git(root.path(), &["commit", "-m", "base"]);
        let head = git(root.path(), &["rev-parse", "HEAD"]);
        let run = crate::tools::security::test_run_context_for(root.path());
        (root, run, head)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn approved_review_commits_exact_tracked_and_untracked_bytes() {
        let (root, run, parent) = repository();
        std::fs::write(root.path().join("tracked.txt"), "changed\n").expect("changed file");
        std::fs::write(root.path().join("new.txt"), "new\n").expect("new file");

        let review = prepare_commit_review(&run).expect("prepare exact review");
        assert_eq!(
            review.paths(),
            &[PathBuf::from("new.txt"), PathBuf::from("tracked.txt")]
        );
        let approval = review
            .approve(review.paths(), review.destination(), "tested commit")
            .expect("bind approval");
        let receipt = commit_approved_review(&run, review, approval).expect("commit review");

        assert_eq!(receipt.parent, parent);
        assert_eq!(receipt.commit_id, git(root.path(), &["rev-parse", "HEAD"]));
        assert_eq!(receipt.destination, "refs/heads/main");
        assert!(git(root.path(), &["status", "--porcelain=v1"]).is_empty());
        assert_eq!(git(root.path(), &["show", "HEAD:tracked.txt"]), "changed");
        assert_eq!(git(root.path(), &["show", "HEAD:new.txt"]), "new");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn post_approval_file_change_invalidates_without_advancing_head() {
        let (root, run, parent) = repository();
        std::fs::write(root.path().join("tracked.txt"), "reviewed\n").expect("reviewed file");
        let review = prepare_commit_review(&run).expect("prepare exact review");
        let approval = review
            .approve(review.paths(), review.destination(), "tested commit")
            .expect("bind approval");
        std::fs::write(root.path().join("tracked.txt"), "changed later\n")
            .expect("concurrent file change");

        assert!(matches!(
            commit_approved_review(&run, review, approval),
            Err(GitTransactionError::ConcurrentMutation { .. })
        ));
        assert_eq!(git(root.path(), &["rev-parse", "HEAD"]), parent);
        assert_eq!(
            std::fs::read_to_string(root.path().join("tracked.txt")).expect("worktree file"),
            "changed later\n"
        );
        assert!(git(root.path(), &["diff", "--cached", "--name-only"]).is_empty());
    }

    #[cfg(all(unix, target_os = "linux"))]
    #[test]
    fn hostile_path_is_nul_safe_and_terminal_inert() {
        use std::os::unix::ffi::OsStrExt as _;

        let (root, run, _) = repository();
        let hostile = OsStr::from_bytes(b"line\n\x1b]0;forged\x07.txt");
        std::fs::write(root.path().join(hostile), "content\n").expect("hostile path file");

        let review = prepare_commit_review(&run).expect("prepare hostile path review");
        assert_eq!(review.paths().len(), 1);
        assert_eq!(review.paths()[0].as_os_str().as_bytes(), hostile.as_bytes());
        let rendered = review.rendered_paths().remove(0);
        assert!(!rendered.contains('\u{1b}'));
        assert!(!rendered.contains('\u{7}'));
        assert!(!rendered.contains('\n'));
        assert!(rendered.contains("\\x1b"));
        assert!(rendered.contains("\\x0a"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn repository_selected_clean_filter_is_refused() {
        let (root, run, parent) = repository();
        std::fs::write(
            root.path().join(".gitattributes"),
            "tracked.txt filter=host-command\n",
        )
        .expect("attributes");
        std::fs::write(root.path().join("tracked.txt"), "changed\n").expect("changed file");

        assert!(matches!(
            prepare_commit_review(&run),
            Err(GitTransactionError::ActiveFilter { .. })
        ));
        assert_eq!(git(root.path(), &["rev-parse", "HEAD"]), parent);
        assert!(git(root.path(), &["diff", "--cached", "--name-only"]).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linked_worktree_uses_its_exact_ref_and_common_object_store() {
        let outer = tempfile::tempdir().expect("temporary repository parent");
        let main = outer.path().join("main");
        std::fs::create_dir(&main).expect("main repository directory");
        git(&main, &["init", "-b", "main"]);
        git(&main, &["config", "--local", "user.name", "Test User"]);
        git(
            &main,
            &["config", "--local", "user.email", "test@example.invalid"],
        );
        std::fs::write(main.join("tracked.txt"), "base\n").expect("base file");
        git(&main, &["add", "--", "tracked.txt"]);
        git(&main, &["commit", "-m", "base"]);
        let linked = outer.path().join("linked");
        git(
            &main,
            &[
                "worktree",
                "add",
                "-b",
                "feature/test-transaction",
                linked.to_str().expect("UTF-8 test path"),
            ],
        );
        let parent = git(&linked, &["rev-parse", "HEAD"]);
        std::fs::write(linked.join("tracked.txt"), "linked change\n").expect("linked change");
        let run = crate::tools::security::test_run_context_for(&linked);

        let review = prepare_commit_review(&run).expect("prepare linked-worktree review");
        assert_eq!(review.destination(), "refs/heads/feature/test-transaction");
        let approval = review
            .approve(review.paths(), review.destination(), "linked commit")
            .expect("approve linked-worktree review");
        let receipt = commit_approved_review(&run, review, approval).expect("commit linked review");

        assert_eq!(receipt.parent, parent);
        assert_eq!(receipt.commit_id, git(&linked, &["rev-parse", "HEAD"]));
        assert!(git(&linked, &["status", "--porcelain=v1"]).is_empty());
    }
}
