//! Verifiable, generation-atomic plugin installation transactions.
//!
//! Package bytes are staged on the destination filesystem, bounded and
//! validated as a complete tree, then published under an immutable digest
//! generation. The scope-owned `installed_plugins.json` entry is the sole
//! activation pointer and is replaced only after the generation is durable.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeSet, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::install::{InstallScope, InstalledPlugins, PluginInstallEntry};
use super::policy::{ArtifactTrustPolicy, PluginPolicy, PolicyAction};
use super::validate::{verify_signature, PluginSignature, PublicKey};
use super::Plugin;

/// Detached verification envelope shipped beside, but excluded from, package bytes.
pub const ARTIFACT_ENVELOPE_PATH: &str = ".claude-plugin/artifact.json";
/// Current detached statement and generation receipt schema.
pub const ARTIFACT_SCHEMA_VERSION: u32 = 1;

const MAX_TREE_FILES: usize = 4_096;
const MAX_TREE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_TREE_DEPTH: usize = 16;
const MAX_ENVELOPE_BYTES: u64 = 256 * 1024;
const MAX_DEPENDENCIES: usize = 128;
const MAX_TRANSACTIONS: usize = 64;
const LOCK_WAIT: Duration = Duration::from_secs(5);
const LOCK_RETRY: Duration = Duration::from_millis(25);

/// A dependency pinned into the signed closure of one plugin artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDependency {
    /// Canonical dependency package identity.
    pub package: String,
    /// Immutable dependency tree digest.
    pub artifact_digest: String,
    /// Immutable source revision, when the dependency is source-backed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
}

/// Canonical statement signed by plugin publishers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactStatement {
    /// Statement schema version.
    pub schema_version: u32,
    /// Exact manifest package name.
    pub package: String,
    /// Exact manifest version, when declared.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Publisher identity asserted by the statement and constrained by host policy.
    pub publisher: String,
    /// SHA-256 of the bounded canonical package tree.
    pub artifact_digest: String,
    /// Immutable source revision. Non-git packages use their artifact digest.
    pub source_revision: String,
    /// Monotonic publisher sequence used for rollback and mix-and-match defense.
    pub sequence: u64,
    /// Publisher statement time in Unix seconds.
    pub published_at_unix: u64,
    /// Optional expiry time used for freeze protection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,
    /// Complete, deterministically ordered dependency closure.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<ArtifactDependency>,
}

/// One detached signature over [`ArtifactStatement`]'s canonical bytes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSignature {
    /// Stable identifier of the host-approved signing key.
    pub key_id: String,
    /// Ed25519 signature over [`canonical_statement_bytes`].
    pub signature: PluginSignature,
}

/// Detached package verification metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactEnvelope {
    /// Artifact statement bound to package bytes.
    pub statement: ArtifactStatement,
    /// Detached signatures; signer trust comes only from host policy.
    pub signatures: Vec<ArtifactSignature>,
}

/// Source observed by the host while staging an artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSourceProvenance {
    /// Source family (`git`, `marketplace-path`, `local-directory`, or cache).
    pub kind: String,
    /// Canonical source locator observed by the host.
    pub locator: String,
    /// Ref/version requested by the caller, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_revision: Option<String>,
    /// Immutable revision observed after materialization.
    pub resolved_revision: String,
}

/// Strength of verification recorded for an activated generation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactVerificationLevel {
    /// Host computed and persisted an immutable digest, with no signature mandate.
    DigestBound,
    /// At least one legacy trusted-key action accepted a detached signature.
    Signed,
    /// A threshold publisher/namespace/revocation policy accepted the artifact.
    PolicyVerified,
}

/// Durable evidence for one immutable package generation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactGenerationReceipt {
    /// Receipt schema version.
    pub schema_version: u32,
    /// Tracker identity activated by this receipt.
    pub plugin_id: String,
    /// Verified signed statement (or a host-authored digest-only statement).
    pub statement: ArtifactStatement,
    /// Host-observed source provenance.
    pub source: ArtifactSourceProvenance,
    /// Distinct signer IDs that passed the applicable host policy.
    pub verified_signers: Vec<String>,
    /// Verification strength reached during staging.
    pub verification: ArtifactVerificationLevel,
    /// Host activation time in Unix seconds.
    pub activated_at_unix: u64,
}

/// Typed failures from staged package verification and activation.
#[derive(Debug, thiserror::Error)]
pub enum PluginTransactionError {
    /// A filesystem operation failed.
    #[error("plugin transaction I/O failed during {operation}: {source}")]
    Io {
        /// Operation that failed.
        operation: &'static str,
        /// Original filesystem error.
        #[source]
        source: io::Error,
    },
    /// A staged tree violated a bounded-package invariant.
    #[error("plugin package rejected: {0}")]
    InvalidPackage(String),
    /// Detached verification failed.
    #[error("plugin artifact verification failed: {0}")]
    Verification(String),
    /// A concurrent installer owns the transaction lock.
    #[error("plugin transaction lock is unavailable: {0}")]
    LockUnavailable(String),
    /// An update attempted rollback, freeze, or metadata mix-and-match.
    #[error("plugin update rejected: {0}")]
    Rollback(String),
    /// Durable activation state could not be committed.
    #[error("plugin activation failed: {0}")]
    Activation(String),
}

impl PluginTransactionError {
    const fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }
}

/// Canonical bytes over which detached signatures are computed.
///
/// Struct field order is fixed by this schema and dependency order is checked
/// before verification, making the serialized representation unambiguous.
///
/// # Errors
/// Returns [`PluginTransactionError::Verification`] if serialization fails.
pub fn canonical_statement_bytes(
    statement: &ArtifactStatement,
) -> Result<Vec<u8>, PluginTransactionError> {
    serde_json::to_vec(statement).map_err(|error| {
        PluginTransactionError::Verification(format!(
            "cannot serialize canonical artifact statement: {error}"
        ))
    })
}

/// Stable key ID used by detached envelopes for an Ed25519 public key.
#[must_use]
pub fn public_key_id(key: &PublicKey) -> String {
    hex_digest(&key.0)
}

/// Compute the bounded canonical SHA-256 tree digest for a package directory.
///
/// The detached envelope and root Git administrative directory are excluded;
/// every other path, entry type, byte length, and file byte is covered.
///
/// # Errors
/// Returns a typed package or I/O error for links, special files, invalid
/// names, exceeded bounds, or unreadable entries.
pub fn digest_package_tree(root: &Path) -> Result<String, PluginTransactionError> {
    let metadata = fs::symlink_metadata(root)
        .map_err(|error| PluginTransactionError::io("inspect staged package root", error))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(PluginTransactionError::InvalidPackage(
            "package root must be a real directory, not a link or special file".to_string(),
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(b"openclaudia-plugin-tree-v1\0");
    let mut budget = TreeBudget::default();
    digest_directory(root, root, 0, &mut budget, &mut hasher)?;
    Ok(hex_bytes(&hasher.finalize()))
}

#[derive(Default)]
struct TreeBudget {
    files: usize,
    bytes: u64,
}

fn digest_directory(
    root: &Path,
    directory: &Path,
    depth: usize,
    budget: &mut TreeBudget,
    hasher: &mut Sha256,
) -> Result<(), PluginTransactionError> {
    if depth > MAX_TREE_DEPTH {
        return Err(PluginTransactionError::InvalidPackage(format!(
            "package exceeds maximum directory depth {MAX_TREE_DEPTH}"
        )));
    }
    let mut entries = fs::read_dir(directory)
        .map_err(|error| PluginTransactionError::io("read staged package directory", error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| PluginTransactionError::io("enumerate staged package directory", error))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);

    for entry in entries {
        let path = entry.path();
        let relative = path.strip_prefix(root).map_err(|_| {
            PluginTransactionError::InvalidPackage("package entry escaped its root".to_string())
        })?;
        let relative_text = relative.to_str().ok_or_else(|| {
            PluginTransactionError::InvalidPackage(format!(
                "package path is not valid UTF-8: {}",
                relative.display()
            ))
        })?;
        if relative_text == ".git" || relative_text.starts_with(".git/") {
            continue;
        }
        if relative_text == ARTIFACT_ENVELOPE_PATH {
            continue;
        }

        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| PluginTransactionError::io("inspect staged package entry", error))?;
        if metadata.file_type().is_symlink() {
            return Err(PluginTransactionError::InvalidPackage(format!(
                "symbolic links are not permitted in plugin packages: {relative_text}"
            )));
        }
        if metadata.is_dir() {
            hash_record(hasher, b'D', relative_text.as_bytes(), 0);
            digest_directory(root, &path, depth.saturating_add(1), budget, hasher)?;
        } else if metadata.is_file() {
            budget.files = budget.files.saturating_add(1);
            if budget.files > MAX_TREE_FILES {
                return Err(PluginTransactionError::InvalidPackage(format!(
                    "package exceeds maximum file count {MAX_TREE_FILES}"
                )));
            }
            let length = metadata.len();
            if length > MAX_FILE_BYTES {
                return Err(PluginTransactionError::InvalidPackage(format!(
                    "package file {relative_text} exceeds {MAX_FILE_BYTES} bytes"
                )));
            }
            budget.bytes = budget.bytes.saturating_add(length);
            if budget.bytes > MAX_TREE_BYTES {
                return Err(PluginTransactionError::InvalidPackage(format!(
                    "package exceeds aggregate byte limit {MAX_TREE_BYTES}"
                )));
            }
            hash_record(hasher, b'F', relative_text.as_bytes(), length);
            let mut file = File::open(&path)
                .map_err(|error| PluginTransactionError::io("open staged package file", error))?;
            let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
            loop {
                let read = file.read(&mut buffer).map_err(|error| {
                    PluginTransactionError::io("read staged package file", error)
                })?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
        } else {
            return Err(PluginTransactionError::InvalidPackage(format!(
                "special filesystem entries are not permitted: {relative_text}"
            )));
        }
    }
    Ok(())
}

fn hash_record(hasher: &mut Sha256, kind: u8, path: &[u8], length: u64) {
    hasher.update([kind]);
    hasher.update(u64::try_from(path.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(path);
    hasher.update(length.to_be_bytes());
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_bytes(&hasher.finalize())
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn unix_now() -> Result<u64, PluginTransactionError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| {
            PluginTransactionError::Activation(format!("system clock precedes Unix epoch: {error}"))
        })
}

fn read_envelope(root: &Path) -> Result<Option<ArtifactEnvelope>, PluginTransactionError> {
    let path = root.join(ARTIFACT_ENVELOPE_PATH);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(PluginTransactionError::io(
                "inspect artifact envelope",
                error,
            ))
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(PluginTransactionError::Verification(
            "artifact envelope must be a real regular file".to_string(),
        ));
    }
    if metadata.len() > MAX_ENVELOPE_BYTES {
        return Err(PluginTransactionError::Verification(format!(
            "artifact envelope exceeds {MAX_ENVELOPE_BYTES} bytes"
        )));
    }
    let bytes = fs::read(&path)
        .map_err(|error| PluginTransactionError::io("read artifact envelope", error))?;
    serde_json::from_slice(&bytes).map(Some).map_err(|error| {
        PluginTransactionError::Verification(format!("invalid artifact envelope: {error}"))
    })
}

fn validate_statement(
    statement: &ArtifactStatement,
    plugin: &Plugin,
    digest: &str,
    source: &ArtifactSourceProvenance,
    now: u64,
) -> Result<(), PluginTransactionError> {
    if statement.schema_version != ARTIFACT_SCHEMA_VERSION {
        return Err(PluginTransactionError::Verification(format!(
            "unsupported artifact statement schema {}",
            statement.schema_version
        )));
    }
    if statement.package != plugin.name()
        || statement.version != plugin.manifest.version
        || statement.artifact_digest != digest
        || statement.source_revision != source.resolved_revision
    {
        return Err(PluginTransactionError::Verification(
            "artifact statement does not match the staged package name, version, digest, or source revision"
                .to_string(),
        ));
    }
    if statement.publisher.trim().is_empty() || statement.published_at_unix == 0 {
        return Err(PluginTransactionError::Verification(
            "artifact statement publisher and publication time are required".to_string(),
        ));
    }
    if statement.expires_at_unix.is_some_and(|expiry| now > expiry) {
        return Err(PluginTransactionError::Verification(
            "artifact statement is expired (freeze protection)".to_string(),
        ));
    }
    if statement.dependencies.len() > MAX_DEPENDENCIES {
        return Err(PluginTransactionError::Verification(format!(
            "dependency closure exceeds {MAX_DEPENDENCIES} entries"
        )));
    }
    let mut previous: Option<&ArtifactDependency> = None;
    let mut names = HashSet::new();
    for dependency in &statement.dependencies {
        if dependency.package.trim().is_empty()
            || !valid_digest(&dependency.artifact_digest)
            || dependency
                .source_revision
                .as_ref()
                .is_some_and(|revision| revision.trim().is_empty())
            || !names.insert(dependency.package.as_str())
        {
            return Err(PluginTransactionError::Verification(
                "dependency closure contains an invalid or duplicate immutable pin".to_string(),
            ));
        }
        if previous.is_some_and(|prior| prior >= dependency) {
            return Err(PluginTransactionError::Verification(
                "dependency closure must be strictly sorted in canonical order".to_string(),
            ));
        }
        previous = Some(dependency);
    }
    Ok(())
}

fn verify_legacy_keys(
    envelope: &ArtifactEnvelope,
    payload: &[u8],
    trusted_keys: &[PublicKey],
) -> Result<Vec<String>, PluginTransactionError> {
    for key in trusted_keys {
        let key_id = public_key_id(key);
        if envelope.signatures.iter().any(|candidate| {
            candidate.key_id == key_id
                && verify_signature(payload, &candidate.signature, std::slice::from_ref(key))
                    .is_ok()
        }) {
            return Ok(vec![key_id]);
        }
    }
    Err(PluginTransactionError::Verification(
        "no detached artifact signature matched a trusted key".to_string(),
    ))
}

fn verify_artifact_policy(
    envelope: &ArtifactEnvelope,
    payload: &[u8],
    trust: &ArtifactTrustPolicy,
    now: u64,
) -> Result<Vec<String>, PluginTransactionError> {
    if trust.signature_threshold == 0 || trust.signature_threshold > trust.trusted_signers.len() {
        return Err(PluginTransactionError::Verification(
            "host artifact signature threshold is invalid".to_string(),
        ));
    }
    if trust
        .revoked_artifact_digests
        .contains(&envelope.statement.artifact_digest)
    {
        return Err(PluginTransactionError::Verification(
            "artifact digest is revoked by host policy".to_string(),
        ));
    }
    if trust
        .max_statement_age_seconds
        .is_some_and(|maximum| now.saturating_sub(envelope.statement.published_at_unix) > maximum)
    {
        return Err(PluginTransactionError::Verification(
            "artifact statement is older than host freshness policy permits".to_string(),
        ));
    }

    let mut accepted = BTreeSet::new();
    for signature in &envelope.signatures {
        if accepted.contains(&signature.key_id)
            || trust.revoked_signer_ids.contains(&signature.key_id)
        {
            continue;
        }
        let Some(signer) = trust
            .trusted_signers
            .iter()
            .find(|signer| signer.key_id == signature.key_id)
        else {
            continue;
        };
        if !signer.authorizes(
            &envelope.statement.publisher,
            &envelope.statement.package,
            envelope.statement.published_at_unix,
        ) {
            continue;
        }
        if public_key_id(&signer.public_key) != signer.key_id {
            return Err(PluginTransactionError::Verification(format!(
                "host signer {} has a key-id/public-key mismatch",
                signer.key_id
            )));
        }
        if verify_signature(
            payload,
            &signature.signature,
            std::slice::from_ref(&signer.public_key),
        )
        .is_ok()
        {
            accepted.insert(signature.key_id.clone());
        }
    }
    if accepted.len() < trust.signature_threshold {
        return Err(PluginTransactionError::Verification(format!(
            "artifact has {} accepted signature(s), but policy requires {}",
            accepted.len(),
            trust.signature_threshold
        )));
    }
    Ok(accepted.into_iter().collect())
}

fn verify_staged_artifact(
    plugin_id: &str,
    root: &Path,
    source: ArtifactSourceProvenance,
    policy: &PluginPolicy,
) -> Result<ArtifactGenerationReceipt, PluginTransactionError> {
    let digest = digest_package_tree(root)?;
    let plugin = Plugin::load(root).map_err(|error| {
        PluginTransactionError::InvalidPackage(format!("plugin validation failed: {error}"))
    })?;
    let now = unix_now()?;
    let envelope = read_envelope(root)?;
    let requires_signature = policy.actions.iter().any(|action| {
        matches!(
            action,
            PolicyAction::RequireSignature { .. }
                | PolicyAction::RequireArtifactVerification { .. }
        )
    });
    if requires_signature && envelope.is_none() {
        return Err(PluginTransactionError::Verification(
            "detached artifact envelope is required by host policy".to_string(),
        ));
    }

    let mut level = ArtifactVerificationLevel::DigestBound;
    let mut verified_signers = BTreeSet::new();
    let statement = if requires_signature {
        let envelope = envelope.ok_or_else(|| {
            PluginTransactionError::Verification(
                "detached artifact envelope is required by host policy".to_string(),
            )
        })?;
        validate_statement(&envelope.statement, &plugin, &digest, &source, now)?;
        let payload = canonical_statement_bytes(&envelope.statement)?;
        for action in &policy.actions {
            match action {
                PolicyAction::RequireSignature { trusted_keys } => {
                    verified_signers.extend(verify_legacy_keys(&envelope, &payload, trusted_keys)?);
                    if level == ArtifactVerificationLevel::DigestBound {
                        level = ArtifactVerificationLevel::Signed;
                    }
                }
                PolicyAction::RequireArtifactVerification { trust } => {
                    verified_signers
                        .extend(verify_artifact_policy(&envelope, &payload, trust, now)?);
                    level = ArtifactVerificationLevel::PolicyVerified;
                }
            }
        }
        envelope.statement
    } else {
        // Unsigned package metadata is never allowed to create rollback,
        // freshness, publisher, or dependency authority. The host records
        // only what it directly observed from the staged bytes and source.
        ArtifactStatement {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            package: plugin.name().to_string(),
            version: plugin.manifest.version.clone(),
            publisher: "host-observed-unsigned".to_string(),
            artifact_digest: digest,
            source_revision: source.resolved_revision.clone(),
            sequence: 0,
            published_at_unix: now,
            expires_at_unix: None,
            dependencies: Vec::new(),
        }
    };

    Ok(ArtifactGenerationReceipt {
        schema_version: ARTIFACT_SCHEMA_VERSION,
        plugin_id: plugin_id.to_string(),
        statement,
        source,
        verified_signers: verified_signers.into_iter().collect(),
        verification: level,
        activated_at_unix: now,
    })
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum TransactionPhase {
    Staging,
    Verified,
    Published,
    Activated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransactionJournal {
    schema_version: u32,
    transaction_id: String,
    plugin_id: String,
    phase: TransactionPhase,
    generation_path: Option<PathBuf>,
}

struct TransactionLock {
    _file: File,
}

impl TransactionLock {
    fn acquire(root: &Path) -> Result<Self, PluginTransactionError> {
        fs::create_dir_all(root)
            .map_err(|error| PluginTransactionError::io("create plugin transaction root", error))?;
        let metadata = fs::symlink_metadata(root).map_err(|error| {
            PluginTransactionError::io("inspect plugin transaction root", error)
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(PluginTransactionError::LockUnavailable(
                "plugin storage root is not a real directory".to_string(),
            ));
        }
        let lock_path = root.join("transactions.lock");
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let file = options
            .open(&lock_path)
            .map_err(|error| PluginTransactionError::io("open plugin transaction lock", error))?;
        let started = Instant::now();
        loop {
            match try_lock_file(&file) {
                Ok(()) => return Ok(Self { _file: file }),
                Err(error)
                    if error.kind() == io::ErrorKind::Interrupted
                        || (error.kind() == io::ErrorKind::WouldBlock
                            && started.elapsed() < LOCK_WAIT) =>
                {
                    std::thread::sleep(LOCK_RETRY);
                }
                Err(error) => {
                    return Err(PluginTransactionError::LockUnavailable(error.to_string()));
                }
            }
        }
    }
}

#[cfg(unix)]
fn try_lock_file(file: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd as _;
    // SAFETY: `file` owns a live descriptor and `flock` retains no pointer.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn try_lock_file(file: &File) -> io::Result<()> {
    crate::windows_fs::lock_exclusive(file)
}

#[cfg(not(any(unix, windows)))]
fn try_lock_file(_: &File) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "plugin transactions require a supported interprocess file lock",
    ))
}

/// One same-filesystem plugin install/update transaction.
pub struct PluginInstallTransaction {
    _lock: TransactionLock,
    project_root: PathBuf,
    plugin_root: PathBuf,
    transaction_dir: PathBuf,
    package_stage: PathBuf,
    journal: TransactionJournal,
    source: ArtifactSourceProvenance,
    complete: bool,
}

impl PluginInstallTransaction {
    /// Create a durable staging journal while holding the project plugin lock.
    ///
    /// # Errors
    /// Returns a lock, I/O, or durable-state error if staging cannot begin.
    pub fn begin(
        project_root: &Path,
        plugin_id: &str,
        source: ArtifactSourceProvenance,
    ) -> Result<Self, PluginTransactionError> {
        let plugin_root = project_root.join(".openclaudia/plugins");
        let lock = TransactionLock::acquire(&plugin_root)?;
        let transactions = plugin_root.join(".transactions");
        fs::create_dir_all(&transactions)
            .map_err(|error| PluginTransactionError::io("create transaction directory", error))?;
        let transaction_id = uuid::Uuid::new_v4().simple().to_string();
        let transaction_dir = transactions.join(&transaction_id);
        fs::create_dir(&transaction_dir).map_err(|error| {
            PluginTransactionError::io("create transaction staging directory", error)
        })?;
        sync_directory(&transactions)?;
        let package_stage = transaction_dir.join("package");
        let journal = TransactionJournal {
            schema_version: ARTIFACT_SCHEMA_VERSION,
            transaction_id,
            plugin_id: plugin_id.to_string(),
            phase: TransactionPhase::Staging,
            generation_path: None,
        };
        write_json_atomic(&transaction_dir.join("transaction.json"), &journal)?;
        Ok(Self {
            _lock: lock,
            project_root: project_root.to_path_buf(),
            plugin_root,
            transaction_dir,
            package_stage,
            journal,
            source,
            complete: false,
        })
    }

    /// Destination into which the source fetch/copy must materialize the package.
    #[must_use]
    pub fn staging_path(&self) -> &Path {
        &self.package_stage
    }

    /// Bind the immutable revision observed after materialization.
    ///
    /// Git callers set the resolved commit; directory/cache callers bind the
    /// canonical tree digest. This must happen before verification.
    ///
    /// # Errors
    /// Returns [`PluginTransactionError::InvalidPackage`] for an empty revision.
    pub fn bind_resolved_revision(
        &mut self,
        resolved_revision: impl Into<String>,
    ) -> Result<(), PluginTransactionError> {
        let resolved_revision = resolved_revision.into();
        if resolved_revision.trim().is_empty() {
            return Err(PluginTransactionError::InvalidPackage(
                "resolved source revision cannot be empty".to_string(),
            ));
        }
        self.source.resolved_revision = resolved_revision;
        Ok(())
    }

    /// Replace a provisional source-derived identity with the validated
    /// package manifest name before verification and publication.
    ///
    /// Direct Git and offline-cache sources do not have an authoritative
    /// catalogue name. Their URL/cache labels are provenance only; the staged
    /// manifest owns the package identity.
    ///
    /// # Errors
    /// Returns an invalid-package error for unsafe names or after verification
    /// has begun.
    pub fn rebind_package_identity(
        &mut self,
        plugin_id: impl Into<String>,
    ) -> Result<(), PluginTransactionError> {
        if !matches!(self.journal.phase, TransactionPhase::Staging) {
            return Err(PluginTransactionError::InvalidPackage(
                "package identity cannot change after verification".to_string(),
            ));
        }
        let plugin_id = plugin_id.into();
        super::validate::validate_plugin_dir_name(&plugin_id).map_err(|error| {
            PluginTransactionError::InvalidPackage(format!(
                "invalid staged package identity: {error}"
            ))
        })?;
        self.journal.plugin_id = plugin_id;
        self.persist_journal()
    }

    /// Validate complete staged bytes and apply detached host policy.
    ///
    /// # Errors
    /// Returns a typed package, verification, or I/O error on rejection.
    pub fn verify(
        &mut self,
        policy: &PluginPolicy,
    ) -> Result<ArtifactGenerationReceipt, PluginTransactionError> {
        let git_admin = self.package_stage.join(".git");
        if let Ok(metadata) = fs::symlink_metadata(&git_admin) {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(PluginTransactionError::InvalidPackage(
                    "root .git entry is not a real directory".to_string(),
                ));
            }
            fs::remove_dir_all(&git_admin)
                .map_err(|error| PluginTransactionError::io("remove staged Git metadata", error))?;
        }
        let receipt = verify_staged_artifact(
            &self.journal.plugin_id,
            &self.package_stage,
            self.source.clone(),
            policy,
        )?;
        let envelope = self.package_stage.join(ARTIFACT_ENVELOPE_PATH);
        if envelope.exists() {
            fs::remove_file(&envelope).map_err(|error| {
                PluginTransactionError::io("remove verified detached envelope from package", error)
            })?;
        }
        sync_package_tree(&self.package_stage)?;
        self.journal.phase = TransactionPhase::Verified;
        self.persist_journal()?;
        Ok(receipt)
    }

    /// Publish and activate a verified generation, retaining its predecessor.
    ///
    /// # Errors
    /// Returns a typed rollback, publication, or activation error. Before the
    /// tracker commit, any error leaves the previous active generation intact.
    pub fn activate(
        mut self,
        receipt: &ArtifactGenerationReceipt,
    ) -> Result<PathBuf, PluginTransactionError> {
        let mut installed = InstalledPlugins::load(&self.project_root);
        let previous =
            active_entry(&installed, &self.journal.plugin_id, &self.project_root).cloned();
        if let Some(previous_entry) = previous.as_ref() {
            if let Some(previous_receipt) =
                read_generation_receipt(Path::new(&previous_entry.install_path))?
            {
                validate_successor(&previous_receipt, receipt)?;
            }
        }

        let package_key = hex_digest(self.journal.plugin_id.as_bytes());
        let generations = self.plugin_root.join(".generations").join(package_key);
        fs::create_dir_all(&generations).map_err(|error| {
            PluginTransactionError::io("create package generations directory", error)
        })?;
        let generation = generations.join(&receipt.statement.artifact_digest);
        let package_path = generation.join("package");
        if generation.exists() {
            verify_generation(&package_path, Some(receipt))?;
            if self.package_stage.exists() {
                fs::remove_dir_all(&self.package_stage).map_err(|error| {
                    PluginTransactionError::io("remove duplicate staged generation", error)
                })?;
            }
        } else {
            // Persist the intended final path before publication. Recovery can
            // then remove a fully-renamed but not-yet-activated generation
            // after a process crash, while temporary-directory cleanup covers
            // crashes before the rename.
            self.journal.generation_path = Some(generation.clone());
            self.persist_journal()?;
            let temporary = generations.join(format!(
                ".{}.{}.tmp",
                receipt.statement.artifact_digest, self.journal.transaction_id
            ));
            let publication = (|| {
                fs::create_dir(&temporary).map_err(|error| {
                    PluginTransactionError::io("create generation publication directory", error)
                })?;
                fs::rename(&self.package_stage, temporary.join("package")).map_err(|error| {
                    PluginTransactionError::io("move verified package into generation", error)
                })?;
                write_json_atomic(&temporary.join("receipt.json"), receipt)?;
                write_file_durable(
                    &temporary.join("ready"),
                    b"openclaudia-plugin-generation-v1\n",
                )?;
                sync_directory(&temporary)?;
                fs::rename(&temporary, &generation).map_err(|error| {
                    PluginTransactionError::io("publish immutable plugin generation", error)
                })?;
                sync_directory(&generations)
            })();
            if let Err(error) = publication {
                let _ = fs::remove_dir_all(&temporary);
                let _ = fs::remove_dir_all(&generation);
                let _ = sync_directory(&generations);
                return Err(error);
            }
        }

        self.journal.phase = TransactionPhase::Published;
        self.journal.generation_path = Some(generation);
        self.persist_journal()?;

        let installed_at = previous
            .as_ref()
            .and_then(|entry| entry.installed_at.clone())
            .or_else(|| Some(chrono::Utc::now().to_rfc3339()));
        installed.upsert(
            &self.journal.plugin_id,
            PluginInstallEntry {
                scope: InstallScope::Project,
                project_path: Some(self.project_root.to_string_lossy().to_string()),
                install_path: package_path.to_string_lossy().to_string(),
                version: receipt.statement.version.clone(),
                installed_at,
                last_updated: previous.as_ref().map(|_| chrono::Utc::now().to_rfc3339()),
                git_commit_sha: (receipt.source.kind == "git")
                    .then(|| receipt.source.resolved_revision.clone()),
            },
        );
        installed.save(&self.project_root).map_err(|error| {
            PluginTransactionError::Activation(format!(
                "could not atomically publish active generation: {error}"
            ))
        })?;

        // Activation is committed once the tracker rename succeeds. Cleanup
        // is recovery-owned bookkeeping and cannot turn that committed effect
        // into a reported install failure.
        self.journal.phase = TransactionPhase::Activated;
        let _ = self.persist_journal();
        let _ = fs::remove_dir_all(&self.transaction_dir);
        if let Some(parent) = self.transaction_dir.parent() {
            let _ = sync_directory(parent);
        }
        self.complete = true;
        Ok(package_path)
    }

    fn persist_journal(&self) -> Result<(), PluginTransactionError> {
        write_json_atomic(
            &self.transaction_dir.join("transaction.json"),
            &self.journal,
        )
    }
}

impl Drop for PluginInstallTransaction {
    fn drop(&mut self) {
        if !self.complete && !matches!(self.journal.phase, TransactionPhase::Published) {
            let _ = fs::remove_dir_all(&self.transaction_dir);
        }
    }
}

fn active_entry<'a>(
    installed: &'a InstalledPlugins,
    plugin_id: &str,
    project_root: &Path,
) -> Option<&'a PluginInstallEntry> {
    let project = project_root.to_string_lossy();
    installed.plugins.get(plugin_id).and_then(|entries| {
        entries.iter().find(|entry| {
            matches!(&entry.scope, InstallScope::Project | InstallScope::Local)
                && entry.project_path.as_deref() == Some(project.as_ref())
        })
    })
}

fn validate_successor(
    previous: &ArtifactGenerationReceipt,
    next: &ArtifactGenerationReceipt,
) -> Result<(), PluginTransactionError> {
    if previous.plugin_id != next.plugin_id {
        return Err(PluginTransactionError::Rollback(
            "successor attempts to change the activated package identity".to_string(),
        ));
    }
    if previous.statement.publisher != next.statement.publisher
        && previous.verification != ArtifactVerificationLevel::DigestBound
    {
        return Err(PluginTransactionError::Rollback(
            "verified publisher changed without an explicit trust transition".to_string(),
        ));
    }
    if previous.verification == ArtifactVerificationLevel::DigestBound
        && (previous.source.kind != next.source.kind
            || previous.source.locator != next.source.locator)
    {
        return Err(PluginTransactionError::Rollback(
            "unsigned update changed its observed source identity".to_string(),
        ));
    }
    if next.statement.sequence < previous.statement.sequence
        || next.statement.published_at_unix < previous.statement.published_at_unix
    {
        return Err(PluginTransactionError::Rollback(
            "signed sequence or publication time moved backwards".to_string(),
        ));
    }
    if previous.verification != ArtifactVerificationLevel::DigestBound
        && next.statement.sequence == previous.statement.sequence
        && next.statement.artifact_digest != previous.statement.artifact_digest
    {
        return Err(PluginTransactionError::Rollback(
            "one signed sequence names different artifact bytes (mix-and-match)".to_string(),
        ));
    }
    if previous.verification != ArtifactVerificationLevel::DigestBound
        && next.verification == ArtifactVerificationLevel::DigestBound
    {
        return Err(PluginTransactionError::Rollback(
            "update would downgrade a signed generation to unsigned bytes".to_string(),
        ));
    }
    Ok(())
}

/// Verify an activated immutable generation before discovery loads it.
///
/// Legacy flat installs return `Ok(None)` for compatibility. Generation-backed
/// installs fail closed on missing readiness, receipt, or changed package bytes.
///
/// # Errors
/// Returns a typed verification or I/O error for an incomplete or changed generation.
pub fn verify_installed_generation(
    package_path: &Path,
) -> Result<Option<ArtifactGenerationReceipt>, PluginTransactionError> {
    read_generation_receipt(package_path)?.map_or(Ok(None), |receipt| {
        verify_generation(package_path, Some(&receipt))?;
        Ok(Some(receipt))
    })
}

fn read_generation_receipt(
    package_path: &Path,
) -> Result<Option<ArtifactGenerationReceipt>, PluginTransactionError> {
    let Some(generation) = package_path.parent() else {
        return Ok(None);
    };
    let path = generation.join("receipt.json");
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(PluginTransactionError::io(
                "inspect generation receipt",
                error,
            ))
        }
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_ENVELOPE_BYTES
    {
        return Err(PluginTransactionError::Verification(
            "generation receipt is missing, linked, or oversized".to_string(),
        ));
    }
    let bytes = fs::read(path)
        .map_err(|error| PluginTransactionError::io("read generation receipt", error))?;
    serde_json::from_slice(&bytes).map(Some).map_err(|error| {
        PluginTransactionError::Verification(format!("invalid generation receipt: {error}"))
    })
}

fn verify_generation(
    package_path: &Path,
    expected: Option<&ArtifactGenerationReceipt>,
) -> Result<(), PluginTransactionError> {
    let generation = package_path.parent().ok_or_else(|| {
        PluginTransactionError::Verification("generation package has no parent".to_string())
    })?;
    let ready = generation.join("ready");
    let ready_meta = fs::symlink_metadata(&ready)
        .map_err(|error| PluginTransactionError::io("inspect generation ready marker", error))?;
    if ready_meta.file_type().is_symlink() || !ready_meta.is_file() {
        return Err(PluginTransactionError::Verification(
            "generation has no valid ready marker".to_string(),
        ));
    }
    let stored = read_generation_receipt(package_path)?.ok_or_else(|| {
        PluginTransactionError::Verification("generation receipt is missing".to_string())
    })?;
    if expected.is_some_and(|receipt| !receipts_name_same_generation(receipt, &stored)) {
        return Err(PluginTransactionError::Verification(
            "existing generation receipt conflicts with the verified activation receipt"
                .to_string(),
        ));
    }
    let receipt = stored;
    let actual = digest_package_tree(package_path)?;
    if actual != receipt.statement.artifact_digest {
        return Err(PluginTransactionError::Verification(format!(
            "activated generation digest changed: expected {}, observed {actual}",
            receipt.statement.artifact_digest
        )));
    }
    Ok(())
}

fn receipts_name_same_generation(
    candidate: &ArtifactGenerationReceipt,
    stored: &ArtifactGenerationReceipt,
) -> bool {
    candidate.schema_version == stored.schema_version
        && candidate.plugin_id == stored.plugin_id
        && candidate.statement == stored.statement
        && candidate.source.kind == stored.source.kind
        && candidate.source.locator == stored.source.locator
        && candidate.source.resolved_revision == stored.source.resolved_revision
        && candidate.verified_signers == stored.verified_signers
        && candidate.verification == stored.verification
}

fn sync_package_tree(root: &Path) -> Result<(), PluginTransactionError> {
    let mut entries = fs::read_dir(root)
        .map_err(|error| PluginTransactionError::io("read package for durability sync", error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            PluginTransactionError::io("enumerate package for durability sync", error)
        })?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            PluginTransactionError::io("inspect package during durability sync", error)
        })?;
        if metadata.file_type().is_symlink() {
            return Err(PluginTransactionError::InvalidPackage(format!(
                "package changed to a symlink during staging: {}",
                path.display()
            )));
        }
        if metadata.is_dir() {
            sync_package_tree(&path)?;
        } else if metadata.is_file() {
            File::open(&path)
                .and_then(|file| file.sync_all())
                .map_err(|error| PluginTransactionError::io("synchronize package file", error))?;
        } else {
            return Err(PluginTransactionError::InvalidPackage(format!(
                "package changed to a special file during staging: {}",
                path.display()
            )));
        }
    }
    sync_directory(root)
}

/// Reconcile abandoned transaction-owned staging before plugin discovery.
///
/// A tracker already pointing at the published generation proves activation
/// committed; otherwise the transaction's unpublished generation is removed.
///
/// # Errors
/// Returns a typed lock, recovery-state, or I/O error if reconciliation cannot finish.
pub fn recover_pending_transactions(
    project_root: &Path,
    installed: &InstalledPlugins,
) -> Result<(), PluginTransactionError> {
    let plugin_root = project_root.join(".openclaudia/plugins");
    if !plugin_root.exists() {
        return Ok(());
    }
    let _lock = TransactionLock::acquire(&plugin_root)?;
    cleanup_orphan_publication_temps(&plugin_root)?;
    let transactions = plugin_root.join(".transactions");
    if !transactions.exists() {
        return Ok(());
    }
    let mut entries = fs::read_dir(&transactions)
        .map_err(|error| PluginTransactionError::io("read recovery transaction directory", error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| PluginTransactionError::io("enumerate recovery transactions", error))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    if entries.len() > MAX_TRANSACTIONS {
        return Err(PluginTransactionError::Activation(format!(
            "{} pending plugin transactions exceed recovery limit {MAX_TRANSACTIONS}",
            entries.len()
        )));
    }
    let active_paths = installed
        .plugins
        .values()
        .flatten()
        .map(|entry| PathBuf::from(&entry.install_path))
        .collect::<HashSet<_>>();
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| PluginTransactionError::io("inspect recovery transaction", error))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(PluginTransactionError::Activation(format!(
                "unsafe entry in plugin transaction recovery directory: {}",
                path.display()
            )));
        }
        let journal = read_journal(&path.join("transaction.json"));
        if let Ok(journal) = journal {
            if let Some(generation) = journal.generation_path {
                validate_recovery_generation_path(&plugin_root, &generation)?;
                let package = generation.join("package");
                if !active_paths.contains(&package) {
                    match fs::symlink_metadata(&generation) {
                        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
                            return Err(PluginTransactionError::Activation(format!(
                                "unsafe unactivated plugin generation: {}",
                                generation.display()
                            )));
                        }
                        Ok(_) => {
                            fs::remove_dir_all(&generation).map_err(|error| {
                                PluginTransactionError::io(
                                    "remove unactivated published generation",
                                    error,
                                )
                            })?;
                        }
                        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                        Err(error) => {
                            return Err(PluginTransactionError::io(
                                "inspect unactivated published generation",
                                error,
                            ));
                        }
                    }
                }
            }
        }
        fs::remove_dir_all(&path)
            .map_err(|error| PluginTransactionError::io("remove abandoned transaction", error))?;
    }
    sync_directory(&transactions)?;
    Ok(())
}

fn validate_recovery_generation_path(
    plugin_root: &Path,
    generation: &Path,
) -> Result<(), PluginTransactionError> {
    let generations = plugin_root.join(".generations");
    let relative = generation.strip_prefix(&generations).map_err(|_| {
        PluginTransactionError::Activation(format!(
            "transaction journal generation escapes plugin storage: {}",
            generation.display()
        ))
    })?;
    let mut components = relative.components();
    let valid_component = |component| match component {
        Some(Component::Normal(value)) => value.to_str().is_some_and(valid_digest),
        _ => false,
    };
    if !valid_component(components.next())
        || !valid_component(components.next())
        || components.next().is_some()
    {
        return Err(PluginTransactionError::Activation(format!(
            "transaction journal generation has an invalid storage identity: {}",
            generation.display()
        )));
    }
    Ok(())
}

fn cleanup_orphan_publication_temps(plugin_root: &Path) -> Result<(), PluginTransactionError> {
    let generations = plugin_root.join(".generations");
    if !generations.exists() {
        return Ok(());
    }
    let mut buckets = fs::read_dir(&generations)
        .map_err(|error| PluginTransactionError::io("read plugin generation directory", error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            PluginTransactionError::io("enumerate plugin generation directory", error)
        })?;
    buckets.sort_by_key(std::fs::DirEntry::file_name);
    if buckets.len() > MAX_TREE_FILES {
        return Err(PluginTransactionError::Activation(format!(
            "plugin generation bucket count exceeds recovery limit {MAX_TREE_FILES}"
        )));
    }
    let mut inspected = 0_usize;
    for bucket in buckets {
        let bucket_path = bucket.path();
        let metadata = fs::symlink_metadata(&bucket_path).map_err(|error| {
            PluginTransactionError::io("inspect plugin generation bucket", error)
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(PluginTransactionError::Activation(format!(
                "unsafe entry in plugin generation directory: {}",
                bucket_path.display()
            )));
        }
        let mut entries = fs::read_dir(&bucket_path)
            .map_err(|error| PluginTransactionError::io("read generation bucket", error))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| PluginTransactionError::io("enumerate generation bucket", error))?;
        entries.sort_by_key(std::fs::DirEntry::file_name);
        inspected = inspected.checked_add(entries.len()).ok_or_else(|| {
            PluginTransactionError::Activation(
                "plugin generation recovery entry count overflowed".to_string(),
            )
        })?;
        if inspected > MAX_TREE_FILES {
            return Err(PluginTransactionError::Activation(format!(
                "plugin generation count exceeds recovery limit {MAX_TREE_FILES}"
            )));
        }
        for entry in entries {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.starts_with('.')
                || !Path::new(name)
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("tmp"))
            {
                continue;
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                PluginTransactionError::io("inspect generation publication temp", error)
            })?;
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                return Err(PluginTransactionError::Activation(format!(
                    "unsafe generation publication temp: {}",
                    path.display()
                )));
            }
            fs::remove_dir_all(&path).map_err(|error| {
                PluginTransactionError::io("remove orphan generation publication temp", error)
            })?;
        }
        sync_directory(&bucket_path)?;
    }
    sync_directory(&generations)
}

fn read_journal(path: &Path) -> Result<TransactionJournal, PluginTransactionError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| PluginTransactionError::io("inspect transaction journal", error))?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_ENVELOPE_BYTES
    {
        return Err(PluginTransactionError::Activation(
            "transaction journal is missing, linked, or oversized".to_string(),
        ));
    }
    let bytes = fs::read(path)
        .map_err(|error| PluginTransactionError::io("read transaction journal", error))?;
    serde_json::from_slice(&bytes).map_err(|error| {
        PluginTransactionError::Activation(format!("invalid transaction journal: {error}"))
    })
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), PluginTransactionError> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| {
        PluginTransactionError::Activation(format!(
            "cannot serialize durable plugin state: {error}"
        ))
    })?;
    let parent = path.parent().ok_or_else(|| {
        PluginTransactionError::Activation("durable plugin state has no parent".to_string())
    })?;
    fs::create_dir_all(parent)
        .map_err(|error| PluginTransactionError::io("create durable state directory", error))?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("state"),
        uuid::Uuid::new_v4().simple()
    ));
    write_file_durable(&temporary, &bytes)?;
    crate::file_error::replace_file_atomic(&temporary, path).map_err(|error| {
        let _ = fs::remove_file(&temporary);
        PluginTransactionError::io("atomically replace durable plugin state", error)
    })?;
    sync_directory(parent)
}

fn write_file_durable(path: &Path, bytes: &[u8]) -> Result<(), PluginTransactionError> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|error| PluginTransactionError::io("create durable plugin file", error))?;
    file.write_all(bytes)
        .map_err(|error| PluginTransactionError::io("write durable plugin file", error))?;
    file.sync_all()
        .map_err(|error| PluginTransactionError::io("synchronize durable plugin file", error))
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), PluginTransactionError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| PluginTransactionError::io("synchronize plugin directory", error))
}

#[cfg(not(unix))]
const fn sync_directory(_: &Path) -> Result<(), PluginTransactionError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_removes_orphan_publication_temp_without_tracker_change() {
        let project = tempfile::tempdir().expect("project");
        let bucket = project
            .path()
            .join(".openclaudia/plugins/.generations/package-digest");
        let orphan = bucket.join(".artifact.transaction.tmp");
        fs::create_dir_all(orphan.join("package")).expect("orphan publication");
        fs::write(orphan.join("package/partial"), b"partial").expect("partial package");

        recover_pending_transactions(project.path(), &InstalledPlugins::default())
            .expect("recovery");

        assert!(!orphan.exists());
        assert!(bucket.exists());
    }

    #[test]
    fn recovery_rejects_journal_generation_outside_plugin_storage() {
        let project = tempfile::tempdir().expect("project");
        let outside = project.path().join("must-survive");
        fs::create_dir(&outside).expect("outside directory");
        fs::write(outside.join("marker"), b"keep").expect("outside marker");

        let transaction = project
            .path()
            .join(".openclaudia/plugins/.transactions/transaction");
        fs::create_dir_all(&transaction).expect("transaction directory");
        write_json_atomic(
            &transaction.join("transaction.json"),
            &TransactionJournal {
                schema_version: ARTIFACT_SCHEMA_VERSION,
                transaction_id: "transaction".to_string(),
                plugin_id: "example".to_string(),
                phase: TransactionPhase::Published,
                generation_path: Some(outside.clone()),
            },
        )
        .expect("journal");

        let error = recover_pending_transactions(project.path(), &InstalledPlugins::default())
            .expect_err("out-of-root generation must be rejected");

        assert!(matches!(error, PluginTransactionError::Activation(_)));
        assert!(outside.join("marker").is_file());
    }
}
