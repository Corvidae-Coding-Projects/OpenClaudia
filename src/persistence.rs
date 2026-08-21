//! Descriptor-relative, generation-checked persistent file storage.
//!
//! A [`PersistentStorage`] is an explicit filesystem capability: its trusted
//! root is opened once, pinned by descriptor, and every target is resolved
//! beneath that descriptor without following links. Commits use a per-target
//! advisory lock, a bounded owner-only staging file, `fsync`, descriptor-
//! relative rename, and parent-directory `fsync`.
//!
//! Publication and durability are deliberately separate states. If the
//! rename succeeds but the directory sync fails, callers receive
//! [`CommitState::PublishedDurabilityUncertain`] with the published content
//! generation. Retrying the same bytes with the original expected generation
//! reconciles the visible generation, syncs the directory, and returns
//! [`CommitState::Recovered`] rather than publishing twice.
//!
//! Generation exclusion is cooperative: every `OpenClaudia` writer for a
//! target must use this API and its sidecar lock. POSIX advisory locks cannot
//! stop an unrelated same-user process that deliberately bypasses the API;
//! host root selection and process/sandbox policy remain the authority against
//! such a peer.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(unix)]
use std::path::Component;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::runtime::ContentDigest;

#[cfg(unix)]
const MAX_TARGET_COMPONENTS: usize = 32;
#[cfg(unix)]
const MAX_TARGET_BYTES: usize = 4_096;
#[cfg(unix)]
const INTERNAL_SIDECAR_PREFIX: &[u8] = b".openclaudia-persistence-";
#[cfg(all(unix, not(test)))]
const LOCK_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);
#[cfg(all(unix, test))]
const LOCK_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(75);
#[cfg(unix)]
const LOCK_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(5);

/// Semantic class of a persisted artifact.
///
/// Classes have fixed byte ceilings and restrictive creation modes so a
/// caller cannot silently turn a credential-sized operation into an
/// unbounded artifact write or apply secret-file policy accidentally to an
/// unrelated surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FileClass {
    /// Provider credentials, refresh material, and secret references.
    Credentials,
    /// Validated `OpenClaudia` configuration or managed settings.
    Configuration,
    /// Small canonical application state and transactional manifests.
    State,
    /// Canonical portable technical-memory manifests, checkpoints, and parts.
    ///
    /// This class is owner-private and capped before allocation so a package
    /// claiming a small part cannot cause the generic artifact ceiling to be
    /// materialized during validation.
    PortableMemoryPackage,
    /// Session, transcript, and checkpoint documents.
    Session,
    /// Verification, ledger, and evidence receipts.
    Evidence,
    /// Bounded opaque cache or artifact content.
    Artifact,
}

impl FileClass {
    /// Maximum number of bytes accepted for this class.
    #[must_use]
    pub const fn max_bytes(self) -> u64 {
        match self {
            Self::Credentials => 1_024 * 1_024,
            Self::Configuration | Self::PortableMemoryPackage => 4 * 1_024 * 1_024,
            Self::State => 16 * 1_024 * 1_024,
            Self::Session | Self::Evidence => 64 * 1_024 * 1_024,
            Self::Artifact => 256 * 1_024 * 1_024,
        }
    }

    #[cfg(unix)]
    const fn unix_create_mode(self) -> u32 {
        // Persistent agent state is private by default. A later exporter may
        // deliberately copy a reviewed artifact to a broader destination;
        // the canonical store never needs group/world access.
        let _ = self;
        0o600
    }

    #[cfg(unix)]
    const fn unix_allowed_existing_mode(self) -> u32 {
        match self {
            // Legacy session/config/artifact files were commonly created
            // under umask as 0644. Their explicit class may ingest that
            // read-only compatibility shape and the next commit narrows it to
            // the canonical 0600 creation mode. Secret and canonical state
            // classes never admit group/world visibility.
            Self::Configuration | Self::Session | Self::Artifact => 0o644,
            Self::Credentials | Self::State | Self::Evidence | Self::PortableMemoryPackage => 0o600,
        }
    }
}

/// Content identity used as the optimistic generation precondition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state", content = "digest")]
#[non_exhaustive]
pub enum StorageGeneration {
    /// No leaf exists at the target name.
    Missing,
    /// A regular, validated file exists with this exact content digest.
    Present(ContentDigest),
}

impl StorageGeneration {
    #[cfg(unix)]
    fn for_bytes(bytes: &[u8]) -> Self {
        Self::Present(ContentDigest::sha256(bytes))
    }
}

impl fmt::Display for StorageGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => formatter.write_str("missing"),
            Self::Present(digest) => digest.fmt(formatter),
        }
    }
}

struct DiagnosticGeneration {
    generation: StorageGeneration,
    class: FileClass,
}

impl DiagnosticGeneration {
    const fn new(generation: StorageGeneration, class: FileClass) -> Self {
        Self { generation, class }
    }
}

impl fmt::Display for DiagnosticGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.class == FileClass::Credentials
            && matches!(self.generation, StorageGeneration::Present(_))
        {
            formatter.write_str("[REDACTED]")
        } else {
            self.generation.fmt(formatter)
        }
    }
}

impl fmt::Debug for DiagnosticGeneration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, formatter)
    }
}

/// Bounded file content whose owned allocation is erased on final drop.
#[derive(PartialEq, Eq)]
pub struct BoundedFileBytes(zeroize::Zeroizing<Vec<u8>>);

impl BoundedFileBytes {
    #[cfg(unix)]
    fn new(bytes: Vec<u8>) -> Self {
        Self(zeroize::Zeroizing::new(bytes))
    }

    /// Number of observed bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the observed file was empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for BoundedFileBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedFileBytes")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

/// Output-only result of a bounded descriptor-relative observation.
#[derive(PartialEq, Eq)]
pub struct ReadState {
    class: FileClass,
    generation: StorageGeneration,
    bytes: Option<BoundedFileBytes>,
}

impl ReadState {
    #[cfg(unix)]
    const fn missing(class: FileClass) -> Self {
        Self {
            class,
            generation: StorageGeneration::Missing,
            bytes: None,
        }
    }

    #[cfg(unix)]
    fn present(class: FileClass, bytes: Vec<u8>) -> Self {
        Self {
            class,
            generation: StorageGeneration::for_bytes(&bytes),
            bytes: Some(BoundedFileBytes::new(bytes)),
        }
    }

    /// File class applied while validating this observation.
    #[must_use]
    pub const fn class(&self) -> FileClass {
        self.class
    }

    /// Generation suitable for a later [`PersistentStorage::commit`].
    #[must_use]
    pub const fn generation(&self) -> StorageGeneration {
        self.generation
    }

    /// Borrow the redacting, zeroizing content handle, or return `None` when
    /// the target is missing.
    #[must_use]
    pub const fn bytes(&self) -> Option<&BoundedFileBytes> {
        self.bytes.as_ref()
    }

    /// Materialize exact bytes only for the duration of an explicit operation.
    ///
    /// The owned allocation remains zeroizing and its normal [`Debug`] surface
    /// remains redacted. Callers should parse or compare inside `operation`
    /// rather than copying sensitive content into a longer-lived buffer.
    pub fn expose_bytes<R>(&self, operation: impl FnOnce(Option<&[u8]>) -> R) -> R {
        operation(self.bytes.as_ref().map(|bytes| bytes.0.as_slice()))
    }
}

impl fmt::Debug for ReadState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("ReadState");
        debug.field("class", &self.class);
        debug.field(
            "generation",
            &DiagnosticGeneration::new(self.generation, self.class),
        );
        debug.field("bytes", &self.bytes).finish()
    }
}

/// Stable identity of the pinned storage-root kernel object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StorageRootId {
    device: u64,
    inode: u64,
}

impl StorageRootId {
    /// Filesystem device identity.
    #[must_use]
    pub const fn device(self) -> u64 {
        self.device
    }

    /// Inode identity on the filesystem device.
    #[must_use]
    pub const fn inode(self) -> u64 {
        self.inode
    }
}

/// State reached by a commit attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum CommitState {
    /// Desired bytes already matched the caller's expected generation.
    Unchanged,
    /// New bytes and the containing directory are durably committed.
    CommittedDurable,
    /// New bytes are visible, but directory durability could not be proven.
    PublishedDurabilityUncertain,
    /// A retry found the desired generation already published and made it
    /// durable without republishing it.
    Recovered,
}

/// Bounded diagnostic for a failed directory durability operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurabilityFailure {
    kind: String,
    raw_os_error: Option<i32>,
}

impl DurabilityFailure {
    #[cfg(unix)]
    fn from_io(error: &io::Error) -> Self {
        Self {
            kind: format!("{:?}", error.kind()),
            raw_os_error: error.raw_os_error(),
        }
    }

    /// Stable standard-library error-kind name.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Platform error code, when one was available.
    #[must_use]
    pub const fn raw_os_error(&self) -> Option<i32> {
        self.raw_os_error
    }
}

/// Typed output-only receipt for one persistence operation.
///
/// Receipts intentionally do not implement [`Deserialize`]: untrusted stored
/// bytes must not be mistaken for a result issued by a live storage
/// capability.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct CommitReceipt {
    root: StorageRootId,
    #[serde(serialize_with = "serialize_receipt_target")]
    target: PathBuf,
    class: FileClass,
    previous: StorageGeneration,
    generation: StorageGeneration,
    state: CommitState,
    durability_failure: Option<DurabilityFailure>,
}

impl fmt::Debug for CommitReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommitReceipt")
            .field("root", &self.root)
            .field("target", &self.target)
            .field("class", &self.class)
            .field(
                "previous",
                &DiagnosticGeneration::new(self.previous, self.class),
            )
            .field(
                "generation",
                &DiagnosticGeneration::new(self.generation, self.class),
            )
            .field("state", &self.state)
            .field("durability_failure", &self.durability_failure)
            .finish()
    }
}

#[derive(Serialize)]
struct EncodedReceiptTarget {
    encoding: &'static str,
    value: String,
}

fn serialize_receipt_target<S>(target: &Path, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt as _;

        EncodedReceiptTarget {
            encoding: "unix_bytes_hex",
            value: encode_bytes_hex(target.as_os_str().as_bytes()),
        }
        .serialize(serializer)
    }

    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;

        let mut value = String::new();
        for unit in target.as_os_str().encode_wide() {
            push_hex_u16(&mut value, unit);
        }
        EncodedReceiptTarget {
            encoding: "windows_utf16_hex",
            value,
        }
        .serialize(serializer)
    }

    #[cfg(not(any(unix, windows)))]
    EncodedReceiptTarget {
        encoding: "lossy_display",
        value: target.to_string_lossy().into_owned(),
    }
    .serialize(serializer)
}

#[cfg(unix)]
fn encode_bytes_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(windows)]
fn push_hex_u16(encoded: &mut String, unit: u16) {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    for shift in [12_u16, 8, 4, 0] {
        let nibble = usize::from((unit >> shift) & 0x000f);
        encoded.push(char::from(HEX[nibble]));
    }
}

impl CommitReceipt {
    /// Exact pinned root identity used for the operation.
    #[must_use]
    pub const fn root(&self) -> StorageRootId {
        self.root
    }

    /// Canonical root-relative target identity.
    #[must_use]
    pub fn target(&self) -> &Path {
        &self.target
    }

    /// Explicit file class applied to the operation.
    #[must_use]
    pub const fn class(&self) -> FileClass {
        self.class
    }

    /// Generation observed before the operation or supplied by the retry.
    #[must_use]
    pub const fn previous_generation(&self) -> StorageGeneration {
        self.previous
    }

    /// Visible generation after the operation.
    #[must_use]
    pub const fn generation(&self) -> StorageGeneration {
        self.generation
    }

    /// Publication/durability state.
    #[must_use]
    pub const fn state(&self) -> CommitState {
        self.state
    }

    /// Bounded cause when directory durability remains uncertain.
    #[must_use]
    pub const fn durability_failure(&self) -> Option<&DurabilityFailure> {
        self.durability_failure.as_ref()
    }
}

/// Phase that failed before this process published new target bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum UnchangedPhase {
    Cleanup,
    StageCreate,
    StageWrite,
    StageSync,
    NamespaceCheck,
    Rename,
}

/// Errors from descriptor-safe persistence.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PersistenceError {
    /// The platform cannot uphold the handle-relative contract.
    #[error("descriptor-safe persistence is unsupported for {operation} on this platform")]
    UnsupportedPlatform { operation: &'static str },

    /// The trusted root could not be accepted as a private directory
    /// capability.
    #[error("invalid persistence root {}: {reason}", path.display())]
    InvalidRoot { path: PathBuf, reason: String },

    /// A relative target or one of its descriptor-resolved components failed
    /// validation.
    #[error("invalid persistence target {}: {reason}", target.display())]
    InvalidTarget { target: PathBuf, reason: String },

    /// A bounded operation failed before a target generation was available.
    #[error("persistence {operation} failed for {}: {source}", target.display())]
    Io {
        operation: &'static str,
        target: PathBuf,
        #[source]
        source: io::Error,
    },

    /// The file or proposed content exceeds its explicit class ceiling.
    #[error(
        "persistence target {} is {actual_bytes} bytes, exceeding {class:?} limit {max_bytes}",
        target.display()
    )]
    TooLarge {
        target: PathBuf,
        class: FileClass,
        actual_bytes: u64,
        max_bytes: u64,
    },

    /// The expected generation no longer names the current file.
    #[error("persistence generation conflict for {}", target.display())]
    Conflict {
        target: PathBuf,
        expected: StorageGeneration,
        observed: StorageGeneration,
    },

    /// An I/O step failed before rename; the receipt-like fields prove this
    /// process did not publish a new target generation.
    #[error(
        "persistence {phase:?} failed before publication for {}: {source}",
        target.display()
    )]
    Unchanged {
        target: PathBuf,
        phase: UnchangedPhase,
        observed: StorageGeneration,
        #[source]
        source: io::Error,
    },
}

impl PersistenceError {
    /// Observed target generation when the failure proves publication did not
    /// occur or when a generation conflict was detected.
    #[must_use]
    pub const fn observed_generation(&self) -> Option<StorageGeneration> {
        match self {
            Self::Conflict { observed, .. } | Self::Unchanged { observed, .. } => Some(*observed),
            _ => None,
        }
    }

    /// `Some(Unchanged)` only when this process proved it did not publish a
    /// replacement before returning the error.
    #[must_use]
    pub const fn commit_state(&self) -> Option<CommitState> {
        match self {
            Self::Unchanged { .. } => Some(CommitState::Unchanged),
            _ => None,
        }
    }
}

struct StorageRoot {
    path: PathBuf,
    id: StorageRootId,
    #[cfg(unix)]
    directory: std::fs::File,
    #[cfg(unix)]
    control: ActiveCheckpointControl,
}

/// Authorized persistent-storage root pinned to one directory descriptor.
#[derive(Clone)]
pub struct PersistentStorage {
    root: Arc<StorageRoot>,
}

impl fmt::Debug for PersistentStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistentStorage")
            .field("root", &self.root.path)
            .field("root_id", &self.root.id)
            .finish_non_exhaustive()
    }
}

impl PersistentStorage {
    /// Open and pin an existing trusted root without following a symlink in
    /// any absolute path component.
    ///
    /// The root must be absolute, owned by the effective user, and not
    /// writable by group or world. Callers remain responsible for choosing a
    /// root authorized by host policy; after construction no operation
    /// reconsults ambient CWD or a string-prefix allowlist.
    ///
    /// # Errors
    /// Returns [`PersistenceError::InvalidRoot`] for an untrusted root or
    /// [`PersistenceError::UnsupportedPlatform`] when no race-safe backend is
    /// available.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, PersistenceError> {
        open_storage(root.as_ref())
    }

    /// Identity of the pinned root kernel object.
    #[must_use]
    pub fn root_id(&self) -> StorageRootId {
        self.root.id
    }

    /// Diagnostic path used when the root capability was opened.
    #[must_use]
    pub fn root_path(&self) -> &Path {
        &self.root.path
    }

    /// Read one bounded regular file relative to the pinned root.
    ///
    /// This operation never creates a lock, sidecar, or missing directory,
    /// which makes it suitable for bounded read-only compatibility adapters.
    ///
    /// # Errors
    /// Returns a typed error for invalid targets, links, owner/mode/type
    /// violations, oversized content, or underlying I/O failure.
    pub fn read(
        &self,
        target: impl AsRef<Path>,
        class: FileClass,
    ) -> Result<ReadState, PersistenceError> {
        read_storage(self, target.as_ref(), class)
    }

    /// Atomically commit bytes if `expected` still names the current
    /// generation.
    ///
    /// The target must be root-relative and all parent directories must
    /// already exist. Missing directory creation is intentionally a separate
    /// host-authorized operation so a data commit cannot silently widen its
    /// filesystem scope.
    /// All cooperating writers for the target must use this method; the
    /// underlying OS lock is advisory.
    ///
    /// # Errors
    /// Returns [`PersistenceError::Conflict`] when another writer committed a
    /// different generation, [`PersistenceError::Unchanged`] for a proved
    /// pre-publication failure, or another typed validation/I/O error.
    pub fn commit(
        &self,
        target: impl AsRef<Path>,
        class: FileClass,
        expected: StorageGeneration,
        contents: impl AsRef<[u8]>,
    ) -> Result<CommitReceipt, PersistenceError> {
        commit_storage(self, target.as_ref(), class, expected, contents.as_ref())
    }
}

#[cfg(not(unix))]
fn open_storage(root: &Path) -> Result<PersistentStorage, PersistenceError> {
    let _ = root;
    Err(PersistenceError::UnsupportedPlatform { operation: "open" })
}

#[cfg(not(unix))]
fn read_storage(
    _storage: &PersistentStorage,
    _target: &Path,
    _class: FileClass,
) -> Result<ReadState, PersistenceError> {
    Err(PersistenceError::UnsupportedPlatform { operation: "read" })
}

#[cfg(not(unix))]
fn commit_storage(
    _storage: &PersistentStorage,
    _target: &Path,
    _class: FileClass,
    _expected: StorageGeneration,
    _contents: &[u8],
) -> Result<CommitReceipt, PersistenceError> {
    Err(PersistenceError::UnsupportedPlatform {
        operation: "commit",
    })
}

#[cfg(unix)]
struct ParentHandle {
    directory: std::fs::File,
    relative: PathBuf,
    leaf: std::ffi::OsString,
    identity: StorageRootId,
}

#[cfg(unix)]
struct TargetLock {
    file: std::fs::File,
    name: std::ffi::OsString,
    identity: StorageRootId,
}

#[cfg(unix)]
struct StageFile<'a> {
    parent: &'a std::fs::File,
    name: std::ffi::CString,
    file: std::fs::File,
    identity: StorageRootId,
    synced_version: Option<(u64, u64, u64, i64, i64, i64, i64)>,
    active: bool,
}

#[cfg(unix)]
struct PublishContext<'a> {
    storage: &'a PersistentStorage,
    parent: &'a ParentHandle,
    lock: &'a TargetLock,
    target: PathBuf,
    class: FileClass,
    observed: StorageGeneration,
    desired: StorageGeneration,
}

#[cfg(unix)]
impl StageFile<'_> {
    fn mark_synced(&mut self) -> io::Result<()> {
        self.synced_version = Some(metadata_version(&self.file.metadata()?));
        Ok(())
    }

    fn validate_for_publish(&self, class: FileClass, desired: StorageGeneration) -> io::Result<()> {
        use sha2::Digest as _;
        use std::io::{Read as _, Seek as _};

        validate_private_sidecar(&self.file)?;
        let metadata = self.file.metadata()?;
        if self.synced_version != Some(metadata_version(&metadata)) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "persistence stage metadata changed after it was synchronized",
            ));
        }
        if metadata.len() > class.max_bytes() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "persistence stage grew beyond its file-class bound",
            ));
        }

        let mut reader = self.file.try_clone()?;
        reader.seek(io::SeekFrom::Start(0))?;
        let mut digest = sha2::Sha256::new();
        let mut buffer = [0_u8; 16 * 1_024];
        let mut total = 0_u64;
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            total = total.saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
            if total > class.max_bytes() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "persistence stage changed beyond its file-class bound",
                ));
            }
            digest.update(&buffer[..count]);
        }
        let actual: [u8; 32] = digest.finalize().into();
        let StorageGeneration::Present(expected_digest) = desired else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "a staged publication must have a present generation",
            ));
        };
        if total != metadata.len() || actual != *expected_digest.as_bytes() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "persistence stage changed after it was synchronized",
            ));
        }
        Ok(())
    }

    fn binding_matches(&self) -> io::Result<bool> {
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::MetadataExt as _;

        let name = std::ffi::OsStr::from_bytes(self.name.as_bytes());
        let bound = match open_at(
            self.parent,
            name,
            libc::O_RDWR | libc::O_NONBLOCK | libc::O_NOCTTY,
            0,
        ) {
            Ok(bound) => bound,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        validate_private_sidecar(&bound)?;
        let metadata = bound.metadata()?;
        Ok(metadata.dev() == self.identity.device && metadata.ino() == self.identity.inode)
    }

    fn publish(&mut self, leaf: &std::ffi::OsStr) -> io::Result<()> {
        use std::os::fd::AsRawFd as _;

        let leaf = c_string(leaf)?;
        // SAFETY: both descriptors are live directories and both names are
        // NUL-terminated. `renameat` changes directory entries without
        // following the destination leaf when replacing it.
        let result = unsafe {
            libc::renameat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                self.parent.as_raw_fd(),
                leaf.as_ptr(),
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        self.active = false;
        Ok(())
    }
}

#[cfg(unix)]
impl Drop for StageFile<'_> {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd as _;

        if self.active && self.binding_matches().unwrap_or(false) {
            // SAFETY: the parent descriptor outlives this guard and `name` is
            // a single NUL-terminated component. Unlinking a name never
            // follows a symlink stored at that name.
            unsafe {
                libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0);
            }
        }
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Checkpoint {
    ParentOpened,
    BeforeStageWrite,
    AfterStageWrite,
    BeforeStageSync,
    BeforeRename,
    AfterRename,
    BeforeDirectorySync,
}

#[cfg(unix)]
fn open_storage(path: &Path) -> Result<PersistentStorage, PersistenceError> {
    use std::os::unix::fs::MetadataExt as _;

    if !path.is_absolute() {
        return Err(PersistenceError::InvalidRoot {
            path: path.to_path_buf(),
            reason: "root must be absolute; ambient CWD is not an authority".to_string(),
        });
    }

    let directory =
        open_absolute_directory(path).map_err(|source| PersistenceError::InvalidRoot {
            path: path.to_path_buf(),
            reason: format!("descriptor-relative open failed: {source}"),
        })?;
    validate_directory(&directory, path, true).map_err(|reason| PersistenceError::InvalidRoot {
        path: path.to_path_buf(),
        reason,
    })?;
    let metadata = directory
        .metadata()
        .map_err(|source| PersistenceError::Io {
            operation: "inspect root",
            target: path.to_path_buf(),
            source,
        })?;
    let id = StorageRootId {
        device: metadata.dev(),
        inode: metadata.ino(),
    };

    Ok(PersistentStorage {
        root: Arc::new(StorageRoot {
            path: path.to_path_buf(),
            id,
            directory,
            control: ActiveCheckpointControl::default(),
        }),
    })
}

#[cfg(unix)]
fn read_storage(
    storage: &PersistentStorage,
    target: &Path,
    class: FileClass,
) -> Result<ReadState, PersistenceError> {
    let target = validate_target(target)?;
    validate_directory(&storage.root.directory, &storage.root.path, true).map_err(|reason| {
        PersistenceError::InvalidRoot {
            path: storage.root.path.clone(),
            reason,
        }
    })?;
    let parent = open_parent(storage, &target)?;
    checkpoint(storage, Checkpoint::ParentOpened).map_err(|source| PersistenceError::Io {
        operation: "pause after read parent open",
        target: target.clone(),
        source,
    })?;
    let state = observe(&parent, &target, class)?;
    if !parent_binding_matches(storage, &parent).map_err(|source| PersistenceError::Io {
        operation: "revalidate parent namespace",
        target: target.clone(),
        source,
    })? {
        return Err(PersistenceError::InvalidTarget {
            target,
            reason: "parent directory changed identity while the file was read".to_string(),
        });
    }
    tracing::debug!(
        target: "openclaudia::persistence",
        event = "persistent_read",
        root_device = storage.root.id.device,
        root_inode = storage.root.id.inode,
        file_class = ?class,
        generation = %DiagnosticGeneration::new(state.generation(), class),
        relative_target = %target.display(),
        "observed descriptor-relative persistent state"
    );
    Ok(state)
}

#[cfg(unix)]
fn commit_storage(
    storage: &PersistentStorage,
    target: &Path,
    class: FileClass,
    expected: StorageGeneration,
    contents: &[u8],
) -> Result<CommitReceipt, PersistenceError> {
    let target = validate_target(target)?;
    let actual_bytes = u64::try_from(contents.len()).unwrap_or(u64::MAX);
    if actual_bytes > class.max_bytes() {
        return Err(PersistenceError::TooLarge {
            target,
            class,
            actual_bytes,
            max_bytes: class.max_bytes(),
        });
    }
    validate_directory(&storage.root.directory, &storage.root.path, true).map_err(|reason| {
        PersistenceError::InvalidRoot {
            path: storage.root.path.clone(),
            reason,
        }
    })?;

    let parent = open_parent(storage, &target)?;
    checkpoint(storage, Checkpoint::ParentOpened).map_err(|source| PersistenceError::Io {
        operation: "pause after parent open",
        target: target.clone(),
        source,
    })?;
    let lock = acquire_lock(&parent, &target).map_err(|source| PersistenceError::Io {
        operation: "acquire target lock",
        target: target.clone(),
        source,
    })?;

    let observed_state = observe(&parent, &target, class)?;
    let observed = observed_state.generation();
    ensure_parent_binding(storage, &parent, &target, observed)?;

    let desired = StorageGeneration::for_bytes(contents);
    if observed == desired {
        cleanup_staging(&parent, &target).map_err(|source| PersistenceError::Unchanged {
            target: target.clone(),
            phase: UnchangedPhase::Cleanup,
            observed,
            source,
        })?;
        return reconcile_visible(storage, &parent, target, class, expected, observed);
    }
    if observed != expected {
        return Err(PersistenceError::Conflict {
            target,
            expected,
            observed,
        });
    }
    cleanup_staging(&parent, &target).map_err(|source| PersistenceError::Unchanged {
        target: target.clone(),
        phase: UnchangedPhase::Cleanup,
        observed,
        source,
    })?;

    let stage = write_synced_stage(storage, &parent, &target, class, observed, contents)?;
    if let Some(reconciled) = verify_publish_preconditions(
        storage, &parent, &target, class, expected, observed, desired,
    )? {
        return Ok(reconciled);
    }
    publish_stage(
        PublishContext {
            storage,
            parent: &parent,
            lock: &lock,
            target,
            class,
            observed,
            desired,
        },
        stage,
    )
}

#[cfg(unix)]
fn write_synced_stage<'a>(
    storage: &PersistentStorage,
    parent: &'a ParentHandle,
    target: &Path,
    class: FileClass,
    observed: StorageGeneration,
    contents: &[u8],
) -> Result<StageFile<'a>, PersistenceError> {
    use std::io::Write as _;

    let mut stage =
        create_stage(parent, target, class).map_err(|source| PersistenceError::Unchanged {
            target: target.to_path_buf(),
            phase: UnchangedPhase::StageCreate,
            observed,
            source,
        })?;
    checkpoint(storage, Checkpoint::BeforeStageWrite).map_err(|source| {
        PersistenceError::Unchanged {
            target: target.to_path_buf(),
            phase: UnchangedPhase::StageWrite,
            observed,
            source,
        }
    })?;
    stage
        .file
        .write_all(contents)
        .map_err(|source| PersistenceError::Unchanged {
            target: target.to_path_buf(),
            phase: UnchangedPhase::StageWrite,
            observed,
            source,
        })?;
    checkpoint(storage, Checkpoint::AfterStageWrite).map_err(|source| {
        PersistenceError::Unchanged {
            target: target.to_path_buf(),
            phase: UnchangedPhase::StageWrite,
            observed,
            source,
        }
    })?;
    checkpoint(storage, Checkpoint::BeforeStageSync).map_err(|source| {
        PersistenceError::Unchanged {
            target: target.to_path_buf(),
            phase: UnchangedPhase::StageSync,
            observed,
            source,
        }
    })?;
    stage
        .file
        .sync_all()
        .map_err(|source| PersistenceError::Unchanged {
            target: target.to_path_buf(),
            phase: UnchangedPhase::StageSync,
            observed,
            source,
        })?;
    stage
        .mark_synced()
        .map_err(|source| PersistenceError::Unchanged {
            target: target.to_path_buf(),
            phase: UnchangedPhase::StageSync,
            observed,
            source,
        })?;
    Ok(stage)
}

#[cfg(unix)]
fn verify_publish_preconditions(
    storage: &PersistentStorage,
    parent: &ParentHandle,
    target: &Path,
    class: FileClass,
    expected: StorageGeneration,
    observed: StorageGeneration,
    desired: StorageGeneration,
) -> Result<Option<CommitReceipt>, PersistenceError> {
    // Re-observe after staging. This catches every cooperating writer through
    // the lock and narrows the remaining window for non-cooperating writers.
    let before_publish = observe(parent, target, class)?.generation();
    ensure_parent_binding(storage, parent, target, observed)?;
    if before_publish == desired {
        return Ok(Some(reconcile_visible(
            storage,
            parent,
            target.to_path_buf(),
            class,
            expected,
            before_publish,
        )?));
    }
    if before_publish != observed {
        return Err(PersistenceError::Conflict {
            target: target.to_path_buf(),
            expected,
            observed: before_publish,
        });
    }
    Ok(None)
}

#[cfg(unix)]
fn publish_stage(
    context: PublishContext<'_>,
    mut stage: StageFile<'_>,
) -> Result<CommitReceipt, PersistenceError> {
    let PublishContext {
        storage,
        parent,
        lock,
        target,
        class,
        observed,
        desired,
    } = context;
    checkpoint(storage, Checkpoint::BeforeRename).map_err(|source| {
        PersistenceError::Unchanged {
            target: target.clone(),
            phase: UnchangedPhase::Rename,
            observed,
            source,
        }
    })?;
    if !parent_binding_matches(storage, parent).map_err(|source| PersistenceError::Unchanged {
        target: target.clone(),
        phase: UnchangedPhase::NamespaceCheck,
        observed,
        source,
    })? {
        return Err(PersistenceError::Unchanged {
            target,
            phase: UnchangedPhase::NamespaceCheck,
            observed,
            source: io::Error::other(
                "parent directory identity changed at the publication boundary",
            ),
        });
    }
    if !lock
        .binding_matches(parent)
        .map_err(|source| PersistenceError::Unchanged {
            target: target.clone(),
            phase: UnchangedPhase::NamespaceCheck,
            observed,
            source,
        })?
    {
        return Err(PersistenceError::Unchanged {
            target,
            phase: UnchangedPhase::NamespaceCheck,
            observed,
            source: io::Error::other("target lock identity changed before publication"),
        });
    }
    ensure_stage_binding(&stage, &target, observed)?;
    stage
        .validate_for_publish(class, desired)
        .map_err(|source| PersistenceError::Unchanged {
            target: target.clone(),
            phase: UnchangedPhase::StageSync,
            observed,
            source,
        })?;
    stage
        .publish(&parent.leaf)
        .map_err(|source| PersistenceError::Unchanged {
            target: target.clone(),
            phase: UnchangedPhase::Rename,
            observed,
            source,
        })?;

    let after_rename = checkpoint(storage, Checkpoint::AfterRename)
        .and_then(|()| checkpoint(storage, Checkpoint::BeforeDirectorySync))
        .and_then(|()| parent.directory.sync_all());
    let namespace_stable = parent_binding_matches(storage, parent);
    let durability_error = after_rename
        .err()
        .or_else(|| namespace_stable.as_ref().err().map(clone_io_error))
        .or_else(|| {
            namespace_stable
                .ok()
                .filter(|stable| !stable)
                .map(|_| io::Error::other("parent directory identity changed after publication"))
        });
    if let Some(source) = durability_error {
        return Ok(receipt(
            storage,
            target,
            class,
            observed,
            desired,
            CommitState::PublishedDurabilityUncertain,
            Some(DurabilityFailure::from_io(&source)),
        ));
    }

    Ok(receipt(
        storage,
        target,
        class,
        observed,
        desired,
        CommitState::CommittedDurable,
        None,
    ))
}

#[cfg(unix)]
fn reconcile_visible(
    storage: &PersistentStorage,
    parent: &ParentHandle,
    target: PathBuf,
    class: FileClass,
    expected: StorageGeneration,
    visible: StorageGeneration,
) -> Result<CommitReceipt, PersistenceError> {
    ensure_parent_binding(storage, parent, &target, visible)?;
    if visible == expected {
        return Ok(receipt(
            storage,
            target,
            class,
            expected,
            visible,
            CommitState::Unchanged,
            None,
        ));
    }

    let durability = checkpoint(storage, Checkpoint::BeforeDirectorySync)
        .and_then(|()| parent.directory.sync_all());
    let binding = parent_binding_matches(storage, parent);
    match binding {
        Ok(false) => Err(PersistenceError::Unchanged {
            target,
            phase: UnchangedPhase::NamespaceCheck,
            observed: visible,
            source: io::Error::other("parent directory identity changed during reconciliation"),
        }),
        Err(source) => Err(PersistenceError::Unchanged {
            target,
            phase: UnchangedPhase::NamespaceCheck,
            observed: visible,
            source,
        }),
        Ok(true) => match durability {
            Ok(()) => Ok(receipt(
                storage,
                target,
                class,
                expected,
                visible,
                CommitState::Recovered,
                None,
            )),
            Err(source) => Ok(receipt(
                storage,
                target,
                class,
                expected,
                visible,
                CommitState::PublishedDurabilityUncertain,
                Some(DurabilityFailure::from_io(&source)),
            )),
        },
    }
}

#[cfg(unix)]
fn ensure_parent_binding(
    storage: &PersistentStorage,
    parent: &ParentHandle,
    target: &Path,
    observed: StorageGeneration,
) -> Result<(), PersistenceError> {
    if parent_binding_matches(storage, parent).map_err(|source| PersistenceError::Unchanged {
        target: target.to_path_buf(),
        phase: UnchangedPhase::NamespaceCheck,
        observed,
        source,
    })? {
        Ok(())
    } else {
        Err(PersistenceError::Unchanged {
            target: target.to_path_buf(),
            phase: UnchangedPhase::NamespaceCheck,
            observed,
            source: io::Error::other("parent directory identity changed before publication"),
        })
    }
}

#[cfg(unix)]
fn ensure_stage_binding(
    stage: &StageFile<'_>,
    target: &Path,
    observed: StorageGeneration,
) -> Result<(), PersistenceError> {
    if stage
        .binding_matches()
        .map_err(|source| PersistenceError::Unchanged {
            target: target.to_path_buf(),
            phase: UnchangedPhase::NamespaceCheck,
            observed,
            source,
        })?
    {
        Ok(())
    } else {
        Err(PersistenceError::Unchanged {
            target: target.to_path_buf(),
            phase: UnchangedPhase::NamespaceCheck,
            observed,
            source: io::Error::other("staging file identity changed before publication"),
        })
    }
}

#[cfg(unix)]
fn receipt(
    storage: &PersistentStorage,
    target: PathBuf,
    class: FileClass,
    previous: StorageGeneration,
    generation: StorageGeneration,
    state: CommitState,
    durability_failure: Option<DurabilityFailure>,
) -> CommitReceipt {
    let result = CommitReceipt {
        root: storage.root.id,
        target,
        class,
        previous,
        generation,
        state,
        durability_failure,
    };
    tracing::info!(
        target: "openclaudia::persistence",
        event = "persistent_commit",
        root_device = result.root.device,
        root_inode = result.root.inode,
        file_class = ?result.class,
        previous_generation = %DiagnosticGeneration::new(result.previous, result.class),
        generation = %DiagnosticGeneration::new(result.generation, result.class),
        commit_state = ?result.state,
        relative_target = %result.target.display(),
        durability_error_kind = result.durability_failure.as_ref().map(DurabilityFailure::kind),
        "completed descriptor-relative persistence operation"
    );
    result
}

#[cfg(unix)]
fn validate_target(target: &Path) -> Result<PathBuf, PersistenceError> {
    use std::os::unix::ffi::OsStrExt as _;

    if target.as_os_str().is_empty() || target.as_os_str().as_bytes().len() > MAX_TARGET_BYTES {
        return Err(PersistenceError::InvalidTarget {
            target: target.to_path_buf(),
            reason: format!("target must contain 1..={MAX_TARGET_BYTES} bytes"),
        });
    }
    let mut canonical = PathBuf::new();
    let mut count = 0_usize;
    for component in target.components() {
        match component {
            Component::Normal(name) => {
                if name.as_bytes().contains(&0) {
                    return Err(PersistenceError::InvalidTarget {
                        target: target.to_path_buf(),
                        reason: "target component contains NUL".to_string(),
                    });
                }
                if name.as_bytes().starts_with(INTERNAL_SIDECAR_PREFIX) {
                    return Err(PersistenceError::InvalidTarget {
                        target: target.to_path_buf(),
                        reason: "target collides with the reserved persistence sidecar namespace"
                            .to_string(),
                    });
                }
                canonical.push(name);
                count += 1;
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(PersistenceError::InvalidTarget {
                    target: target.to_path_buf(),
                    reason: "target must be root-relative without parent traversal".to_string(),
                });
            }
        }
    }
    if count == 0 || count > MAX_TARGET_COMPONENTS {
        return Err(PersistenceError::InvalidTarget {
            target: target.to_path_buf(),
            reason: format!("target must contain 1..={MAX_TARGET_COMPONENTS} components"),
        });
    }
    Ok(canonical)
}

#[cfg(unix)]
fn open_absolute_directory(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::ffi::OsStrExt as _;

    let mut current = open_directory_path(Path::new("/"))?;
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                if name.as_bytes().contains(&0) {
                    return Err(io::Error::from_raw_os_error(libc::EINVAL));
                }
                current = open_directory_at(&current, name)?;
            }
            Component::ParentDir | Component::Prefix(_) => {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
        }
    }
    Ok(current)
}

#[cfg(unix)]
fn open_directory_path(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
}

#[cfg(unix)]
fn open_directory_at(parent: &std::fs::File, name: &std::ffi::OsStr) -> io::Result<std::fs::File> {
    open_at(parent, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
}

#[cfg(unix)]
fn open_at(
    parent: &std::fs::File,
    name: &std::ffi::OsStr,
    flags: i32,
    mode: u32,
) -> io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};

    let name = c_string(name)?;
    // SAFETY: `parent` is a live directory descriptor, `name` is a single
    // NUL-terminated component, and a successful result is newly owned.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: `openat` returned a new descriptor owned by this call.
        Ok(unsafe { std::fs::File::from_raw_fd(fd) })
    }
}

#[cfg(unix)]
fn c_string(name: &std::ffi::OsStr) -> io::Result<std::ffi::CString> {
    use std::os::unix::ffi::OsStrExt as _;

    std::ffi::CString::new(name.as_bytes()).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))
}

#[cfg(unix)]
fn validate_directory(
    directory: &std::fs::File,
    display: &Path,
    require_owner: bool,
) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = directory
        .metadata()
        .map_err(|error| format!("cannot inspect directory: {error}"))?;
    if !metadata.file_type().is_dir() {
        return Err("descriptor does not name a directory".to_string());
    }
    // SAFETY: `geteuid` has no preconditions and does not retain pointers.
    let effective_uid = unsafe { libc::geteuid() };
    if require_owner && metadata.uid() != effective_uid {
        return Err(format!(
            "directory owner {} differs from effective user {effective_uid}",
            metadata.uid()
        ));
    }
    let mode = metadata.mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(format!(
            "directory mode {mode:#05o} permits group/world mutation at {}",
            display.display()
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn open_parent(
    storage: &PersistentStorage,
    target: &Path,
) -> Result<ParentHandle, PersistenceError> {
    use std::os::unix::fs::MetadataExt as _;

    let components = target
        .components()
        .map(|component| match component {
            Component::Normal(name) => name.to_os_string(),
            _ => unreachable!("validated target contains only normal components"),
        })
        .collect::<Vec<_>>();
    let (leaf, parents) = components
        .split_last()
        .expect("validated target has at least one component");
    let mut directory =
        storage
            .root
            .directory
            .try_clone()
            .map_err(|source| PersistenceError::Io {
                operation: "duplicate root descriptor",
                target: target.to_path_buf(),
                source,
            })?;
    let mut relative = PathBuf::new();
    for component in parents {
        relative.push(component);
        directory = open_directory_at(&directory, component).map_err(|source| {
            PersistenceError::InvalidTarget {
                target: target.to_path_buf(),
                reason: format!(
                    "cannot enter parent {} without following links: {source}",
                    relative.display()
                ),
            }
        })?;
        validate_directory(&directory, &relative, true).map_err(|reason| {
            PersistenceError::InvalidTarget {
                target: target.to_path_buf(),
                reason: format!("parent {} is not trusted: {reason}", relative.display()),
            }
        })?;
    }
    let metadata = directory
        .metadata()
        .map_err(|source| PersistenceError::Io {
            operation: "inspect parent descriptor",
            target: target.to_path_buf(),
            source,
        })?;
    Ok(ParentHandle {
        directory,
        relative,
        leaf: leaf.clone(),
        identity: StorageRootId {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
    })
}

#[cfg(unix)]
fn parent_binding_matches(storage: &PersistentStorage, parent: &ParentHandle) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt as _;

    let mut directory = storage.root.directory.try_clone()?;
    validate_directory(&directory, &storage.root.path, true)
        .map_err(|reason| io::Error::new(io::ErrorKind::PermissionDenied, reason))?;
    for component in parent.relative.components() {
        let Component::Normal(name) = component else {
            return Ok(false);
        };
        directory = open_directory_at(&directory, name)?;
        validate_directory(&directory, &parent.relative, true)
            .map_err(|reason| io::Error::new(io::ErrorKind::PermissionDenied, reason))?;
    }
    let metadata = directory.metadata()?;
    Ok(metadata.dev() == parent.identity.device && metadata.ino() == parent.identity.inode)
}

#[cfg(unix)]
fn observe(
    parent: &ParentHandle,
    target: &Path,
    class: FileClass,
) -> Result<ReadState, PersistenceError> {
    use std::io::Read as _;

    let mut file = match open_at(
        &parent.directory,
        &parent.leaf,
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY,
        0,
    ) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(ReadState::missing(class));
        }
        Err(source) => {
            return Err(PersistenceError::InvalidTarget {
                target: target.to_path_buf(),
                reason: format!("leaf cannot be opened without following links: {source}"),
            });
        }
    };
    let before = validate_regular_file(&file, target, class)?;
    if before.len() > class.max_bytes() {
        return Err(PersistenceError::TooLarge {
            target: target.to_path_buf(),
            class,
            actual_bytes: before.len(),
            max_bytes: class.max_bytes(),
        });
    }
    let capacity = usize::try_from(before.len()).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(class.max_bytes().saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| PersistenceError::Io {
            operation: "read bounded file",
            target: target.to_path_buf(),
            source,
        })?;
    let actual_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual_bytes > class.max_bytes() {
        return Err(PersistenceError::TooLarge {
            target: target.to_path_buf(),
            class,
            actual_bytes,
            max_bytes: class.max_bytes(),
        });
    }
    let after = file.metadata().map_err(|source| PersistenceError::Io {
        operation: "reinspect bounded file",
        target: target.to_path_buf(),
        source,
    })?;
    if metadata_version(&before) != metadata_version(&after) {
        return Err(PersistenceError::InvalidTarget {
            target: target.to_path_buf(),
            reason: "file changed while its bounded generation was read".to_string(),
        });
    }
    Ok(ReadState::present(class, bytes))
}

#[cfg(unix)]
fn validate_regular_file(
    file: &std::fs::File,
    target: &Path,
    class: FileClass,
) -> Result<std::fs::Metadata, PersistenceError> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file.metadata().map_err(|source| PersistenceError::Io {
        operation: "inspect regular file",
        target: target.to_path_buf(),
        source,
    })?;
    if !metadata.file_type().is_file() {
        return Err(PersistenceError::InvalidTarget {
            target: target.to_path_buf(),
            reason: "leaf is not a regular file".to_string(),
        });
    }
    if metadata.nlink() != 1 {
        return Err(PersistenceError::InvalidTarget {
            target: target.to_path_buf(),
            reason: format!(
                "leaf has {} hard links; exactly one is required",
                metadata.nlink()
            ),
        });
    }
    // SAFETY: `geteuid` has no preconditions and does not retain pointers.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid {
        return Err(PersistenceError::InvalidTarget {
            target: target.to_path_buf(),
            reason: format!(
                "leaf owner {} differs from effective user {effective_uid}",
                metadata.uid()
            ),
        });
    }
    let mode = metadata.mode() & 0o7777;
    if mode & !class.unix_allowed_existing_mode() != 0 {
        return Err(PersistenceError::InvalidTarget {
            target: target.to_path_buf(),
            reason: format!(
                "leaf mode {mode:#05o} exceeds {class:?} allowance {:#05o}",
                class.unix_allowed_existing_mode()
            ),
        });
    }
    Ok(metadata)
}

#[cfg(unix)]
fn metadata_version(metadata: &std::fs::Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    use std::os::unix::fs::MetadataExt as _;

    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

#[cfg(unix)]
fn target_sidecar_name(prefix: &str, target: &Path) -> std::ffi::OsString {
    use std::os::unix::ffi::OsStrExt as _;

    let digest = ContentDigest::sha256(target.as_os_str().as_bytes()).to_string();
    let hexadecimal = digest.strip_prefix("sha256:").unwrap_or(digest.as_str());
    std::ffi::OsString::from(format!(".openclaudia-persistence-{prefix}-{hexadecimal}"))
}

#[cfg(unix)]
fn acquire_lock(parent: &ParentHandle, target: &Path) -> io::Result<TargetLock> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::MetadataExt as _;

    let name = target_sidecar_name("lock", target);
    let file = open_at(
        &parent.directory,
        &name,
        libc::O_RDWR | libc::O_CREAT | libc::O_NONBLOCK | libc::O_NOCTTY,
        0o600,
    )?;
    validate_private_sidecar(&file)?;
    let started = std::time::Instant::now();
    loop {
        // SAFETY: the descriptor is live and `flock` retains no pointer.
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            let metadata = file.metadata()?;
            return Ok(TargetLock {
                file,
                name,
                identity: StorageRootId {
                    device: metadata.dev(),
                    inode: metadata.ino(),
                },
            });
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if error.kind() != io::ErrorKind::WouldBlock {
            return Err(error);
        }
        if started.elapsed() >= LOCK_WAIT_TIMEOUT {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "persistence target lock deadline exceeded",
            ));
        }
        std::thread::sleep(LOCK_RETRY_DELAY);
    }
}

#[cfg(unix)]
impl TargetLock {
    fn binding_matches(&self, parent: &ParentHandle) -> io::Result<bool> {
        use std::os::unix::fs::MetadataExt as _;

        validate_private_sidecar(&self.file)?;
        let bound = match open_at(
            &parent.directory,
            &self.name,
            libc::O_RDWR | libc::O_NONBLOCK | libc::O_NOCTTY,
            0,
        ) {
            Ok(bound) => bound,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        validate_private_sidecar(&bound)?;
        let metadata = bound.metadata()?;
        Ok(metadata.dev() == self.identity.device && metadata.ino() == self.identity.inode)
    }
}

#[cfg(unix)]
fn validate_private_sidecar(file: &std::fs::File) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file.metadata()?;
    // SAFETY: `geteuid` has no preconditions and does not retain pointers.
    let effective_uid = unsafe { libc::geteuid() };
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.uid() != effective_uid
        || (metadata.mode() & 0o7777) & !0o600 != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "persistence sidecar failed owner/type/mode/link checks",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn cleanup_staging(parent: &ParentHandle, target: &Path) -> io::Result<()> {
    use std::os::fd::AsRawFd as _;

    let name = target_sidecar_name("stage", target);
    match open_at(
        &parent.directory,
        &name,
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOCTTY,
        0,
    ) {
        Ok(file) => validate_private_sidecar(&file)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    }
    let name = c_string(&name)?;
    // SAFETY: the directory descriptor and NUL-terminated component are live;
    // unlinkat removes only the named entry and follows no link.
    if unsafe { libc::unlinkat(parent.directory.as_raw_fd(), name.as_ptr(), 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn create_stage<'a>(
    parent: &'a ParentHandle,
    target: &Path,
    class: FileClass,
) -> io::Result<StageFile<'a>> {
    use std::os::unix::fs::MetadataExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    let name = target_sidecar_name("stage", target);
    let c_name = c_string(&name)?;
    let file = open_at(
        &parent.directory,
        &name,
        libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        class.unix_create_mode(),
    )?;
    let metadata = file.metadata()?;
    let stage = StageFile {
        parent: &parent.directory,
        name: c_name,
        file,
        identity: StorageRootId {
            device: metadata.dev(),
            inode: metadata.ino(),
        },
        synced_version: None,
        active: true,
    };
    stage
        .file
        .set_permissions(std::fs::Permissions::from_mode(class.unix_create_mode()))?;
    validate_private_sidecar(&stage.file)?;
    Ok(stage)
}

#[cfg(unix)]
fn clone_io_error(error: &io::Error) -> io::Error {
    error.raw_os_error().map_or_else(
        || io::Error::new(error.kind(), error.to_string()),
        io::Error::from_raw_os_error,
    )
}

#[cfg(unix)]
trait CheckpointControl {
    fn check(&self, checkpoint: Checkpoint) -> io::Result<()>;
}

#[cfg(all(unix, not(test)))]
#[derive(Default)]
struct NoCheckpointControl;

#[cfg(all(unix, not(test)))]
impl CheckpointControl for NoCheckpointControl {
    fn check(&self, _checkpoint: Checkpoint) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(all(unix, not(test)))]
type ActiveCheckpointControl = NoCheckpointControl;

#[cfg(all(unix, test))]
#[derive(Default)]
struct TestControl {
    action: std::sync::Mutex<Option<(Checkpoint, TestAction)>>,
}

#[cfg(all(unix, test))]
enum TestAction {
    Error(i32),
    Exit(i32),
    Pause {
        entered: Arc<std::sync::Barrier>,
        resume: Arc<std::sync::Barrier>,
    },
}

#[cfg(all(unix, test))]
type ActiveCheckpointControl = TestControl;

#[cfg(all(unix, test))]
impl CheckpointControl for TestControl {
    fn check(&self, checkpoint: Checkpoint) -> io::Result<()> {
        let action = {
            let mut slot = self
                .action
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match slot.as_ref() {
                Some((expected, _)) if *expected == checkpoint => {
                    slot.take().map(|(_, action)| action)
                }
                _ => None,
            }
        };
        match action {
            None => Ok(()),
            Some(TestAction::Error(raw_os_error)) => {
                Err(io::Error::from_raw_os_error(raw_os_error))
            }
            Some(TestAction::Exit(code)) => std::process::exit(code),
            Some(TestAction::Pause { entered, resume }) => {
                entered.wait();
                resume.wait();
                Ok(())
            }
        }
    }
}

#[cfg(all(unix, test))]
impl PersistentStorage {
    fn set_test_action(&self, checkpoint: Checkpoint, action: TestAction) {
        *self
            .root
            .control
            .action
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some((checkpoint, action));
    }
}

#[cfg(unix)]
fn checkpoint(storage: &PersistentStorage, checkpoint: Checkpoint) -> io::Result<()> {
    storage.root.control.check(checkpoint)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::{Barrier, Mutex};

    const CRASH_MODE_ENV: &str = "OPENCLAUDIA_S031_CRASH_MODE";
    const CRASH_ROOT_ENV: &str = "OPENCLAUDIA_S031_CRASH_ROOT";

    #[derive(Clone, Default)]
    struct TraceWriter(Arc<Mutex<Vec<u8>>>);

    struct TraceGuard(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for TraceGuard {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .write(bytes)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for TraceWriter {
        type Writer = TraceGuard;

        fn make_writer(&'writer self) -> Self::Writer {
            TraceGuard(Arc::clone(&self.0))
        }
    }

    fn fixture() -> (tempfile::TempDir, PersistentStorage) {
        let root = tempfile::tempdir().expect("private storage root");
        let storage = PersistentStorage::open(root.path()).expect("open storage root");
        (root, storage)
    }

    fn capture_trace<R>(operation: impl FnOnce() -> R) -> (R, String) {
        let output = TraceWriter::default();
        let capture = Arc::clone(&output.0);
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_writer(output)
            .finish();
        let result = tracing::subscriber::with_default(subscriber, operation);
        let trace = String::from_utf8(
            capture
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        )
        .expect("UTF-8 trace");
        (result, trace)
    }

    fn seed_private(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).expect("seed file");
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("restrict seed mode");
    }

    fn present_generation(state: &ReadState) -> StorageGeneration {
        let generation = state.generation();
        assert!(matches!(generation, StorageGeneration::Present(_)));
        generation
    }

    #[test]
    fn commit_receipts_distinguish_durable_unchanged_and_recovered() {
        let (_root, storage) = fixture();
        let target = Path::new("state.json");

        let committed = storage
            .commit(
                target,
                FileClass::State,
                StorageGeneration::Missing,
                b"generation-one",
            )
            .expect("first commit");
        assert_eq!(committed.state(), CommitState::CommittedDurable);
        assert_eq!(committed.root(), storage.root_id());
        assert_eq!(committed.target(), target);
        assert_eq!(committed.class(), FileClass::State);
        assert_eq!(committed.previous_generation(), StorageGeneration::Missing);

        let observed = storage
            .read(target, FileClass::State)
            .expect("read committed");
        observed.expose_bytes(|bytes| assert_eq!(bytes, Some(b"generation-one".as_slice())));
        assert_eq!(observed.generation(), committed.generation());

        let unchanged = storage
            .commit(
                target,
                FileClass::State,
                observed.generation(),
                b"generation-one",
            )
            .expect("idempotent no-op");
        assert_eq!(unchanged.state(), CommitState::Unchanged);

        let recovered = storage
            .commit(
                target,
                FileClass::State,
                StorageGeneration::Missing,
                b"generation-one",
            )
            .expect("retry reconciles visible desired generation");
        assert_eq!(recovered.state(), CommitState::Recovered);
        assert_eq!(recovered.generation(), committed.generation());
    }

    #[test]
    fn unchanged_content_does_not_claim_a_new_uncertain_publication() {
        let (_root, storage) = fixture();
        let committed = storage
            .commit(
                "state.json",
                FileClass::State,
                StorageGeneration::Missing,
                b"already-visible",
            )
            .expect("initial commit");
        storage.set_test_action(
            Checkpoint::BeforeDirectorySync,
            TestAction::Error(libc::EIO),
        );

        let unchanged = storage
            .commit(
                "state.json",
                FileClass::State,
                committed.generation(),
                b"already-visible",
            )
            .expect("no-op does not publish or require a directory sync");
        assert_eq!(unchanged.state(), CommitState::Unchanged);
        assert!(unchanged.durability_failure().is_none());
    }

    #[test]
    fn read_only_missing_observation_creates_no_sidecars() {
        let (root, storage) = fixture();
        let observed = storage
            .read("foreign.json", FileClass::Credentials)
            .expect("bounded missing read");
        assert_eq!(observed.class(), FileClass::Credentials);
        assert_eq!(observed.generation(), StorageGeneration::Missing);
        assert!(observed.bytes().is_none());
        assert_eq!(std::fs::read_dir(root.path()).expect("entries").count(), 0);
    }

    #[test]
    fn observed_credential_bytes_are_zeroizing_and_debug_redacted() {
        let (_root, storage) = fixture();
        let sentinel = b"s031-credential-debug-sentinel";
        let receipt = storage
            .commit(
                "credential.json",
                FileClass::Credentials,
                StorageGeneration::Missing,
                sentinel,
            )
            .expect("credential commit");
        let receipt_debug = format!("{receipt:?}");
        assert!(!receipt_debug.contains("s031-credential-debug-sentinel"));
        assert!(!receipt_debug.contains(&receipt.generation().to_string()));

        let observed = storage
            .read("credential.json", FileClass::Credentials)
            .expect("credential read");
        observed.expose_bytes(|bytes| assert_eq!(bytes, Some(sentinel.as_slice())));
        let generation = observed.generation().to_string();
        let debug = format!("{observed:?}");
        assert!(!debug.contains("s031-credential-debug-sentinel"));
        assert!(!debug.contains(&generation));
        assert!(debug.contains(&format!("len: {}", sentinel.len())));
        let content_debug = format!("{:?}", observed.bytes());
        assert!(!content_debug.contains("s031-credential-debug-sentinel"));

        let conflict = storage
            .commit(
                "credential.json",
                FileClass::Credentials,
                StorageGeneration::Missing,
                b"different-credential",
            )
            .expect_err("stale credential writer must conflict");
        let display = conflict.to_string();
        assert!(!display.contains(&receipt.generation().to_string()));
        assert!(!display.contains("s031-credential-debug-sentinel"));
    }

    #[test]
    fn absolute_parent_and_empty_targets_are_rejected() {
        let (_root, storage) = fixture();
        for target in [
            Path::new("/absolute"),
            Path::new("../escape"),
            Path::new(""),
            Path::new(".openclaudia-persistence-lock-forged"),
        ] {
            assert!(matches!(
                storage.read(target, FileClass::State),
                Err(PersistenceError::InvalidTarget { .. })
            ));
        }

        let too_deep = std::iter::repeat_n("component", MAX_TARGET_COMPONENTS + 1)
            .collect::<Vec<_>>()
            .join("/");
        let too_long = "x".repeat(MAX_TARGET_BYTES + 1);
        for target in [Path::new(&too_deep), Path::new(&too_long)] {
            assert!(matches!(
                storage.read(target, FileClass::State),
                Err(PersistenceError::InvalidTarget { .. })
            ));
        }
    }

    #[test]
    fn relative_broad_and_symlinked_roots_are_rejected() {
        assert!(matches!(
            PersistentStorage::open("relative-root"),
            Err(PersistenceError::InvalidRoot { .. })
        ));

        let broad = tempfile::tempdir().expect("broad root");
        std::fs::set_permissions(broad.path(), std::fs::Permissions::from_mode(0o777))
            .expect("broad root mode");
        assert!(matches!(
            PersistentStorage::open(broad.path()),
            Err(PersistenceError::InvalidRoot { .. })
        ));

        let root = tempfile::tempdir().expect("real root");
        let holder = tempfile::tempdir().expect("link holder");
        let link = holder.path().join("root-link");
        std::os::unix::fs::symlink(root.path(), &link).expect("root symlink");
        assert!(matches!(
            PersistentStorage::open(&link),
            Err(PersistenceError::InvalidRoot { .. })
        ));

        std::fs::create_dir(root.path().join("nested")).expect("nested root");
        std::fs::set_permissions(
            root.path().join("nested"),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("nested root mode");
        let ancestor = holder.path().join("ancestor-link");
        std::os::unix::fs::symlink(root.path(), &ancestor).expect("root ancestor symlink");
        assert!(matches!(
            PersistentStorage::open(ancestor.join("nested")),
            Err(PersistenceError::InvalidRoot { .. })
        ));
    }

    #[test]
    fn non_utf8_target_identity_round_trips_without_loss() {
        use std::os::unix::ffi::OsStringExt as _;

        let (_root, storage) = fixture();
        let target = PathBuf::from(std::ffi::OsString::from_vec(vec![b's', b't', 0xff]));
        let receipt = storage
            .commit(
                &target,
                FileClass::State,
                StorageGeneration::Missing,
                b"non-utf8-target",
            )
            .expect("commit non-UTF-8 target");
        assert_eq!(receipt.target(), target);
        let serialized = serde_json::to_value(&receipt).expect("serialize exact receipt target");
        assert_eq!(serialized["target"]["encoding"], "unix_bytes_hex");
        assert_eq!(serialized["target"]["value"], "7374ff");
        storage
            .read(&target, FileClass::State)
            .expect("read non-UTF-8 target")
            .expose_bytes(|bytes| assert_eq!(bytes, Some(b"non-utf8-target".as_slice())));
    }

    #[test]
    fn parent_and_leaf_symlinks_cannot_redirect_reads_or_writes() {
        let (root, storage) = fixture();
        let outside = tempfile::tempdir().expect("outside");
        seed_private(&outside.path().join("state.json"), b"outside-sentinel");
        std::os::unix::fs::symlink(outside.path(), root.path().join("linked"))
            .expect("parent symlink");

        assert!(matches!(
            storage.commit(
                "linked/state.json",
                FileClass::State,
                StorageGeneration::Missing,
                b"redirect-attempt",
            ),
            Err(PersistenceError::InvalidTarget { .. })
        ));
        assert_eq!(
            std::fs::read(outside.path().join("state.json")).expect("outside remains"),
            b"outside-sentinel"
        );

        let outside_leaf = outside.path().join("leaf.json");
        seed_private(&outside_leaf, b"leaf-sentinel");
        std::os::unix::fs::symlink(&outside_leaf, root.path().join("leaf.json"))
            .expect("leaf symlink");
        assert!(matches!(
            storage.read("leaf.json", FileClass::State),
            Err(PersistenceError::InvalidTarget { .. })
        ));
        assert!(matches!(
            storage.commit(
                "leaf.json",
                FileClass::State,
                StorageGeneration::Missing,
                b"redirect-attempt",
            ),
            Err(PersistenceError::InvalidTarget { .. })
        ));
        assert_eq!(
            std::fs::read(outside_leaf).expect("outside leaf"),
            b"leaf-sentinel"
        );
    }

    #[test]
    fn parent_and_leaf_swaps_cannot_redirect_a_read() {
        for swap_parent in [true, false] {
            let (root, storage) = fixture();
            let outside = tempfile::tempdir().expect("outside");
            let target = if swap_parent {
                std::fs::create_dir(root.path().join("parent")).expect("parent");
                std::fs::set_permissions(
                    root.path().join("parent"),
                    std::fs::Permissions::from_mode(0o700),
                )
                .expect("parent mode");
                PathBuf::from("parent/state.json")
            } else {
                PathBuf::from("state.json")
            };
            seed_private(&root.path().join(&target), b"inside-state");
            seed_private(&outside.path().join("state.json"), b"outside-secret");
            let entered = Arc::new(Barrier::new(2));
            let resume = Arc::new(Barrier::new(2));
            storage.set_test_action(
                Checkpoint::ParentOpened,
                TestAction::Pause {
                    entered: Arc::clone(&entered),
                    resume: Arc::clone(&resume),
                },
            );

            let read_target = target.clone();
            let reader = std::thread::spawn(move || storage.read(read_target, FileClass::State));
            entered.wait();
            if swap_parent {
                std::fs::rename(root.path().join("parent"), root.path().join("parked"))
                    .expect("park parent");
                std::os::unix::fs::symlink(outside.path(), root.path().join("parent"))
                    .expect("swap parent");
            } else {
                std::fs::remove_file(root.path().join(&target)).expect("remove inside leaf");
                std::os::unix::fs::symlink(
                    outside.path().join("state.json"),
                    root.path().join(&target),
                )
                .expect("swap leaf");
            }
            resume.wait();

            let error = reader
                .join()
                .expect("reader thread")
                .expect_err("namespace swap must not return bytes");
            assert!(
                !error.to_string().contains("outside-secret"),
                "outside bytes must not enter the result: {error}"
            );
            assert_eq!(
                std::fs::read(outside.path().join("state.json")).expect("outside remains"),
                b"outside-secret"
            );
        }
    }

    #[test]
    fn swapped_parent_is_detected_at_the_publication_boundary() {
        let (root, storage) = fixture();
        std::fs::create_dir(root.path().join("parent")).expect("parent");
        std::fs::set_permissions(
            root.path().join("parent"),
            std::fs::Permissions::from_mode(0o700),
        )
        .expect("parent mode");
        let outside = tempfile::tempdir().expect("outside");
        let entered = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        storage.set_test_action(
            Checkpoint::BeforeRename,
            TestAction::Pause {
                entered: Arc::clone(&entered),
                resume: Arc::clone(&resume),
            },
        );

        let writer = std::thread::spawn(move || {
            storage.commit(
                "parent/state.json",
                FileClass::State,
                StorageGeneration::Missing,
                b"new-state",
            )
        });
        entered.wait();
        std::fs::rename(root.path().join("parent"), root.path().join("parked"))
            .expect("park parent");
        std::os::unix::fs::symlink(outside.path(), root.path().join("parent"))
            .expect("swap parent to symlink");
        resume.wait();

        let error = writer
            .join()
            .expect("writer thread")
            .expect_err("namespace swap must fail");
        assert_eq!(error.commit_state(), Some(CommitState::Unchanged));
        assert_eq!(
            error.observed_generation(),
            Some(StorageGeneration::Missing)
        );
        assert!(!outside.path().join("state.json").exists());
        assert!(!root.path().join("parked/state.json").exists());

        std::fs::remove_file(root.path().join("parent")).expect("remove symlink");
        std::fs::rename(root.path().join("parked"), root.path().join("parent"))
            .expect("restore parent");
    }

    #[test]
    fn swapped_parent_cannot_produce_a_conflict_for_the_wrong_namespace() {
        let (root, storage) = fixture();
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).expect("parent");
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700))
            .expect("parent mode");
        seed_private(&parent.join("state.json"), b"detached-generation");
        let outside = tempfile::tempdir().expect("outside");
        seed_private(&outside.path().join("state.json"), b"outside-generation");
        let entered = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        storage.set_test_action(
            Checkpoint::ParentOpened,
            TestAction::Pause {
                entered: Arc::clone(&entered),
                resume: Arc::clone(&resume),
            },
        );

        let writer = std::thread::spawn(move || {
            storage.commit(
                "parent/state.json",
                FileClass::State,
                StorageGeneration::Missing,
                b"new-state",
            )
        });
        entered.wait();
        std::fs::rename(&parent, root.path().join("parked")).expect("park parent");
        std::os::unix::fs::symlink(outside.path(), &parent).expect("replace parent namespace");
        resume.wait();

        let error = writer
            .join()
            .expect("writer thread")
            .expect_err("detached observation is not a target-generation conflict");
        assert!(matches!(
            error,
            PersistenceError::Unchanged {
                phase: UnchangedPhase::NamespaceCheck,
                ..
            }
        ));
        assert_eq!(
            std::fs::read(outside.path().join("state.json")).expect("outside unchanged"),
            b"outside-generation"
        );
        assert_eq!(
            std::fs::read(root.path().join("parked/state.json")).expect("detached unchanged"),
            b"detached-generation"
        );
    }

    #[test]
    fn parent_mode_change_is_detected_at_the_publication_boundary() {
        let (root, storage) = fixture();
        let parent_path = root.path().join("parent");
        std::fs::create_dir(&parent_path).expect("parent");
        std::fs::set_permissions(&parent_path, std::fs::Permissions::from_mode(0o700))
            .expect("private parent mode");
        let entered = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        storage.set_test_action(
            Checkpoint::BeforeRename,
            TestAction::Pause {
                entered: Arc::clone(&entered),
                resume: Arc::clone(&resume),
            },
        );

        let writer = std::thread::spawn(move || {
            storage.commit(
                "parent/state.json",
                FileClass::State,
                StorageGeneration::Missing,
                b"new-state",
            )
        });
        entered.wait();
        std::fs::set_permissions(&parent_path, std::fs::Permissions::from_mode(0o777))
            .expect("broaden parent mode");
        resume.wait();

        let error = writer
            .join()
            .expect("writer thread")
            .expect_err("unsafe parent mode must stop publication");
        assert_eq!(error.commit_state(), Some(CommitState::Unchanged));
        assert!(matches!(
            error,
            PersistenceError::Unchanged {
                phase: UnchangedPhase::NamespaceCheck,
                ..
            }
        ));
        assert!(!parent_path.join("state.json").exists());
    }

    #[test]
    fn staging_generation_change_is_detected_at_the_publication_boundary() {
        let (root, storage) = fixture();
        let target = Path::new("state.json");
        let entered = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        storage.set_test_action(
            Checkpoint::BeforeRename,
            TestAction::Pause {
                entered: Arc::clone(&entered),
                resume: Arc::clone(&resume),
            },
        );

        let writer = std::thread::spawn(move || {
            storage.commit(
                target,
                FileClass::State,
                StorageGeneration::Missing,
                b"intended-generation",
            )
        });
        entered.wait();
        std::fs::write(
            root.path().join(target_sidecar_name("stage", target)),
            b"tampered-generation",
        )
        .expect("alter staged bytes");
        resume.wait();

        let error = writer
            .join()
            .expect("writer thread")
            .expect_err("changed staged generation must not publish");
        assert!(matches!(
            error,
            PersistenceError::Unchanged {
                phase: UnchangedPhase::StageSync,
                ..
            }
        ));
        assert!(!root.path().join(target).exists());
    }

    #[test]
    fn rebound_staging_name_cannot_publish_unvalidated_bytes() {
        let (root, storage) = fixture();
        let target = Path::new("state.json");
        let entered = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        storage.set_test_action(
            Checkpoint::BeforeRename,
            TestAction::Pause {
                entered: Arc::clone(&entered),
                resume: Arc::clone(&resume),
            },
        );

        let writer = std::thread::spawn(move || {
            storage.commit(
                target,
                FileClass::State,
                StorageGeneration::Missing,
                b"validated-generation",
            )
        });
        entered.wait();
        let stage = root.path().join(target_sidecar_name("stage", target));
        let parked = root.path().join("parked-stage");
        std::fs::rename(&stage, &parked).expect("park validated stage inode");
        seed_private(&stage, b"substituted-generation");
        resume.wait();

        let error = writer
            .join()
            .expect("writer thread")
            .expect_err("rebound staging name must stop publication");
        assert!(matches!(
            error,
            PersistenceError::Unchanged {
                phase: UnchangedPhase::NamespaceCheck,
                ..
            }
        ));
        assert!(!root.path().join(target).exists());
        assert_eq!(
            std::fs::read(parked).expect("validated stage retained"),
            b"validated-generation"
        );
        assert_eq!(
            std::fs::read(stage).expect("replacement not unlinked"),
            b"substituted-generation"
        );
    }

    #[test]
    fn transient_staging_hardlink_is_detected_before_publication() {
        let (root, storage) = fixture();
        let outside = tempfile::tempdir().expect("outside");
        let target = Path::new("state.json");
        let entered = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        storage.set_test_action(
            Checkpoint::BeforeRename,
            TestAction::Pause {
                entered: Arc::clone(&entered),
                resume: Arc::clone(&resume),
            },
        );

        let writer = std::thread::spawn(move || {
            storage.commit(
                target,
                FileClass::State,
                StorageGeneration::Missing,
                b"private-generation",
            )
        });
        entered.wait();
        let stage = root.path().join(target_sidecar_name("stage", target));
        let transient = outside.path().join("transient-link");
        std::fs::hard_link(&stage, &transient).expect("link staged inode");
        std::fs::remove_file(&transient).expect("remove transient hardlink");
        resume.wait();

        let error = writer
            .join()
            .expect("writer thread")
            .expect_err("post-sync metadata mutation must stop publication");
        assert!(matches!(
            error,
            PersistenceError::Unchanged {
                phase: UnchangedPhase::StageSync,
                ..
            }
        ));
        assert!(!root.path().join(target).exists());
    }

    #[test]
    fn lock_namespace_change_is_detected_at_the_publication_boundary() {
        let (root, storage) = fixture();
        let target = Path::new("state.json");
        let entered = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        storage.set_test_action(
            Checkpoint::BeforeRename,
            TestAction::Pause {
                entered: Arc::clone(&entered),
                resume: Arc::clone(&resume),
            },
        );

        let writer = std::thread::spawn(move || {
            storage.commit(
                target,
                FileClass::State,
                StorageGeneration::Missing,
                b"must-not-publish",
            )
        });
        entered.wait();
        std::fs::remove_file(root.path().join(target_sidecar_name("lock", target)))
            .expect("unlink held lock name");
        resume.wait();

        let error = writer
            .join()
            .expect("writer thread")
            .expect_err("changed lock identity must stop publication");
        assert!(matches!(
            error,
            PersistenceError::Unchanged {
                phase: UnchangedPhase::NamespaceCheck,
                ..
            }
        ));
        assert!(!root.path().join(target).exists());
    }

    #[test]
    fn leaf_symlink_swap_is_replaced_without_following_outside_target() {
        let (root, storage) = fixture();
        let outside = tempfile::tempdir().expect("outside");
        let outside_leaf = outside.path().join("sentinel");
        seed_private(&outside_leaf, b"outside");
        let entered = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        storage.set_test_action(
            Checkpoint::BeforeRename,
            TestAction::Pause {
                entered: Arc::clone(&entered),
                resume: Arc::clone(&resume),
            },
        );

        let writer = std::thread::spawn(move || {
            storage.commit(
                "state.json",
                FileClass::State,
                StorageGeneration::Missing,
                b"inside",
            )
        });
        entered.wait();
        std::os::unix::fs::symlink(&outside_leaf, root.path().join("state.json"))
            .expect("swapped leaf");
        resume.wait();
        let receipt = writer.join().expect("writer").expect("safe replacement");
        assert_eq!(receipt.state(), CommitState::CommittedDurable);
        assert_eq!(
            std::fs::read(root.path().join("state.json")).unwrap(),
            b"inside"
        );
        assert_eq!(std::fs::read(outside_leaf).unwrap(), b"outside");
    }

    #[test]
    fn hardlinks_and_overbroad_modes_are_rejected() {
        let (root, storage) = fixture();
        let outside = tempfile::NamedTempFile::new().expect("outside file");
        std::fs::set_permissions(outside.path(), std::fs::Permissions::from_mode(0o600))
            .expect("outside mode");
        std::fs::hard_link(outside.path(), root.path().join("hardlink")).expect("hard link");
        assert!(matches!(
            storage.read("hardlink", FileClass::State),
            Err(PersistenceError::InvalidTarget { .. })
        ));

        seed_private(&root.path().join("broad.json"), b"state");
        std::fs::set_permissions(
            root.path().join("broad.json"),
            std::fs::Permissions::from_mode(0o640),
        )
        .expect("broaden mode");
        assert!(matches!(
            storage.read("broad.json", FileClass::State),
            Err(PersistenceError::InvalidTarget { .. })
        ));

        seed_private(&root.path().join("setuid.json"), b"state");
        std::fs::set_permissions(
            root.path().join("setuid.json"),
            std::fs::Permissions::from_mode(0o4600),
        )
        .expect("set special mode");
        assert!(matches!(
            storage.read("setuid.json", FileClass::State),
            Err(PersistenceError::InvalidTarget { .. })
        ));
    }

    #[test]
    fn fifo_leaf_is_rejected_without_blocking_for_a_writer() {
        use std::os::unix::ffi::OsStrExt as _;

        let (root, storage) = fixture();
        let fifo = root.path().join("state.pipe");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).expect("FIFO path");
        // SAFETY: the path is NUL-terminated and points into a private
        // temporary directory owned by this test.
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);

        let started = std::time::Instant::now();
        assert!(matches!(
            storage.read("state.pipe", FileClass::State),
            Err(PersistenceError::InvalidTarget { .. })
        ));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn fifo_staging_sidecar_is_rejected_without_blocking_cleanup() {
        use std::os::unix::ffi::OsStrExt as _;

        let (root, storage) = fixture();
        let target = Path::new("state.json");
        let stage = root.path().join(target_sidecar_name("stage", target));
        let stage_c = std::ffi::CString::new(stage.as_os_str().as_bytes()).expect("FIFO path");
        // SAFETY: the path is NUL-terminated and points into a private
        // temporary directory owned by this test.
        assert_eq!(unsafe { libc::mkfifo(stage_c.as_ptr(), 0o600) }, 0);

        let started = std::time::Instant::now();
        let error = storage
            .commit(
                target,
                FileClass::State,
                StorageGeneration::Missing,
                b"must-not-publish",
            )
            .expect_err("special staging sidecar must fail closed");
        assert!(matches!(
            error,
            PersistenceError::Unchanged {
                phase: UnchangedPhase::Cleanup,
                ..
            }
        ));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert!(!root.path().join(target).exists());
    }

    #[test]
    fn fifo_lock_sidecar_is_rejected_without_blocking_acquisition() {
        use std::os::unix::ffi::OsStrExt as _;

        let (root, storage) = fixture();
        let target = Path::new("state.json");
        let lock = root.path().join(target_sidecar_name("lock", target));
        let lock_c = std::ffi::CString::new(lock.as_os_str().as_bytes()).expect("FIFO path");
        // SAFETY: the path is NUL-terminated and points into a private
        // temporary directory owned by this test.
        assert_eq!(unsafe { libc::mkfifo(lock_c.as_ptr(), 0o600) }, 0);

        let started = std::time::Instant::now();
        let error = storage
            .commit(
                target,
                FileClass::State,
                StorageGeneration::Missing,
                b"must-not-publish",
            )
            .expect_err("special lock sidecar must fail closed");
        assert!(matches!(
            error,
            PersistenceError::Io {
                operation: "acquire target lock",
                ..
            }
        ));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        assert!(!root.path().join(target).exists());
    }

    #[test]
    fn target_lock_wait_has_a_bounded_deadline() {
        let (_root, storage) = fixture();
        let target = validate_target(Path::new("state.json")).expect("target");
        let parent = open_parent(&storage, &target).expect("parent");
        let held = acquire_lock(&parent, &target).expect("held lock");

        let started = std::time::Instant::now();
        let error = storage
            .commit(
                &target,
                FileClass::State,
                StorageGeneration::Missing,
                b"blocked",
            )
            .expect_err("second lock acquisition must time out");
        assert!(matches!(
            error,
            PersistenceError::Io {
                operation: "acquire target lock",
                source,
                ..
            } if source.kind() == io::ErrorKind::TimedOut
        ));
        assert!(started.elapsed() < std::time::Duration::from_secs(1));

        drop(held);
        assert_eq!(
            storage
                .commit(
                    &target,
                    FileClass::State,
                    StorageGeneration::Missing,
                    b"unblocked",
                )
                .expect("commit after release")
                .state(),
            CommitState::CommittedDurable
        );
    }

    #[test]
    fn class_bounds_apply_before_write_and_during_read() {
        let (root, storage) = fixture();
        let oversized =
            vec![b'x'; usize::try_from(FileClass::Credentials.max_bytes()).unwrap() + 1];
        assert!(matches!(
            storage.commit(
                "too-large",
                FileClass::Credentials,
                StorageGeneration::Missing,
                &oversized,
            ),
            Err(PersistenceError::TooLarge { .. })
        ));
        assert_eq!(std::fs::read_dir(root.path()).expect("entries").count(), 0);

        seed_private(&root.path().join("too-large"), &oversized);
        assert!(matches!(
            storage.read("too-large", FileClass::Credentials),
            Err(PersistenceError::TooLarge { .. })
        ));

        let exact = vec![b'y'; usize::try_from(FileClass::Credentials.max_bytes()).unwrap()];
        let receipt = storage
            .commit(
                "exact-limit",
                FileClass::Credentials,
                StorageGeneration::Missing,
                &exact,
            )
            .expect("class limit is inclusive");
        assert_eq!(
            storage
                .read("exact-limit", FileClass::Credentials)
                .expect("read exact class limit")
                .generation(),
            receipt.generation()
        );
    }

    #[test]
    fn explicit_legacy_read_policy_narrows_mode_on_commit() {
        let (root, storage) = fixture();
        for (name, class) in [
            ("config.json", FileClass::Configuration),
            ("session.json", FileClass::Session),
            ("artifact.json", FileClass::Artifact),
        ] {
            let path = root.path().join(name);
            seed_private(&path, b"legacy");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
                .expect("legacy mode");
            let observed = storage.read(name, class).expect("legacy read");
            storage
                .commit(name, class, observed.generation(), b"narrowed")
                .expect("narrowing commit");
            assert_eq!(
                std::fs::metadata(path)
                    .expect("narrowed metadata")
                    .permissions()
                    .mode()
                    & 0o7777,
                0o600
            );
        }

        let credential = root.path().join("credential.json");
        seed_private(&credential, b"legacy-secret");
        std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o644))
            .expect("unsafe credential mode");
        assert!(matches!(
            storage.read("credential.json", FileClass::Credentials),
            Err(PersistenceError::InvalidTarget { .. })
        ));
    }

    #[test]
    fn disk_full_and_rename_failures_leave_old_generation_intact() {
        for (checkpoint, raw_error, phase) in [
            (
                Checkpoint::AfterStageWrite,
                libc::ENOSPC,
                UnchangedPhase::StageWrite,
            ),
            (
                Checkpoint::BeforeRename,
                libc::EXDEV,
                UnchangedPhase::Rename,
            ),
        ] {
            let (_root, storage) = fixture();
            let first = storage
                .commit(
                    "state.json",
                    FileClass::State,
                    StorageGeneration::Missing,
                    b"old",
                )
                .expect("seed commit");
            storage.set_test_action(checkpoint, TestAction::Error(raw_error));
            let error = storage
                .commit("state.json", FileClass::State, first.generation(), b"new")
                .expect_err("fault must fail before publication");
            assert!(matches!(
                &error,
                PersistenceError::Unchanged { phase: actual, .. } if *actual == phase
            ));
            assert_eq!(error.observed_generation(), Some(first.generation()));
            storage
                .read("state.json", FileClass::State)
                .unwrap()
                .expose_bytes(|bytes| assert_eq!(bytes, Some(b"old".as_slice())));
        }
    }

    #[test]
    fn directory_fsync_failure_is_uncertain_then_retry_recovers() {
        let (_root, storage) = fixture();
        storage.set_test_action(
            Checkpoint::BeforeDirectorySync,
            TestAction::Error(libc::EIO),
        );
        let uncertain = storage
            .commit(
                "state.json",
                FileClass::State,
                StorageGeneration::Missing,
                b"published",
            )
            .expect("post-rename fsync is a typed state, not an ordinary error");
        assert_eq!(uncertain.state(), CommitState::PublishedDurabilityUncertain);
        let failure = uncertain
            .durability_failure()
            .expect("uncertain receipt must carry a bounded cause");
        assert_eq!(failure.raw_os_error(), Some(libc::EIO));
        assert_eq!(
            failure.kind(),
            format!("{:?}", io::Error::from_raw_os_error(libc::EIO).kind())
        );
        storage
            .read("state.json", FileClass::State)
            .unwrap()
            .expose_bytes(|bytes| assert_eq!(bytes, Some(b"published".as_slice())));

        let recovered = storage
            .commit(
                "state.json",
                FileClass::State,
                StorageGeneration::Missing,
                b"published",
            )
            .expect("retry reconciles before republishing");
        assert_eq!(recovered.state(), CommitState::Recovered);
        assert_eq!(recovered.generation(), uncertain.generation());
    }

    #[test]
    fn concurrent_writers_preserve_one_knowable_generation() {
        let (_root, storage) = fixture();
        let initial = storage
            .commit(
                "state.json",
                FileClass::State,
                StorageGeneration::Missing,
                b"initial",
            )
            .expect("initial");
        let barrier = Arc::new(Barrier::new(3));
        let mut workers = Vec::new();
        for bytes in [b"writer-a".as_slice(), b"writer-b".as_slice()] {
            let storage = storage.clone();
            let barrier = Arc::clone(&barrier);
            let expected = initial.generation();
            let bytes = bytes.to_vec();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                storage.commit("state.json", FileClass::State, expected, bytes)
            }));
        }
        barrier.wait();
        let results = workers
            .into_iter()
            .map(|worker| worker.join().expect("writer thread"))
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(PersistenceError::Conflict { .. })))
                .count(),
            1
        );
        let winner = results
            .iter()
            .find_map(|result| result.as_ref().ok())
            .expect("one winner");
        let final_state = storage
            .read("state.json", FileClass::State)
            .expect("final read");
        assert_eq!(final_state.generation(), winner.generation());
        final_state.expose_bytes(|bytes| {
            assert!(matches!(
                bytes,
                Some(bytes) if bytes == b"writer-a" || bytes == b"writer-b"
            ));
        });
    }

    #[test]
    #[ignore = "spawned only by crash_boundary_recovery"]
    fn crash_worker() {
        let mode = std::env::var(CRASH_MODE_ENV).expect("crash mode");
        let root = PathBuf::from(std::env::var_os(CRASH_ROOT_ENV).expect("crash root"));
        let storage = PersistentStorage::open(root).expect("worker storage");
        let expected = storage
            .read("state.json", FileClass::State)
            .expect("worker read")
            .generation();
        let checkpoint = match mode.as_str() {
            "before" => Checkpoint::BeforeRename,
            "after" => Checkpoint::AfterRename,
            other => panic!("unknown crash mode {other}"),
        };
        storage.set_test_action(checkpoint, TestAction::Exit(91));
        let _ = storage.commit("state.json", FileClass::State, expected, b"after-crash");
        panic!("crash checkpoint did not exit");
    }

    #[test]
    fn crash_boundary_recovery_preserves_a_knowable_generation() {
        for mode in ["before", "after"] {
            let (root, storage) = fixture();
            let initial = storage
                .commit(
                    "state.json",
                    FileClass::State,
                    StorageGeneration::Missing,
                    b"before-crash",
                )
                .expect("initial");
            let status = std::process::Command::new(std::env::current_exe().expect("test binary"))
                .arg("--exact")
                .arg("persistence::tests::crash_worker")
                .arg("--ignored")
                .arg("--test-threads=1")
                .env(CRASH_MODE_ENV, mode)
                .env(CRASH_ROOT_ENV, root.path())
                .status()
                .expect("spawn crash worker");
            assert_eq!(status.code(), Some(91));

            let visible = storage
                .read("state.json", FileClass::State)
                .expect("post-crash read");
            if mode == "before" {
                assert_eq!(visible.generation(), initial.generation());
                visible.expose_bytes(|bytes| {
                    assert_eq!(bytes, Some(b"before-crash".as_slice()));
                });
                let committed = storage
                    .commit(
                        "state.json",
                        FileClass::State,
                        initial.generation(),
                        b"after-crash",
                    )
                    .expect("retry after pre-rename crash");
                assert_eq!(committed.state(), CommitState::CommittedDurable);
                assert!(std::fs::read_dir(root.path())
                    .expect("post-recovery entries")
                    .all(|entry| {
                        !entry
                            .expect("entry")
                            .file_name()
                            .to_string_lossy()
                            .contains("-stage-")
                    }));
            } else {
                visible.expose_bytes(|bytes| {
                    assert_eq!(bytes, Some(b"after-crash".as_slice()));
                });
                let recovered = storage
                    .commit(
                        "state.json",
                        FileClass::State,
                        initial.generation(),
                        b"after-crash",
                    )
                    .expect("retry after post-rename crash");
                assert_eq!(recovered.state(), CommitState::Recovered);
                assert_eq!(recovered.generation(), visible.generation());
            }
        }
    }

    #[test]
    fn file_classes_have_distinct_bounded_policies() {
        assert!(FileClass::Credentials.max_bytes() < FileClass::Configuration.max_bytes());
        assert_eq!(
            FileClass::Configuration.max_bytes(),
            FileClass::PortableMemoryPackage.max_bytes()
        );
        assert!(FileClass::Configuration.max_bytes() < FileClass::State.max_bytes());
        assert!(FileClass::State.max_bytes() < FileClass::Session.max_bytes());
        assert_eq!(
            FileClass::Session.max_bytes(),
            FileClass::Evidence.max_bytes()
        );
        assert!(FileClass::Evidence.max_bytes() < FileClass::Artifact.max_bytes());
    }

    #[test]
    fn present_generation_helper_is_not_fabricated() {
        let (_root, storage) = fixture();
        let receipt = storage
            .commit(
                "state.json",
                FileClass::State,
                StorageGeneration::Missing,
                b"real-io",
            )
            .unwrap();
        let state = storage.read("state.json", FileClass::State).unwrap();
        assert_eq!(present_generation(&state), receipt.generation());
    }

    #[test]
    fn commit_trace_carries_resource_generation_class_and_state() {
        let (_root, storage) = fixture();
        let (receipt, trace) = capture_trace(|| {
            storage
                .commit(
                    "state.json",
                    FileClass::State,
                    StorageGeneration::Missing,
                    b"trace-generation",
                )
                .expect("traced commit")
        });
        assert!(trace.contains("persistent_commit"), "trace: {trace}");
        assert!(trace.contains("file_class=State"), "trace: {trace}");
        assert!(
            trace.contains("commit_state=CommittedDurable"),
            "trace: {trace}"
        );
        assert!(
            trace.contains("relative_target=state.json"),
            "trace: {trace}"
        );
        assert!(
            trace.contains(&receipt.generation().to_string()),
            "trace: {trace}"
        );
        assert!(
            trace.contains(&format!("root_device={}", storage.root_id().device())),
            "trace: {trace}"
        );
        assert!(
            trace.contains(&format!("root_inode={}", storage.root_id().inode())),
            "trace: {trace}"
        );
    }

    #[test]
    fn credential_trace_redacts_present_content_generations() {
        let (_root, storage) = fixture();
        let desired = StorageGeneration::for_bytes(b"credential-trace-secret");
        let (_receipt, trace) = capture_trace(|| {
            storage
                .commit(
                    "credential.json",
                    FileClass::Credentials,
                    StorageGeneration::Missing,
                    b"credential-trace-secret",
                )
                .expect("credential commit")
        });

        assert!(trace.contains("file_class=Credentials"), "trace: {trace}");
        assert!(trace.contains("generation=[REDACTED]"), "trace: {trace}");
        assert!(!trace.contains(&desired.to_string()), "trace: {trace}");
        assert!(!trace.contains("credential-trace-secret"), "trace: {trace}");
    }
}
