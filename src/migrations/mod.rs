//! Fail-closed startup migrations for persistent agent state.
//!
//! Every registered migration is required to be idempotent. The runner holds a
//! bounded, store-scoped process lock, stops at the first failure, catches
//! panic control flow, and returns a typed terminal state. A caller may start a
//! writable agent surface only after receiving
//! [`StartupMigrationStatus::Writable`]. Migration implementations must never
//! place persisted content in a panic payload: Rust invokes the process-global
//! panic hook before [`std::panic::catch_unwind`] returns control to the runner.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

mod ledger;
mod registry;
mod session_state_v1;
mod stamp_transcript_schema_v1;

#[cfg(test)]
mod tests;

pub use ledger::CompletionLedger;
pub use stamp_transcript_schema_v1::{
    foreign_transcript_import_is_current, read_foreign_transcript_import_contract,
    ForeignTranscriptImport,
};

#[cfg(not(test))]
const LOCK_WAIT_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(test)]
const LOCK_WAIT_TIMEOUT: Duration = Duration::from_millis(100);
const LOCK_RETRY_DELAY: Duration = Duration::from_millis(5);

/// Persistent store whose startup state was inspected or changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MigrationStore {
    /// Host-selected directories needed to construct the migration context.
    StartupContext,
    /// `OpenClaudia`-owned local application data.
    OpenClaudiaData,
    /// The legacy Claude transcript compatibility directory.
    ClaudeTranscripts,
}

impl fmt::Display for MigrationStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::StartupContext => "startup context",
            Self::OpenClaudiaData => "OpenClaudia data",
            Self::ClaudeTranscripts => "legacy transcript metadata",
        })
    }
}

/// Stable category for a migration failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MigrationFailureKind {
    ContextUnavailable,
    LockUnavailable,
    InvalidPersistentState,
    UnsupportedFutureSchema,
    ResourceLimitExceeded,
    ConcurrentChange,
    PublicationFailed,
    DurabilityUncertain,
    MigrationPanicked,
    NonIdempotentRegistration,
}

impl MigrationFailureKind {
    /// Stable machine-readable diagnostic code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ContextUnavailable => "migration_context_unavailable",
            Self::LockUnavailable => "migration_lock_unavailable",
            Self::InvalidPersistentState => "migration_invalid_persistent_state",
            Self::UnsupportedFutureSchema => "migration_future_schema",
            Self::ResourceLimitExceeded => "migration_resource_limit",
            Self::ConcurrentChange => "migration_concurrent_change",
            Self::PublicationFailed => "migration_publication_failed",
            Self::DurabilityUncertain => "migration_durability_uncertain",
            Self::MigrationPanicked => "migration_panicked",
            Self::NonIdempotentRegistration => "migration_non_idempotent_registration",
        }
    }
}

/// Redacted, actionable cause returned by a migration.
///
/// Paths, persisted bytes, parser excerpts, and panic payloads are
/// intentionally absent. `io_kind` retains an operator-useful OS category
/// without copying potentially sensitive error text into startup diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationFailure {
    kind: MigrationFailureKind,
    store: MigrationStore,
    operation: &'static str,
    io_kind: Option<io::ErrorKind>,
    committed_artifacts: usize,
}

impl MigrationFailure {
    pub(crate) const fn new(
        kind: MigrationFailureKind,
        store: MigrationStore,
        operation: &'static str,
    ) -> Self {
        Self {
            kind,
            store,
            operation,
            io_kind: None,
            committed_artifacts: 0,
        }
    }

    pub(crate) fn from_io(
        kind: MigrationFailureKind,
        store: MigrationStore,
        operation: &'static str,
        error: &io::Error,
    ) -> Self {
        Self {
            kind,
            store,
            operation,
            io_kind: Some(error.kind()),
            committed_artifacts: 0,
        }
    }

    pub(crate) const fn with_committed_artifacts(mut self, count: usize) -> Self {
        self.committed_artifacts = count;
        self
    }

    /// Stable failure category.
    #[must_use]
    pub const fn kind(&self) -> MigrationFailureKind {
        self.kind
    }

    /// Persistent store affected by the failed operation.
    #[must_use]
    pub const fn store(&self) -> MigrationStore {
        self.store
    }

    /// Content-free name of the operation that failed.
    #[must_use]
    pub const fn operation(&self) -> &'static str {
        self.operation
    }

    /// Standard-library I/O category, when the failure came from the OS.
    #[must_use]
    pub const fn io_kind(&self) -> Option<io::ErrorKind> {
        self.io_kind
    }

    /// Number of artifacts atomically published before the terminal failure.
    #[must_use]
    pub const fn committed_artifacts(&self) -> usize {
        self.committed_artifacts
    }

    /// Operator action that can move the store back toward a known state.
    #[must_use]
    pub const fn recovery(&self) -> &'static str {
        match self.kind {
            MigrationFailureKind::ContextUnavailable => {
                "configure absolute user data/home directories and restart"
            }
            MigrationFailureKind::LockUnavailable => {
                "wait for the other OpenClaudia process to finish, then restart"
            }
            MigrationFailureKind::InvalidPersistentState => {
                "restore the affected store from a known-good backup or inspect it with an offline recovery tool, then restart"
            }
            MigrationFailureKind::UnsupportedFutureSchema => {
                "start with an OpenClaudia version that supports the stored schema"
            }
            MigrationFailureKind::ResourceLimitExceeded => {
                "reduce or archive the affected store with a backup retained, then restart"
            }
            MigrationFailureKind::ConcurrentChange => {
                "stop other writers to the affected store and restart"
            }
            MigrationFailureKind::PublicationFailed => {
                "repair storage capacity, ownership, and permissions, then restart; already-published artifacts are idempotent"
            }
            MigrationFailureKind::DurabilityUncertain => {
                "verify the storage device and restart to reconcile the visible generation"
            }
            MigrationFailureKind::MigrationPanicked => {
                "preserve the store and report the migration diagnostic code before retrying"
            }
            MigrationFailureKind::NonIdempotentRegistration => {
                "remove or replace the non-idempotent startup migration before restarting"
            }
        }
    }
}

impl fmt::Display for MigrationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} while performing {} on {}",
            self.kind.code(),
            self.operation,
            self.store
        )?;
        if let Some(kind) = self.io_kind {
            write!(formatter, " (I/O category: {kind:?})")?;
        }
        if self.committed_artifacts > 0 {
            write!(
                formatter,
                " after {} atomic artifact publication(s)",
                self.committed_artifacts
            )?;
        }
        write!(formatter, "; recovery: {}", self.recovery())
    }
}

impl std::error::Error for MigrationFailure {}

/// Result of one registered migration.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum MigrationOutcome {
    /// The complete inspected store was already current.
    Current,
    /// The migration atomically published this many artifacts.
    Applied { changed_artifacts: usize },
    /// The store is not safe to open writable.
    Failed(MigrationFailure),
}

/// Whether the runner may invoke a migration on every startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunPolicy {
    /// The migration detects current target state and can safely be retried.
    Idempotent,
    /// Legacy policy retained for API compatibility but rejected by the
    /// fail-closed startup runner.
    OnceOnly,
}

/// Contract implemented by each ordered startup migration.
pub trait Migration: Send + Sync {
    /// Stable identifier used in redacted diagnostics.
    fn id(&self) -> &'static str;

    /// Short content-free summary for logs and diagnostics.
    fn description(&self) -> &'static str;

    /// Store whose state is owned by this migration.
    fn store(&self) -> MigrationStore;

    /// Startup accepts only idempotent registrations.
    fn run_policy(&self) -> RunPolicy {
        RunPolicy::Idempotent
    }

    /// Inspect, validate, and atomically publish this migration.
    fn run(&self, ctx: &MigrationContext) -> MigrationOutcome;
}

/// Explicit paths authorized for startup migration work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationContext {
    /// Legacy Claude transcript compatibility root.
    pub claude_home: PathBuf,
    /// `OpenClaudia`-owned application-data root.
    pub openclaudia_data: PathBuf,
    /// Host-selected workspace used to rebind legacy session identity.
    pub workspace_root: PathBuf,
}

impl MigrationContext {
    fn validate(&self) -> Result<(), MigrationFailure> {
        if self.claude_home.is_absolute()
            && self.openclaudia_data.is_absolute()
            && self.workspace_root.is_absolute()
        {
            Ok(())
        } else {
            Err(MigrationFailure::new(
                MigrationFailureKind::ContextUnavailable,
                MigrationStore::StartupContext,
                "validate absolute migration roots",
            ))
        }
    }

    /// Resolve real startup roots without falling back to the ambient working
    /// directory.
    ///
    /// # Errors
    /// Returns a typed failure when a platform directory is unavailable or an
    /// explicit environment override is relative.
    pub fn from_env() -> Result<Self, MigrationFailure> {
        let claude_home = std::env::var_os("CLAUDE_CONFIG_HOME_DIR")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .or_else(|| dirs::home_dir().map(|home| home.join(".claude")))
            .ok_or_else(|| {
                MigrationFailure::new(
                    MigrationFailureKind::ContextUnavailable,
                    MigrationStore::StartupContext,
                    "resolve legacy transcript root",
                )
            })?;
        let openclaudia_data = dirs::data_local_dir()
            .map(|directory| directory.join("openclaudia"))
            .ok_or_else(|| {
                MigrationFailure::new(
                    MigrationFailureKind::ContextUnavailable,
                    MigrationStore::StartupContext,
                    "resolve OpenClaudia data root",
                )
            })?;
        let workspace_root = std::env::current_dir().map_err(|error| {
            MigrationFailure::from_io(
                MigrationFailureKind::ContextUnavailable,
                MigrationStore::StartupContext,
                "resolve trusted startup workspace",
                &error,
            )
        })?;
        let context = Self {
            claude_home,
            openclaudia_data,
            workspace_root,
        };
        context.validate()?;
        Ok(context)
    }

    /// Compatibility constructor for tests that do not migrate legacy files.
    /// The owned data root is also used as the deterministic workspace.
    #[must_use]
    pub fn with_paths(claude_home: PathBuf, openclaudia_data: PathBuf) -> Self {
        let workspace_root = openclaudia_data.clone();
        Self {
            claude_home,
            openclaudia_data,
            workspace_root,
        }
    }

    /// Explicit constructor for a host that owns storage and workspace roots.
    #[must_use]
    pub const fn with_paths_and_workspace(
        claude_home: PathBuf,
        openclaudia_data: PathBuf,
        workspace_root: PathBuf,
    ) -> Self {
        Self {
            claude_home,
            openclaudia_data,
            workspace_root,
        }
    }
}

/// Per-migration report returned in registry order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationReport {
    pub id: &'static str,
    pub description: &'static str,
    pub store: MigrationStore,
    pub outcome: MigrationOutcome,
}

/// Failure that prevents a normal writable startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupMigrationFailure {
    migration_id: &'static str,
    cause: MigrationFailure,
}

impl StartupMigrationFailure {
    const fn new(migration_id: &'static str, cause: MigrationFailure) -> Self {
        Self {
            migration_id,
            cause,
        }
    }

    /// Stable migration or startup-phase identifier.
    #[must_use]
    pub const fn migration_id(&self) -> &'static str {
        self.migration_id
    }

    /// Typed, content-redacted failure cause.
    #[must_use]
    pub const fn cause(&self) -> &MigrationFailure {
        &self.cause
    }
}

impl fmt::Display for StartupMigrationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "startup blocked by migration {}: {}",
            self.migration_id, self.cause
        )
    }
}

impl std::error::Error for StartupMigrationFailure {}

/// Terminal state of the startup migration gate.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StartupMigrationStatus {
    /// All registered migrations reached a known current state. Writable
    /// startup may continue.
    Writable { reports: Vec<MigrationReport> },
    /// Startup must stop or enter a separately implemented read-only recovery
    /// surface. Normal writable agent sessions are forbidden.
    RecoveryRequired {
        reports: Vec<MigrationReport>,
        failure: StartupMigrationFailure,
    },
}

impl StartupMigrationStatus {
    /// Ordered reports produced before the terminal state.
    #[must_use]
    pub fn reports(&self) -> &[MigrationReport] {
        match self {
            Self::Writable { reports } | Self::RecoveryRequired { reports, .. } => reports,
        }
    }

    /// Whether the caller may open migrated stores writable.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        matches!(self, Self::Writable { .. })
    }

    /// Consume the status at the composition root and enforce the gate.
    ///
    /// # Errors
    /// Returns the typed terminal failure when writable startup is forbidden.
    pub fn into_writable(self) -> Result<Vec<MigrationReport>, StartupMigrationFailure> {
        match self {
            Self::Writable { reports } => Ok(reports),
            Self::RecoveryRequired { failure, .. } => Err(failure),
        }
    }
}

struct MigrationLock {
    _file: std::fs::File,
}

impl MigrationLock {
    fn open_file(lock_path: &Path) -> Result<std::fs::File, MigrationFailure> {
        let mut options = std::fs::OpenOptions::new();
        options.create(true).read(true).write(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;

            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        options.open(lock_path).map_err(|error| {
            MigrationFailure::from_io(
                MigrationFailureKind::LockUnavailable,
                MigrationStore::OpenClaudiaData,
                "open migration lock",
                &error,
            )
        })
    }

    #[cfg(unix)]
    fn acquire_platform(file: &std::fs::File) -> Result<(), MigrationFailure> {
        use std::os::fd::AsRawFd as _;
        use std::os::unix::fs::PermissionsExt as _;

        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| {
                MigrationFailure::from_io(
                    MigrationFailureKind::LockUnavailable,
                    MigrationStore::OpenClaudiaData,
                    "secure migration lock",
                    &error,
                )
            })?;
        let started = Instant::now();
        loop {
            // SAFETY: the descriptor is live for the call and `flock`
            // retains neither the integer nor a pointer.
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if error.kind() != io::ErrorKind::WouldBlock || started.elapsed() >= LOCK_WAIT_TIMEOUT {
                return Err(MigrationFailure::from_io(
                    MigrationFailureKind::LockUnavailable,
                    MigrationStore::OpenClaudiaData,
                    "acquire bounded migration lock",
                    &error,
                ));
            }
            std::thread::sleep(LOCK_RETRY_DELAY);
        }
    }

    #[cfg(windows)]
    fn acquire_platform(file: &std::fs::File) -> Result<(), MigrationFailure> {
        use std::os::windows::io::AsRawHandle as _;

        const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;
        const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x0000_0001;
        let started = Instant::now();
        loop {
            let mut overlapped =
                std::mem::MaybeUninit::<windows_sys::Win32::System::IO::OVERLAPPED>::zeroed();
            // SAFETY: the handle remains live and a zeroed OVERLAPPED is
            // valid for this synchronous whole-file lock attempt.
            let result = unsafe {
                windows_sys::Win32::Storage::FileSystem::LockFileEx(
                    file.as_raw_handle() as _,
                    LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                    0,
                    u32::MAX,
                    u32::MAX,
                    overlapped.as_mut_ptr(),
                )
            };
            if result != 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if started.elapsed() >= LOCK_WAIT_TIMEOUT {
                return Err(MigrationFailure::from_io(
                    MigrationFailureKind::LockUnavailable,
                    MigrationStore::OpenClaudiaData,
                    "acquire bounded migration lock",
                    &error,
                ));
            }
            std::thread::sleep(LOCK_RETRY_DELAY);
        }
    }

    #[cfg(not(any(unix, windows)))]
    const fn acquire_platform(_: &std::fs::File) -> Result<(), MigrationFailure> {
        Err(MigrationFailure::new(
            MigrationFailureKind::LockUnavailable,
            MigrationStore::OpenClaudiaData,
            "acquire migration lock on unsupported platform",
        ))
    }

    fn acquire(ctx: &MigrationContext) -> Result<Self, MigrationFailure> {
        std::fs::create_dir_all(&ctx.openclaudia_data).map_err(|error| {
            MigrationFailure::from_io(
                MigrationFailureKind::LockUnavailable,
                MigrationStore::OpenClaudiaData,
                "create migration lock directory",
                &error,
            )
        })?;
        let lock_path = ctx.openclaudia_data.join(".startup-migrations.lock");
        let file = Self::open_file(&lock_path)?;
        Self::acquire_platform(&file)?;
        Ok(Self { _file: file })
    }
}

fn recovery_status(
    reports: Vec<MigrationReport>,
    migration_id: &'static str,
    cause: MigrationFailure,
) -> StartupMigrationStatus {
    tracing::error!(
        migration_id,
        diagnostic_code = cause.kind().code(),
        store = %cause.store(),
        operation = cause.operation(),
        committed_artifacts = cause.committed_artifacts(),
        recovery = cause.recovery(),
        "startup migration requires recovery"
    );
    StartupMigrationStatus::RecoveryRequired {
        reports,
        failure: StartupMigrationFailure::new(migration_id, cause),
    }
}

fn run_registered(
    ctx: &MigrationContext,
    migrations: Vec<Box<dyn Migration>>,
) -> StartupMigrationStatus {
    if let Err(cause) = ctx.validate() {
        return recovery_status(Vec::new(), "startup-context", cause);
    }
    let _lock = match MigrationLock::acquire(ctx) {
        Ok(lock) => lock,
        Err(cause) => return recovery_status(Vec::new(), "startup-store-lock", cause),
    };
    let mut reports = Vec::with_capacity(migrations.len());
    for migration in migrations {
        let id = migration.id();
        let description = migration.description();
        let store = migration.store();
        if migration.run_policy() != RunPolicy::Idempotent {
            let cause = MigrationFailure::new(
                MigrationFailureKind::NonIdempotentRegistration,
                store,
                "validate migration registration",
            );
            reports.push(MigrationReport {
                id,
                description,
                store,
                outcome: MigrationOutcome::Failed(cause.clone()),
            });
            return recovery_status(reports, id, cause);
        }
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| migration.run(ctx)))
            .unwrap_or_else(|_| {
                MigrationOutcome::Failed(MigrationFailure::new(
                    MigrationFailureKind::MigrationPanicked,
                    store,
                    "execute contained migration",
                ))
            });
        let failure = match &outcome {
            MigrationOutcome::Failed(cause) => Some(cause.clone()),
            MigrationOutcome::Current | MigrationOutcome::Applied { .. } => None,
        };
        reports.push(MigrationReport {
            id,
            description,
            store,
            outcome,
        });
        if let Some(cause) = failure {
            return recovery_status(reports, id, cause);
        }
    }
    StartupMigrationStatus::Writable { reports }
}

/// Run every registered migration under the fail-closed startup gate.
#[must_use]
pub fn run_all(ctx: &MigrationContext) -> StartupMigrationStatus {
    run_registered(ctx, registry::all())
}

/// Resolve the production migration context and run the complete gate.
#[must_use]
pub fn run_startup() -> StartupMigrationStatus {
    match MigrationContext::from_env() {
        Ok(context) => run_all(&context),
        Err(cause) => recovery_status(Vec::new(), "startup-context", cause),
    }
}

/// Count changed artifacts without discarding the terminal failure state.
///
/// # Errors
/// Returns the same typed recovery requirement as [`run_all`].
pub fn run_all_count_applied(ctx: &MigrationContext) -> Result<usize, StartupMigrationFailure> {
    let reports = run_all(ctx).into_writable()?;
    Ok(reports
        .iter()
        .map(|report| match &report.outcome {
            MigrationOutcome::Applied { changed_artifacts } => *changed_artifacts,
            MigrationOutcome::Current | MigrationOutcome::Failed(_) => 0,
        })
        .sum())
}
