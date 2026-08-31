//! Typed, bounded, restart-reconcilable background-job records.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const JOB_SCHEMA_VERSION: u32 = 1;
pub(super) const MAX_JOB_OUTPUT_BYTES: usize = 2 * 1024 * 1024;
const MAX_JOB_READ_BYTES: usize = 256 * 1024;
const JOB_RECORD_FILE: &str = "job.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum JobOutputStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct JobOutputEvent {
    pub sequence: u64,
    pub stream: JobOutputStream,
    pub text: String,
    pub byte_len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum BackgroundJobState {
    Starting,
    Running,
    Exited { exit_code: i32 },
    Killed,
    TimedOut,
    Cancelled { reason: String },
    DeliveryFailed { error: String },
    Lost { reason: String },
}

impl BackgroundJobState {
    pub(super) const fn is_running(&self) -> bool {
        matches!(self, Self::Starting | Self::Running)
    }

    pub(super) const fn is_terminal(&self) -> bool {
        !self.is_running()
    }

    pub(super) const fn exit_code(&self) -> Option<i32> {
        match self {
            Self::Exited { exit_code } => Some(*exit_code),
            Self::Starting
            | Self::Running
            | Self::Killed
            | Self::TimedOut
            | Self::Cancelled { .. }
            | Self::DeliveryFailed { .. }
            | Self::Lost { .. } => None,
        }
    }

    pub(super) fn label(&self) -> String {
        match self {
            Self::Starting => "starting".to_string(),
            Self::Running => "running".to_string(),
            Self::Exited { exit_code } => format!("finished (exit code: {exit_code})"),
            Self::Killed => "killed".to_string(),
            Self::TimedOut => "timed out".to_string(),
            Self::Cancelled { reason } => format!("cancelled ({reason})"),
            Self::DeliveryFailed { error } => format!("delivery failed ({error})"),
            Self::Lost { reason } => format!("lost ({reason})"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackgroundJobRecord {
    schema_version: u32,
    job_id: String,
    owner_run: String,
    owner_session: String,
    owner_label: String,
    workspace_root: String,
    workspace_generation: u64,
    capability_generation: u64,
    budget_id: String,
    budget_generation: u64,
    command: String,
    pid: Option<u32>,
    created_unix_ms: u64,
    updated_unix_ms: u64,
    deadline_unix_ms: u64,
    state: BackgroundJobState,
    events: Vec<JobOutputEvent>,
    next_sequence: u64,
    retained_bytes: usize,
    stdout_truncated: bool,
    stderr_truncated: bool,
    default_cursor: u64,
}

impl BackgroundJobRecord {
    fn new(
        run: &crate::tools::security::ToolRunContext,
        job_id: &str,
        command: &str,
        timeout: Duration,
    ) -> Result<Self, String> {
        let descriptor = run.runtime().descriptor();
        let budget = run
            .budget()
            .snapshot()
            .map_err(|error| format!("Cannot snapshot background-job budget: {error}"))?;
        let now = unix_millis();
        Ok(Self {
            schema_version: JOB_SCHEMA_VERSION,
            job_id: job_id.to_string(),
            owner_run: run.run_id().to_string(),
            owner_session: run.session_id().to_string(),
            owner_label: run.process_owner().to_string(),
            workspace_root: run.project_root().to_string_lossy().into_owned(),
            workspace_generation: descriptor.workspace.generation.get(),
            capability_generation: run.generation().get(),
            budget_id: budget.budget_id.to_string(),
            budget_generation: budget.generation.get(),
            command: command.to_string(),
            pid: None,
            created_unix_ms: now,
            updated_unix_ms: now,
            deadline_unix_ms: now
                .saturating_add(u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX)),
            state: BackgroundJobState::Starting,
            events: Vec::new(),
            next_sequence: 0,
            retained_bytes: 0,
            stdout_truncated: false,
            stderr_truncated: false,
            default_cursor: 0,
        })
    }

    fn validate_for_run(&self, run: &crate::tools::security::ToolRunContext) -> Result<(), String> {
        if self.schema_version != JOB_SCHEMA_VERSION {
            return Err(format!(
                "Unsupported background-job schema version {}",
                self.schema_version
            ));
        }
        uuid::Uuid::parse_str(&self.job_id)
            .map_err(|_| "Background-job id is not a UUID".to_string())?;
        uuid::Uuid::parse_str(&self.owner_run)
            .map_err(|_| "Background-job run id is not a UUID".to_string())?;
        if self.owner_session != run.session_id()
            || self.workspace_root != run.project_root().to_string_lossy()
        {
            return Err("Background-job record is outside the requesting session/workspace".into());
        }
        if self.retained_bytes > MAX_JOB_OUTPUT_BYTES {
            return Err("Background-job record exceeds its output bound".to_string());
        }
        let mut previous = 0_u64;
        let mut observed_bytes = 0_usize;
        for event in &self.events {
            if event.sequence <= previous || event.sequence > self.next_sequence {
                return Err("Background-job output sequence is invalid".to_string());
            }
            previous = event.sequence;
            observed_bytes = observed_bytes
                .checked_add(event.byte_len)
                .ok_or_else(|| "Background-job output accounting overflowed".to_string())?;
        }
        if observed_bytes != self.retained_bytes || self.default_cursor > self.next_sequence {
            return Err("Background-job output accounting is inconsistent".to_string());
        }
        Ok(())
    }
}

#[derive(Debug)]
pub(super) struct JobRead {
    pub state: BackgroundJobState,
    pub events: Vec<JobOutputEvent>,
    pub next_cursor: u64,
    pub has_more: bool,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
}

pub(super) struct JobSummary {
    pub id: String,
    pub command: String,
    pub state: BackgroundJobState,
    pub created_unix_ms: u64,
}

struct JobArtifact {
    root: PathBuf,
    #[cfg(unix)]
    storage: crate::persistence::PersistentStorage,
    #[cfg(unix)]
    generation: crate::persistence::StorageGeneration,
}

impl JobArtifact {
    fn create(
        run: &crate::tools::security::ToolRunContext,
        job_id: &str,
        record: &BackgroundJobRecord,
    ) -> Result<Self, String> {
        let run_root = run_storage_root(run)?;
        ensure_private_directory(&run_root)?;
        let root = run_root.join(job_id);
        create_private_directory(&root)?;
        #[cfg(unix)]
        let mut artifact = Self {
            storage: crate::persistence::PersistentStorage::open(&root)
                .map_err(|error| format!("Cannot open background-job storage: {error}"))?,
            generation: crate::persistence::StorageGeneration::Missing,
            root,
        };
        #[cfg(not(unix))]
        let mut artifact = Self { root };
        artifact.persist(record)?;
        Ok(artifact)
    }

    fn load(root: PathBuf) -> Result<(Self, BackgroundJobRecord), String> {
        #[cfg(unix)]
        {
            let storage = crate::persistence::PersistentStorage::open(&root)
                .map_err(|error| format!("Cannot open background-job storage: {error}"))?;
            let observed = storage
                .read(JOB_RECORD_FILE, crate::persistence::FileClass::State)
                .map_err(|error| format!("Cannot read background-job record: {error}"))?;
            let record = observed.expose_bytes(|bytes| {
                let bytes = bytes.ok_or_else(|| "Background-job record is missing".to_string())?;
                serde_json::from_slice(bytes)
                    .map_err(|error| format!("Invalid background-job record: {error}"))
            })?;
            let generation = observed.generation();
            Ok((
                Self {
                    root,
                    storage,
                    generation,
                },
                record,
            ))
        }
        #[cfg(not(unix))]
        {
            let bytes = read_portable_record(&root.join(JOB_RECORD_FILE))?;
            let record = serde_json::from_slice(&bytes)
                .map_err(|error| format!("Invalid background-job record: {error}"))?;
            Ok((Self { root }, record))
        }
    }

    fn persist(&mut self, record: &BackgroundJobRecord) -> Result<(), String> {
        let bytes = serde_json::to_vec(record)
            .map_err(|error| format!("Cannot encode background-job record: {error}"))?;
        #[cfg(unix)]
        {
            let receipt = self
                .storage
                .commit(
                    JOB_RECORD_FILE,
                    crate::persistence::FileClass::State,
                    self.generation,
                    bytes,
                )
                .map_err(|error| format!("Cannot persist background-job record: {error}"))?;
            self.generation = receipt.generation();
            if receipt.durability_failure().is_some() {
                tracing::warn!(
                    target: "openclaudia::bash",
                    job_root = %self.root.display(),
                    "Background-job record is visible but directory durability is uncertain"
                );
            }
            Ok(())
        }
        #[cfg(not(unix))]
        write_portable_record(&self.root.join(JOB_RECORD_FILE), &bytes)
    }
}

pub(super) struct JobCore {
    artifact: JobArtifact,
    record: BackgroundJobRecord,
}

impl JobCore {
    pub(super) fn create(
        run: &crate::tools::security::ToolRunContext,
        job_id: &str,
        command: &str,
        timeout: Duration,
    ) -> Result<Self, String> {
        let record = BackgroundJobRecord::new(run, job_id, command, timeout)?;
        let artifact = JobArtifact::create(run, job_id, &record)?;
        Ok(Self { artifact, record })
    }

    fn load(run: &crate::tools::security::ToolRunContext, root: PathBuf) -> Result<Self, String> {
        let (artifact, record) = JobArtifact::load(root)?;
        record.validate_for_run(run)?;
        Ok(Self { artifact, record })
    }

    fn mutate(&mut self, operation: impl FnOnce(&mut BackgroundJobRecord)) -> Result<(), String> {
        let previous = self.record.clone();
        operation(&mut self.record);
        self.record.updated_unix_ms = unix_millis();
        if let Err(error) = self.artifact.persist(&self.record) {
            self.record = previous;
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn mark_running(&mut self, pid: u32) -> Result<(), String> {
        self.mutate(|record| {
            record.pid = Some(pid);
            record.state = BackgroundJobState::Running;
        })
    }

    pub(super) fn append_output(
        &mut self,
        stream: JobOutputStream,
        bytes: &[u8],
    ) -> Result<(), String> {
        if bytes.is_empty() || self.record.state.is_terminal() {
            return Ok(());
        }
        let remaining = MAX_JOB_OUTPUT_BYTES.saturating_sub(self.record.retained_bytes);
        let keep = remaining.min(bytes.len());
        let already_truncated = match stream {
            JobOutputStream::Stdout => self.record.stdout_truncated,
            JobOutputStream::Stderr => self.record.stderr_truncated,
        };
        if keep == 0 && already_truncated {
            return Ok(());
        }
        self.mutate(|record| {
            if keep > 0 {
                record.next_sequence = record.next_sequence.saturating_add(1);
                record.events.push(JobOutputEvent {
                    sequence: record.next_sequence,
                    stream,
                    text: String::from_utf8_lossy(&bytes[..keep]).into_owned(),
                    byte_len: keep,
                });
                record.retained_bytes = record.retained_bytes.saturating_add(keep);
            }
            if keep < bytes.len() {
                match stream {
                    JobOutputStream::Stdout => record.stdout_truncated = true,
                    JobOutputStream::Stderr => record.stderr_truncated = true,
                }
            }
        })
    }

    pub(super) fn set_state(&mut self, state: BackgroundJobState) -> Result<(), String> {
        if let Err(error) = self.mutate(|record| record.state = state) {
            self.record.state = BackgroundJobState::DeliveryFailed {
                error: error.clone(),
            };
            self.record.updated_unix_ms = unix_millis();
            return Err(error);
        }
        Ok(())
    }

    pub(super) fn reconcile_lost(&mut self) -> Result<(), String> {
        if self.record.state.is_terminal() {
            return Ok(());
        }
        self.set_state(BackgroundJobState::Lost {
            reason: "runtime restarted before the owned process published a terminal receipt"
                .to_string(),
        })
    }

    pub(super) fn read(&mut self, cursor: Option<u64>) -> Result<JobRead, String> {
        let start = cursor.unwrap_or(self.record.default_cursor);
        if start > self.record.next_sequence {
            return Err(format!(
                "Cursor {start} is beyond background job {} output cursor {}",
                self.record.job_id, self.record.next_sequence
            ));
        }
        let mut events = Vec::new();
        let mut page_bytes = 0_usize;
        let mut next_cursor = start;
        for event in self
            .record
            .events
            .iter()
            .filter(|event| event.sequence > start)
        {
            if !events.is_empty() && page_bytes.saturating_add(event.byte_len) > MAX_JOB_READ_BYTES
            {
                break;
            }
            page_bytes = page_bytes.saturating_add(event.byte_len);
            next_cursor = event.sequence;
            events.push(event.clone());
        }
        let has_more = next_cursor < self.record.next_sequence;
        if cursor.is_none() && next_cursor != self.record.default_cursor {
            self.mutate(|record| record.default_cursor = next_cursor)?;
        }
        Ok(JobRead {
            state: self.record.state.clone(),
            events,
            next_cursor,
            has_more,
            stdout_truncated: self.record.stdout_truncated,
            stderr_truncated: self.record.stderr_truncated,
        })
    }

    pub(super) fn summary(&self) -> JobSummary {
        JobSummary {
            id: self.record.job_id.clone(),
            command: self.record.command.clone(),
            state: self.record.state.clone(),
            created_unix_ms: self.record.created_unix_ms,
        }
    }

    pub(super) fn owner_run(&self) -> &str {
        &self.record.owner_run
    }

    pub(super) fn owner_session(&self) -> &str {
        &self.record.owner_session
    }

    pub(super) fn owner_label(&self) -> &str {
        &self.record.owner_label
    }

    pub(super) fn workspace_root(&self) -> &str {
        &self.record.workspace_root
    }

    pub(super) const fn state(&self) -> &BackgroundJobState {
        &self.record.state
    }

    pub(super) const fn pid(&self) -> Option<u32> {
        self.record.pid
    }

    pub(super) fn ledger_output(&self, stream: JobOutputStream, max_bytes: usize) -> String {
        let mut output = String::new();
        for event in self
            .record
            .events
            .iter()
            .filter(|event| event.stream == stream)
        {
            if output.len() >= max_bytes {
                break;
            }
            let remaining = max_bytes - output.len();
            output.push_str(crate::tools::safe_truncate(&event.text, remaining));
        }
        output
    }
}

pub(super) fn recover_jobs(
    run: &crate::tools::security::ToolRunContext,
) -> Result<Vec<JobCore>, String> {
    let session_root = session_storage_root(run)?;
    let metadata = match std::fs::symlink_metadata(&session_root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(format!(
                "Cannot inspect background-job session storage '{}': {error}",
                session_root.display()
            ));
        }
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("Background-job session storage is not a real directory".to_string());
    }
    let mut recovered = Vec::new();
    for run_entry in std::fs::read_dir(&session_root)
        .map_err(|error| format!("Cannot enumerate background-job runs: {error}"))?
        .take(512)
    {
        let run_entry =
            run_entry.map_err(|error| format!("Cannot inspect job run entry: {error}"))?;
        let run_name = run_entry.file_name();
        let Some(run_name) = run_name.to_str() else {
            continue;
        };
        if uuid::Uuid::parse_str(run_name).is_err()
            || !run_entry
                .file_type()
                .map_err(|error| format!("Cannot inspect job run type: {error}"))?
                .is_dir()
        {
            continue;
        }
        for job_entry in std::fs::read_dir(run_entry.path())
            .map_err(|error| format!("Cannot enumerate background jobs: {error}"))?
            .take(512)
        {
            let job_entry = job_entry
                .map_err(|error| format!("Cannot inspect background-job entry: {error}"))?;
            let job_name = job_entry.file_name();
            let Some(job_name) = job_name.to_str() else {
                continue;
            };
            if uuid::Uuid::parse_str(job_name).is_err()
                || !job_entry
                    .file_type()
                    .map_err(|error| format!("Cannot inspect background-job type: {error}"))?
                    .is_dir()
            {
                continue;
            }
            match JobCore::load(run, job_entry.path()) {
                Ok(mut job) => {
                    job.reconcile_lost()?;
                    recovered.push(job);
                }
                Err(error) => tracing::warn!(
                    target: "openclaudia::bash",
                    path = %job_entry.path().display(),
                    %error,
                    "Ignoring invalid persisted background-job record"
                ),
            }
        }
    }
    recovered.sort_by_key(|job| job.record.created_unix_ms);
    if recovered.len() > 100 {
        recovered.drain(..recovered.len() - 100);
    }
    Ok(recovered)
}

fn run_storage_root(run: &crate::tools::security::ToolRunContext) -> Result<PathBuf, String> {
    Ok(session_storage_root(run)?.join(run.run_id().to_string()))
}

fn session_storage_root(run: &crate::tools::security::ToolRunContext) -> Result<PathBuf, String> {
    Ok(run.background_job_storage_root()?.join(run.session_id()))
}

fn create_private_directory(path: &Path) -> Result<(), String> {
    match std::fs::create_dir(path) {
        Ok(()) => {
            secure_directory_permissions(path)?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Err(format!(
            "Background-job directory already exists: {}",
            path.display()
        )),
        Err(error) => Err(format!(
            "Cannot create background-job directory '{}': {error}",
            path.display()
        )),
    }
}

fn ensure_private_directory(path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|error| {
        format!(
            "Cannot create background-job storage '{}': {error}",
            path.display()
        )
    })?;
    secure_directory_permissions(path)
}

fn secure_directory_permissions(path: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        format!(
            "Cannot inspect background-job storage '{}': {error}",
            path.display()
        )
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "Background-job storage '{}' is not a real directory",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != unsafe { libc::geteuid() } {
            return Err(format!(
                "Background-job storage '{}' is not owned by the current user",
                path.display()
            ));
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(
            |error| {
                format!(
                    "Cannot secure background-job storage '{}': {error}",
                    path.display()
                )
            },
        )?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn read_portable_record(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    let file = std::fs::File::open(path)
        .map_err(|error| format!("Cannot open background-job record: {error}"))?;
    let mut bytes = Vec::new();
    file.take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("Cannot read background-job record: {error}"))?;
    if bytes.len() > 16 * 1024 * 1024 {
        return Err("Background-job record exceeds its storage bound".to_string());
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn write_portable_record(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write as _;
    let staging = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&staging)
            .map_err(|error| format!("Cannot stage background-job record: {error}"))?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|error| format!("Cannot synchronize background-job record: {error}"))?;
        crate::file_error::replace_file_atomic(&staging, path)
            .map_err(|error| format!("Cannot publish background-job record: {error}"))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&staging);
    }
    result
}

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
