//! Durable, authorized execution authority for cron schedules.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Datelike, TimeZone as _, Timelike, Utc};
use futures::stream::{FuturesUnordered, StreamExt as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::permissions::{ApprovalBinding, HostApprovalEvidence, PermissionManager};
use crate::persistence::{CommitState, FileClass, PersistentStorage, StorageGeneration};
use crate::runtime::{CancellationHandle, CancellationReason, CancellationTree, RunId};
use crate::subagent::{ScheduledAgentRunOutcome, ScheduledAgentRunPolicy};
use crate::tools::args::ToolArgs as _;
use crate::tools::safe_truncate;

use super::{format_list_prompt, validate_cron_expression, ScheduleStore, SCHEDULES_FILE};

const SCHEMA_VERSION: u32 = 1;
const STATE_FILE: &str = "scheduler-v1.json";
const MAX_SCHEDULES: usize = 50;
const MAX_RUN_HISTORY: usize = 2_000;
const MAX_DELIVERY_HISTORY: usize = 2_000;
const MAX_CAS_ATTEMPTS: usize = 8;
const MAX_CLAIMS_PER_TICK: usize = 8;
const MAX_CRON_SEARCH_MINUTES: usize = 5 * 366 * 24 * 60;
const LEASE_GRACE_SECONDS: i64 = 30;
const DEFAULT_MISFIRE_GRACE_SECONDS: u64 = 300;
const DEFAULT_MAX_RUN_SECONDS: u64 = 900;
const DEFAULT_RETRY_BACKOFF_SECONDS: u64 = 60;
const DEFAULT_MAX_RETRIES: u32 = 2;
const DEFAULT_MAX_TURNS: u64 = 20;
const DEFAULT_MAX_OUTPUT_TOKENS: u32 = 4_096;
const DEFAULT_MAX_TOOL_CALLS: u64 = 40;
const DEFAULT_MAX_COST_MICROUSD: u64 = 10_000_000;
const POLL_SECONDS: u64 = 15;
const REVOCATION_POLL_SECONDS: u64 = 2;
const OUTPUT_EXCERPT_BYTES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TimeZonePolicy {
    Utc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DstPolicy {
    UtcHasNoTransitions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MisfirePolicy {
    Skip,
    RunOnce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum OverlapPolicy {
    Skip,
    QueueOne,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum NotificationPolicy {
    HistoryOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ScheduleStatus {
    Enabled,
    Revoked,
    Expired,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetryPolicy {
    max_retries: u32,
    backoff_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)] // Stable persisted names make each bound explicit.
struct RunBudgetPolicy {
    max_turns: u64,
    max_output_tokens: u32,
    max_tool_calls: u64,
    max_cost_microusd: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalAuthority {
    receipt_id: String,
    evidence_digest: String,
    actor_id: String,
    workspace_digest: String,
    capability_generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActiveLease {
    run_id: RunId,
    worker_id: String,
    fence: u64,
    scheduled_for: DateTime<Utc>,
    attempt: u32,
    lease_until: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingRetry {
    scheduled_for: DateTime<Utc>,
    attempt: u32,
    not_before: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableSchedule {
    id: String,
    name: String,
    cron_expression: String,
    prompt: String,
    recurring: bool,
    durable_requested: bool,
    status: ScheduleStatus,
    status_reason: Option<String>,
    timezone: TimeZonePolicy,
    dst_policy: DstPolicy,
    misfire_policy: MisfirePolicy,
    misfire_grace_seconds: u64,
    overlap_policy: OverlapPolicy,
    retry: RetryPolicy,
    max_run_seconds: u64,
    expires_at: Option<DateTime<Utc>>,
    max_runs: Option<u64>,
    provider: String,
    model: String,
    allowed_tools: Vec<String>,
    budget: RunBudgetPolicy,
    notification: NotificationPolicy,
    approval: ApprovalAuthority,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    next_fire_at: Option<DateTime<Utc>>,
    active_lease: Option<ActiveLease>,
    pending_retry: Option<PendingRetry>,
    queued_for: Option<DateTime<Utc>>,
    run_count: u64,
    occurrence_count: u64,
    last_run_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum RunStatus {
    Running,
    Succeeded,
    Failed,
    Cancelled,
    AbandonedLease,
    SkippedMisfire,
    SkippedOverlap,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunHistoryRecord {
    run_id: RunId,
    schedule_id: String,
    schedule_name: String,
    scheduled_for: DateTime<Utc>,
    attempt: u32,
    fence: Option<u64>,
    worker_id: Option<String>,
    status: RunStatus,
    claimed_at: Option<DateTime<Utc>>,
    started_at: Option<DateTime<Utc>>,
    finished_at: Option<DateTime<Utc>>,
    turns_used: u64,
    output_sha256: Option<String>,
    output_excerpt: Option<String>,
    detail: Option<String>,
    cancellation_receipt: Option<crate::runtime::CancellationReceipt>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DeliveryStatus {
    Recorded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryHistoryRecord {
    run_id: RunId,
    schedule_id: String,
    policy: NotificationPolicy,
    status: DeliveryStatus,
    recorded_at: DateTime<Utc>,
    result_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SchedulerState {
    schema_version: u32,
    next_fence: u64,
    schedules: Vec<DurableSchedule>,
    run_history: Vec<RunHistoryRecord>,
    delivery_history: Vec<DeliveryHistoryRecord>,
}

impl Default for SchedulerState {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            next_fence: 1,
            schedules: Vec::new(),
            run_history: Vec::new(),
            delivery_history: Vec::new(),
        }
    }
}

impl SchedulerState {
    fn validate(&self) -> Result<(), String> {
        if self.schema_version != SCHEMA_VERSION || self.next_fence == 0 {
            return Err("scheduler state has an unsupported schema or exhausted fence".to_string());
        }
        if self.schedules.len() > MAX_SCHEDULES
            || self.run_history.len() > MAX_RUN_HISTORY
            || self.delivery_history.len() > MAX_DELIVERY_HISTORY
        {
            return Err("scheduler state exceeds its bounded record limits".to_string());
        }
        let mut ids = HashSet::new();
        let mut names = HashSet::new();
        for schedule in &self.schedules {
            validate_cron_expression(&schedule.cron_expression)?;
            if Uuid::parse_str(&schedule.id).is_err()
                || schedule.name.trim().is_empty()
                || schedule.name.len() > 128
                || schedule.cron_expression.len() > 256
                || schedule.prompt.trim().is_empty()
                || schedule.prompt.len() > 64 * 1024
                || schedule.provider.trim().is_empty()
                || schedule.model.trim().is_empty()
                || schedule.max_run_seconds == 0
                || schedule.misfire_grace_seconds > 86_400
                || schedule.retry.max_retries > 10
                || schedule.retry.backoff_seconds == 0
                || schedule.budget.max_turns == 0
                || schedule.budget.max_output_tokens == 0
                || schedule.budget.max_tool_calls == 0
                || schedule.budget.max_cost_microusd == 0
                || schedule.allowed_tools.is_empty()
                || !ids.insert(schedule.id.as_str())
                || !names.insert(schedule.name.as_str())
            {
                return Err(format!("scheduler record '{}' is invalid", schedule.name));
            }
        }
        let mut run_ids = HashSet::new();
        if self
            .run_history
            .iter()
            .any(|record| !run_ids.insert(record.run_id))
        {
            return Err("scheduler run history contains a duplicate run identity".to_string());
        }
        Ok(())
    }

    fn bound_history(&mut self) {
        if self.run_history.len() > MAX_RUN_HISTORY {
            let remove = self.run_history.len() - MAX_RUN_HISTORY;
            self.run_history.drain(..remove);
        }
        if self.delivery_history.len() > MAX_DELIVERY_HISTORY {
            let remove = self.delivery_history.len() - MAX_DELIVERY_HISTORY;
            self.delivery_history.drain(..remove);
        }
    }
}

#[derive(Debug, Clone)]
struct StoredSchedulerState {
    state: SchedulerState,
    generation: StorageGeneration,
}

#[derive(Debug, Clone)]
struct SchedulerRepository {
    storage: PersistentStorage,
    target: PathBuf,
}

impl SchedulerRepository {
    fn for_run(run: &crate::tools::ToolRunContext) -> Result<Self, String> {
        let workspace_digest = crate::permissions::approval_workspace_digest(run.project_root());
        let root = run
            .background_job_storage_root()?
            .join("cron-scheduler")
            .join(workspace_digest);
        create_private_directory(&root)?;
        let storage = PersistentStorage::open(&root)
            .map_err(|error| format!("Cannot pin trusted scheduler storage: {error}"))?;
        Ok(Self {
            storage,
            target: PathBuf::from(STATE_FILE),
        })
    }

    fn for_run_read_only(run: &crate::tools::ToolRunContext) -> Result<Option<Self>, String> {
        let workspace_digest = crate::permissions::approval_workspace_digest(run.project_root());
        let root = run
            .background_job_storage_root()?
            .join("cron-scheduler")
            .join(workspace_digest);
        match std::fs::symlink_metadata(&root) {
            Ok(_) => PersistentStorage::open(&root)
                .map(|storage| {
                    Some(Self {
                        storage,
                        target: PathBuf::from(STATE_FILE),
                    })
                })
                .map_err(|error| format!("Cannot pin trusted scheduler storage: {error}")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(format!("Cannot inspect trusted scheduler storage: {error}")),
        }
    }

    fn load(&self) -> Result<StoredSchedulerState, String> {
        let read = self
            .storage
            .read(&self.target, FileClass::State)
            .map_err(|error| format!("Cannot read trusted scheduler state: {error}"))?;
        let generation = read.generation();
        let state = read.expose_bytes(|bytes| {
            bytes.map_or_else(
                || Ok(SchedulerState::default()),
                |bytes| {
                    serde_json::from_slice::<SchedulerState>(bytes).map_err(|error| {
                        format!("Trusted scheduler state is invalid JSON: {error}")
                    })
                },
            )
        })?;
        state.validate()?;
        Ok(StoredSchedulerState { state, generation })
    }

    fn update<R>(
        &self,
        mut mutation: impl FnMut(&mut SchedulerState) -> Result<R, String>,
    ) -> Result<R, String> {
        for _ in 0..MAX_CAS_ATTEMPTS {
            let StoredSchedulerState {
                mut state,
                generation,
            } = self.load()?;
            let result = mutation(&mut state)?;
            state.bound_history();
            state.validate()?;
            let bytes = serde_json::to_vec_pretty(&state)
                .map_err(|error| format!("Cannot encode trusted scheduler state: {error}"))?;
            match self
                .storage
                .commit(&self.target, FileClass::State, generation, &bytes)
            {
                Ok(receipt)
                    if matches!(
                        receipt.state(),
                        CommitState::CommittedDurable
                            | CommitState::Recovered
                            | CommitState::Unchanged
                    ) =>
                {
                    return Ok(result);
                }
                Ok(receipt) => {
                    return Err(format!(
                        "Scheduler state was published but directory durability is uncertain ({:?})",
                        receipt.state()
                    ));
                }
                Err(crate::persistence::PersistenceError::Conflict { .. }) => {}
                Err(error) => {
                    return Err(format!("Cannot commit trusted scheduler state: {error}"))
                }
            }
        }
        Err("Scheduler state changed concurrently too many times; retry the operation".to_string())
    }
}

fn create_private_directory(path: &Path) -> Result<(), String> {
    #[cfg(not(windows))]
    std::fs::create_dir_all(path)
        .map_err(|error| format!("Cannot create scheduler storage directory: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|error| format!("Cannot make scheduler storage owner-private: {error}"))?;
    }
    #[cfg(windows)]
    {
        let parent = path
            .parent()
            .ok_or_else(|| "Scheduler storage directory has no parent".to_string())?;
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("Cannot create scheduler storage parent: {error}"))?;
        crate::windows_fs::create_private_directory(path)
            .map_err(|error| format!("Cannot make scheduler storage owner-private: {error}"))?;
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct RuntimeAuthority {
    actor_id: String,
    workspace_digest: String,
    capability_generation: u64,
    provider: String,
}

fn runtime_authority(
    run: &crate::tools::ToolRunContext,
    config: &crate::config::AppConfig,
) -> RuntimeAuthority {
    let manager = PermissionManager::trusted_for_run(
        run,
        config.permissions.enabled,
        config.permissions.default_allow.clone(),
        config.web_fetch.preapproved_domains.clone(),
    );
    RuntimeAuthority {
        actor_id: ApprovalBinding::for_run(run).actor_id().to_string(),
        workspace_digest: crate::permissions::approval_workspace_digest(run.project_root()),
        capability_generation: manager.approval_capability_generation(),
        provider: config.proxy.target.clone(),
    }
}

fn field_matches(field: &str, value: u32, spec_min: u32) -> bool {
    field.split(',').any(|atom| {
        let (head, step) = atom.split_once('/').map_or((atom, 1), |(head, step)| {
            (head, step.parse::<u32>().unwrap_or(1))
        });
        if step == 0 {
            return false;
        }
        let (start, end) = if head == "*" {
            (spec_min, u32::MAX)
        } else if let Some((start, end)) = head.split_once('-') {
            (
                start.parse::<u32>().unwrap_or(u32::MAX),
                end.parse::<u32>().unwrap_or(0),
            )
        } else {
            let exact = head.parse::<u32>().unwrap_or(u32::MAX);
            (exact, exact)
        };
        value >= start && value <= end && (value - start).is_multiple_of(step)
    })
}

fn cron_matches(expression: &str, instant: DateTime<Utc>) -> bool {
    let fields = expression.split_whitespace().collect::<Vec<_>>();
    if fields.len() != 5 {
        return false;
    }
    let minute = field_matches(fields[0], instant.minute(), 0);
    let hour = field_matches(fields[1], instant.hour(), 0);
    let day = field_matches(fields[2], instant.day(), 1);
    let month = field_matches(fields[3], instant.month(), 1);
    let weekday = field_matches(fields[4], instant.weekday().num_days_from_sunday(), 0);
    let day_restricted = fields[2] != "*";
    let weekday_restricted = fields[4] != "*";
    let calendar_day = if day_restricted && weekday_restricted {
        day || weekday
    } else {
        day && weekday
    };
    minute && hour && month && calendar_day
}

fn next_fire_after(expression: &str, after: DateTime<Utc>) -> Result<DateTime<Utc>, String> {
    validate_cron_expression(expression)?;
    let next_minute = after
        .timestamp()
        .div_euclid(60)
        .checked_add(1)
        .and_then(|minute| minute.checked_mul(60))
        .ok_or_else(|| "cron next-fire timestamp overflowed".to_string())?;
    let mut candidate = Utc
        .timestamp_opt(next_minute, 0)
        .single()
        .ok_or_else(|| "cron next-fire timestamp is outside the supported range".to_string())?;
    for _ in 0..MAX_CRON_SEARCH_MINUTES {
        if cron_matches(expression, candidate) {
            return Ok(candidate);
        }
        candidate = candidate
            .checked_add_signed(chrono::Duration::minutes(1))
            .ok_or_else(|| "cron next-fire timestamp overflowed".to_string())?;
    }
    Err("cron expression has no UTC occurrence within five years".to_string())
}

fn occurrence_run_id(schedule_id: &str, scheduled_for: DateTime<Utc>, attempt: u32) -> RunId {
    let mut hasher = Sha256::new();
    hasher.update(b"openclaudia:cron-occurrence:v1\0");
    hasher.update(schedule_id.as_bytes());
    hasher.update(b"\0");
    hasher.update(scheduled_for.to_rfc3339().as_bytes());
    hasher.update(b"\0");
    hasher.update(attempt.to_le_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    RunId::from_uuid(Uuid::from_bytes(bytes))
}

fn optional_u64(args: &HashMap<String, Value>, key: &str, default: u64) -> Result<u64, String> {
    args.get(key).map_or(Ok(default), |value| {
        value
            .as_u64()
            .ok_or_else(|| format!("Invalid '{key}' argument: expected non-negative integer"))
    })
}

fn optional_enum<'a>(
    args: &'a HashMap<String, Value>,
    key: &str,
    default: &'a str,
) -> Result<&'a str, String> {
    args.get(key).map_or(Ok(default), |value| {
        value
            .as_str()
            .ok_or_else(|| format!("Invalid '{key}' argument: expected string"))
    })
}

fn approved_tools(args: &HashMap<String, Value>) -> Result<Vec<String>, String> {
    const DEFAULT_TOOLS: &[&str] = &["read_file", "list_files", "web_fetch"];
    const SCHEDULABLE_TOOLS: &[&str] = &[
        "bash",
        "bash_output",
        "kill_shell",
        "kill_shells_for_agent",
        "read_file",
        "write_file",
        "edit_file",
        "list_files",
        "web_fetch",
    ];
    let tools = args.get("allowed_tools").map_or_else(
        || Ok(DEFAULT_TOOLS.iter().map(ToString::to_string).collect()),
        |value| {
            value
                .as_array()
                .ok_or_else(|| "Invalid 'allowed_tools' argument: expected array".to_string())?
                .iter()
                .map(|tool| {
                    tool.as_str().map(str::to_string).ok_or_else(|| {
                        "Invalid 'allowed_tools' argument: every item must be a string".to_string()
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        },
    )?;
    let unique = tools.iter().collect::<HashSet<_>>();
    if tools.is_empty()
        || unique.len() != tools.len()
        || tools
            .iter()
            .any(|tool| !SCHEDULABLE_TOOLS.contains(&tool.as_str()))
    {
        return Err(
            "'allowed_tools' must be a unique non-empty set of schedulable tools".to_string(),
        );
    }
    Ok(tools)
}

fn args_value(args: &HashMap<String, Value>) -> Result<Value, String> {
    serde_json::to_value(args)
        .map_err(|error| format!("Cannot bind schedule arguments to host approval: {error}"))
}

fn required_string(args: &HashMap<String, Value>, key: &'static str) -> Result<String, String> {
    let value = args.arg_string(key).map_err(|error| error.to_string())?;
    if value.trim().is_empty() {
        return Err(format!(
            "Invalid '{key}' argument: expected non-empty string"
        ));
    }
    Ok(value)
}

#[allow(clippy::too_many_lines)]
pub fn execute_authorized_cron_create(
    run: &Arc<crate::tools::ToolRunContext>,
    args: &HashMap<String, Value>,
    approval: &HostApprovalEvidence,
    config: &crate::config::AppConfig,
) -> (String, bool) {
    let result = (|| -> Result<String, String> {
        let name = required_string(args, "name")?;
        let cron_expression = required_string(args, "schedule")?;
        let prompt = required_string(args, "prompt")?;
        if name.len() > 128 || cron_expression.len() > 256 || prompt.len() > 64 * 1024 {
            return Err(
                "Schedule name, cron expression, or prompt exceeds its bounded size".to_string(),
            );
        }
        validate_cron_expression(&cron_expression)
            .map_err(|error| format!("Invalid cron expression: {error}"))?;
        let timezone = optional_enum(args, "timezone", "UTC")?;
        if timezone != "UTC" {
            return Err(format!(
                "Unsupported timezone '{timezone}': this scheduler accepts only UTC and never guesses DST transitions"
            ));
        }
        let misfire_policy = match optional_enum(args, "misfire_policy", "run_once")? {
            "skip" => MisfirePolicy::Skip,
            "run_once" => MisfirePolicy::RunOnce,
            other => return Err(format!("Unsupported misfire policy '{other}'")),
        };
        let overlap_policy = match optional_enum(args, "overlap_policy", "skip")? {
            "skip" => OverlapPolicy::Skip,
            "queue_one" => OverlapPolicy::QueueOne,
            other => return Err(format!("Unsupported overlap policy '{other}'")),
        };
        let recurring = args.get("recurring").map_or(Ok(true), |value| {
            value
                .as_bool()
                .ok_or_else(|| "Invalid 'recurring' argument: expected boolean".to_string())
        })?;
        let durable_requested = args.get("durable").map_or(Ok(true), |value| {
            value
                .as_bool()
                .ok_or_else(|| "Invalid 'durable' argument: expected boolean".to_string())
        })?;
        let misfire_grace_seconds =
            optional_u64(args, "misfire_grace_seconds", DEFAULT_MISFIRE_GRACE_SECONDS)?;
        let max_run_seconds = optional_u64(args, "max_run_seconds", DEFAULT_MAX_RUN_SECONDS)?;
        let max_retries = optional_u64(args, "max_retries", u64::from(DEFAULT_MAX_RETRIES))?;
        let retry_backoff_seconds =
            optional_u64(args, "retry_backoff_seconds", DEFAULT_RETRY_BACKOFF_SECONDS)?;
        let max_turns = optional_u64(args, "max_turns", DEFAULT_MAX_TURNS)?;
        let max_output_tokens = optional_u64(
            args,
            "max_output_tokens",
            u64::from(DEFAULT_MAX_OUTPUT_TOKENS),
        )?;
        let max_tool_calls = optional_u64(args, "max_tool_calls", DEFAULT_MAX_TOOL_CALLS)?;
        let max_cost_microusd = optional_u64(args, "max_cost_microusd", DEFAULT_MAX_COST_MICROUSD)?;
        if misfire_grace_seconds > 86_400
            || !(1..=86_400).contains(&max_run_seconds)
            || max_retries > 10
            || !(1..=86_400).contains(&retry_backoff_seconds)
            || !(1..=100).contains(&max_turns)
            || !(1..=32_768).contains(&max_output_tokens)
            || !(1..=1_000).contains(&max_tool_calls)
            || max_cost_microusd == 0
        {
            return Err(
                "Schedule retry, run, misfire, or budget limits are out of range".to_string(),
            );
        }
        let expires_at = args
            .get("expires_at")
            .map(|value| {
                let raw = value.as_str().ok_or_else(|| {
                    "Invalid 'expires_at' argument: expected RFC3339 string".to_string()
                })?;
                DateTime::parse_from_rfc3339(raw)
                    .map(|instant| instant.with_timezone(&Utc))
                    .map_err(|error| format!("Invalid 'expires_at' argument: {error}"))
            })
            .transpose()?;
        let max_runs = match args.get("max_runs") {
            None => None,
            Some(value) => Some(value.as_u64().ok_or_else(|| {
                "Invalid 'max_runs' argument: expected positive integer".to_string()
            })?),
        };
        if max_runs == Some(0) {
            return Err("Invalid 'max_runs' argument: expected positive integer".to_string());
        }
        let now = Utc::now();
        if expires_at.is_some_and(|expiry| expiry <= now) {
            return Err("Schedule expiry must be in the future".to_string());
        }
        let allowed_tools = approved_tools(args)?;
        let requested_model = match args.get("model") {
            None => None,
            Some(value) => Some(
                value
                    .as_str()
                    .ok_or_else(|| "Invalid 'model' argument: expected string".to_string())?
                    .to_string(),
            ),
        };
        let model = requested_model
            .or_else(|| {
                config
                    .active_provider()
                    .and_then(|provider| provider.model.clone())
            })
            .ok_or_else(|| {
                format!(
                    "Provider '{}' has no active model; specify the schedule 'model' explicitly",
                    config.proxy.target
                )
            })?;
        if model.trim().is_empty() || model.len() > 256 {
            return Err("Schedule model identity is invalid".to_string());
        }
        let arguments = args_value(args)?;
        let actor_id = ApprovalBinding::for_run(run).actor_id().to_string();
        let workspace_digest = crate::permissions::approval_workspace_digest(run.project_root());
        if approval.actor_id != actor_id
            || approval.workspace_digest != workspace_digest
            || !approval.authorizes_exact_host_call(
                "ScheduleCreate",
                "external_mutation",
                None,
                &name,
                &arguments,
            )
        {
            return Err(
                "Fresh host approval does not authorize this exact durable schedule".to_string(),
            );
        }
        let next_fire_at = next_fire_after(&cron_expression, now)?;
        let next_fire_display = next_fire_at.to_rfc3339();
        let schedule_id = Uuid::new_v4().to_string();
        let schedule = DurableSchedule {
            id: schedule_id,
            name: name.clone(),
            cron_expression: cron_expression.clone(),
            prompt,
            recurring,
            durable_requested,
            status: ScheduleStatus::Enabled,
            status_reason: None,
            timezone: TimeZonePolicy::Utc,
            dst_policy: DstPolicy::UtcHasNoTransitions,
            misfire_policy,
            misfire_grace_seconds,
            overlap_policy,
            retry: RetryPolicy {
                max_retries: u32::try_from(max_retries)
                    .map_err(|_| "max_retries is too large".to_string())?,
                backoff_seconds: retry_backoff_seconds,
            },
            max_run_seconds,
            expires_at,
            max_runs,
            provider: config.proxy.target.clone(),
            model,
            allowed_tools,
            budget: RunBudgetPolicy {
                max_turns,
                max_output_tokens: u32::try_from(max_output_tokens)
                    .map_err(|_| "max_output_tokens is too large".to_string())?,
                max_tool_calls,
                max_cost_microusd,
            },
            notification: NotificationPolicy::HistoryOnly,
            approval: ApprovalAuthority {
                receipt_id: approval.receipt_id.clone(),
                evidence_digest: approval.evidence_digest.clone(),
                actor_id,
                workspace_digest,
                capability_generation: approval.capability_generation,
            },
            created_at: now,
            updated_at: now,
            next_fire_at: Some(next_fire_at),
            active_lease: None,
            pending_retry: None,
            queued_for: None,
            run_count: 0,
            occurrence_count: 0,
            last_run_at: None,
        };
        let repository = SchedulerRepository::for_run(run)?;
        if read_legacy_schedules(run)?
            .iter()
            .any(|legacy| legacy.name == name)
        {
            return Err(format!(
                "Legacy unapproved metadata named '{name}' already exists; delete it, then recreate it with explicit durable authority"
            ));
        }
        repository.update(|state| {
            if state.schedules.len() >= MAX_SCHEDULES {
                return Err(format!(
                    "Maximum authorized schedule limit ({MAX_SCHEDULES}) reached"
                ));
            }
            if state.schedules.iter().any(|existing| existing.name == name) {
                return Err(format!("Schedule '{name}' already exists"));
            }
            state.schedules.push(schedule.clone());
            Ok(())
        })?;
        Ok(format!(
            "Created authorized schedule '{name}'\nCron: {cron_expression}\nTimezone: UTC (no DST transitions)\nNext run: {next_fire_display}\nMisfire: {misfire_policy:?} | Overlap: {overlap_policy:?} | Max run: {max_run_seconds}s\nRetries: {max_retries} | Notification: durable history",
        ))
    })();
    match result {
        Ok(message) => (message, false),
        Err(error) => (error, true),
    }
}

fn resolve_authorized_schedule_index(
    schedules: &[DurableSchedule],
    args: &HashMap<String, Value>,
) -> Result<Option<usize>, String> {
    let name = args
        .get("name")
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| "Invalid 'name' argument: expected string".to_string())
        })
        .transpose()?;
    let id = args
        .get("id")
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| "Invalid 'id' argument: expected string".to_string())
        })
        .transpose()?;
    let index = args
        .get("index")
        .map(|value| {
            value
                .as_u64()
                .filter(|index| *index > 0)
                .ok_or_else(|| "Invalid 'index' argument: expected integer >= 1".to_string())
        })
        .transpose()?;
    let identifier_count =
        usize::from(name.is_some()) + usize::from(id.is_some()) + usize::from(index.is_some());
    if identifier_count != 1 {
        return Err("Provide exactly one of 'name', 'index', or legacy 'id'".to_string());
    }
    if let Some(name) = name {
        return Ok(schedules.iter().position(|schedule| schedule.name == name));
    }
    if let Some(id) = id {
        return Ok(schedules.iter().position(|schedule| schedule.id == id));
    }
    if let Some(index) = index {
        let zero_based = usize::try_from(index - 1)
            .map_err(|_| "Invalid 'index' argument: value is too large".to_string())?;
        return Ok((zero_based < schedules.len()).then_some(zero_based));
    }
    Err("Missing 'name' (preferred), 'index', or legacy 'id' argument".to_string())
}

pub fn execute_authorized_cron_delete(
    run: &Arc<crate::tools::ToolRunContext>,
    args: &HashMap<String, Value>,
    approval: &HostApprovalEvidence,
) -> (String, bool) {
    let result = (|| -> Result<Option<String>, String> {
        let arguments = args_value(args)?;
        let repository = SchedulerRepository::for_run(run)?;
        repository.update(|state| {
            let Some(index) = resolve_authorized_schedule_index(&state.schedules, args)? else {
                return Ok(None);
            };
            let schedule = &state.schedules[index];
            let target = schedule.name.clone();
            if approval.actor_id != schedule.approval.actor_id
                || approval.workspace_digest != schedule.approval.workspace_digest
                || !approval.authorizes_exact_host_call(
                    "ScheduleDelete",
                    "external_mutation",
                    None,
                    "cron_delete",
                    &arguments,
                )
            {
                return Err("Fresh host approval does not authorize this exact schedule deletion".to_string());
            }
            if schedule.active_lease.is_some() {
                return Err(format!(
                    "Schedule '{target}' is currently running; stop its scheduler owner before deletion"
                ));
            }
            state.schedules.remove(index);
            Ok(Some(target))
        })
    })();
    match result {
        Ok(Some(name)) => (format!("Deleted authorized schedule '{name}'"), false),
        Ok(None) => super::execute_cron_delete(run, args),
        Err(error) => (error, true),
    }
}

fn read_legacy_schedules(
    run: &crate::tools::ToolRunContext,
) -> Result<Vec<super::Schedule>, String> {
    run.require(crate::tools::ToolResource::WorkspaceRead)
        .map_err(|error| error.to_string())?;
    let path = run.working_directory().join(SCHEDULES_FILE);
    ScheduleStore::load_locked(&path)
        .map(|store| store.schedules)
        .map_err(|error| format!("Failed to load legacy schedule metadata: {error}"))
}

pub fn execute_authorized_cron_list(run: &Arc<crate::tools::ToolRunContext>) -> (String, bool) {
    let result = (|| -> Result<String, String> {
        let state = SchedulerRepository::for_run_read_only(run)?.map_or_else(
            || Ok(SchedulerState::default()),
            |repository| repository.load().map(|stored| stored.state),
        )?;
        let legacy = read_legacy_schedules(run)?;
        if state.schedules.is_empty() && legacy.is_empty() {
            return Ok("No schedules stored.".to_string());
        }
        let mut output = String::from("Durable authorized schedules:\n\n");
        for (index, schedule) in state.schedules.iter().enumerate() {
            use std::fmt::Write as _;
            let _ = write!(
                output,
                "  {}. {} [{:?}]\n    Cron: {} UTC | Next: {} | Expires: {}\n    Prompt: {}\n    Provider/model: {}/{} | Tools: {}\n    Misfire: {:?} | Overlap: {:?} | Retries: {} | Max run: {}s\n    Budget: {} turns | {} output tokens/turn | {} tool calls | {} microUSD\n    Runs: {} | Occurrences: {} | Last: {}\n    Authority generation: {} | Notification: history\n",
                index + 1,
                schedule.name,
                schedule.status,
                schedule.cron_expression,
                schedule.next_fire_at.map_or_else(|| "none".to_string(), |value| value.to_rfc3339()),
                schedule.expires_at.map_or_else(|| "none".to_string(), |value| value.to_rfc3339()),
                format_list_prompt(&schedule.prompt),
                schedule.provider,
                schedule.model,
                schedule.allowed_tools.join(","),
                schedule.misfire_policy,
                schedule.overlap_policy,
                schedule.retry.max_retries,
                schedule.max_run_seconds,
                schedule.budget.max_turns,
                schedule.budget.max_output_tokens,
                schedule.budget.max_tool_calls,
                schedule.budget.max_cost_microusd,
                schedule.run_count,
                schedule.occurrence_count,
                schedule.last_run_at.map_or_else(|| "never".to_string(), |value| value.to_rfc3339()),
                schedule.approval.capability_generation,
            );
            if let Some(reason) = &schedule.status_reason {
                let _ = writeln!(output, "    Status detail: {reason}");
            }
            output.push('\n');
        }
        if !legacy.is_empty() {
            output.push_str("Legacy unapproved metadata (never executed automatically):\n\n");
            for (index, schedule) in legacy.into_iter().enumerate() {
                use std::fmt::Write as _;
                let _ = writeln!(
                    output,
                    "  {}. {} [{}] {}\n    Cron: {}\n    Prompt: {}\n",
                    index + 1,
                    if schedule.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    },
                    schedule.id,
                    schedule.name,
                    schedule.cron_expression,
                    format_list_prompt(&schedule.prompt),
                );
            }
        }
        if !state.run_history.is_empty() {
            output.push_str("Recent run history:\n");
            for record in state.run_history.iter().rev().take(10) {
                use std::fmt::Write as _;
                let _ = writeln!(
                    output,
                    "  - {} {} attempt {}: {:?} ({})",
                    record.schedule_name,
                    record.scheduled_for.to_rfc3339(),
                    record.attempt,
                    record.status,
                    record.run_id,
                );
            }
        }
        if !state.delivery_history.is_empty() {
            output.push_str("Recent notification delivery history:\n");
            for delivery in state.delivery_history.iter().rev().take(10) {
                use std::fmt::Write as _;
                let _ = writeln!(
                    output,
                    "  - {} {:?}/{:?} at {} result {}",
                    delivery.run_id,
                    delivery.policy,
                    delivery.status,
                    delivery.recorded_at.to_rfc3339(),
                    delivery.result_sha256,
                );
            }
        }
        Ok(output)
    })();
    match result {
        Ok(output) => (output, false),
        Err(error) => (error, true),
    }
}

#[derive(Debug, Clone)]
struct ClaimedRun {
    schedule: DurableSchedule,
    lease: ActiveLease,
}

fn terminal_delivery(
    state: &mut SchedulerState,
    run_id: RunId,
    schedule_id: &str,
    policy: NotificationPolicy,
    now: DateTime<Utc>,
    result: &str,
) {
    state.delivery_history.push(DeliveryHistoryRecord {
        run_id,
        schedule_id: schedule_id.to_string(),
        policy,
        status: DeliveryStatus::Recorded,
        recorded_at: now,
        result_sha256: crate::runtime::ContentDigest::sha256(result.as_bytes()).to_string(),
    });
}

fn retry_not_before(schedule: &DurableSchedule, attempt: u32, now: DateTime<Utc>) -> DateTime<Utc> {
    let exponent = attempt.saturating_sub(1).min(16);
    let multiplier = 1_u64 << exponent;
    let seconds = schedule.retry.backoff_seconds.saturating_mul(multiplier);
    now.checked_add_signed(chrono::Duration::seconds(
        i64::try_from(seconds).unwrap_or(i64::MAX),
    ))
    .unwrap_or(DateTime::<Utc>::MAX_UTC)
}

fn advance_next_fire(schedule: &mut DurableSchedule, after: DateTime<Utc>) -> Result<(), String> {
    if schedule.recurring {
        schedule.next_fire_at = Some(next_fire_after(&schedule.cron_expression, after)?);
    } else {
        schedule.next_fire_at = None;
    }
    Ok(())
}

fn finalize_occurrence(schedule: &mut DurableSchedule, now: DateTime<Utc>) {
    schedule.occurrence_count = schedule.occurrence_count.saturating_add(1);
    schedule.updated_at = now;
    if schedule
        .max_runs
        .is_some_and(|limit| schedule.occurrence_count >= limit)
        || (!schedule.recurring && schedule.next_fire_at.is_none())
    {
        schedule.status = ScheduleStatus::Completed;
        schedule.status_reason = Some("schedule reached its terminal occurrence".to_string());
    }
}

fn reconcile_expired_leases(state: &mut SchedulerState, now: DateTime<Utc>) {
    let mut terminals = Vec::new();
    for schedule in &mut state.schedules {
        let Some(lease) = schedule
            .active_lease
            .as_ref()
            .filter(|lease| lease.lease_until <= now)
            .cloned()
        else {
            continue;
        };
        schedule.active_lease = None;
        if let Some(record) = state
            .run_history
            .iter_mut()
            .find(|record| record.run_id == lease.run_id && record.status == RunStatus::Running)
        {
            record.status = RunStatus::AbandonedLease;
            record.finished_at = Some(now);
            record.detail = Some("worker lease expired before a terminal transition".to_string());
        }
        if lease.attempt <= schedule.retry.max_retries {
            schedule.pending_retry = Some(PendingRetry {
                scheduled_for: lease.scheduled_for,
                attempt: lease.attempt + 1,
                not_before: retry_not_before(schedule, lease.attempt, now),
            });
        } else {
            finalize_occurrence(schedule, now);
        }
        terminals.push((
            lease.run_id,
            schedule.id.clone(),
            schedule.notification,
            "abandoned_lease",
        ));
    }
    for (run_id, schedule_id, policy, result) in terminals {
        terminal_delivery(state, run_id, &schedule_id, policy, now, result);
    }
}

fn revoke_invalid_authority(
    state: &mut SchedulerState,
    authority: &RuntimeAuthority,
    now: DateTime<Utc>,
) {
    for schedule in &mut state.schedules {
        if schedule.status != ScheduleStatus::Enabled {
            continue;
        }
        let reason = if schedule.approval.actor_id != authority.actor_id
            || schedule.approval.workspace_digest != authority.workspace_digest
        {
            Some("schedule owner or workspace binding no longer matches")
        } else if schedule.approval.capability_generation != authority.capability_generation {
            Some("schedule approval capability generation was revoked")
        } else if schedule.provider != authority.provider {
            Some("schedule provider binding no longer matches runtime configuration")
        } else {
            None
        };
        if let Some(reason) = reason {
            schedule.status = ScheduleStatus::Revoked;
            schedule.status_reason = Some(reason.to_string());
            schedule.pending_retry = None;
            schedule.queued_for = None;
            schedule.next_fire_at = None;
            schedule.updated_at = now;
        } else if schedule.expires_at.is_some_and(|expiry| expiry <= now) {
            schedule.status = ScheduleStatus::Expired;
            schedule.status_reason = Some("schedule expiry reached".to_string());
            schedule.pending_retry = None;
            schedule.queued_for = None;
            schedule.next_fire_at = None;
            schedule.updated_at = now;
        }
    }
}

fn skipped_record(
    schedule: &DurableSchedule,
    scheduled_for: DateTime<Utc>,
    status: RunStatus,
    detail: &str,
    now: DateTime<Utc>,
) -> RunHistoryRecord {
    RunHistoryRecord {
        run_id: occurrence_run_id(&schedule.id, scheduled_for, 1),
        schedule_id: schedule.id.clone(),
        schedule_name: schedule.name.clone(),
        scheduled_for,
        attempt: 1,
        fence: None,
        worker_id: None,
        status,
        claimed_at: None,
        started_at: None,
        finished_at: Some(now),
        turns_used: 0,
        output_sha256: None,
        output_excerpt: None,
        detail: Some(detail.to_string()),
        cancellation_receipt: None,
    }
}

#[allow(clippy::too_many_lines)]
fn claim_due(
    repository: &SchedulerRepository,
    authority: &RuntimeAuthority,
    worker_id: &str,
    now: DateTime<Utc>,
) -> Result<Option<ClaimedRun>, String> {
    repository.update(|state| {
        reconcile_expired_leases(state, now);
        revoke_invalid_authority(state, authority, now);
        for index in 0..state.schedules.len() {
            if state.schedules[index].status != ScheduleStatus::Enabled {
                continue;
            }
            let occurrence = if let Some(retry) = state.schedules[index].pending_retry.clone() {
                if retry.not_before > now {
                    continue;
                }
                Some((retry.scheduled_for, retry.attempt, true))
            } else if let Some(queued) = state.schedules[index].queued_for {
                Some((queued, 1, false))
            } else {
                state.schedules[index]
                    .next_fire_at
                    .filter(|scheduled| *scheduled <= now)
                    .map(|scheduled| (scheduled, 1, false))
            };
            let Some((scheduled_for, attempt, retrying)) = occurrence else {
                continue;
            };

            if state.schedules[index].active_lease.is_some() {
                if retrying {
                    continue;
                }
                let policy = state.schedules[index].overlap_policy;
                let snapshot = state.schedules[index].clone();
                match policy {
                    OverlapPolicy::Skip => {
                        let record = skipped_record(
                            &snapshot,
                            scheduled_for,
                            RunStatus::SkippedOverlap,
                            "a prior occurrence still holds the schedule lease",
                            now,
                        );
                        advance_next_fire(&mut state.schedules[index], now)?;
                        finalize_occurrence(&mut state.schedules[index], now);
                        terminal_delivery(
                            state,
                            record.run_id,
                            &record.schedule_id,
                            snapshot.notification,
                            now,
                            "skipped_overlap",
                        );
                        state.run_history.push(record);
                    }
                    OverlapPolicy::QueueOne => {
                        state.schedules[index].queued_for = Some(scheduled_for);
                        advance_next_fire(&mut state.schedules[index], now)?;
                    }
                }
                continue;
            }

            let lateness = u64::try_from(
                now.signed_duration_since(scheduled_for)
                    .num_seconds()
                    .max(0),
            )
            .unwrap_or(0);
            if !retrying
                && lateness > state.schedules[index].misfire_grace_seconds
                && state.schedules[index].misfire_policy == MisfirePolicy::Skip
            {
                let snapshot = state.schedules[index].clone();
                let record = skipped_record(
                    &snapshot,
                    scheduled_for,
                    RunStatus::SkippedMisfire,
                    "occurrence exceeded its configured misfire grace",
                    now,
                );
                if state.schedules[index].queued_for == Some(scheduled_for) {
                    state.schedules[index].queued_for = None;
                } else {
                    advance_next_fire(&mut state.schedules[index], now)?;
                }
                finalize_occurrence(&mut state.schedules[index], now);
                terminal_delivery(
                    state,
                    record.run_id,
                    &record.schedule_id,
                    snapshot.notification,
                    now,
                    "skipped_misfire",
                );
                state.run_history.push(record);
                continue;
            }

            if retrying {
                state.schedules[index].pending_retry = None;
            } else if state.schedules[index].queued_for == Some(scheduled_for) {
                state.schedules[index].queued_for = None;
            } else {
                let advance_after = if lateness > state.schedules[index].misfire_grace_seconds {
                    now
                } else {
                    scheduled_for
                };
                advance_next_fire(&mut state.schedules[index], advance_after)?;
            }
            let fence = state.next_fence;
            state.next_fence = state
                .next_fence
                .checked_add(1)
                .ok_or_else(|| "scheduler fence counter is exhausted".to_string())?;
            let run_id = occurrence_run_id(&state.schedules[index].id, scheduled_for, attempt);
            if state
                .run_history
                .iter()
                .any(|record| record.run_id == run_id)
            {
                return Err(format!(
                    "Occurrence {run_id} already has durable history; refusing duplicate dispatch"
                ));
            }
            let lease_until = now
                .checked_add_signed(chrono::Duration::seconds(
                    i64::try_from(state.schedules[index].max_run_seconds)
                        .unwrap_or(i64::MAX)
                        .saturating_add(LEASE_GRACE_SECONDS),
                ))
                .ok_or_else(|| "scheduler lease deadline overflowed".to_string())?;
            let lease = ActiveLease {
                run_id,
                worker_id: worker_id.to_string(),
                fence,
                scheduled_for,
                attempt,
                lease_until,
            };
            state.schedules[index].active_lease = Some(lease.clone());
            state.schedules[index].run_count = state.schedules[index].run_count.saturating_add(1);
            state.schedules[index].last_run_at = Some(now);
            state.schedules[index].updated_at = now;
            state.run_history.push(RunHistoryRecord {
                run_id,
                schedule_id: state.schedules[index].id.clone(),
                schedule_name: state.schedules[index].name.clone(),
                scheduled_for,
                attempt,
                fence: Some(fence),
                worker_id: Some(worker_id.to_string()),
                status: RunStatus::Running,
                claimed_at: Some(now),
                started_at: Some(now),
                finished_at: None,
                turns_used: 0,
                output_sha256: None,
                output_excerpt: None,
                detail: None,
                cancellation_receipt: None,
            });
            return Ok(Some(ClaimedRun {
                schedule: state.schedules[index].clone(),
                lease,
            }));
        }
        Ok(None)
    })
}

fn settle_run(
    repository: &SchedulerRepository,
    claim: &ClaimedRun,
    outcome: &ScheduledAgentRunOutcome,
    now: DateTime<Utc>,
) -> Result<(), String> {
    repository.update(|state| {
        let index = state
            .schedules
            .iter()
            .position(|schedule| schedule.id == claim.schedule.id)
            .ok_or_else(|| "claimed schedule was deleted before settlement".to_string())?;
        let active = state.schedules[index]
            .active_lease
            .as_ref()
            .ok_or_else(|| "claimed schedule no longer has an active lease".to_string())?;
        if active.worker_id != claim.lease.worker_id
            || active.fence != claim.lease.fence
            || active.run_id != claim.lease.run_id
        {
            return Err("stale scheduler worker was fenced from settlement".to_string());
        }
        let output_sha256 =
            crate::runtime::ContentDigest::sha256(outcome.output.as_bytes()).to_string();
        let record = state
            .run_history
            .iter_mut()
            .find(|record| {
                record.run_id == claim.lease.run_id && record.status == RunStatus::Running
            })
            .ok_or_else(|| "active occurrence has no running history record".to_string())?;
        record.status = if outcome.cancellation_receipt.is_some() {
            RunStatus::Cancelled
        } else if outcome.success {
            RunStatus::Succeeded
        } else {
            RunStatus::Failed
        };
        record.finished_at = Some(now);
        record.turns_used = outcome.turns_used;
        record.output_sha256 = Some(output_sha256.clone());
        record.output_excerpt =
            Some(safe_truncate(&outcome.output, OUTPUT_EXCERPT_BYTES).to_string());
        record.detail = (!outcome.success)
            .then(|| safe_truncate(&outcome.output, OUTPUT_EXCERPT_BYTES).to_string());
        record
            .cancellation_receipt
            .clone_from(&outcome.cancellation_receipt);
        state.schedules[index].active_lease = None;
        state.schedules[index].updated_at = now;
        if !outcome.success && claim.lease.attempt <= state.schedules[index].retry.max_retries {
            state.schedules[index].pending_retry = Some(PendingRetry {
                scheduled_for: claim.lease.scheduled_for,
                attempt: claim.lease.attempt + 1,
                not_before: retry_not_before(&state.schedules[index], claim.lease.attempt, now),
            });
        } else {
            finalize_occurrence(&mut state.schedules[index], now);
        }
        terminal_delivery(
            state,
            claim.lease.run_id,
            &claim.schedule.id,
            claim.schedule.notification,
            now,
            &format!(
                "{}:{output_sha256}",
                if outcome.cancellation_receipt.is_some() {
                    "cancelled"
                } else if outcome.success {
                    "succeeded"
                } else {
                    "failed"
                }
            ),
        );
        Ok(())
    })
}

trait ScheduledRunDispatcher: Send + Sync {
    fn dispatch<'a>(
        &'a self,
        policy: &'a ScheduledAgentRunPolicy,
    ) -> Pin<Box<dyn Future<Output = ScheduledAgentRunOutcome> + Send + 'a>>;
}

#[derive(Clone)]
struct RuntimeDispatcher {
    run: Arc<crate::tools::ToolRunContext>,
    config: Arc<crate::config::AppConfig>,
    client: reqwest::Client,
}

impl ScheduledRunDispatcher for RuntimeDispatcher {
    fn dispatch<'a>(
        &'a self,
        policy: &'a ScheduledAgentRunPolicy,
    ) -> Pin<Box<dyn Future<Output = ScheduledAgentRunOutcome> + Send + 'a>> {
        Box::pin(crate::subagent::run_scheduled_agent(
            &self.run,
            policy,
            &self.config,
            &self.client,
        ))
    }
}

struct SchedulerService {
    repository: SchedulerRepository,
    authority: RuntimeAuthority,
    worker_id: String,
    dispatcher: Arc<dyn ScheduledRunDispatcher>,
    run: Arc<crate::tools::ToolRunContext>,
    config: Arc<crate::config::AppConfig>,
    cancellation: CancellationHandle,
    active_run_ids: Arc<Mutex<HashSet<RunId>>>,
}

type ScheduledRunFuture =
    Pin<Box<dyn Future<Output = (ClaimedRun, ScheduledAgentRunOutcome)> + Send + 'static>>;

impl SchedulerService {
    async fn run(mut self) -> Result<(), String> {
        let owner_cancellation = self.run.runtime().cancellation();
        let mut ticker = tokio::time::interval(Duration::from_secs(POLL_SECONDS));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut active = FuturesUnordered::<ScheduledRunFuture>::new();
        let mut terminal_error = None;
        loop {
            tokio::select! {
                _receipt = self.cancellation.cancelled() => break,
                _receipt = owner_cancellation.cancelled() => {
                    let _receipt = self.cancellation.cancel(CancellationReason::ParentTerminated);
                    break;
                }
                _instant = ticker.tick() => {
                    if let Err(error) = self.claim_available(&active) {
                        let _receipt = self.cancellation.cancel(CancellationReason::RuntimeFailure {
                            detail: error.clone(),
                        });
                        terminal_error = Some(error);
                        break;
                    }
                }
                Some((claim, outcome)) = active.next(), if !active.is_empty() => {
                    self.settle_completed(&claim, &outcome)?;
                }
            }
        }

        while let Some((claim, outcome)) = active.next().await {
            self.settle_completed(&claim, &outcome)?;
        }
        terminal_error.map_or(Ok(()), Err)
    }

    fn claim_available(
        &mut self,
        active: &FuturesUnordered<ScheduledRunFuture>,
    ) -> Result<(), String> {
        for _ in 0..MAX_CLAIMS_PER_TICK {
            if self.cancellation.is_cancelled() {
                break;
            }
            self.authority = runtime_authority(&self.run, &self.config);
            let Some(claim) = claim_due(
                &self.repository,
                &self.authority,
                &self.worker_id,
                Utc::now(),
            )?
            else {
                break;
            };
            let run_cancellation = self.cancellation.child();
            self.active_run_ids
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(claim.lease.run_id);
            let policy = ScheduledAgentRunPolicy {
                run_id: claim.lease.run_id,
                task: format!("Scheduled task: {}", claim.schedule.name),
                prompt: claim.schedule.prompt.clone(),
                model: claim.schedule.model.clone(),
                allowed_tools: claim.schedule.allowed_tools.clone(),
                max_turns: claim.schedule.budget.max_turns,
                max_output_tokens: claim.schedule.budget.max_output_tokens,
                max_tool_calls: claim.schedule.budget.max_tool_calls,
                max_cost_microusd: claim.schedule.budget.max_cost_microusd,
                timeout: Duration::from_secs(claim.schedule.max_run_seconds),
                cancellation: run_cancellation.clone(),
            };
            let dispatcher = Arc::clone(&self.dispatcher);
            let run = Arc::clone(&self.run);
            let config = Arc::clone(&self.config);
            active.push(Box::pin(async move {
                let dispatch_future = dispatcher.dispatch(&policy);
                tokio::pin!(dispatch_future);
                let mut revocation_poll =
                    tokio::time::interval(Duration::from_secs(REVOCATION_POLL_SECONDS));
                revocation_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                let outcome = loop {
                    tokio::select! {
                        outcome = &mut dispatch_future => break outcome,
                        _instant = revocation_poll.tick() => {
                            let current = runtime_authority(&run, &config);
                            if current.actor_id != claim.schedule.approval.actor_id
                                || current.workspace_digest != claim.schedule.approval.workspace_digest
                                || current.capability_generation != claim.schedule.approval.capability_generation
                                || current.provider != claim.schedule.provider
                            {
                                let _receipt = run_cancellation.cancel(CancellationReason::RuntimeFailure {
                                    detail: "durable schedule authority was revoked while running".to_string(),
                                });
                            }
                        }
                    }
                };
                (claim, outcome)
            }));
        }
        Ok(())
    }

    fn settle_completed(
        &self,
        claim: &ClaimedRun,
        outcome: &ScheduledAgentRunOutcome,
    ) -> Result<(), String> {
        let settlement = settle_run(&self.repository, claim, outcome, Utc::now());
        self.active_run_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&claim.lease.run_id);
        settlement
    }
}

/// Owned lifecycle handle for the sole production cron scheduler authority.
///
/// Composition roots start one handle for their active run and must call
/// [`Self::shutdown`] before retiring that run. Drop still cancels and aborts
/// as a last-resort no-detachment guarantee.
pub struct SchedulerServiceHandle {
    cancellation: CancellationHandle,
    join: Option<tokio::task::JoinHandle<Result<(), String>>>,
    run: Arc<crate::tools::ToolRunContext>,
    active_run_ids: Arc<Mutex<HashSet<RunId>>>,
}

impl SchedulerServiceHandle {
    pub(crate) fn start(
        run: Arc<crate::tools::ToolRunContext>,
        config: Arc<crate::config::AppConfig>,
        client: reqwest::Client,
    ) -> Result<Self, String> {
        let repository = SchedulerRepository::for_run(&run)?;
        let _state = repository.load()?;
        let runtime = tokio::runtime::Handle::try_current().map_err(|error| {
            format!("Scheduler service requires an active Tokio runtime: {error}")
        })?;
        let cancellation = CancellationTree::new().root();
        let active_run_ids = Arc::new(Mutex::new(HashSet::new()));
        let service = SchedulerService {
            repository,
            authority: runtime_authority(&run, &config),
            worker_id: Uuid::new_v4().to_string(),
            dispatcher: Arc::new(RuntimeDispatcher {
                run: Arc::clone(&run),
                config: Arc::clone(&config),
                client,
            }),
            run: Arc::clone(&run),
            config,
            cancellation: cancellation.clone(),
            active_run_ids: Arc::clone(&active_run_ids),
        };
        let join = runtime.spawn(async move {
            let result = service.run().await;
            if let Err(error) = &result {
                tracing::error!(%error, "Durable scheduler service terminated with an error");
            }
            result
        });
        Ok(Self {
            cancellation,
            join: Some(join),
            run,
            active_run_ids,
        })
    }

    pub(crate) async fn shutdown(mut self) -> Result<(), String> {
        let _receipt = self
            .cancellation
            .cancel(CancellationReason::FrontendDisconnected);
        let Some(join) = self.join.take() else {
            return Ok(());
        };
        join.await
            .map_err(|error| format!("Scheduler service task failed to join: {error}"))?
    }
}

impl Drop for SchedulerServiceHandle {
    fn drop(&mut self) {
        let _receipt = self
            .cancellation
            .cancel(CancellationReason::FrontendDisconnected);
        let active_run_ids = self
            .active_run_ids
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        for run_id in active_run_ids {
            let _cleanup = crate::subagent::stop_scheduled_agent(
                &self.run,
                run_id,
                CancellationReason::ParentTerminated,
            );
        }
        if let Some(join) = self.join.take() {
            join.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_schedule(id: String, now: DateTime<Utc>) -> DurableSchedule {
        DurableSchedule {
            id,
            name: "fixture".to_string(),
            cron_expression: "* * * * *".to_string(),
            prompt: "check".to_string(),
            recurring: true,
            durable_requested: true,
            status: ScheduleStatus::Enabled,
            status_reason: None,
            timezone: TimeZonePolicy::Utc,
            dst_policy: DstPolicy::UtcHasNoTransitions,
            misfire_policy: MisfirePolicy::RunOnce,
            misfire_grace_seconds: 300,
            overlap_policy: OverlapPolicy::Skip,
            retry: RetryPolicy {
                max_retries: 2,
                backoff_seconds: 10,
            },
            max_run_seconds: 60,
            expires_at: None,
            max_runs: None,
            provider: "test".to_string(),
            model: "test".to_string(),
            allowed_tools: vec!["read_file".to_string()],
            budget: RunBudgetPolicy {
                max_turns: 1,
                max_output_tokens: 1,
                max_tool_calls: 1,
                max_cost_microusd: 1,
            },
            notification: NotificationPolicy::HistoryOnly,
            approval: ApprovalAuthority {
                receipt_id: Uuid::new_v4().to_string(),
                evidence_digest: "a".repeat(64),
                actor_id: "b".repeat(64),
                workspace_digest: "c".repeat(64),
                capability_generation: 1,
            },
            created_at: now,
            updated_at: now,
            next_fire_at: Some(now),
            active_lease: None,
            pending_retry: None,
            queued_for: None,
            run_count: 0,
            occurrence_count: 0,
            last_run_at: None,
        }
    }

    fn test_repository(root: &tempfile::TempDir) -> SchedulerRepository {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        SchedulerRepository {
            storage: PersistentStorage::open(root.path()).unwrap(),
            target: PathBuf::from(STATE_FILE),
        }
    }

    #[test]
    fn utc_schedule_has_deterministic_occurrence_identity() {
        let scheduled_for = DateTime::parse_from_rfc3339("2026-11-01T01:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(
            occurrence_run_id("f8bd2a18-e6b7-48d2-b786-bb47822797f3", scheduled_for, 1),
            occurrence_run_id("f8bd2a18-e6b7-48d2-b786-bb47822797f3", scheduled_for, 1)
        );
        assert_ne!(
            occurrence_run_id("f8bd2a18-e6b7-48d2-b786-bb47822797f3", scheduled_for, 1),
            occurrence_run_id("f8bd2a18-e6b7-48d2-b786-bb47822797f3", scheduled_for, 2)
        );
    }

    #[test]
    fn utc_cron_matching_is_explicit_at_dst_boundaries() {
        let first = DateTime::parse_from_rfc3339("2026-11-01T01:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let second = DateTime::parse_from_rfc3339("2026-11-01T02:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(cron_matches("30 1 * * *", first));
        assert!(!cron_matches("30 1 * * *", second));
    }

    #[test]
    fn concurrent_workers_claim_one_occurrence_once() {
        let now = DateTime::parse_from_rfc3339("2026-08-27T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let root = tempfile::tempdir().unwrap();
        let repository = test_repository(&root);
        let schedule = fixture_schedule(Uuid::new_v4().to_string(), now);
        repository
            .update(|state| {
                state.schedules.push(schedule.clone());
                Ok(())
            })
            .unwrap();
        let authority = RuntimeAuthority {
            actor_id: "b".repeat(64),
            workspace_digest: "c".repeat(64),
            capability_generation: 1,
            provider: "test".to_string(),
        };
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let mut workers = Vec::new();
        for worker_id in ["worker-a", "worker-b"] {
            let repository = repository.clone();
            let authority = authority.clone();
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                claim_due(&repository, &authority, worker_id, now).unwrap()
            }));
        }
        barrier.wait();
        let claimed = workers
            .into_iter()
            .filter_map(|worker| worker.join().unwrap())
            .count();
        assert_eq!(claimed, 1);
        let state = repository.load().unwrap().state;
        assert_eq!(state.run_history.len(), 1);
        assert!(state.schedules[0].active_lease.is_some());
    }

    #[test]
    fn distinct_due_schedules_can_hold_concurrent_leases() {
        let now = DateTime::parse_from_rfc3339("2026-08-27T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let root = tempfile::tempdir().unwrap();
        let repository = test_repository(&root);
        let first = fixture_schedule(Uuid::new_v4().to_string(), now);
        let mut second = fixture_schedule(Uuid::new_v4().to_string(), now);
        second.name = "fixture-two".to_string();
        repository
            .update(|state| {
                state.schedules.extend([first.clone(), second.clone()]);
                Ok(())
            })
            .unwrap();
        let authority = RuntimeAuthority {
            actor_id: "b".repeat(64),
            workspace_digest: "c".repeat(64),
            capability_generation: 1,
            provider: "test".to_string(),
        };

        let first_claim = claim_due(&repository, &authority, "worker", now)
            .unwrap()
            .expect("first due schedule");
        let second_claim = claim_due(&repository, &authority, "worker", now)
            .unwrap()
            .expect("second due schedule");
        assert_ne!(first_claim.schedule.id, second_claim.schedule.id);
        let state = repository.load().unwrap().state;
        assert_eq!(
            state
                .schedules
                .iter()
                .filter(|schedule| schedule.active_lease.is_some())
                .count(),
            2
        );
    }

    #[test]
    fn due_occurrence_records_overlap_while_prior_lease_is_live() {
        let first_due = DateTime::parse_from_rfc3339("2026-08-27T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let second_due = first_due + chrono::Duration::minutes(1);
        let root = tempfile::tempdir().unwrap();
        let repository = test_repository(&root);
        let schedule = fixture_schedule(Uuid::new_v4().to_string(), first_due);
        repository
            .update(|state| {
                state.schedules.push(schedule.clone());
                Ok(())
            })
            .unwrap();
        let authority = RuntimeAuthority {
            actor_id: "b".repeat(64),
            workspace_digest: "c".repeat(64),
            capability_generation: 1,
            provider: "test".to_string(),
        };
        claim_due(&repository, &authority, "worker", first_due)
            .unwrap()
            .expect("first occurrence claims a lease");
        repository
            .update(|state| {
                state.schedules[0].next_fire_at = Some(second_due);
                Ok(())
            })
            .unwrap();

        assert!(claim_due(&repository, &authority, "worker", second_due)
            .unwrap()
            .is_none());
        let state = repository.load().unwrap().state;
        assert!(state.run_history.iter().any(|record| {
            record.scheduled_for == second_due && record.status == RunStatus::SkippedOverlap
        }));
        assert!(state.schedules[0].active_lease.is_some());
    }

    #[test]
    fn capability_generation_revocation_disables_future_runs() {
        let now = DateTime::parse_from_rfc3339("2026-08-27T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut state = SchedulerState::default();
        state
            .schedules
            .push(fixture_schedule(Uuid::new_v4().to_string(), now));
        revoke_invalid_authority(
            &mut state,
            &RuntimeAuthority {
                actor_id: "b".repeat(64),
                workspace_digest: "c".repeat(64),
                capability_generation: 2,
                provider: "test".to_string(),
            },
            now,
        );
        assert_eq!(state.schedules[0].status, ScheduleStatus::Revoked);
        assert!(state.schedules[0].next_fire_at.is_none());
    }

    #[test]
    fn expired_lease_becomes_abandoned_and_retries() {
        let now = DateTime::parse_from_rfc3339("2026-08-27T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let schedule_id = Uuid::new_v4().to_string();
        let run_id = occurrence_run_id(&schedule_id, now, 1);
        let mut state = SchedulerState::default();
        state.schedules.push(DurableSchedule {
            id: schedule_id.clone(),
            name: "restart".to_string(),
            cron_expression: "0 * * * *".to_string(),
            prompt: "check".to_string(),
            recurring: true,
            durable_requested: true,
            status: ScheduleStatus::Enabled,
            status_reason: None,
            timezone: TimeZonePolicy::Utc,
            dst_policy: DstPolicy::UtcHasNoTransitions,
            misfire_policy: MisfirePolicy::RunOnce,
            misfire_grace_seconds: 300,
            overlap_policy: OverlapPolicy::Skip,
            retry: RetryPolicy {
                max_retries: 2,
                backoff_seconds: 10,
            },
            max_run_seconds: 60,
            expires_at: None,
            max_runs: None,
            provider: "test".to_string(),
            model: "test".to_string(),
            allowed_tools: vec!["read_file".to_string()],
            budget: RunBudgetPolicy {
                max_turns: 1,
                max_output_tokens: 1,
                max_tool_calls: 1,
                max_cost_microusd: 1,
            },
            notification: NotificationPolicy::HistoryOnly,
            approval: ApprovalAuthority {
                receipt_id: Uuid::new_v4().to_string(),
                evidence_digest: "a".repeat(64),
                actor_id: "b".repeat(64),
                workspace_digest: "c".repeat(64),
                capability_generation: 1,
            },
            created_at: now,
            updated_at: now,
            next_fire_at: None,
            active_lease: Some(ActiveLease {
                run_id,
                worker_id: "dead-worker".to_string(),
                fence: 1,
                scheduled_for: now,
                attempt: 1,
                lease_until: now - chrono::Duration::seconds(1),
            }),
            pending_retry: None,
            queued_for: None,
            run_count: 0,
            occurrence_count: 0,
            last_run_at: None,
        });
        state.run_history.push(RunHistoryRecord {
            run_id,
            schedule_id,
            schedule_name: "restart".to_string(),
            scheduled_for: now,
            attempt: 1,
            fence: Some(1),
            worker_id: Some("dead-worker".to_string()),
            status: RunStatus::Running,
            claimed_at: Some(now),
            started_at: Some(now),
            finished_at: None,
            turns_used: 0,
            output_sha256: None,
            output_excerpt: None,
            detail: None,
            cancellation_receipt: None,
        });
        reconcile_expired_leases(&mut state, now);
        assert_eq!(state.run_history[0].status, RunStatus::AbandonedLease);
        assert_eq!(
            state.schedules[0].pending_retry.as_ref().unwrap().attempt,
            2
        );
        assert!(state.schedules[0].active_lease.is_none());
    }
}
