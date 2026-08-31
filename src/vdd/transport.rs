//! HTTP transport for the VDD loop: adversary + builder request plumbing.

use std::future::Future;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use chrono::Utc;
use reqwest::Client;
use serde_json::Value;
use tracing::{debug, info};
use zeroize::Zeroizing;

use crate::config::{AppConfig, ProviderConfig, VddConfig};
use crate::providers::{get_adapter, ApiKey, ProviderAdapter};
use crate::proxy::ChatCompletionRequest;
use crate::session::TokenUsage;

use crate::vdd::error::{VddError, VddProviderCallOutcome, VddProviderCallReceipt};
use crate::vdd::helpers::truncate_output;

const MAX_VDD_MODEL_INPUT_TOKENS_PER_CALL: u64 = 64 * 1024;
const MAX_VDD_REVIEW_INPUT_TOKENS: u64 = 512 * 1024;
const VDD_TRANSPORT_INPUT_TOKEN_OVERHEAD: u64 = 4 * 1024;
const MAX_VDD_STRUCTURED_RESPONSE_BYTES: usize = 512 * 1024;
const MAX_VDD_ANALYZER_BYTES_PER_STREAM: usize = 128 * 1024;

/// Aggregate, review-scoped admission held across every model and analyzer
/// stage. The canonical run ledger receives one worst-case reservation before
/// work starts; individual stages settle only against this local authority so
/// a multi-stage review cannot multiply the parent run's limits.
pub struct VddReviewBudget {
    reservation: Mutex<Option<crate::runtime::BudgetReservation>>,
    state: Mutex<VddReviewBudgetState>,
    limits: VddReviewLimits,
    deadline: tokio::time::Instant,
    timeout_seconds: u64,
    cancellation: crate::runtime::CancellationHandle,
}

#[derive(Clone, Copy)]
struct VddReviewLimits {
    input_tokens: u64,
    output_tokens: u64,
    model_calls: u64,
    process_calls: u64,
    storage_bytes: u64,
}

#[derive(Default)]
struct VddReviewBudgetState {
    charged: crate::runtime::BudgetAmounts,
    storage_bytes: u64,
    active_calls: u64,
    provider_receipts: Vec<VddProviderCallReceipt>,
}

#[derive(Debug)]
pub enum VddReviewWaitError {
    Deadline,
    Cancelled(crate::runtime::CancellationReason),
}

impl VddReviewBudget {
    #[allow(clippy::too_many_lines)] // Aggregate admission calculates every bounded resource in one reservation.
    pub(crate) fn admit(
        run: &crate::tools::ToolRunContext,
        config: &VddConfig,
        blocking: bool,
    ) -> Result<Self, VddError> {
        config.validate_settings().map_err(VddError::ConfigError)?;
        let iterations = if blocking {
            u64::from(config.thresholds.max_iterations)
        } else {
            1
        };
        // One adversary and one verifier call per iteration, plus a possible
        // builder revision after every non-terminal blocking iteration.
        let model_calls = if blocking {
            iterations
                .checked_mul(3)
                .and_then(|calls| calls.checked_sub(1))
        } else {
            Some(2)
        }
        .ok_or_else(|| VddError::ConfigError("VDD model-call budget overflow".to_string()))?;
        let commands_per_iteration = if !config.static_analysis.enabled {
            0
        } else if config.static_analysis.commands.is_empty() {
            u64::try_from(crate::config::VddStaticAnalysis::MAX_COMMANDS)
                .map_err(|_| VddError::ConfigError("VDD process budget overflow".to_string()))?
        } else {
            u64::try_from(config.static_analysis.commands.len())
                .map_err(|_| VddError::ConfigError("VDD process budget overflow".to_string()))?
        };
        let process_calls = iterations
            .checked_mul(commands_per_iteration)
            .ok_or_else(|| VddError::ConfigError("VDD process budget overflow".to_string()))?;
        let input_tokens = model_calls
            .checked_mul(MAX_VDD_MODEL_INPUT_TOKENS_PER_CALL)
            .ok_or_else(|| VddError::ConfigError("VDD input budget overflow".to_string()))?
            .min(MAX_VDD_REVIEW_INPUT_TOKENS);
        let output_tokens = model_calls
            .checked_mul(u64::from(config.adversary.max_tokens))
            .ok_or_else(|| VddError::ConfigError("VDD output budget overflow".to_string()))?;
        let model_storage = model_calls
            .checked_mul(
                u64::try_from(MAX_VDD_STRUCTURED_RESPONSE_BYTES).map_err(|_| {
                    VddError::ConfigError("VDD storage budget overflow".to_string())
                })?,
            )
            .ok_or_else(|| VddError::ConfigError("VDD storage budget overflow".to_string()))?;
        let process_storage = process_calls
            .checked_mul(
                u64::try_from(MAX_VDD_ANALYZER_BYTES_PER_STREAM)
                    .map_err(|_| VddError::ConfigError("VDD storage budget overflow".to_string()))?
                    .checked_mul(2)
                    .ok_or_else(|| {
                        VddError::ConfigError("VDD storage budget overflow".to_string())
                    })?,
            )
            .ok_or_else(|| VddError::ConfigError("VDD storage budget overflow".to_string()))?;
        let storage_bytes = model_storage
            .checked_add(process_storage)
            .ok_or_else(|| VddError::ConfigError("VDD storage budget overflow".to_string()))?;
        let conservative_cost = crate::session::conservative_budget_cost_microusd(&TokenUsage {
            input_tokens,
            output_tokens,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
        })
        .map_err(|error| VddError::ConfigError(format!("VDD cost budget overflow: {error}")))?;
        let requested = Duration::from_secs(config.adversary.request_timeout_seconds);
        let remaining = run.budget().remaining_time().map_err(|error| {
            VddError::ConfigError(format!("Run budget denied VDD review deadline: {error}"))
        })?;
        let timeout = requested.min(remaining);
        if timeout.is_zero() {
            return Err(VddError::ConfigError(
                "Run budget has no time remaining for VDD review".to_string(),
            ));
        }
        let now = tokio::time::Instant::now();
        let reservation = run
            .budget()
            .reserve(crate::runtime::BudgetAmounts {
                input_tokens,
                output_tokens,
                turns: model_calls,
                provider_calls: model_calls,
                tool_calls: process_calls,
                retries: 0,
                concurrent_calls: 1,
                cost_microusd: conservative_cost.microusd,
                ..crate::runtime::BudgetAmounts::default()
            })
            .map_err(|error| {
                VddError::ConfigError(format!("Run budget denied aggregate VDD review: {error}"))
            })?;
        let timeout_seconds = timeout.as_secs().max(1);
        Ok(Self {
            reservation: Mutex::new(Some(reservation)),
            state: Mutex::new(VddReviewBudgetState::default()),
            limits: VddReviewLimits {
                input_tokens,
                output_tokens,
                model_calls,
                process_calls,
                storage_bytes,
            },
            deadline: now + timeout,
            timeout_seconds,
            cancellation: run.runtime().cancellation(),
        })
    }

    pub(crate) fn begin_model_call<'a>(
        &'a self,
        provider: &str,
        model: &str,
        request: &mut Value,
        configured_max_output: u64,
    ) -> Result<VddModelCall<'a>, String> {
        if !request.is_object() {
            return Err("VDD provider request must be a JSON object".to_string());
        }
        self.ensure_live()?;
        let mut state = self.lock_state();
        if state.active_calls >= 1 {
            return Err("VDD review concurrency budget is exhausted".to_string());
        }
        let remaining_calls = self
            .limits
            .model_calls
            .saturating_sub(state.charged.provider_calls);
        if remaining_calls == 0 {
            return Err("VDD aggregate model-call budget is exhausted".to_string());
        }
        let remaining_output = self
            .limits
            .output_tokens
            .saturating_sub(state.charged.output_tokens);
        let output_cap = configured_max_output.min(remaining_output);
        if output_cap == 0 {
            return Err("VDD aggregate output-token budget is exhausted".to_string());
        }
        let reserved_output = clamp_vdd_provider_output(request, output_cap)?;
        let request_bytes = u64::try_from(request.to_string().len())
            .map_err(|_| "VDD provider request is too large to account for".to_string())?;
        if request_bytes > MAX_VDD_MODEL_INPUT_TOKENS_PER_CALL {
            return Err(format!(
                "VDD provider input exceeded the {MAX_VDD_MODEL_INPUT_TOKENS_PER_CALL}-byte call limit"
            ));
        }
        let remaining_input = self
            .limits
            .input_tokens
            .saturating_sub(state.charged.input_tokens);
        // UTF-8 byte length is a conservative upper bound for provider-visible
        // request tokens. Keep an additional fixed allowance for the owned SDK
        // transport prefixes that are added after this JSON boundary.
        let estimated_input = request_bytes
            .saturating_add(VDD_TRANSPORT_INPUT_TOKEN_OVERHEAD)
            .min(MAX_VDD_MODEL_INPUT_TOKENS_PER_CALL);
        let reserved_input = estimated_input.min(remaining_input);
        if reserved_input == 0 {
            return Err("VDD aggregate input-token budget is exhausted".to_string());
        }
        state.active_calls += 1;
        drop(state);
        Ok(VddModelCall {
            budget: self,
            provider: provider.to_string(),
            model: model.to_string(),
            reserved_input,
            reserved_output,
            settled: false,
        })
    }

    pub(crate) fn begin_process(&self) -> Result<(), String> {
        self.ensure_live()?;
        let mut state = self.lock_state();
        if state.active_calls >= 1 {
            return Err("VDD review concurrency budget is exhausted".to_string());
        }
        if state.charged.tool_calls >= self.limits.process_calls {
            return Err("VDD aggregate process budget is exhausted".to_string());
        }
        state.active_calls += 1;
        drop(state);
        Ok(())
    }

    pub(crate) fn finish_process(&self, storage_bytes: usize) -> Result<(), String> {
        let mut state = self.lock_state();
        let tool_calls = state
            .charged
            .tool_calls
            .checked_add(1)
            .ok_or_else(|| "VDD process accounting overflow".to_string())?;
        let storage_bytes = u64::try_from(storage_bytes)
            .map_err(|_| "VDD storage accounting overflow".to_string())?;
        let total_storage = state
            .storage_bytes
            .checked_add(storage_bytes)
            .filter(|total| *total <= self.limits.storage_bytes)
            .ok_or_else(|| "VDD aggregate storage budget is exhausted".to_string())?;
        state.active_calls = state.active_calls.saturating_sub(1);
        state.charged.tool_calls = tool_calls;
        state.storage_bytes = total_storage;
        drop(state);
        Ok(())
    }

    pub(crate) fn abandon_process(&self) {
        let mut state = self.lock_state();
        state.active_calls = state.active_calls.saturating_sub(1);
        state.charged.tool_calls = state.charged.tool_calls.saturating_add(1);
    }

    pub(crate) fn remaining_time(&self) -> Result<Duration, String> {
        self.ensure_live()?;
        self.deadline
            .checked_duration_since(tokio::time::Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| "VDD aggregate review deadline expired".to_string())
    }

    pub(crate) const fn deadline(&self) -> tokio::time::Instant {
        self.deadline
    }

    pub(crate) const fn timeout_seconds(&self) -> u64 {
        self.timeout_seconds
    }

    pub(crate) const fn response_limit() -> usize {
        MAX_VDD_STRUCTURED_RESPONSE_BYTES
    }

    pub(crate) const fn analyzer_output_limit() -> usize {
        MAX_VDD_ANALYZER_BYTES_PER_STREAM
    }

    pub(crate) async fn wait<F: Future>(&self, future: F) -> Result<F::Output, VddReviewWaitError> {
        tokio::select! {
            biased;
            receipt = self.cancellation.cancelled() => {
                Err(VddReviewWaitError::Cancelled(receipt.reason))
            }
            () = tokio::time::sleep_until(self.deadline) => Err(VddReviewWaitError::Deadline),
            output = future => Ok(output),
        }
    }

    pub(crate) fn cancellation(&self) -> crate::runtime::CancellationHandle {
        self.cancellation.clone()
    }

    pub(crate) fn provider_receipts(&self) -> Vec<VddProviderCallReceipt> {
        self.lock_state().provider_receipts.clone()
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)] // One settlement binds identity, reservation, usage, storage, and terminal outcome atomically.
    fn settle_model(
        &self,
        provider: &str,
        requested_model: &str,
        resolved_model: Option<&str>,
        reserved_input: u64,
        reserved_output: u64,
        usage: Option<&TokenUsage>,
        storage_bytes: usize,
        completed: bool,
    ) -> Result<(), String> {
        let cost_model = resolved_model.unwrap_or(requested_model);
        let (input_tokens, output_tokens, cost_microusd, usage_known) = usage.map_or_else(
            || {
                let usage = TokenUsage {
                    input_tokens: reserved_input,
                    output_tokens: reserved_output,
                    cache_read_tokens: 0,
                    cache_write_tokens: 0,
                };
                crate::session::conservative_budget_cost_microusd(&usage)
                    .map(|cost| (reserved_input, reserved_output, cost.microusd, false))
                    .map_err(|error| format!("VDD unknown-usage cost overflow: {error}"))
            },
            |usage| {
                let input = usage
                    .input_tokens
                    .checked_add(usage.cache_read_tokens)
                    .and_then(|value| value.checked_add(usage.cache_write_tokens))
                    .ok_or_else(|| "VDD provider usage overflow".to_string())?;
                if input > reserved_input || usage.output_tokens > reserved_output {
                    return Err(
                        "VDD provider usage exceeded its pre-reserved call budget".to_string()
                    );
                }
                crate::session::calculate_budget_cost_microusd(cost_model, usage)
                    .map(|cost| (input, usage.output_tokens, cost.microusd, true))
                    .map_err(|error| format!("VDD provider cost overflow: {error}"))
            },
        )?;
        let storage_bytes = u64::try_from(storage_bytes)
            .map_err(|_| "VDD storage accounting overflow".to_string())?;
        let mut state = self.lock_state();
        let input_total = state
            .charged
            .input_tokens
            .checked_add(input_tokens)
            .ok_or_else(|| "VDD input accounting overflow".to_string())?;
        let output_total = state
            .charged
            .output_tokens
            .checked_add(output_tokens)
            .ok_or_else(|| "VDD output accounting overflow".to_string())?;
        let turns = state
            .charged
            .turns
            .checked_add(1)
            .ok_or_else(|| "VDD turn accounting overflow".to_string())?;
        let provider_calls = state
            .charged
            .provider_calls
            .checked_add(1)
            .ok_or_else(|| "VDD provider-call accounting overflow".to_string())?;
        let cost_total = state
            .charged
            .cost_microusd
            .checked_add(cost_microusd)
            .ok_or_else(|| "VDD cost accounting overflow".to_string())?;
        let storage_total = state
            .storage_bytes
            .checked_add(storage_bytes)
            .filter(|total| *total <= self.limits.storage_bytes)
            .ok_or_else(|| "VDD aggregate storage budget is exhausted".to_string())?;
        if input_total > self.limits.input_tokens
            || output_total > self.limits.output_tokens
            || provider_calls > self.limits.model_calls
        {
            return Err("VDD aggregate model budget is exhausted".to_string());
        }
        state.active_calls = state.active_calls.saturating_sub(1);
        state.charged.input_tokens = input_total;
        state.charged.output_tokens = output_total;
        state.charged.turns = turns;
        state.charged.provider_calls = provider_calls;
        state.charged.cost_microusd = cost_total;
        state.storage_bytes = storage_total;
        state.provider_receipts.push(VddProviderCallReceipt {
            provider: provider.to_string(),
            requested_model: requested_model.to_string(),
            resolved_model: resolved_model.map(ToString::to_string),
            outcome: if completed {
                VddProviderCallOutcome::Completed
            } else {
                VddProviderCallOutcome::FailedOrUnknown
            },
            usage_known,
            input_tokens,
            output_tokens,
            response_bytes: storage_bytes,
            completed_at: Utc::now(),
        });
        drop(state);
        tracing::info!(
            provider,
            requested_model,
            resolved_model,
            input_tokens,
            output_tokens,
            usage_known,
            "VDD provider call reconciled against aggregate review budget"
        );
        Ok(())
    }

    fn ensure_live(&self) -> Result<(), String> {
        if let Some(receipt) = self.cancellation.receipt() {
            return Err(format!("VDD review was cancelled: {:?}", receipt.reason));
        }
        self.remaining_deadline_only()
    }

    fn remaining_deadline_only(&self) -> Result<(), String> {
        if tokio::time::Instant::now() >= self.deadline {
            Err("VDD aggregate review deadline expired".to_string())
        } else {
            Ok(())
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, VddReviewBudgetState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Drop for VddReviewBudget {
    fn drop(&mut self) {
        let actual = self.lock_state().charged;
        let reservation = self
            .reservation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(reservation) = reservation {
            if let Err(error) = reservation.reconcile(actual) {
                tracing::error!("VDD aggregate budget reconciliation failed: {error}");
                let _receipt =
                    self.cancellation
                        .cancel(crate::runtime::CancellationReason::RuntimeFailure {
                            detail: error.to_string(),
                        });
            }
        }
    }
}

pub struct VddModelCall<'a> {
    budget: &'a VddReviewBudget,
    provider: String,
    model: String,
    reserved_input: u64,
    reserved_output: u64,
    settled: bool,
}

impl VddModelCall<'_> {
    pub(crate) fn finish(
        mut self,
        usage: Option<&TokenUsage>,
        storage_bytes: usize,
        resolved_model: Option<&str>,
    ) -> Result<(), String> {
        let result = self.budget.settle_model(
            &self.provider,
            &self.model,
            resolved_model,
            self.reserved_input,
            self.reserved_output,
            usage,
            storage_bytes,
            true,
        );
        let (result, settled) = match result {
            Ok(()) => (Ok(()), true),
            Err(error) => match self.budget.settle_model(
                &self.provider,
                &self.model,
                None,
                self.reserved_input,
                self.reserved_output,
                None,
                0,
                false,
            ) {
                Ok(()) => (Err(error), true),
                Err(unknown_error) => (
                    Err(format!(
                        "{error}; retaining the conservative reservation also failed: {unknown_error}"
                    )),
                    false,
                ),
            },
        };
        self.settled = settled;
        result
    }
}

impl Drop for VddModelCall<'_> {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        if let Err(error) = self.budget.settle_model(
            &self.provider,
            &self.model,
            None,
            self.reserved_input,
            self.reserved_output,
            None,
            0,
            false,
        ) {
            tracing::error!("VDD failed to retain unknown provider reservation: {error}");
            let _receipt = self
                .budget
                .cancellation
                .cancel(crate::runtime::CancellationReason::RuntimeFailure { detail: error });
        }
    }
}

fn clamp_vdd_provider_output(request: &mut Value, hard_cap: u64) -> Result<u64, String> {
    let current = if request.get("generationConfig").is_some() {
        request
            .pointer("/generationConfig/maxOutputTokens")
            .and_then(Value::as_u64)
    } else if request.get("options").is_some() {
        request
            .pointer("/options/num_predict")
            .and_then(Value::as_u64)
    } else if request.get("input").is_some() && request.get("messages").is_none() {
        request.get("max_output_tokens").and_then(Value::as_u64)
    } else {
        request
            .get("max_completion_tokens")
            .or_else(|| request.get("max_tokens"))
            .and_then(Value::as_u64)
    }
    .unwrap_or_else(|| u64::from(crate::DEFAULT_MAX_TOKENS));
    let capped = current.min(hard_cap);
    if capped == 0 {
        return Err("VDD provider output budget is exhausted".to_string());
    }
    if request.get("generationConfig").is_some() {
        request["generationConfig"]["maxOutputTokens"] = Value::from(capped);
    } else if request.get("options").is_some() {
        request["options"]["num_predict"] = Value::from(capped);
    } else if request.get("input").is_some() && request.get("messages").is_none() {
        request["max_output_tokens"] = Value::from(capped);
    } else if request.get("max_completion_tokens").is_some() {
        request["max_completion_tokens"] = Value::from(capped);
    } else {
        request["max_tokens"] = Value::from(capped);
    }
    Ok(capped)
}

/// Runtime authentication material for a provider used by VDD.
///
/// This is deliberately separate from [`VddConfig`]: startup can select
/// account-backed auth for the current session without persisting bearer tokens
/// into `.openclaudia/config.yaml`.
#[derive(Clone, PartialEq, Eq)]
pub enum VddProviderAuth {
    ApiKey(ApiKey),
    ClaudeAgentSdk(crate::claude_agent_sdk::ClaudeAgentSdk),
    CodexAgentSdk(crate::codex_agent_sdk::CodexAgentSdk),
    ClaudeCodeToken(crate::secrets::OAuthToken),
    None,
}

impl std::fmt::Debug for VddProviderAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiKey(_) => f.write_str("VddProviderAuth::ApiKey(<redacted>)"),
            Self::ClaudeAgentSdk(_) => f.write_str("VddProviderAuth::ClaudeAgentSdk"),
            Self::CodexAgentSdk(_) => f.write_str("VddProviderAuth::CodexAgentSdk"),
            Self::ClaudeCodeToken(_) => f.write_str("VddProviderAuth::ClaudeCodeToken(<redacted>)"),
            Self::None => f.write_str("VddProviderAuth::None"),
        }
    }
}

impl VddProviderAuth {
    #[must_use]
    pub const fn api_key(api_key: ApiKey) -> Self {
        Self::ApiKey(api_key)
    }

    #[must_use]
    pub const fn claude_code_token(token: crate::secrets::OAuthToken) -> Self {
        Self::ClaudeCodeToken(token)
    }

    #[must_use]
    pub const fn claude_agent_sdk(sdk: crate::claude_agent_sdk::ClaudeAgentSdk) -> Self {
        Self::ClaudeAgentSdk(sdk)
    }

    #[must_use]
    pub const fn codex_agent_sdk(sdk: crate::codex_agent_sdk::CodexAgentSdk) -> Self {
        Self::CodexAgentSdk(sdk)
    }
}

async fn complete_vdd_via_codex_agent_sdk(
    sdk: &crate::codex_agent_sdk::CodexAgentSdk,
    provider_name: &str,
    request: &Value,
    budget: &VddReviewBudget,
) -> Result<crate::codex_agent_sdk::CodexAgentSdkTurn, String> {
    if !provider_name.eq_ignore_ascii_case("openai") {
        return Err(format!(
            "Codex SDK auth can only be used with OpenAI, got '{provider_name}'"
        ));
    }
    let turn = sdk
        .complete_turn_bounded(request, "high", budget.deadline(), budget.cancellation())
        .await
        .map_err(|error| error.to_string())?;
    if !turn.tool_calls.is_empty() {
        return Err(format!(
            "Codex SDK returned {} tool call(s) to a no-tools VDD request",
            turn.tool_calls.len()
        ));
    }
    if turn.content.trim().is_empty() {
        return Err("Codex SDK completed VDD request without assistant content".to_string());
    }
    Ok(turn)
}

fn codex_agent_sdk_response_json(turn: &crate::codex_agent_sdk::CodexAgentSdkTurn) -> Value {
    serde_json::json!({
        "output_text": turn.content,
        "usage": {
            "input_tokens": turn.usage.input_tokens,
            "output_tokens": turn.usage.output_tokens,
            "cached_input_tokens": turn.usage.cache_read_tokens,
            "cache_write_input_tokens": turn.usage.cache_write_tokens,
        }
    })
}

async fn complete_vdd_via_claude_agent_sdk(
    sdk: &crate::claude_agent_sdk::ClaudeAgentSdk,
    provider_name: &str,
    request: &Value,
    budget: &VddReviewBudget,
) -> Result<crate::claude_agent_sdk::ClaudeAgentSdkTurn, String> {
    if !provider_name.eq_ignore_ascii_case("anthropic") {
        return Err(format!(
            "Claude Agent SDK auth can only be used with Anthropic, got '{provider_name}'"
        ));
    }
    let turn = sdk
        .complete_turn_bounded(request, "high", budget.deadline(), budget.cancellation())
        .await
        .map_err(|error| error.to_string())?;
    if !turn.tool_calls.is_empty() {
        return Err(format!(
            "Claude Agent SDK returned {} tool call(s) to a no-tools VDD request",
            turn.tool_calls.len()
        ));
    }
    if turn.content.trim().is_empty() {
        return Err("Claude Agent SDK completed VDD request without assistant content".to_string());
    }
    Ok(turn)
}

fn claude_agent_sdk_response_json(turn: &crate::claude_agent_sdk::ClaudeAgentSdkTurn) -> Value {
    serde_json::json!({
        "content": [{"type": "text", "text": turn.content}],
        "stop_reason": "end_turn",
        "usage": {
            "input_tokens": turn.usage.input_tokens,
            "output_tokens": turn.usage.output_tokens,
            "cache_read_input_tokens": turn.usage.cache_read_tokens,
            "cache_creation_input_tokens": turn.usage.cache_write_tokens,
        }
    })
}

/// Forward a request to a provider and return the raw reqwest response.
///
/// URL composition is entirely delegated to the adapter via `endpoint`
/// (the return value of `ProviderAdapter::chat_endpoint`), so provider-specific
/// path conventions (e.g. Google's `/v1beta/models/{model}:generateContent`)
/// are handled in the adapter, not here.
pub async fn forward_request(
    client: &Client,
    provider_name: &str,
    provider: &ProviderConfig,
    endpoint: &str,
    body: &Value,
    mut headers: crate::secrets::SensitiveHeaders,
    deadline: tokio::time::Instant,
) -> Result<reqwest::Response, String> {
    let base_url = provider
        .base_url
        .trim_end_matches('/')
        .trim_end_matches("/v1")
        .trim_end_matches('/');

    // endpoint already encodes the full provider-specific path, including
    // any model name or version segment (e.g. Google's v1beta path). OAuth
    // and Codex-backed flows may provide a fully-qualified endpoint.
    let url = if endpoint.starts_with("http://") || endpoint.starts_with("https://") {
        endpoint.to_string()
    } else {
        format!("{base_url}{endpoint}")
    };

    crate::provider_transport::validate_endpoint(provider_name, &url)
        .map_err(|error| error.to_string())?;

    debug!("VDD: Sending verifier request");

    headers.extend(&provider.headers);
    let req = headers
        .apply(client.post(&url).json(body))
        .map_err(|error| format!("invalid provider headers: {error}"))?;

    let header_deadline = deadline
        .min(tokio::time::Instant::now() + crate::provider_transport::RESPONSE_HEADER_TIMEOUT);
    let response = crate::provider_transport::send_until(req, header_deadline)
        .await
        .map_err(|error| error.to_string())?;
    if response.status().is_success() {
        return Ok(response);
    }

    let status = response.status();
    let body = tokio::time::timeout_at(deadline, read_bounded_failure_body(response))
        .await
        .map_err(|_| "provider error body exceeded the VDD review deadline".to_string())??;
    Err(format!(
        "provider returned HTTP {status}: {}",
        headers.sanitize_diagnostic(&body)
    ))
}

async fn read_bounded_failure_body(
    response: reqwest::Response,
) -> Result<Zeroizing<String>, String> {
    use futures::StreamExt as _;

    let mut stream = response.bytes_stream();
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = stream.next().await {
        let chunk =
            chunk.map_err(|error| format!("failed to read provider error body: {error}"))?;
        let remaining = crate::secrets::MAX_DIAGNOSTIC_INPUT_BYTES.saturating_sub(bytes.len());
        bytes.extend_from_slice(&chunk[..chunk.len().min(remaining)]);
        if chunk.len() > remaining || remaining == 0 {
            break;
        }
    }
    Ok(Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned()))
}

#[cfg(test)]
fn responses_text_from_json(json: &Value) -> Option<String> {
    if let Some(text) = json.get("output_text").and_then(Value::as_str) {
        return Some(text.to_string());
    }

    let mut out = String::new();
    for item in json.get("output").and_then(Value::as_array)? {
        for part in item
            .get("content")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(text) = part
                .get("text")
                .and_then(Value::as_str)
                .or_else(|| part.get("content").and_then(Value::as_str))
            {
                out.push_str(text);
            }
        }
    }
    (!out.is_empty()).then_some(out)
}

#[cfg(test)]
fn responses_usage_from_json(json: &Value) -> TokenUsage {
    let Some(usage) = json.get("usage") else {
        return TokenUsage::default();
    };
    let raw_input_tokens = usage
        .get("input_tokens")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let cache_read_tokens = usage
        .get("input_tokens_details")
        .and_then(|details| details.get("cached_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let cache_write_tokens = usage
        .get("input_tokens_details")
        .and_then(|details| details.get("cache_write_tokens"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    TokenUsage {
        input_tokens: raw_input_tokens
            .saturating_sub(cache_read_tokens)
            .saturating_sub(cache_write_tokens),
        output_tokens: usage
            .get("output_tokens")
            .and_then(Value::as_u64)
            .unwrap_or(0),
        cache_read_tokens,
        cache_write_tokens,
    }
}

#[cfg(test)]
fn responses_text_from_sse(raw: &str) -> Result<(String, TokenUsage), VddError> {
    let mut text = String::new();
    let mut usage = TokenUsage::default();
    let mut completed = false;
    for line in raw.lines() {
        let Some(data) = line.trim_start().strip_prefix("data:") else {
            continue;
        };
        let data = data.trim();
        if data.is_empty() || data == "[DONE]" {
            continue;
        }
        let json = serde_json::from_str::<Value>(data).map_err(|e| {
            VddError::AdversaryRequestFailed(format!("responses SSE frame decode: {e}"))
        })?;
        match json.get("type").and_then(Value::as_str).unwrap_or_default() {
            "response.output_text.delta" => {
                if let Some(delta) = json.get("delta").and_then(Value::as_str) {
                    text.push_str(delta);
                }
            }
            "response.completed" => {
                if let Some(response) = json.get("response") {
                    crate::pipeline::validate_openai_responses_terminal_json(response).map_err(
                        |error| {
                            VddError::AdversaryRequestFailed(format!(
                                "responses terminal validation: {error}"
                            ))
                        },
                    )?;
                    completed = true;
                    usage.accumulate(&responses_usage_from_json(response));
                    if text.is_empty() {
                        if let Some(final_text) = responses_text_from_json(response) {
                            text = final_text;
                        }
                    }
                }
            }
            "response.failed" | "response.incomplete" => {
                let message = json
                    .get("response")
                    .and_then(|response| response.get("error"))
                    .or_else(|| json.get("error"))
                    .and_then(|error| {
                        error
                            .get("message")
                            .and_then(Value::as_str)
                            .or_else(|| error.as_str())
                    })
                    .unwrap_or("Responses API request failed");
                return Err(VddError::AdversaryRequestFailed(message.to_string()));
            }
            _ => {}
        }
    }
    if !completed {
        return Err(VddError::AdversaryRequestFailed(
            "Responses stream ended before response.completed".to_string(),
        ));
    }
    if text.trim().is_empty() {
        return Err(VddError::AdversaryRequestFailed(
            "Responses verifier completed without assistant content".to_string(),
        ));
    }
    Ok((text, usage))
}

fn validate_vdd_chat_terminal(
    adapter: &dyn ProviderAdapter,
    response: &Value,
) -> Result<(), String> {
    let normalized = adapter
        .transform_response(response.clone(), false)
        .map_err(|error| format!("provider response transform failed: {error}"))?;
    let terminal = crate::pipeline::validate_chat_completion_terminal(&normalized)?;
    if terminal != crate::pipeline::ProviderTerminalOutcome::Completed {
        return Err("VDD provider requested tools in a no-tools verification turn".to_string());
    }
    Ok(())
}

fn validate_resolved_model_identity(
    provider_name: &str,
    requested_model: &str,
    endpoint: &str,
    response: &Value,
) -> Result<String, String> {
    let canonical_provider = get_adapter(provider_name)
        .map_err(|error| error.to_string())?
        .name()
        .to_ascii_lowercase();
    let envelope_model = response
        .get("model")
        .or_else(|| response.get("modelVersion"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|model| !model.is_empty());
    let resolved = if matches!(canonical_provider.as_str(), "google" | "gemini") {
        // Gemini identifies the selected model in the model-addressed endpoint;
        // newer responses additionally expose `modelVersion`.
        if !endpoint.contains(requested_model) {
            return Err("Google VDD endpoint does not bind the requested model".to_string());
        }
        envelope_model.unwrap_or(requested_model)
    } else {
        envelope_model.ok_or_else(|| {
            "VDD provider response is missing its resolved model identity".to_string()
        })?
    };
    if resolved.len() > 512 {
        return Err("VDD provider returned an oversized model identity".to_string());
    }
    tracing::info!(
        provider = canonical_provider,
        requested_model,
        resolved_model = resolved,
        "VDD transport observed resolved provider model identity"
    );
    Ok(resolved.to_string())
}

fn nonzero_usage(usage: &TokenUsage) -> Option<&TokenUsage> {
    (usage.input_tokens != 0
        || usage.output_tokens != 0
        || usage.cache_read_tokens != 0
        || usage.cache_write_tokens != 0)
        .then_some(usage)
}

fn map_review_wait_error(
    error: VddReviewWaitError,
    provider: &str,
    budget: &VddReviewBudget,
) -> VddError {
    match error {
        VddReviewWaitError::Deadline => VddError::Timeout {
            provider: provider.to_string(),
            elapsed_secs: budget.timeout_seconds(),
        },
        VddReviewWaitError::Cancelled(reason) => VddError::AdversaryRequestFailed(format!(
            "VDD review was cancelled before provider completion: {reason:?}"
        )),
    }
}

fn adversary_headers_and_endpoint(
    config: &VddConfig,
    provider_config: &ProviderConfig,
    adapter: &dyn ProviderAdapter,
    request: &ChatCompletionRequest,
    transformed: &mut Value,
    runtime_auth: Option<&VddProviderAuth>,
) -> Result<(crate::secrets::SensitiveHeaders, String), VddError> {
    match runtime_auth {
        Some(VddProviderAuth::ApiKey(api_key)) => Ok((
            adapter.get_headers(api_key),
            adapter.chat_endpoint(&request.model),
        )),
        Some(VddProviderAuth::ClaudeCodeToken(token)) => {
            if !config.adversary.provider.eq_ignore_ascii_case("anthropic") {
                return Err(VddError::ConfigError(format!(
                    "Claude Code auth can only be used with Anthropic VDD adversary, got '{}'",
                    config.adversary.provider
                )));
            }
            crate::claude_credentials::inject_oauth_prefix_only(transformed)
                .map_err(|error| VddError::ConfigError(error.to_string()))?;
            Ok((
                crate::claude_credentials::get_oauth_headers(token)
                    .map_err(|error| VddError::ConfigError(error.to_string()))?,
                crate::claude_credentials::get_oauth_endpoint(&request.model)
                    .map_err(|error| VddError::ConfigError(error.to_string()))?,
            ))
        }
        Some(VddProviderAuth::None) => Ok((
            crate::secrets::SensitiveHeaders::new(),
            adapter.chat_endpoint(&request.model),
        )),
        None => {
            let api_key = config
                .adversary
                .api_key
                .as_ref()
                .or(provider_config.api_key.as_ref())
                .ok_or_else(|| {
                    VddError::ConfigError(format!(
                        "No API key for adversary provider '{}'",
                        config.adversary.provider
                    ))
                })?;
            Ok((
                adapter.get_headers(api_key),
                adapter.chat_endpoint(&request.model),
            ))
        }
        Some(VddProviderAuth::ClaudeAgentSdk(_) | VddProviderAuth::CodexAgentSdk(_)) => {
            unreachable!("handled above")
        }
    }
}

/// Send a request to the adversary provider. Returns (`response_text`, `token_usage`).
///
/// The caller-owned aggregate review deadline covers the send and bounded body
/// read, so no stage receives a fresh full timeout.
#[allow(clippy::too_many_lines)] // Keep the bounded VDD request and its budget settlement in one transaction.
pub async fn send_to_adversary(
    budget: &VddReviewBudget,
    client: &Client,
    config: &VddConfig,
    app_config: &AppConfig,
    request: &ChatCompletionRequest,
    runtime_auth: Option<&VddProviderAuth>,
) -> Result<(String, TokenUsage), VddError> {
    let provider_config = app_config
        .providers
        .get(&config.adversary.provider)
        .ok_or_else(|| {
            VddError::ConfigError(format!(
                "Adversary provider '{}' not configured in providers section",
                config.adversary.provider
            ))
        })?;

    // Crosslink #433: a typo in `config.adversary.provider` now surfaces
    // as `ConfigError` instead of being silently mapped to OpenAIAdapter.
    let adapter = get_adapter(&config.adversary.provider)
        .map_err(|e| VddError::ConfigError(e.to_string()))?;
    let mut transformed = adapter
        .transform_request(request)
        .map_err(|e| VddError::AdversaryRequestFailed(e.to_string()))?;

    if let Some(VddProviderAuth::CodexAgentSdk(sdk)) = runtime_auth {
        let model_call = budget
            .begin_model_call(
                &config.adversary.provider,
                &request.model,
                &mut transformed,
                u64::from(config.adversary.max_tokens),
            )
            .map_err(|error| {
                VddError::AdversaryRequestFailed(format!(
                    "Run budget denied provider call: {error}"
                ))
            })?;
        let turn =
            complete_vdd_via_codex_agent_sdk(sdk, &config.adversary.provider, &transformed, budget)
                .await
                .map_err(VddError::AdversaryRequestFailed)?;
        if turn.content.len() > VddReviewBudget::response_limit() {
            return Err(VddError::AdversaryRequestFailed(format!(
                "Codex SDK VDD output exceeded the {}-byte review limit",
                VddReviewBudget::response_limit()
            )));
        }
        let usage = nonzero_usage(&turn.usage);
        model_call
            .finish(usage, turn.content.len(), Some(&request.model))
            .map_err(|error| {
                VddError::AdversaryRequestFailed(format!(
                    "Aggregate VDD budget reconciliation failed: {error}"
                ))
            })?;
        info!(
            response_length = turn.content.len(),
            "VDD: Received Codex SDK adversary response"
        );
        return Ok((turn.content, turn.usage));
    }

    if let Some(VddProviderAuth::ClaudeAgentSdk(sdk)) = runtime_auth {
        let model_call = budget
            .begin_model_call(
                &config.adversary.provider,
                &request.model,
                &mut transformed,
                u64::from(config.adversary.max_tokens),
            )
            .map_err(|error| {
                VddError::AdversaryRequestFailed(format!(
                    "Run budget denied provider call: {error}"
                ))
            })?;
        let turn = complete_vdd_via_claude_agent_sdk(
            sdk,
            &config.adversary.provider,
            &transformed,
            budget,
        )
        .await
        .map_err(VddError::AdversaryRequestFailed)?;
        if turn.content.len() > VddReviewBudget::response_limit() {
            return Err(VddError::AdversaryRequestFailed(format!(
                "Claude Agent SDK VDD output exceeded the {}-byte review limit",
                VddReviewBudget::response_limit()
            )));
        }
        let usage = nonzero_usage(&turn.usage);
        model_call
            .finish(usage, turn.content.len(), Some(&request.model))
            .map_err(|error| {
                VddError::AdversaryRequestFailed(format!(
                    "Aggregate VDD budget reconciliation failed: {error}"
                ))
            })?;
        info!(
            response_length = turn.content.len(),
            "VDD: Received Agent SDK adversary response"
        );
        return Ok((turn.content, turn.usage));
    }

    let (headers, endpoint) = adversary_headers_and_endpoint(
        config,
        provider_config,
        adapter,
        request,
        &mut transformed,
        runtime_auth,
    )?;

    let provider_name = config.adversary.provider.clone();
    let model_call = budget
        .begin_model_call(
            &provider_name,
            &request.model,
            &mut transformed,
            u64::from(config.adversary.max_tokens),
        )
        .map_err(|error| {
            VddError::AdversaryRequestFailed(format!("Run budget denied provider call: {error}"))
        })?;

    let response = budget
        .wait(forward_request(
            client,
            &config.adversary.provider,
            provider_config,
            &endpoint,
            &transformed,
            headers,
            budget.deadline(),
        ))
        .await
        .map_err(|error| map_review_wait_error(error, &provider_name, budget))?
        .map_err(VddError::AdversaryRequestFailed)?;

    // The body consumes the remainder of the same deadline rather than
    // receiving a fresh timeout window after response headers arrive.
    let response_json: Value = budget
        .wait(crate::provider_transport::read_json_capped(
            response,
            VddReviewBudget::response_limit(),
        ))
        .await
        .map_err(|error| map_review_wait_error(error, &provider_name, budget))?
        .map_err(|e| VddError::AdversaryRequestFailed(e.to_string()))?;
    validate_vdd_chat_terminal(adapter, &response_json)
        .map_err(VddError::AdversaryRequestFailed)?;

    // Crosslink #479: route extraction through the ProviderAdapter trait
    // so provider-specific response shapes (Gemini, Ollama, Anthropic) are
    // handled the same way they are on the main proxy path. The previous
    // free functions silently returned an empty string / zero tokens for
    // any provider whose response shape they did not hardcode.
    let text = adapter
        .extract_response_text(&response_json)
        .unwrap_or_default();
    if text.trim().is_empty() {
        return Err(VddError::AdversaryRequestFailed(
            "Adversary completed without assistant content".to_string(),
        ));
    }
    let resolved_model =
        validate_resolved_model_identity(&provider_name, &request.model, &endpoint, &response_json)
            .map_err(VddError::AdversaryRequestFailed)?;
    let reported_tokens = adapter.extract_token_usage(&response_json);
    let tokens = reported_tokens.clone().unwrap_or_default();
    model_call
        .finish(
            reported_tokens.as_ref().and_then(nonzero_usage),
            response_json.to_string().len(),
            Some(&resolved_model),
        )
        .map_err(|error| {
            VddError::AdversaryRequestFailed(format!(
                "Aggregate VDD budget reconciliation failed: {error}"
            ))
        })?;

    // Always log at INFO level for debugging, truncated
    info!(
        response_length = text.len(),
        "VDD: Received adversary response ({} chars)",
        text.len()
    );

    if config.tracking.log_adversary_responses {
        // Log first 1000 chars to see what we're getting
        info!(
            "VDD: Adversary response preview: {}",
            truncate_output(&text, 1000)
        );
    }

    Ok((text, tokens))
}

/// Send a revision request back to the builder provider.
///
/// The builder revision consumes the same aggregate review deadline as the
/// adversary, verifier, and analyzer stages. It cannot start a fresh timeout
/// window after earlier stages have spent the review's wall-clock allowance.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // Existing transport boundary plus the shared run authority.
pub async fn send_to_builder(
    budget: &VddReviewBudget,
    client: &Client,
    _config: &VddConfig,
    app_config: &AppConfig,
    request: &ChatCompletionRequest,
    provider_name: &str,
    api_key: Option<&ApiKey>,
    runtime_auth: Option<&VddProviderAuth>,
) -> Result<(String, Value, TokenUsage), VddError> {
    let provider_config = app_config.providers.get(provider_name).ok_or_else(|| {
        VddError::BuilderRevisionFailed(format!(
            "Builder provider '{provider_name}' not configured"
        ))
    })?;

    // Crosslink #433: explicit error for an unknown builder provider
    // name, no silent OpenAIAdapter fallback.
    let adapter = get_adapter(provider_name).map_err(|e| VddError::ConfigError(e.to_string()))?;
    let mut transformed = adapter
        .transform_request(request)
        .map_err(|e| VddError::BuilderRevisionFailed(e.to_string()))?;

    if let Some(VddProviderAuth::CodexAgentSdk(sdk)) = runtime_auth {
        let model_call = budget
            .begin_model_call(
                provider_name,
                &request.model,
                &mut transformed,
                u64::from(request.max_tokens.unwrap_or(crate::DEFAULT_MAX_TOKENS)),
            )
            .map_err(|error| {
                VddError::BuilderRevisionFailed(format!("Run budget denied provider call: {error}"))
            })?;
        let turn = match complete_vdd_via_codex_agent_sdk(sdk, provider_name, &transformed, budget)
            .await
        {
            Ok(turn) => turn,
            Err(error) => {
                return Err(VddError::BuilderRevisionFailed(error));
            }
        };
        if turn.content.len() > VddReviewBudget::response_limit() {
            return Err(VddError::BuilderRevisionFailed(format!(
                "Codex SDK VDD output exceeded the {}-byte review limit",
                VddReviewBudget::response_limit()
            )));
        }
        model_call
            .finish(
                nonzero_usage(&turn.usage),
                turn.content.len(),
                Some(&request.model),
            )
            .map_err(|error| {
                VddError::BuilderRevisionFailed(format!(
                    "Aggregate VDD budget reconciliation failed: {error}"
                ))
            })?;
        let response = codex_agent_sdk_response_json(&turn);
        return Ok((turn.content, response, turn.usage));
    }

    if let Some(VddProviderAuth::ClaudeAgentSdk(sdk)) = runtime_auth {
        let model_call = budget
            .begin_model_call(
                provider_name,
                &request.model,
                &mut transformed,
                u64::from(request.max_tokens.unwrap_or(crate::DEFAULT_MAX_TOKENS)),
            )
            .map_err(|error| {
                VddError::BuilderRevisionFailed(format!("Run budget denied provider call: {error}"))
            })?;
        let turn = complete_vdd_via_claude_agent_sdk(sdk, provider_name, &transformed, budget)
            .await
            .map_err(VddError::BuilderRevisionFailed)?;
        if turn.content.len() > VddReviewBudget::response_limit() {
            return Err(VddError::BuilderRevisionFailed(format!(
                "Claude Agent SDK VDD output exceeded the {}-byte review limit",
                VddReviewBudget::response_limit()
            )));
        }
        model_call
            .finish(
                nonzero_usage(&turn.usage),
                turn.content.len(),
                Some(&request.model),
            )
            .map_err(|error| {
                VddError::BuilderRevisionFailed(format!(
                    "Aggregate VDD budget reconciliation failed: {error}"
                ))
            })?;
        let response = claude_agent_sdk_response_json(&turn);
        return Ok((turn.content, response, turn.usage));
    }

    let (headers, endpoint) = match runtime_auth {
        Some(VddProviderAuth::ApiKey(api_key)) => (
            adapter.get_headers(api_key),
            adapter.chat_endpoint(&request.model),
        ),
        Some(VddProviderAuth::ClaudeCodeToken(token)) => {
            if !provider_name.eq_ignore_ascii_case("anthropic") {
                return Err(VddError::ConfigError(format!(
                    "Claude Code auth can only be used with Anthropic builder, got '{provider_name}'"
                )));
            }
            crate::claude_credentials::inject_oauth_prefix_only(&mut transformed)
                .map_err(|error| VddError::ConfigError(error.to_string()))?;
            (
                crate::claude_credentials::get_oauth_headers(token)
                    .map_err(|error| VddError::ConfigError(error.to_string()))?,
                crate::claude_credentials::get_oauth_endpoint(&request.model)
                    .map_err(|error| VddError::ConfigError(error.to_string()))?,
            )
        }
        Some(VddProviderAuth::None) => (
            crate::secrets::SensitiveHeaders::new(),
            adapter.chat_endpoint(&request.model),
        ),
        None => (
            api_key.map(|k| adapter.get_headers(k)).unwrap_or_default(),
            adapter.chat_endpoint(&request.model),
        ),
        Some(VddProviderAuth::ClaudeAgentSdk(_) | VddProviderAuth::CodexAgentSdk(_)) => {
            unreachable!("handled above")
        }
    };

    let pname = provider_name.to_string();
    let model_call = budget
        .begin_model_call(
            provider_name,
            &request.model,
            &mut transformed,
            u64::from(request.max_tokens.unwrap_or(crate::DEFAULT_MAX_TOKENS)),
        )
        .map_err(|error| {
            VddError::BuilderRevisionFailed(format!("Run budget denied provider call: {error}"))
        })?;

    let response = budget
        .wait(forward_request(
            client,
            provider_name,
            provider_config,
            &endpoint,
            &transformed,
            headers,
            budget.deadline(),
        ))
        .await
        .map_err(|error| map_review_wait_error(error, &pname, budget))?
        .map_err(VddError::BuilderRevisionFailed)?;

    let response_json: Value = budget
        .wait(crate::provider_transport::read_json_capped(
            response,
            VddReviewBudget::response_limit(),
        ))
        .await
        .map_err(|error| map_review_wait_error(error, &pname, budget))?
        .map_err(|e| VddError::BuilderRevisionFailed(e.to_string()))?;
    validate_vdd_chat_terminal(adapter, &response_json).map_err(VddError::BuilderRevisionFailed)?;

    // Crosslink #479: trait dispatch instead of hardcoded shape matching.
    let text = adapter
        .extract_response_text(&response_json)
        .unwrap_or_default();
    if text.trim().is_empty() {
        return Err(VddError::BuilderRevisionFailed(
            "Builder completed without assistant content".to_string(),
        ));
    }
    let resolved_model =
        validate_resolved_model_identity(provider_name, &request.model, &endpoint, &response_json)
            .map_err(VddError::BuilderRevisionFailed)?;
    let reported_tokens = adapter.extract_token_usage(&response_json);
    let tokens = reported_tokens.clone().unwrap_or_default();
    model_call
        .finish(
            reported_tokens.as_ref().and_then(nonzero_usage),
            response_json.to_string().len(),
            Some(&resolved_model),
        )
        .map_err(|error| {
            VddError::BuilderRevisionFailed(format!(
                "Aggregate VDD budget reconciliation failed: {error}"
            ))
        })?;

    Ok((text, response_json, tokens))
}

/// Send a verification request through the builder's provider.
/// Reuses the same HTTP plumbing as `send_to_builder` but with a
/// simpler interface (no revision response needed).
#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // Existing transport boundary plus the shared run authority.
pub async fn send_to_builder_for_verification(
    budget: &VddReviewBudget,
    client: &Client,
    _config: &VddConfig,
    app_config: &AppConfig,
    request: &ChatCompletionRequest,
    provider_name: &str,
    api_key: Option<&ApiKey>,
    runtime_auth: Option<&VddProviderAuth>,
) -> Result<(String, TokenUsage), VddError> {
    let provider_config = app_config.providers.get(provider_name).ok_or_else(|| {
        VddError::ConfigError(format!(
            "Builder provider '{provider_name}' not configured — \
             cannot run verification agent"
        ))
    })?;

    // Crosslink #433: explicit error for an unknown verifier provider name.
    let adapter = get_adapter(provider_name).map_err(|e| VddError::ConfigError(e.to_string()))?;
    let mut transformed = adapter
        .transform_request(request)
        .map_err(|e| VddError::AdversaryRequestFailed(format!("verifier transform: {e}")))?;

    if let Some(VddProviderAuth::CodexAgentSdk(sdk)) = runtime_auth {
        let model_call = budget
            .begin_model_call(
                provider_name,
                &request.model,
                &mut transformed,
                u64::from(request.max_tokens.unwrap_or(crate::DEFAULT_MAX_TOKENS)),
            )
            .map_err(|error| {
                VddError::AdversaryRequestFailed(format!(
                    "Run budget denied verifier provider call: {error}"
                ))
            })?;
        let turn = match complete_vdd_via_codex_agent_sdk(sdk, provider_name, &transformed, budget)
            .await
        {
            Ok(turn) => turn,
            Err(error) => {
                return Err(VddError::AdversaryRequestFailed(format!(
                    "verifier request: {error}"
                )));
            }
        };
        if turn.content.len() > VddReviewBudget::response_limit() {
            return Err(VddError::AdversaryRequestFailed(format!(
                "Codex SDK verifier output exceeded the {}-byte review limit",
                VddReviewBudget::response_limit()
            )));
        }
        model_call
            .finish(
                nonzero_usage(&turn.usage),
                turn.content.len(),
                Some(&request.model),
            )
            .map_err(|error| {
                VddError::AdversaryRequestFailed(format!(
                    "Aggregate verifier budget reconciliation failed: {error}"
                ))
            })?;
        return Ok((turn.content, turn.usage));
    }

    if let Some(VddProviderAuth::ClaudeAgentSdk(sdk)) = runtime_auth {
        let model_call = budget
            .begin_model_call(
                provider_name,
                &request.model,
                &mut transformed,
                u64::from(request.max_tokens.unwrap_or(crate::DEFAULT_MAX_TOKENS)),
            )
            .map_err(|error| {
                VddError::AdversaryRequestFailed(format!(
                    "Run budget denied verifier provider call: {error}"
                ))
            })?;
        let turn = complete_vdd_via_claude_agent_sdk(sdk, provider_name, &transformed, budget)
            .await
            .map_err(|error| {
                VddError::AdversaryRequestFailed(format!("verifier request: {error}"))
            })?;
        if turn.content.len() > VddReviewBudget::response_limit() {
            return Err(VddError::AdversaryRequestFailed(format!(
                "Claude Agent SDK verifier output exceeded the {}-byte review limit",
                VddReviewBudget::response_limit()
            )));
        }
        model_call
            .finish(
                nonzero_usage(&turn.usage),
                turn.content.len(),
                Some(&request.model),
            )
            .map_err(|error| {
                VddError::AdversaryRequestFailed(format!(
                    "Aggregate verifier budget reconciliation failed: {error}"
                ))
            })?;
        return Ok((turn.content, turn.usage));
    }

    let (headers, endpoint) = match runtime_auth {
        Some(VddProviderAuth::ApiKey(api_key)) => (
            adapter.get_headers(api_key),
            adapter.chat_endpoint(&request.model),
        ),
        Some(VddProviderAuth::ClaudeCodeToken(token)) => {
            if !provider_name.eq_ignore_ascii_case("anthropic") {
                return Err(VddError::ConfigError(format!(
                    "Claude Code auth can only be used with Anthropic verifier, got '{provider_name}'"
                )));
            }
            crate::claude_credentials::inject_oauth_prefix_only(&mut transformed)
                .map_err(|error| VddError::ConfigError(error.to_string()))?;
            (
                crate::claude_credentials::get_oauth_headers(token)
                    .map_err(|error| VddError::ConfigError(error.to_string()))?,
                crate::claude_credentials::get_oauth_endpoint(&request.model)
                    .map_err(|error| VddError::ConfigError(error.to_string()))?,
            )
        }
        Some(VddProviderAuth::None) => (
            crate::secrets::SensitiveHeaders::new(),
            adapter.chat_endpoint(&request.model),
        ),
        None => (
            api_key.map(|k| adapter.get_headers(k)).unwrap_or_default(),
            adapter.chat_endpoint(&request.model),
        ),
        Some(VddProviderAuth::ClaudeAgentSdk(_) | VddProviderAuth::CodexAgentSdk(_)) => {
            unreachable!("handled above")
        }
    };

    let pname = provider_name.to_string();
    let model_call = budget
        .begin_model_call(
            provider_name,
            &request.model,
            &mut transformed,
            u64::from(request.max_tokens.unwrap_or(crate::DEFAULT_MAX_TOKENS)),
        )
        .map_err(|error| {
            VddError::AdversaryRequestFailed(format!(
                "Run budget denied verifier provider call: {error}"
            ))
        })?;

    let response = budget
        .wait(forward_request(
            client,
            provider_name,
            provider_config,
            &endpoint,
            &transformed,
            headers,
            budget.deadline(),
        ))
        .await
        .map_err(|error| map_review_wait_error(error, &pname, budget))?
        .map_err(|e| VddError::AdversaryRequestFailed(format!("verifier request: {e}")))?;

    let response_json: Value = budget
        .wait(crate::provider_transport::read_json_capped(
            response,
            VddReviewBudget::response_limit(),
        ))
        .await
        .map_err(|error| map_review_wait_error(error, &pname, budget))?
        .map_err(|e| VddError::AdversaryRequestFailed(format!("verifier response: {e}")))?;
    validate_vdd_chat_terminal(adapter, &response_json).map_err(|error| {
        VddError::AdversaryRequestFailed(format!("verifier terminal validation: {error}"))
    })?;

    // Crosslink #479: trait dispatch instead of hardcoded shape matching.
    let text = adapter
        .extract_response_text(&response_json)
        .unwrap_or_default();
    if text.trim().is_empty() {
        return Err(VddError::AdversaryRequestFailed(
            "Verifier completed without assistant content".to_string(),
        ));
    }
    let resolved_model =
        validate_resolved_model_identity(provider_name, &request.model, &endpoint, &response_json)
            .map_err(|error| {
                VddError::AdversaryRequestFailed(format!("verifier model identity: {error}"))
            })?;
    let reported_tokens = adapter.extract_token_usage(&response_json);
    let tokens = reported_tokens.clone().unwrap_or_default();
    model_call
        .finish(
            reported_tokens.as_ref().and_then(nonzero_usage),
            response_json.to_string().len(),
            Some(&resolved_model),
        )
        .map_err(|error| {
            VddError::AdversaryRequestFailed(format!(
                "Aggregate verifier budget reconciliation failed: {error}"
            ))
        })?;

    Ok((text, tokens))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        GuardrailsConfig, HooksConfig, KeybindingsConfig, PermissionsConfig, ProviderConfig,
        ProxyConfig, SessionConfig, ThinkingConfig, VddAdversaryConfig, VddConfig,
    };
    use std::collections::HashMap;
    use std::time::Duration;

    fn cfg_with_timeout(secs: u64) -> VddConfig {
        VddConfig {
            enabled: true,
            adversary: VddAdversaryConfig {
                provider: "openai".to_string(),
                model: None,
                api_key: None,
                temperature: 0.3,
                max_tokens: 256,
                request_timeout_seconds: secs,
            },
            ..Default::default()
        }
    }

    #[test]
    fn responses_verifier_requires_completed_terminal_event() {
        let raw = concat!(
            "data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n",
            "data: [DONE]\n"
        );
        let error = responses_text_from_sse(raw).expect_err("missing completion must fail");
        assert!(
            error.to_string().contains("before response.completed"),
            "{error}"
        );
    }

    #[test]
    fn responses_verifier_rejects_refusal_as_success() {
        let raw = concat!(
            "data: {\"type\":\"response.completed\",\"response\":{",
            "\"id\":\"resp_1\",\"status\":\"completed\",\"output\":[{",
            "\"type\":\"message\",\"content\":[{",
            "\"type\":\"refusal\",\"refusal\":\"cannot comply\"}]}]}}\n",
            "data: [DONE]\n"
        );
        let error = responses_text_from_sse(raw).expect_err("refusal must fail");
        assert!(error.to_string().contains("refused"), "{error}");
    }

    #[test]
    fn responses_usage_keeps_cache_buckets_disjoint() {
        let usage = responses_usage_from_json(&serde_json::json!({
            "usage": {
                "input_tokens": 100,
                "output_tokens": 10,
                "input_tokens_details": {
                    "cached_tokens": 30,
                    "cache_write_tokens": 20
                }
            }
        }));
        assert_eq!(usage.input_tokens, 50);
        assert_eq!(usage.output_tokens, 10);
        assert_eq!(usage.cache_read_tokens, 30);
        assert_eq!(usage.cache_write_tokens, 20);
    }

    #[test]
    fn resolved_model_identity_is_required_and_preserved() {
        let missing = validate_resolved_model_identity(
            "openai",
            "requested-model",
            "/v1/chat/completions",
            &serde_json::json!({}),
        );
        assert!(missing.is_err());

        let resolved = validate_resolved_model_identity(
            "openai",
            "requested-model",
            "/v1/chat/completions",
            &serde_json::json!({"model": "resolved-model"}),
        )
        .expect("provider model identity");
        assert_eq!(resolved, "resolved-model");
    }

    #[test]
    fn review_budget_does_not_multiply_model_calls_between_stages() {
        let config = cfg_with_timeout(30);
        let budget =
            VddReviewBudget::admit(crate::tools::security::test_run_context(), &config, false)
                .expect("aggregate review budget");

        for _ in 0..2 {
            let mut request = serde_json::json!({"model": "gpt-4", "max_tokens": 256});
            budget
                .begin_model_call("openai", "gpt-4", &mut request, 256)
                .expect("pre-reserved stage")
                .finish(None, 0, Some("gpt-4"))
                .expect("unknown usage retains conservative allowance");
        }
        let mut extra = serde_json::json!({"model": "gpt-4", "max_tokens": 256});
        assert!(
            budget
                .begin_model_call("openai", "gpt-4", &mut extra, 256)
                .is_err(),
            "a third stage must not receive a fresh review allowance"
        );
        let receipts = budget.provider_receipts();
        assert_eq!(receipts.len(), 2);
        assert!(receipts.iter().all(|receipt| {
            receipt.requested_model == "gpt-4"
                && receipt.resolved_model.as_deref() == Some("gpt-4")
                && receipt.outcome == VddProviderCallOutcome::Completed
                && !receipt.usage_known
        }));
    }

    #[test]
    fn blocking_review_has_one_aggregate_input_cap_and_exact_call_ceiling() {
        let config = cfg_with_timeout(30);
        let budget =
            VddReviewBudget::admit(crate::tools::security::test_run_context(), &config, true)
                .expect("aggregate blocking review budget");

        assert_eq!(budget.limits.model_calls, 14);
        assert_eq!(budget.limits.input_tokens, MAX_VDD_REVIEW_INPUT_TOKENS);

        for _ in 0..budget.limits.model_calls {
            let mut request = serde_json::json!({"model": "gpt-4", "max_tokens": 256});
            budget
                .begin_model_call("openai", "gpt-4", &mut request, 256)
                .expect("small request within aggregate call ceiling")
                .finish(None, 0, Some("gpt-4"))
                .expect("conservative settlement");
        }
        let mut extra = serde_json::json!({"model": "gpt-4", "max_tokens": 256});
        assert!(budget
            .begin_model_call("openai", "gpt-4", &mut extra, 256)
            .is_err());
    }

    fn app_cfg_with_provider(provider: &str, base_url: &str) -> AppConfig {
        let mut providers = HashMap::new();
        providers.insert(
            provider.to_string(),
            ProviderConfig {
                base_url: base_url.to_string(),
                api_key: Some(
                    crate::providers::ApiKey::try_from_string("test-key".to_string()).unwrap(),
                ),
                model: None,
                headers: crate::secrets::SensitiveHeaders::new(),
                thinking: ThinkingConfig::default(),
            },
        );
        AppConfig {
            proxy: ProxyConfig::default(),
            providers,
            hooks: HooksConfig::default(),
            session: SessionConfig::default(),
            keybindings: KeybindingsConfig::default(),
            vdd: VddConfig::default(),
            guardrails: GuardrailsConfig::default(),
            permissions: PermissionsConfig::default(),
            memory: crate::config::MemoryConfig::default(),
            web_fetch: crate::config::WebFetchConfig::default(),
            remote_actions: crate::config::RemoteActionsConfig::default(),
            policy: crate::services::policy::EnterprisePolicy::default(),
            managed_settings_path: None,
        }
    }

    fn dummy_request() -> ChatCompletionRequest {
        ChatCompletionRequest {
            model: "gpt-4".to_string(),
            messages: vec![],
            temperature: None,
            max_tokens: None,
            stream: None,
            tools: None,
            tool_choice: None,
            extra: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn shared_vdd_transport_redacts_and_bounds_provider_failures() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        const SECRET: &str = "s025-vdd-header-secret-b921a4";
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": {
                    "message": format!("echo {SECRET}"),
                    "padding": "x".repeat(crate::secrets::MAX_DIAGNOSTIC_BYTES * 2)
                }
            })))
            .mount(&server)
            .await;
        let provider = ProviderConfig {
            base_url: server.uri(),
            api_key: None,
            model: None,
            headers: crate::secrets::SensitiveHeaders::new(),
            thinking: ThinkingConfig::default(),
        };
        let mut headers = crate::secrets::SensitiveHeaders::new();
        headers.insert_header_bearer(
            reqwest::header::AUTHORIZATION,
            crate::secrets::SecretString::try_from_string(SECRET.to_string()).expect("secret"),
        );

        let error = forward_request(
            &Client::new(),
            "local",
            &provider,
            "/v1/chat/completions",
            &serde_json::json!({}),
            headers,
            tokio::time::Instant::now() + Duration::from_secs(30),
        )
        .await
        .expect_err("non-success provider response must fail");

        assert!(
            !error.contains(SECRET),
            "VDD leaked provider credential: {error}"
        );
        assert!(error.contains(crate::secrets::REDACTED_SECRET), "{error}");
        assert!(error.len() <= crate::secrets::MAX_DIAGNOSTIC_BYTES + 64);
    }

    #[tokio::test]
    async fn adversary_transport_rejects_rate_limited_malformed_and_oversized_responses() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let cases = [
            (
                "rate-limited",
                ResponseTemplate::new(429).set_body_string("rate limited"),
            ),
            (
                "malformed",
                ResponseTemplate::new(200).set_body_string("not-json"),
            ),
            (
                "oversized",
                ResponseTemplate::new(200).set_body_bytes(vec![
                    b'x';
                    MAX_VDD_STRUCTURED_RESPONSE_BYTES
                        + 1
                ]),
            ),
        ];

        for (case, response) in cases {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/v1/chat/completions"))
                .respond_with(response)
                .mount(&server)
                .await;
            let mut config = cfg_with_timeout(5);
            config.adversary.provider = "local".to_string();
            let app_config = app_cfg_with_provider("local", &server.uri());
            let directory = tempfile::tempdir().expect("run directory");
            let run = crate::tools::security::test_run_context_for(directory.path());
            let budget = VddReviewBudget::admit(&run, &config, false).expect("review budget");
            let error = send_to_adversary(
                &budget,
                &Client::new(),
                &config,
                &app_config,
                &dummy_request(),
                None,
            )
            .await
            .expect_err(case);
            assert!(matches!(error, VddError::AdversaryRequestFailed(_)));
        }
    }

    // ── Crosslink #496: VDD HTTP timeout ──────────────────────────────────
    //
    // A slow / hung adversary upstream cannot block the VDD loop
    // indefinitely. `send_to_adversary` gives the HTTP send and body read one
    // shared monotonic deadline; on expiry it returns
    // `VddError::Timeout { provider, elapsed_secs }`.

    /// The configured timeout value is propagated from
    /// `VddConfig.adversary.request_timeout_seconds` into the actual
    /// timeout the transport applies. We can't observe the duration
    /// directly, but we can pin that the typed config field is honoured
    /// by checking the timeout's serde default + override semantics.
    #[test]
    fn vdd_timeout_default_is_120_seconds() {
        let cfg = VddConfig::default();
        assert_eq!(cfg.adversary.request_timeout_seconds, 120);
    }

    #[test]
    fn vdd_timeout_override_is_respected_via_config() {
        let cfg = cfg_with_timeout(7);
        assert_eq!(cfg.adversary.request_timeout_seconds, 7);
    }

    /// Hit a reserved-IP "blackhole" address (`192.0.2.1` is TEST-NET-1
    /// per RFC 5737; routed-but-unreachable on every machine that
    /// honours the registry). The connect will hang past the 1 s
    /// timeout. Asserts that we get `VddError::Timeout` (the new
    /// variant) — not `AdversaryRequestFailed`.
    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn send_to_adversary_surfaces_timeout_variant_on_hang() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mut cfg = cfg_with_timeout(1);
        cfg.adversary.provider = "local".to_string();
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/chat/completions"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(30)))
            .mount(&server)
            .await;
        let app_cfg = app_cfg_with_provider("local", &server.uri());
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(30))
            .build()
            .unwrap();
        let req = dummy_request();
        let budget =
            VddReviewBudget::admit(crate::tools::security::test_run_context(), &cfg, false)
                .expect("review budget");

        // Run the call and advance virtual time past the 1s budget.
        let handle = tokio::spawn(async move {
            send_to_adversary(&budget, &client, &cfg, &app_cfg, &req, None).await
        });
        // Drive paused-time forward past the configured timeout.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let result = handle.await.expect("join task");

        match result {
            Err(VddError::Timeout {
                provider,
                elapsed_secs,
            }) => {
                assert_eq!(provider, "local");
                assert_eq!(elapsed_secs, 1);
            }
            Err(other) => panic!("expected VddError::Timeout, got {other:?}"),
            Ok(_) => panic!("expected timeout, got successful response"),
        }
    }

    /// The `VddError::Timeout` Display includes both the provider name
    /// and the elapsed seconds so the operator can see *which* upstream
    /// is hung and *how long* it has been waiting — required for
    /// triage. The previous code returned a stringly-typed
    /// `AdversaryRequestFailed("...timed out after {n}s")` which forces
    /// callers to substring-match to detect timeouts.
    #[test]
    fn vdd_timeout_error_display_has_provider_and_seconds() {
        let err = VddError::Timeout {
            provider: "google".to_string(),
            elapsed_secs: 42,
        };
        let display = err.to_string();
        assert!(display.contains("google"), "got: {display}");
        assert!(display.contains("42"), "got: {display}");
    }
}
