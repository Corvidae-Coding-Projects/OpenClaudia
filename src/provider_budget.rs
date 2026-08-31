//! Shared provider-call admission and reconciliation.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::runtime::{
    BudgetAmounts, BudgetDimension, BudgetError, BudgetReceipt, BudgetReservation,
};
use crate::session::{
    calculate_budget_cost_microusd, conservative_budget_cost_microusd, FixedCostError,
    FixedCostEstimate, PricingProvenance, TokenUsage,
};
use crate::tools::ToolRunContext;

/// Provider/model/pricing evidence attached to one settled call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderBudgetReceipt {
    pub provider: String,
    pub model: String,
    pub pricing: PricingProvenance,
    pub budget: BudgetReceipt,
}

/// Provider work could not be admitted or reconciled safely.
#[derive(Debug, Error)]
pub enum ProviderBudgetError {
    #[error("provider request must be a JSON object")]
    InvalidRequest,
    #[error("provider request is too large to account for")]
    RequestTooLarge,
    #[error("provider output budget is exhausted")]
    OutputExhausted,
    #[error(transparent)]
    Cost(#[from] FixedCostError),
    #[error(transparent)]
    Budget(#[from] BudgetError),
}

/// Live reservation held from immediately before a provider call until its
/// terminal usage is known (or explicitly unknown).
#[derive(Debug)]
pub struct ProviderBudgetReservation {
    provider: String,
    model: String,
    reservation: BudgetReservation,
    reservation_pricing: PricingProvenance,
}

impl ProviderBudgetReservation {
    /// Reconcile provider-reported terminal usage. An all-zero report is
    /// treated as missing usage and retains the conservative reservation.
    ///
    /// # Errors
    ///
    /// Returns an error when fixed-point cost or budget reconciliation fails.
    pub fn reconcile(
        self,
        usage: &TokenUsage,
    ) -> Result<ProviderBudgetReceipt, ProviderBudgetError> {
        if usage.input_tokens == 0
            && usage.output_tokens == 0
            && usage.cache_read_tokens == 0
            && usage.cache_write_tokens == 0
        {
            return self.finish_unknown();
        }
        let input_tokens = usage
            .input_tokens
            .checked_add(usage.cache_read_tokens)
            .and_then(|value| value.checked_add(usage.cache_write_tokens))
            .ok_or(ProviderBudgetError::RequestTooLarge)?;
        let cost = calculate_budget_cost_microusd(&self.model, usage)?;
        let budget = self.reservation.reconcile(BudgetAmounts {
            input_tokens,
            output_tokens: usage.output_tokens,
            turns: 1,
            provider_calls: 1,
            cost_microusd: cost.microusd,
            ..BudgetAmounts::default()
        })?;
        let receipt = ProviderBudgetReceipt {
            provider: self.provider,
            model: self.model,
            pricing: cost.provenance,
            budget,
        };
        trace_receipt(&receipt);
        Ok(receipt)
    }

    /// Retain the conservative reservation when a terminal response does not
    /// provide trustworthy usage.
    ///
    /// # Errors
    ///
    /// Returns an error if the live budget authority is unavailable.
    pub fn finish_unknown(self) -> Result<ProviderBudgetReceipt, ProviderBudgetError> {
        let budget = self.reservation.finish_unknown()?;
        let receipt = ProviderBudgetReceipt {
            provider: self.provider,
            model: self.model,
            pricing: self.reservation_pricing,
            budget,
        };
        trace_receipt(&receipt);
        Ok(receipt)
    }
}

/// Clamp one provider request and atomically reserve its worst-case charge.
///
/// `configured_max_output` is the operator's per-response cap; zero means no
/// extra cap beyond the request and remaining run budget.
///
/// # Errors
///
/// Returns an error for malformed requests, exhausted limits, cost overflow,
/// or unavailable live accounting state.
pub fn reserve_provider_call(
    run: &ToolRunContext,
    provider: &str,
    model: &str,
    request: &mut Value,
    configured_max_output: u64,
) -> Result<ProviderBudgetReservation, ProviderBudgetError> {
    if !request.is_object() {
        return Err(ProviderBudgetError::InvalidRequest);
    }
    let input_tokens = u64::try_from(request.to_string().len())
        .map_err(|_| ProviderBudgetError::RequestTooLarge)?;
    let remaining_output = run.budget().remaining(BudgetDimension::OutputTokens)?;
    let remaining_total = run.budget().remaining(BudgetDimension::TotalTokens)?;
    let mut output_cap = remaining_output.min(remaining_total.saturating_sub(input_tokens));
    if configured_max_output != 0 {
        output_cap = output_cap.min(configured_max_output);
    }
    if output_cap == 0 {
        return Err(ProviderBudgetError::OutputExhausted);
    }
    let output_tokens = clamp_provider_output(request, output_cap)?;
    let reserved_usage = TokenUsage {
        input_tokens,
        output_tokens,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
    };
    let FixedCostEstimate {
        microusd,
        provenance,
    } = conservative_budget_cost_microusd(&reserved_usage)?;
    let reservation = run.budget().reserve(BudgetAmounts {
        input_tokens,
        output_tokens,
        turns: 1,
        provider_calls: 1,
        concurrent_calls: 1,
        cost_microusd: microusd,
        ..BudgetAmounts::default()
    })?;
    Ok(ProviderBudgetReservation {
        provider: provider.to_string(),
        model: model.to_string(),
        reservation,
        reservation_pricing: provenance,
    })
}

/// Record one additional provider retry before the replay begins.
///
/// # Errors
///
/// Returns an error when either the retry or provider-call cap is exhausted.
pub fn record_provider_retry(run: &ToolRunContext) -> Result<BudgetReceipt, BudgetError> {
    run.budget()
        .reserve(BudgetAmounts {
            provider_calls: 1,
            retries: 1,
            ..BudgetAmounts::default()
        })?
        .commit()
}

fn clamp_provider_output(request: &mut Value, hard_cap: u64) -> Result<u64, ProviderBudgetError> {
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
        return Err(ProviderBudgetError::OutputExhausted);
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

fn trace_receipt(receipt: &ProviderBudgetReceipt) {
    tracing::info!(
        target: "openclaudia::budget",
        provider = receipt.provider,
        model = receipt.model,
        budget_id = %receipt.budget.budget_id,
        input_tokens = receipt.budget.charged.input_tokens,
        output_tokens = receipt.budget.charged.output_tokens,
        cost_microusd = receipt.budget.charged.cost_microusd,
        certainty = ?receipt.budget.certainty,
        pricing = ?receipt.pricing,
        "provider budget reconciled"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budgeted_run(output_tokens: u64) -> std::sync::Arc<ToolRunContext> {
        let root = tempfile::tempdir().expect("root").keep();
        let limits = crate::runtime::BudgetLimits {
            input_tokens: 10_000,
            output_tokens,
            total_tokens: 20_000,
            turns: 10,
            provider_calls: 10,
            tool_calls: 10,
            elapsed_millis: 60_000,
            retries: 10,
            concurrent_calls: 10,
            child_runs: 10,
            cost_microusd: 10_000_000,
            trace_bytes: 1024,
        };
        ToolRunContext::builder(crate::state::SessionId::new(), &root)
            .working_directory(&root)
            .read_only_roots(Vec::new())
            .read_write_roots(Vec::new())
            .environment_grants(std::collections::HashMap::new())
            .workspace_access(crate::tools::WorkspaceAccess::ReadOnly)
            .process(false)
            .network(true)
            .secrets(false)
            .provider("openai")
            .budget_limits(limits)
            .build()
            .expect("run")
    }

    #[test]
    fn provider_specific_output_fields_are_clamped() {
        let cases = [
            (serde_json::json!({"max_tokens": 100}), "/max_tokens"),
            (
                serde_json::json!({"input": [], "max_output_tokens": 100}),
                "/max_output_tokens",
            ),
            (
                serde_json::json!({"generationConfig": {"maxOutputTokens": 100}}),
                "/generationConfig/maxOutputTokens",
            ),
            (
                serde_json::json!({"options": {"num_predict": 100}}),
                "/options/num_predict",
            ),
        ];
        for (mut request, pointer) in cases {
            assert_eq!(clamp_provider_output(&mut request, 7).expect("cap"), 7);
            assert_eq!(request.pointer(pointer).and_then(Value::as_u64), Some(7));
        }
    }

    #[test]
    fn production_reservation_clamps_and_reconciles_reported_usage() {
        let run = budgeted_run(7);
        let mut request = serde_json::json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "hello"}],
            "max_tokens": 100
        });
        let reservation =
            reserve_provider_call(&run, "openai", "gpt-4o", &mut request, 0).expect("reserve");
        assert_eq!(request["max_tokens"], 7);
        reservation
            .reconcile(&TokenUsage {
                input_tokens: 5,
                output_tokens: 3,
                cache_read_tokens: 0,
                cache_write_tokens: 0,
            })
            .expect("reconcile");
        let snapshot = run.budget().snapshot().expect("snapshot");
        assert_eq!(snapshot.used.input_tokens, 5);
        assert_eq!(snapshot.used.output_tokens, 3);
        assert_eq!(snapshot.used.turns, 1);
        assert_eq!(snapshot.used.provider_calls, 1);
        assert_eq!(snapshot.used.concurrent_calls, 0);
        assert!(snapshot.used.cost_microusd > 0);
    }
}
