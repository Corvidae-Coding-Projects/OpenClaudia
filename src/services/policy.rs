//! Enterprise policy enforcement (crosslink #637).
//!
//! Adds three orthogonal caps that operators can set in
//! `.openclaudia/config.yaml` under a top-level `policy:` block:
//!
//! * **`token_caps`** — per-request or projected per-session token ceilings
//!   the proxy refuses to exceed. Session projection is cumulative recorded
//!   usage plus the current request's estimated input plus its requested (or
//!   default) output budget. This sits above the existing compaction layer:
//!   compaction trims context to fit a budget, this hard-stops when the
//!   projected budget itself is policy-violating.
//! * **`tool_caps`** — per-tool invocation limits per session
//!   (e.g. "no more than 50 bash calls per session"). Prevents a
//!   runaway agent from chewing through quota or sandboxes.
//! * **`model_allowlist`** — explicit set of model names the proxy
//!   will accept; everything else is rejected at request entry. This
//!   is the same kind of static gate Claude Code's managed-settings
//!   layer applies, but moved into config so any deployment can
//!   enable it without a managed-settings deploy.
//!
//! ## What ships
//!
//! * Pure-data [`EnterprisePolicy`] struct + deserialiser.
//! * `check_*` methods that return `Result<(), PolicyError>`.
//! * Proxy request gates for model allowlists and token caps.
//!
//! ## Why not in `config::`
//!
//! The policy struct is policy-state, not just configuration: the
//! deny-counting for `tool_caps` is mutable and lives behind a
//! `Mutex` so multiple request threads share one counter. Keeping it
//! in `services::policy` mirrors `services::auto_compactor` — same
//! pattern, different concern.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Mutex, MutexGuard};
use thiserror::Error;
use tracing::error;

/// Policy-related errors surfaced to call sites.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// The requested model is not in the configured allowlist.
    #[error("model `{model}` is not in the enterprise allowlist")]
    ModelDenied {
        /// The model the caller asked for.
        model: String,
    },
    /// Estimated tokens exceed the configured per-request cap.
    #[error("request exceeds policy token cap: {estimated} > {cap} (per-{scope})")]
    TokenCapExceeded {
        /// Estimated request size.
        estimated: usize,
        /// Configured ceiling.
        cap: usize,
        /// `"request"` or `"session"`.
        scope: &'static str,
    },
    /// A tool has been called more times than its cap allows in this
    /// session.
    #[error("tool `{tool}` exceeded per-session cap of {cap}; consumed={consumed}")]
    ToolCapExceeded {
        /// Canonical tool name.
        tool: String,
        /// Configured ceiling.
        cap: usize,
        /// How many invocations have already been allowed.
        consumed: usize,
    },
}

/// Per-tool invocation cap configuration.
///
/// Map keys are canonical tool names (`"bash"`, `"edit_file"`, etc.);
/// values are the maximum invocations allowed per session.
pub type ToolCaps = HashMap<String, usize>;

/// Operator-facing enterprise policy block.
///
/// Loaded from YAML under `policy:` in the project config. All fields
/// are optional; absent fields disable that policy axis.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnterprisePolicy {
    /// Hard ceiling on tokens per request. `None` disables this check.
    #[serde(default)]
    pub max_request_tokens: Option<usize>,
    /// Hard ceiling on projected tokens per session.
    ///
    /// The enforced value is:
    /// `cumulative_session_tokens + estimated_input_tokens + output_token_budget`.
    /// `output_token_budget` is the request's `max_tokens` when set, otherwise
    /// `OpenClaudia`'s default output budget. `None` disables this check.
    #[serde(default)]
    pub max_session_tokens: Option<usize>,
    /// Per-tool invocation caps. Tools not present in the map are
    /// uncapped.
    #[serde(default)]
    pub tool_caps: ToolCaps,
    /// Model allowlist. When non-empty, only listed models are accepted.
    #[serde(default)]
    pub model_allowlist: HashSet<String>,
}

/// Decision returned by [`EnterprisePolicy::evaluate_tool_call`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Allow the call. Caller MUST follow up with a matching
    /// [`EnterprisePolicy::record_tool_invocation`] to keep the counter
    /// in sync (separated so a dry-run check doesn't consume budget).
    Allow,
    /// Deny the call — the cap is exhausted for this session.
    Deny,
}

/// Input required to check an outbound provider request against the
/// enterprise request policy.
#[derive(Debug, Clone, Copy)]
pub struct ProviderRequestPolicyInput<'a> {
    /// Model that will be sent to the provider.
    pub model: &'a str,
    /// Estimated input/context tokens for this request.
    pub estimated_input_tokens: usize,
    /// Maximum output token budget requested from the provider.
    pub output_token_budget: usize,
    /// Cumulative tokens already recorded for the current session.
    pub cumulative_session_tokens: u64,
}

impl<'a> ProviderRequestPolicyInput<'a> {
    /// Build input for request paths that use `OpenClaudia`'s default output
    /// token budget when no explicit `max_tokens` is present.
    #[must_use]
    pub fn new(
        model: &'a str,
        estimated_input_tokens: usize,
        max_tokens: Option<u32>,
        cumulative_session_tokens: u64,
    ) -> Self {
        Self {
            model,
            estimated_input_tokens,
            output_token_budget: request_output_token_budget(max_tokens),
            cumulative_session_tokens,
        }
    }
}

/// Shared request policy gate for provider-bound calls.
pub struct ProviderRequestPolicy<'a> {
    policy: &'a EnterprisePolicy,
}

impl<'a> ProviderRequestPolicy<'a> {
    /// Create a request policy gate from a read-only policy snapshot.
    #[must_use]
    pub const fn new(policy: &'a EnterprisePolicy) -> Self {
        Self { policy }
    }

    /// Check model allowlist, per-request token cap, and projected
    /// per-session token cap using the same ordering for every entrypoint.
    ///
    /// # Errors
    ///
    /// Returns the first policy error encountered.
    pub fn check(&self, input: ProviderRequestPolicyInput<'_>) -> Result<(), PolicyError> {
        self.policy.check_model(input.model)?;
        self.policy
            .check_request_tokens(input.estimated_input_tokens)?;
        self.policy
            .check_session_tokens(projected_session_policy_tokens(
                input.cumulative_session_tokens,
                input.estimated_input_tokens,
                input.output_token_budget,
            ))
    }
}

/// Shared tool policy gate for paths that already own a policy enforcer and
/// session id.
pub struct ToolExecutionPolicy<'a> {
    enforcer: Option<&'a PolicyEnforcer>,
    session_id: Option<&'a str>,
}

impl<'a> ToolExecutionPolicy<'a> {
    /// Build a tool policy gate. Passing `None` for either value keeps the
    /// historical no-policy behavior for legacy/library callers that have not
    /// been wired to a session-scoped policy enforcer yet.
    #[must_use]
    pub const fn new(enforcer: Option<&'a PolicyEnforcer>, session_id: Option<&'a str>) -> Self {
        Self {
            enforcer,
            session_id,
        }
    }

    /// Dry-run check for a tool invocation when both policy state and a
    /// session id are available. Otherwise this is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::ToolCapExceeded`] when the configured cap has
    /// already been consumed for the session.
    pub fn check_tool(&self, tool: &str) -> Result<(), PolicyError> {
        if let (Some(enforcer), Some(session_id)) = (self.enforcer, self.session_id) {
            enforcer.check_tool(session_id, tool)?;
        }
        Ok(())
    }

    /// Check and record a tool invocation when both policy state and a session
    /// id are available. Otherwise this is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::ToolCapExceeded`] when the configured cap has
    /// already been consumed for the session.
    pub fn check_and_record_tool(&self, tool: &str) -> Result<(), PolicyError> {
        if let (Some(enforcer), Some(session_id)) = (self.enforcer, self.session_id) {
            enforcer.check_and_record_tool(session_id, tool)?;
        }
        Ok(())
    }
}

/// Convert an optional request output cap into policy accounting units.
#[must_use]
pub fn request_output_token_budget(max_tokens: Option<u32>) -> usize {
    let budget = max_tokens.unwrap_or(crate::DEFAULT_MAX_TOKENS);
    usize::try_from(u64::from(budget)).unwrap_or(usize::MAX)
}

/// Saturating session projection used by every provider request policy gate.
#[must_use]
pub fn projected_session_policy_tokens(
    cumulative_total: u64,
    estimated_input: usize,
    output_budget: usize,
) -> usize {
    usize::try_from(cumulative_total)
        .unwrap_or(usize::MAX)
        .saturating_add(estimated_input)
        .saturating_add(output_budget)
}

/// Mutable counter store for per-session per-tool usage.
///
/// Lives behind a `Mutex` so concurrent request handlers share one
/// counter. Counts are by session id so a stale session does not
/// leak budget into a fresh one.
#[derive(Debug, Default)]
struct ToolCounters {
    inner: Mutex<HashMap<(String, String), usize>>, // (session_id, tool) -> count
}

impl ToolCounters {
    fn guard(&self, operation: &'static str) -> MutexGuard<'_, HashMap<(String, String), usize>> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(err) => {
                error!(operation, error = %err, "Policy tool counter lock poisoned");
                err.into_inner()
            }
        }
    }

    fn count(&self, session_id: &str, tool: &str) -> usize {
        let g = self.guard("count");
        g.get(&(session_id.to_string(), tool.to_string()))
            .copied()
            .unwrap_or(0)
    }

    fn increment(&self, session_id: &str, tool: &str) {
        let mut g = self.guard("increment");
        let count = g
            .entry((session_id.to_string(), tool.to_string()))
            .or_insert(0);
        *count = count.saturating_add(1);
        drop(g);
    }

    fn try_increment_capped(
        &self,
        session_id: &str,
        tool: &str,
        cap: Option<usize>,
    ) -> Result<(), (usize, usize)> {
        let mut g = self.guard("try_increment_capped");
        let count = g
            .entry((session_id.to_string(), tool.to_string()))
            .or_insert(0);
        let outcome = if let Some(cap) = cap.filter(|cap| *count >= *cap) {
            Err((cap, *count))
        } else {
            *count = count.saturating_add(1);
            Ok(())
        };
        drop(g);
        outcome
    }

    fn reset_session(&self, session_id: &str) {
        let mut g = self.guard("reset_session");
        g.retain(|(sid, _), _| sid != session_id);
    }
}

impl EnterprisePolicy {
    /// Check whether the model is acceptable.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::ModelDenied`] when an allowlist is configured
    /// and `model` is not on it.
    pub fn check_model(&self, model: &str) -> Result<(), PolicyError> {
        if self.model_allowlist.is_empty() {
            return Ok(());
        }
        if self.model_allowlist.contains(model) {
            return Ok(());
        }
        Err(PolicyError::ModelDenied {
            model: model.to_string(),
        })
    }

    /// Check the per-request token cap.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::TokenCapExceeded`] with `scope = "request"`
    /// when `estimated > max_request_tokens`.
    pub const fn check_request_tokens(&self, estimated: usize) -> Result<(), PolicyError> {
        if let Some(cap) = self.max_request_tokens {
            if estimated > cap {
                return Err(PolicyError::TokenCapExceeded {
                    estimated,
                    cap,
                    scope: "request",
                });
            }
        }
        Ok(())
    }

    /// Check the per-session cumulative token cap.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::TokenCapExceeded`] with `scope = "session"`
    /// when `cumulative > max_session_tokens`.
    pub const fn check_session_tokens(&self, cumulative: usize) -> Result<(), PolicyError> {
        if let Some(cap) = self.max_session_tokens {
            if cumulative > cap {
                return Err(PolicyError::TokenCapExceeded {
                    estimated: cumulative,
                    cap,
                    scope: "session",
                });
            }
        }
        Ok(())
    }
}

/// Mutable policy enforcer that owns the per-session tool counter.
///
/// Kept separate from [`EnterprisePolicy`] so the policy itself can stay
/// a pure-data `Deserialize` target. The enforcer owns the mutable
/// counter and the policy snapshot.
pub struct PolicyEnforcer {
    policy: EnterprisePolicy,
    counters: ToolCounters,
}

impl PolicyEnforcer {
    /// Build an enforcer around a parsed policy.
    #[must_use]
    pub fn new(policy: EnterprisePolicy) -> Self {
        Self {
            policy,
            counters: ToolCounters::default(),
        }
    }

    /// Borrow the underlying policy (read-only).
    #[must_use]
    pub const fn policy(&self) -> &EnterprisePolicy {
        &self.policy
    }

    /// Pure check: would invoking `tool` in `session_id` be allowed?
    ///
    /// Does NOT increment any counter — call [`Self::record_tool_invocation`]
    /// after the decision is acted on.
    #[must_use]
    pub fn evaluate_tool_call(&self, session_id: &str, tool: &str) -> PolicyDecision {
        let Some(&cap) = self.policy.tool_caps.get(tool) else {
            return PolicyDecision::Allow;
        };
        if self.counters.count(session_id, tool) >= cap {
            PolicyDecision::Deny
        } else {
            PolicyDecision::Allow
        }
    }

    /// Record a tool invocation against the per-session counter.
    pub fn record_tool_invocation(&self, session_id: &str, tool: &str) {
        self.counters.increment(session_id, tool);
    }

    /// Dry-run check for a tool invocation without consuming the cap.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::ToolCapExceeded`] when the cap is already hit.
    pub fn check_tool(&self, session_id: &str, tool: &str) -> Result<(), PolicyError> {
        let consumed = self.counters.count(session_id, tool);
        if let Some(&cap) = self.policy.tool_caps.get(tool) {
            if consumed >= cap {
                return Err(PolicyError::ToolCapExceeded {
                    tool: tool.to_string(),
                    cap,
                    consumed,
                });
            }
        }
        Ok(())
    }

    /// Combined check + record. Used when a caller does not care about
    /// the dry-run distinction.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::ToolCapExceeded`] when the cap is hit.
    pub fn check_and_record_tool(&self, session_id: &str, tool: &str) -> Result<(), PolicyError> {
        let cap = self.policy.tool_caps.get(tool).copied();
        self.counters
            .try_increment_capped(session_id, tool, cap)
            .map_err(|(cap, consumed)| PolicyError::ToolCapExceeded {
                tool: tool.to_string(),
                cap,
                consumed,
            })
    }

    /// Reset every counter associated with `session_id`. Called when a
    /// session ends so a long-running daemon does not accumulate
    /// per-session entries indefinitely.
    pub fn reset_session(&self, session_id: &str) {
        self.counters.reset_session(session_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_allowlist_lets_every_model_through() {
        let p = EnterprisePolicy::default();
        assert!(p.check_model("any-model").is_ok());
    }

    #[test]
    fn populated_allowlist_rejects_unknown_models() {
        let mut p = EnterprisePolicy::default();
        p.model_allowlist.insert("claude-sonnet-4-5".to_string());
        assert!(p.check_model("claude-sonnet-4-5").is_ok());
        let err = p.check_model("gpt-4").unwrap_err();
        assert!(matches!(err, PolicyError::ModelDenied { .. }));
    }

    #[test]
    fn request_token_cap_enforced() {
        let p = EnterprisePolicy {
            max_request_tokens: Some(100),
            ..Default::default()
        };
        assert!(p.check_request_tokens(50).is_ok());
        assert!(p.check_request_tokens(100).is_ok());
        let err = p.check_request_tokens(101).unwrap_err();
        match err {
            PolicyError::TokenCapExceeded { scope, .. } => assert_eq!(scope, "request"),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn session_token_cap_enforced() {
        let p = EnterprisePolicy {
            max_session_tokens: Some(1000),
            ..Default::default()
        };
        assert!(p.check_session_tokens(999).is_ok());
        let err = p.check_session_tokens(1001).unwrap_err();
        match err {
            PolicyError::TokenCapExceeded { scope, .. } => assert_eq!(scope, "session"),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn tool_caps_block_after_n_invocations() {
        let mut caps = ToolCaps::new();
        caps.insert("bash".to_string(), 2);
        let p = EnterprisePolicy {
            tool_caps: caps,
            ..Default::default()
        };
        let enforcer = PolicyEnforcer::new(p);

        assert_eq!(
            enforcer.evaluate_tool_call("s1", "bash"),
            PolicyDecision::Allow
        );
        enforcer.record_tool_invocation("s1", "bash");
        assert_eq!(
            enforcer.evaluate_tool_call("s1", "bash"),
            PolicyDecision::Allow
        );
        enforcer.record_tool_invocation("s1", "bash");
        assert_eq!(
            enforcer.evaluate_tool_call("s1", "bash"),
            PolicyDecision::Deny
        );

        // Different session has its own counter.
        assert_eq!(
            enforcer.evaluate_tool_call("s2", "bash"),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn check_and_record_combines_predicate_and_counter() {
        let mut caps = ToolCaps::new();
        caps.insert("edit_file".to_string(), 1);
        let enforcer = PolicyEnforcer::new(EnterprisePolicy {
            tool_caps: caps,
            ..Default::default()
        });
        assert!(enforcer.check_and_record_tool("s", "edit_file").is_ok());
        let err = enforcer
            .check_and_record_tool("s", "edit_file")
            .unwrap_err();
        assert!(matches!(err, PolicyError::ToolCapExceeded { .. }));
    }

    #[test]
    fn reset_session_drops_per_session_counts() {
        let mut caps = ToolCaps::new();
        caps.insert("bash".to_string(), 1);
        let enforcer = PolicyEnforcer::new(EnterprisePolicy {
            tool_caps: caps,
            ..Default::default()
        });
        enforcer.record_tool_invocation("s", "bash");
        assert_eq!(
            enforcer.evaluate_tool_call("s", "bash"),
            PolicyDecision::Deny
        );
        enforcer.reset_session("s");
        assert_eq!(
            enforcer.evaluate_tool_call("s", "bash"),
            PolicyDecision::Allow
        );
    }

    #[test]
    fn policy_parses_from_yaml() {
        let yaml = r"
max_request_tokens: 10000
max_session_tokens: 100000
tool_caps:
  bash: 20
  edit_file: 100
model_allowlist:
  - claude-sonnet-4-5
  - gpt-4
";
        let p: EnterprisePolicy = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(p.max_request_tokens, Some(10_000));
        assert_eq!(p.max_session_tokens, Some(100_000));
        assert_eq!(p.tool_caps.get("bash"), Some(&20));
        assert!(p.model_allowlist.contains("gpt-4"));
    }

    #[test]
    fn provider_request_policy_checks_model_and_token_projection() {
        let mut policy = EnterprisePolicy {
            max_request_tokens: Some(100),
            max_session_tokens: Some(150),
            ..Default::default()
        };
        policy.model_allowlist.insert("allowed-model".to_string());
        let gate = ProviderRequestPolicy::new(&policy);

        gate.check(ProviderRequestPolicyInput {
            model: "allowed-model",
            estimated_input_tokens: 40,
            output_token_budget: 50,
            cumulative_session_tokens: 60,
        })
        .expect("60 + 40 + 50 should be accepted at the cap");

        let denied_model = gate
            .check(ProviderRequestPolicyInput::new(
                "denied-model",
                40,
                Some(50),
                60,
            ))
            .unwrap_err();
        assert!(matches!(denied_model, PolicyError::ModelDenied { .. }));

        let denied_request = gate
            .check(ProviderRequestPolicyInput::new(
                "allowed-model",
                101,
                Some(0),
                0,
            ))
            .unwrap_err();
        assert!(matches!(
            denied_request,
            PolicyError::TokenCapExceeded {
                scope: "request",
                ..
            }
        ));

        let denied_session = gate
            .check(ProviderRequestPolicyInput::new(
                "allowed-model",
                50,
                Some(50),
                51,
            ))
            .unwrap_err();
        assert!(matches!(
            denied_session,
            PolicyError::TokenCapExceeded {
                scope: "session",
                ..
            }
        ));
    }

    #[test]
    fn tool_execution_policy_noops_without_policy_state() {
        let gate = ToolExecutionPolicy::new(None, Some("session"));
        assert!(gate.check_and_record_tool("bash").is_ok());

        let mut caps = ToolCaps::new();
        caps.insert("bash".to_string(), 0);
        let enforcer = PolicyEnforcer::new(EnterprisePolicy {
            tool_caps: caps,
            ..Default::default()
        });
        let gate = ToolExecutionPolicy::new(Some(&enforcer), None);
        assert!(gate.check_and_record_tool("bash").is_ok());
    }

    #[test]
    fn tool_execution_policy_enforces_when_session_and_enforcer_exist() {
        let mut caps = ToolCaps::new();
        caps.insert("bash".to_string(), 1);
        let enforcer = PolicyEnforcer::new(EnterprisePolicy {
            tool_caps: caps,
            ..Default::default()
        });
        let gate = ToolExecutionPolicy::new(Some(&enforcer), Some("s1"));

        assert!(gate.check_and_record_tool("bash").is_ok());
        let err = gate.check_and_record_tool("bash").unwrap_err();
        assert!(matches!(err, PolicyError::ToolCapExceeded { .. }));
    }

    #[test]
    fn tool_execution_policy_dry_run_does_not_consume_cap() {
        let mut caps = ToolCaps::new();
        caps.insert("bash".to_string(), 1);
        let enforcer = PolicyEnforcer::new(EnterprisePolicy {
            tool_caps: caps,
            ..Default::default()
        });
        let gate = ToolExecutionPolicy::new(Some(&enforcer), Some("s1"));

        assert!(gate.check_tool("bash").is_ok());
        assert!(gate.check_tool("bash").is_ok());
        assert!(gate.check_and_record_tool("bash").is_ok());
        let err = gate.check_tool("bash").unwrap_err();
        assert!(matches!(err, PolicyError::ToolCapExceeded { .. }));
    }

    #[test]
    fn concurrent_tool_cap_reservation_is_atomic() {
        let mut caps = ToolCaps::new();
        caps.insert("bash".to_string(), 1);
        let enforcer = std::sync::Arc::new(PolicyEnforcer::new(EnterprisePolicy {
            tool_caps: caps,
            ..Default::default()
        }));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let enforcer = std::sync::Arc::clone(&enforcer);
            let barrier = std::sync::Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                enforcer.check_and_record_tool("shared", "bash").is_ok()
            }));
        }

        let allowed = workers
            .into_iter()
            .map(|worker| worker.join().expect("policy worker"))
            .filter(|allowed| *allowed)
            .count();
        assert_eq!(allowed, 1, "exactly one caller may reserve a cap of one");
    }
}
