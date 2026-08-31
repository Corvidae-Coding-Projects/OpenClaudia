use serde::Deserialize;
use std::path::PathBuf;

use super::default_true;

/// Session configuration
#[derive(Debug, Deserialize, Clone)]
pub struct SessionConfig {
    #[serde(default = "default_timeout_minutes")]
    pub timeout_minutes: u64,
    #[serde(default = "default_persist_path")]
    pub persist_path: PathBuf,
    /// Maximum agentic turns (API round-trips with tool execution) per user message.
    /// 0 means unlimited (like Claude Code). Default: 0 (unlimited).
    #[serde(default)]
    pub max_turns: u32,
    /// Token tracking configuration
    #[serde(default)]
    pub token_tracking: TokenTrackingConfig,
    /// Canonical hard limits shared by the run and every derived child.
    #[serde(default)]
    pub run_budget: RunBudgetConfig,
    /// Legacy token stop-condition syntax, projected into `run_budget` before
    /// the run starts so it is a true hard cap rather than a post-call check.
    #[serde(default)]
    pub stop_conditions: super::StopConditionsConfig,
}

/// Operator-visible hard limits for one canonical run tree.
#[derive(Debug, Deserialize, Clone)]
pub struct RunBudgetConfig {
    #[serde(default = "default_input_tokens")]
    pub input_tokens: u64,
    #[serde(default = "default_output_tokens")]
    pub output_tokens: u64,
    #[serde(default = "default_total_tokens")]
    pub total_tokens: u64,
    #[serde(default = "default_turns")]
    pub turns: u64,
    #[serde(default = "default_provider_calls")]
    pub provider_calls: u64,
    #[serde(default = "default_tool_calls")]
    pub tool_calls: u64,
    #[serde(default = "default_elapsed_millis")]
    pub elapsed_millis: u64,
    #[serde(default = "default_retries")]
    pub retries: u64,
    #[serde(default = "default_concurrent_calls")]
    pub concurrent_calls: u64,
    #[serde(default = "default_child_runs")]
    pub child_runs: u64,
    #[serde(default = "default_cost_microusd")]
    pub cost_microusd: u64,
    #[serde(default = "default_trace_bytes")]
    pub trace_bytes: u64,
}

impl RunBudgetConfig {
    /// Resolve compatibility settings into one immutable runtime contract.
    /// Existing `session.max_turns`, timeout, and per-response output settings
    /// can only narrow this budget; repository data cannot widen it.
    #[must_use]
    pub fn limits_for_session(&self, session: &SessionConfig) -> crate::runtime::BudgetLimits {
        let timeout_millis = session.timeout_minutes.saturating_mul(60_000);
        let turns = if session.max_turns == 0 {
            self.turns
        } else {
            self.turns.min(u64::from(session.max_turns))
        };
        let input_tokens = session
            .stop_conditions
            .max_total_input_tokens
            .map_or(self.input_tokens, |cap| self.input_tokens.min(cap));
        let output_tokens = session
            .stop_conditions
            .max_total_output_tokens
            .map_or(self.output_tokens, |cap| self.output_tokens.min(cap));
        let total_tokens = session
            .stop_conditions
            .max_total_tokens
            .map_or(self.total_tokens, |cap| self.total_tokens.min(cap));
        crate::runtime::BudgetLimits {
            input_tokens,
            output_tokens,
            total_tokens,
            turns,
            provider_calls: self.provider_calls,
            tool_calls: self.tool_calls,
            elapsed_millis: self.elapsed_millis.min(timeout_millis),
            retries: self.retries,
            concurrent_calls: self.concurrent_calls,
            child_runs: self.child_runs,
            cost_microusd: self.cost_microusd,
            trace_bytes: self.trace_bytes,
        }
    }
}

impl Default for RunBudgetConfig {
    fn default() -> Self {
        Self {
            input_tokens: default_input_tokens(),
            output_tokens: default_output_tokens(),
            total_tokens: default_total_tokens(),
            turns: default_turns(),
            provider_calls: default_provider_calls(),
            tool_calls: default_tool_calls(),
            elapsed_millis: default_elapsed_millis(),
            retries: default_retries(),
            concurrent_calls: default_concurrent_calls(),
            child_runs: default_child_runs(),
            cost_microusd: default_cost_microusd(),
            trace_bytes: default_trace_bytes(),
        }
    }
}

const fn default_input_tokens() -> u64 {
    1_000_000
}

const fn default_output_tokens() -> u64 {
    1_000_000
}

const fn default_total_tokens() -> u64 {
    1_500_000
}

const fn default_turns() -> u64 {
    1_000
}

const fn default_provider_calls() -> u64 {
    1_000
}

const fn default_tool_calls() -> u64 {
    10_000
}

const fn default_elapsed_millis() -> u64 {
    86_400_000
}

const fn default_retries() -> u64 {
    100
}

const fn default_concurrent_calls() -> u64 {
    64
}

const fn default_child_runs() -> u64 {
    64
}

const fn default_cost_microusd() -> u64 {
    1_000_000_000
}

const fn default_trace_bytes() -> u64 {
    64 * 1024 * 1024
}

/// Token tracking and budget configuration
#[derive(Debug, Deserialize, Clone)]
pub struct TokenTrackingConfig {
    /// Enable per-turn token tracking (default: true)
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Log token usage at info level each turn (default: true)
    #[serde(default = "default_true")]
    pub log_usage: bool,
    /// Warn when estimated input exceeds this percentage of context window (0.0-1.0)
    /// Default: 0.75 (warn at 75% of context window)
    #[serde(default = "default_warn_threshold")]
    pub warn_threshold: f32,
    /// Maximum output tokens per response (0 = provider default)
    #[serde(default)]
    pub max_output_tokens: u32,
}

const fn default_warn_threshold() -> f32 {
    0.75
}

impl Default for TokenTrackingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            log_usage: true,
            warn_threshold: 0.75,
            max_output_tokens: 0,
        }
    }
}

const fn default_timeout_minutes() -> u64 {
    30
}

fn default_persist_path() -> PathBuf {
    PathBuf::from(".openclaudia/session")
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            timeout_minutes: default_timeout_minutes(),
            persist_path: default_persist_path(),
            max_turns: 0,
            token_tracking: TokenTrackingConfig::default(),
            run_budget: RunBudgetConfig::default(),
            stop_conditions: super::StopConditionsConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_config_default() {
        let config = SessionConfig::default();
        assert_eq!(config.timeout_minutes, 30);
        assert_eq!(config.persist_path, PathBuf::from(".openclaudia/session"));
    }

    #[test]
    fn test_session_config_from_json() {
        let json = r#"{
            "timeout_minutes": 60,
            "persist_path": "/custom/path"
        }"#;

        let config: SessionConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.timeout_minutes, 60);
        assert_eq!(config.persist_path, PathBuf::from("/custom/path"));
    }

    #[test]
    fn legacy_stop_conditions_narrow_the_preflight_budget() {
        let session: SessionConfig = serde_json::from_value(serde_json::json!({
            "stop_conditions": {
                "max_total_input_tokens": 10,
                "max_total_output_tokens": 20,
                "max_total_tokens": 25
            }
        }))
        .expect("session config");
        let limits = session.run_budget.limits_for_session(&session);
        assert_eq!(limits.input_tokens, 10);
        assert_eq!(limits.output_tokens, 20);
        assert_eq!(limits.total_tokens, 25);
    }
}
