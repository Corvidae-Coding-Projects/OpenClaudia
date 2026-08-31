//! `AutoCompactor` — extracted "should-I-compact?" service (crosslink #632).
//!
//! Before this split, every call site that wanted to "compact if needed"
//! had to:
//! 1. Build a `ContextCompactor`.
//! 2. Call `analyze` or `compact` directly and inspect the result.
//! 3. Decide whether to keep the result or roll back.
//!
//! That mixed two responsibilities: the *policy* ("when do I compact?") and
//! the *mechanism* ("how do I compact?"). `AutoCompactor` is the policy
//! seam; `ContextCompactor` stays the mechanism. The autoCompact hook from
//! `compaction.rs`'s pre-existing pipeline is now reachable through this
//! service without callers having to know how the underlying analyzer
//! works.
//!
//! ## Design
//!
//! * Wraps a [`ContextCompactor`] (owned, not borrowed — the service is
//!   `Clone`-cheap because the inner compactor is small).
//! * `should_compact` is the pure predicate.
//! * `auto_compact` is the convenience "decide + act" that returns
//!   `Ok(None)` when no compaction was needed and
//!   `Ok(Some(CompactionResult))` when it ran.
//! * `auto_microcompact` is the same in the partial-budget direction —
//!   uses [`ContextCompactor::microcompact`] from crosslink #634.
//!
//! ## Why a service and not just a fn
//!
//! The proxy constructs this typed owner per request because model-specific
//! compaction overrides do not fit a shared global registry. Its production
//! disposition is recorded in `services::lifecycle_service_catalog`; keeping
//! the dependency explicit avoids hiding request authority in a service
//! locator.

use std::sync::Arc;

use crate::compaction::{
    CompactionError, CompactionResult, ContextCompactor, RequestTokenMeasurement,
};
use crate::hooks::HookEngine;
use crate::memory::MemoryDb;
use crate::proxy::ChatCompletionRequest;

/// Threshold policy for "should this request be compacted?"
///
/// `Auto` defers to the underlying compactor's analyzer (the legacy
/// behaviour). `AlwaysOverBudget` is the strict variant — compact any
/// time the request is at or above `max_context_tokens`, even if the
/// analyzer's preserve-recent window would normally suppress it. The
/// latter is useful for the eager autoCompact hook.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum AutoCompactPolicy {
    /// Use [`ContextCompactor::needs_compaction`] verbatim.
    #[default]
    Auto,
    /// Trigger when `estimate_request_tokens(request) >= max_context_tokens`.
    AlwaysOverBudget,
}

/// Decides when to invoke compaction (crosslink #632).
#[derive(Clone)]
pub struct AutoCompactor {
    compactor: ContextCompactor,
    policy: AutoCompactPolicy,
}

impl AutoCompactor {
    /// Build an `AutoCompactor` around an existing compactor.
    #[must_use]
    pub const fn new(compactor: ContextCompactor, policy: AutoCompactPolicy) -> Self {
        Self { compactor, policy }
    }

    /// Default policy: defer to the compactor's analyzer.
    #[must_use]
    pub const fn auto(compactor: ContextCompactor) -> Self {
        Self::new(compactor, AutoCompactPolicy::Auto)
    }

    /// Borrow the underlying compactor — exposed so call sites that already
    /// have a configured compactor and need the analyzer (e.g. for a
    /// dry-run UI hint) don't need to rebuild one.
    #[must_use]
    pub const fn compactor(&self) -> &ContextCompactor {
        &self.compactor
    }

    /// Pure predicate: should this request be compacted under the current
    /// policy?
    #[must_use]
    pub fn should_compact(
        &self,
        request: &ChatCompletionRequest,
        measurement: Option<RequestTokenMeasurement>,
    ) -> bool {
        match self.policy {
            AutoCompactPolicy::Auto => self.compactor.needs_compaction(request, measurement),
            AutoCompactPolicy::AlwaysOverBudget => {
                let analysis = self
                    .compactor
                    .analyze_with_measurement(request, measurement);
                analysis.current_tokens >= analysis.max_tokens
            }
        }
    }

    /// Decide + act. Returns `Ok(None)` when nothing was needed.
    ///
    /// # Errors
    ///
    /// Propagates `CompactionError::HookBlocked` / `Failed` from the
    /// underlying compactor.
    pub async fn auto_compact(
        &self,
        request: &mut ChatCompletionRequest,
        measurement: Option<RequestTokenMeasurement>,
        hook_engine: Option<&HookEngine>,
        run_context: &std::sync::Arc<crate::tools::ToolRunContext>,
        session_id: Option<&str>,
        memory_db: Option<Arc<MemoryDb>>,
    ) -> Result<Option<CompactionResult>, CompactionError> {
        if !self.should_compact(request, measurement) {
            return Ok(None);
        }
        let result = self
            .compactor
            .compact_with_measurement(
                request,
                hook_engine,
                run_context,
                session_id,
                measurement,
                memory_db,
            )
            .await?;
        Ok(Some(result))
    }

    /// Decide + microcompact. Returns `Ok(None)` when nothing was needed.
    ///
    /// # Errors
    ///
    /// Propagates `CompactionError::HookBlocked` / `Failed` from
    /// [`ContextCompactor::microcompact`].
    pub async fn auto_microcompact(
        &self,
        request: &mut ChatCompletionRequest,
        target_tokens: usize,
        hook_engine: Option<&HookEngine>,
        run_context: &std::sync::Arc<crate::tools::ToolRunContext>,
        session_id: Option<&str>,
        memory_db: Option<Arc<MemoryDb>>,
    ) -> Result<Option<CompactionResult>, CompactionError> {
        if !self.should_compact(request, None) {
            return Ok(None);
        }
        let result = self
            .compactor
            .microcompact(
                request,
                target_tokens,
                hook_engine,
                run_context,
                session_id,
                memory_db,
            )
            .await?;
        Ok(Some(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compaction::CompactionConfig;
    use crate::proxy::{ChatMessage, MessageContent};
    use std::collections::HashMap;

    fn test_run() -> &'static std::sync::Arc<crate::tools::ToolRunContext> {
        crate::tools::security::test_run_context()
    }

    fn small_request() -> ChatCompletionRequest {
        ChatCompletionRequest {
            model: "claude-sonnet-4-5".to_string(),
            messages: vec![ChatMessage {
                role: "user".to_string(),
                content: MessageContent::Text("hello".to_string()),
                name: None,
                tool_calls: None,
                tool_call_id: None,
                extra: std::collections::HashMap::new(),
            }],
            temperature: None,
            max_tokens: None,
            stream: None,
            tools: None,
            tool_choice: None,
            extra: HashMap::new(),
        }
    }

    #[test]
    fn auto_policy_skips_small_request() {
        let compactor = ContextCompactor::new(CompactionConfig::default());
        let ac = AutoCompactor::auto(compactor);
        assert!(!ac.should_compact(&small_request(), None));
    }

    #[test]
    fn always_over_budget_with_low_cap_triggers() {
        let cfg = CompactionConfig {
            max_context_tokens: 1, // force "always over"
            ..CompactionConfig::default()
        };
        let compactor = ContextCompactor::new(cfg);
        let ac = AutoCompactor::new(compactor, AutoCompactPolicy::AlwaysOverBudget);
        assert!(ac.should_compact(&small_request(), None));
    }

    #[tokio::test]
    async fn auto_compact_returns_none_when_not_needed() {
        let compactor = ContextCompactor::new(CompactionConfig::default());
        let ac = AutoCompactor::auto(compactor);
        let mut req = small_request();
        let result = ac
            .auto_compact(&mut req, None, None, test_run(), None, None)
            .await
            .unwrap();
        assert!(result.is_none());
    }
}
