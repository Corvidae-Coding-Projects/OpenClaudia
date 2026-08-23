//! Model pricing and cost calculation.
//!
//! Pricing is looked up by **ordered prefix match** against
//! [`PRICING_TABLE`].  The table is walked top-to-bottom and the first
//! entry whose `prefix` matches the (lower-cased) model id wins.  Order is
//! therefore **load-bearing**: more specific prefixes must precede the
//! shorter prefixes that would otherwise shadow them (e.g. `"gpt-5.2"`
//! must come before `"gpt-5"`, and `"gemini-2.0-flash"` before
//! `"gemini-2"`).  This ordering invariant is enforced at test time by
//! [`tests::ordering_no_entry_is_prefix_of_earlier`].
//!
//! Unknown models return [`PricingError::UnknownModel`] and emit a
//! `tracing::warn!`; callers must handle the error explicitly rather than
//! silently displaying `$0.00`.
//!
//! ## Cache-write TTL multipliers (Anthropic)
//!
//! Anthropic prompt-cache writes are billed at a multiple of the input
//! rate depending on TTL: 1.25× for the default 5-minute ephemeral cache
//! and 2.0× for the 1-hour cache.  The two multipliers are stored
//! separately on [`ModelPricing`] (`cache_write_5m_multiplier` and
//! `cache_write_1hr_multiplier`) and selected by [`CacheWriteTtl`] passed
//! to [`calculate_cost_with_ttl`].  The shorter [`calculate_cost`] entry
//! point defaults to 5 m, matching the Anthropic API default when
//! `cache_control.ttl` is omitted.
//!
//! ## Fast-mode pricing tier (#642)
//!
//! Claude Opus fast mode bills at a premium rate that varies by model:
//! Opus 4.6 / 4.7 use $30 input / $150 output per `MTok`, while Opus 4.8
//! uses $10 input / $50 output per `MTok`. Per-model overrides live on
//! [`ModelPricing::fast_mode_input_per_million`] /
//! [`ModelPricing::fast_mode_output_per_million`] and the
//! [`calculate_cost_fast_mode`] entry point swaps those rates in when
//! set, falling back to the standard rates when not.
//!
//! ## Unknown-model analytics flag (#646)
//!
//! When `calculate_cost` resolves an unknown model it emits a structured
//! `tracing::warn!(target = "openclaudia::analytics", event =
//! "unknown_model_cost", ...)` and sets a thread-local flag observable
//! through [`has_unknown_model_cost`] / [`clear_unknown_model_cost`].
//! This mirrors CC's `tengu_unknown_model_cost` event and feeds the
//! "costs may be inaccurate" session warning.
//!
//! ## Per-request `cost_tracked` event (#649)
//!
//! Every successful cost calculation emits a structured
//! `tracing::info!(target = "openclaudia::analytics", event =
//! "cost_tracked", ...)` carrying model, token buckets, the TTL bucket,
//! fast-mode flag, and the computed `cost_usd`.  Mirrors CC's OTEL
//! `getCostCounter().add()` /
//! `getTokenCounter().add()` per-request emission (see
//! `cost-tracker.ts:291-302`).

use super::state::{TokenUsage, UsageExtras};
use std::cell::Cell;
use thiserror::Error;

/// Fast-mode input rate for Claude Opus 4.6 / 4.7 per million tokens
/// (`COST_TIER_30_150`) — see #642.
pub const FAST_MODE_INPUT_PER_MILLION: f64 = 30.0;

/// Fast-mode output rate for Claude Opus 4.6 / 4.7 per million tokens
/// (`COST_TIER_30_150`) — see #642.
pub const FAST_MODE_OUTPUT_PER_MILLION: f64 = 150.0;

/// Fast-mode input rate for Claude Opus 4.8 per million tokens.
pub const OPUS_4_8_FAST_MODE_INPUT_PER_MILLION: f64 = 10.0;

/// Fast-mode output rate for Claude Opus 4.8 per million tokens.
pub const OPUS_4_8_FAST_MODE_OUTPUT_PER_MILLION: f64 = 50.0;

/// `OpenAI` `GPT-5.5` / `GPT-5.4` long-context pricing threshold.
///
/// Official pricing applies the long-context rate to the whole request
/// when prompt input exceeds 272K tokens.
pub const OPENAI_LONG_CONTEXT_THRESHOLD_TOKENS: u64 = 272_000;

/// Google Gemini Pro-family long-context pricing threshold.
///
/// Google applies the higher long-context rate to the whole request when
/// prompt input exceeds 200K tokens.
pub const GOOGLE_LONG_CONTEXT_THRESHOLD_TOKENS: u64 = 200_000;

/// Errors returned by [`calculate_cost`] / [`calculate_cost_with_ttl`].
#[derive(Debug, Error, PartialEq, Eq, Clone)]
pub enum PricingError {
    /// The model identifier did not match any prefix in [`PRICING_TABLE`].
    ///
    /// The wrapped string is the original model id (case preserved) so
    /// the caller can log or surface it verbatim to the user.
    #[error("no pricing entry matches model `{0}`")]
    UnknownModel(String),
}

/// TTL bucket for Anthropic prompt-cache write pricing.
///
/// Maps directly onto the `ttl` field of `cache_control` in the Messages
/// API: an absent / `"5m"` value selects [`CacheWriteTtl::FiveMinutes`]
/// and a `"1h"` value selects [`CacheWriteTtl::OneHour`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CacheWriteTtl {
    /// Default ephemeral cache — billed at the 5 m multiplier (1.25× input
    /// for Anthropic).
    #[default]
    FiveMinutes,
    /// Long-lived cache — billed at the 1 h multiplier (2.0× input for
    /// Anthropic).
    OneHour,
}

/// Pricing data for a model (per million tokens).
///
/// Cache multipliers are applied against the effective input rate selected
/// by the cost calculator; see module docs for the cache-write TTL split.
#[derive(Debug, Clone, Copy)]
pub struct ModelPricing {
    /// Cost per million input tokens (USD).
    pub input_per_million: f64,
    /// Cost per million output tokens (USD).
    pub output_per_million: f64,
    /// Multiplier applied to the active input rate for prompt-cache reads.
    /// Industry-standard 0.1× for Anthropic; the same ratio is re-used as
    /// a conservative default for providers without explicit cache-read
    /// pricing.
    pub cache_read_multiplier: f64,
    /// Multiplier applied to the active input rate for prompt-cache writes
    /// with the default 5 m ephemeral TTL.  1.25× for Anthropic.
    pub cache_write_5m_multiplier: f64,
    /// Multiplier applied to the active input rate for prompt-cache writes
    /// with the 1 h TTL.  2.0× for Anthropic.  Providers that don't expose
    /// a 1 h tier mirror the 5 m multiplier here so the selection logic
    /// stays uniform.
    pub cache_write_1hr_multiplier: f64,
    /// Per-million-token input rate to bill when the request is issued
    /// in fast mode (`/fast`).  `None` for models without a fast tier;
    /// [`calculate_cost_fast_mode`] then falls back to
    /// [`Self::input_per_million`].  Populated for Claude Opus models
    /// with a documented fast-mode tier (see #642).
    pub fast_mode_input_per_million: Option<f64>,
    /// Per-million-token output rate to bill in fast mode.  Same
    /// fallback rules as [`Self::fast_mode_input_per_million`].
    pub fast_mode_output_per_million: Option<f64>,
    /// Prompt-token threshold above which a provider bills a separate
    /// long-context tier for the whole request.
    pub long_context_threshold_tokens: Option<u64>,
    /// Per-million-token input rate for the long-context tier.
    pub long_context_input_per_million: Option<f64>,
    /// Per-million-token output rate for the long-context tier.
    pub long_context_output_per_million: Option<f64>,
}

impl ModelPricing {
    /// Anthropic-style pricing: 0.1× cache-read, 1.25× cache-write-5m, 2.0× cache-write-1h.
    ///
    /// No fast-mode override by default; use
    /// [`Self::anthropic_with_fast_mode`] for the Opus 4.6+ tier.
    const fn anthropic(input_per_million: f64, output_per_million: f64) -> Self {
        Self {
            input_per_million,
            output_per_million,
            cache_read_multiplier: 0.1,
            cache_write_5m_multiplier: 1.25,
            cache_write_1hr_multiplier: 2.0,
            fast_mode_input_per_million: None,
            fast_mode_output_per_million: None,
            long_context_threshold_tokens: None,
            long_context_input_per_million: None,
            long_context_output_per_million: None,
        }
    }

    /// Anthropic pricing with an explicit fast-mode tier (#642).
    ///
    /// Used for Claude Opus models with a separate fast-mode rate sheet.
    const fn anthropic_with_fast_mode(
        input_per_million: f64,
        output_per_million: f64,
        fast_input: f64,
        fast_output: f64,
    ) -> Self {
        Self {
            input_per_million,
            output_per_million,
            cache_read_multiplier: 0.1,
            cache_write_5m_multiplier: 1.25,
            cache_write_1hr_multiplier: 2.0,
            fast_mode_input_per_million: Some(fast_input),
            fast_mode_output_per_million: Some(fast_output),
            long_context_threshold_tokens: None,
            long_context_input_per_million: None,
            long_context_output_per_million: None,
        }
    }

    /// Non-Anthropic provider pricing: keep the 0.1× / 1.25× ratios that
    /// the previous fixed-ratio code applied uniformly across providers,
    /// and mirror the 5 m multiplier into the 1 h slot since these
    /// providers do not currently differentiate.  This preserves the
    /// pre-refactor cost numbers for legacy `OpenAI` rows / `Google` /
    /// `DeepSeek` / `Qwen`.
    const fn other(input_per_million: f64, output_per_million: f64) -> Self {
        Self {
            input_per_million,
            output_per_million,
            cache_read_multiplier: 0.1,
            cache_write_5m_multiplier: 1.25,
            cache_write_1hr_multiplier: 1.25,
            fast_mode_input_per_million: None,
            fast_mode_output_per_million: None,
            long_context_threshold_tokens: None,
            long_context_input_per_million: None,
            long_context_output_per_million: None,
        }
    }

    /// Non-Anthropic pricing with explicit cache rates. Use this for
    /// providers that publish cache-hit prices as a fraction of their
    /// cache-miss input price.
    const fn other_with_cache(
        input_per_million: f64,
        output_per_million: f64,
        cache_read_multiplier: f64,
        cache_write_multiplier: f64,
    ) -> Self {
        Self {
            input_per_million,
            output_per_million,
            cache_read_multiplier,
            cache_write_5m_multiplier: cache_write_multiplier,
            cache_write_1hr_multiplier: cache_write_multiplier,
            fast_mode_input_per_million: None,
            fast_mode_output_per_million: None,
            long_context_threshold_tokens: None,
            long_context_input_per_million: None,
            long_context_output_per_million: None,
        }
    }

    /// `OpenAI` text pricing with optional cached-input and long-context
    /// rates. `OpenAI` cached input is cheaper, but prompt-cache writes do
    /// not have `Anthropic`'s separate write premium.
    const fn openai_long_context(
        input_per_million: f64,
        output_per_million: f64,
        cache_read_multiplier: f64,
        long_context_input_per_million: f64,
        long_context_output_per_million: f64,
    ) -> Self {
        Self {
            input_per_million,
            output_per_million,
            cache_read_multiplier,
            cache_write_5m_multiplier: 1.0,
            cache_write_1hr_multiplier: 1.0,
            fast_mode_input_per_million: None,
            fast_mode_output_per_million: None,
            long_context_threshold_tokens: Some(OPENAI_LONG_CONTEXT_THRESHOLD_TOKENS),
            long_context_input_per_million: Some(long_context_input_per_million),
            long_context_output_per_million: Some(long_context_output_per_million),
        }
    }

    /// Non-Anthropic pricing with explicit cache and long-context tiers.
    const fn other_with_cache_and_long_context(
        input_per_million: f64,
        output_per_million: f64,
        cache_read_multiplier: f64,
        cache_write_multiplier: f64,
        long_context_threshold_tokens: u64,
        long_context_input_per_million: f64,
        long_context_output_per_million: f64,
    ) -> Self {
        Self {
            input_per_million,
            output_per_million,
            cache_read_multiplier,
            cache_write_5m_multiplier: cache_write_multiplier,
            cache_write_1hr_multiplier: cache_write_multiplier,
            fast_mode_input_per_million: None,
            fast_mode_output_per_million: None,
            long_context_threshold_tokens: Some(long_context_threshold_tokens),
            long_context_input_per_million: Some(long_context_input_per_million),
            long_context_output_per_million: Some(long_context_output_per_million),
        }
    }

    /// Select the cache-write multiplier for the requested TTL.
    #[must_use]
    pub const fn cache_write_multiplier(&self, ttl: CacheWriteTtl) -> f64 {
        match ttl {
            CacheWriteTtl::FiveMinutes => self.cache_write_5m_multiplier,
            CacheWriteTtl::OneHour => self.cache_write_1hr_multiplier,
        }
    }

    /// Effective per-million input rate after applying any fast-mode
    /// override.  Returns [`Self::input_per_million`] when `fast` is
    /// false or no override is configured.
    #[must_use]
    pub const fn effective_input_per_million(&self, fast: bool) -> f64 {
        if fast {
            if let Some(rate) = self.fast_mode_input_per_million {
                return rate;
            }
        }
        self.input_per_million
    }

    /// Effective per-million output rate after applying any fast-mode
    /// override.  Returns [`Self::output_per_million`] when `fast` is
    /// false or no override is configured.
    #[must_use]
    pub const fn effective_output_per_million(&self, fast: bool) -> f64 {
        if fast {
            if let Some(rate) = self.fast_mode_output_per_million {
                return rate;
            }
        }
        self.output_per_million
    }

    const fn uses_long_context_rates(&self, usage: &TokenUsage, fast: bool) -> bool {
        if fast {
            return false;
        }
        let Some(threshold) = self.long_context_threshold_tokens else {
            return false;
        };

        usage
            .input_tokens
            .saturating_add(usage.cache_read_tokens)
            .saturating_add(usage.cache_write_tokens)
            > threshold
    }

    const fn effective_input_per_million_for_usage(&self, usage: &TokenUsage, fast: bool) -> f64 {
        if self.uses_long_context_rates(usage, fast) {
            if let Some(rate) = self.long_context_input_per_million {
                return rate;
            }
        }
        self.effective_input_per_million(fast)
    }

    const fn effective_output_per_million_for_usage(&self, usage: &TokenUsage, fast: bool) -> f64 {
        if self.uses_long_context_rates(usage, fast) {
            if let Some(rate) = self.long_context_output_per_million {
                return rate;
            }
        }
        self.effective_output_per_million(fast)
    }
}

/// Canonical pricing table — **ordered** prefix → rates.
///
/// Lookup is `model_lc.starts_with(prefix)` and the **first** matching
/// row wins, so longer / more-specific prefixes MUST appear before any
/// shorter prefix they would otherwise be shadowed by.  Compare:
///
/// * `"gpt-5.2"` precedes `"gpt-5"` — without this order `"gpt-5.2"`
///   would silently resolve as `"gpt-5"`.
/// * `"gemini-2.0-flash"` precedes `"gemini-2"` for the same reason.
/// * `"o1-mini"` precedes `"o1"`; `"o3-mini"` precedes `"o3"`.
///
/// The [`tests::ordering_no_entry_is_prefix_of_earlier`] test enforces
/// this invariant statically against the table; CI will fail if a new
/// row is inserted in the wrong slot.
pub static PRICING_TABLE: &[(&str, ModelPricing)] = &[
    // ---------------------------------------------------------------------
    // Anthropic — claude family
    //
    // `claude-opus-4-` covers the original dated 2025-05-14 Opus 4
    // release. Newer Opus 4.5+ dateless IDs have separate pricing rows
    // and MUST remain above the generic prefix.
    // ---------------------------------------------------------------------
    ("claude-fable-5", ModelPricing::anthropic(10.0, 50.0)),
    ("claude-mythos-5", ModelPricing::anthropic(10.0, 50.0)),
    ("claude-mythos-preview", ModelPricing::anthropic(10.0, 50.0)),
    ("claude-3-5-haiku", ModelPricing::anthropic(0.80, 4.0)),
    ("claude-3-5-sonnet", ModelPricing::anthropic(3.0, 15.0)),
    ("claude-3-7-sonnet", ModelPricing::anthropic(3.0, 15.0)),
    ("claude-3-haiku", ModelPricing::anthropic(0.25, 1.25)),
    ("claude-3-opus", ModelPricing::anthropic(15.0, 75.0)),
    ("claude-3-sonnet", ModelPricing::anthropic(3.0, 15.0)),
    ("claude-haiku-4", ModelPricing::anthropic(1.0, 5.0)),
    (
        "claude-opus-4-8",
        ModelPricing::anthropic_with_fast_mode(
            5.0,
            25.0,
            OPUS_4_8_FAST_MODE_INPUT_PER_MILLION,
            OPUS_4_8_FAST_MODE_OUTPUT_PER_MILLION,
        ),
    ),
    // Opus 4.6 / 4.7 carry the $30/$150 fast-mode tier. These
    // specific-suffix rows MUST precede the generic `claude-opus-4-`
    // prefix below, otherwise the ordered prefix table would resolve the
    // old Opus 4 row first and lose the fast-mode override.
    (
        "claude-opus-4-6",
        ModelPricing::anthropic_with_fast_mode(
            5.0,
            25.0,
            FAST_MODE_INPUT_PER_MILLION,
            FAST_MODE_OUTPUT_PER_MILLION,
        ),
    ),
    (
        "claude-opus-4-7",
        ModelPricing::anthropic_with_fast_mode(
            5.0,
            25.0,
            FAST_MODE_INPUT_PER_MILLION,
            FAST_MODE_OUTPUT_PER_MILLION,
        ),
    ),
    ("claude-opus-4-5", ModelPricing::anthropic(5.0, 25.0)),
    ("claude-opus-4-1", ModelPricing::anthropic(15.0, 75.0)),
    ("claude-opus-4-", ModelPricing::anthropic(15.0, 75.0)),
    ("claude-opus-4", ModelPricing::anthropic(15.0, 75.0)),
    ("claude-sonnet-4-", ModelPricing::anthropic(3.0, 15.0)),
    ("claude-sonnet-4", ModelPricing::anthropic(3.0, 15.0)),
    // `claude-code-20250219` is the OAuth-only "Claude Code" alias that
    // is billed at Sonnet 4 rates per Anthropic billing docs.
    ("claude-code-", ModelPricing::anthropic(3.0, 15.0)),
    // ---------------------------------------------------------------------
    // OpenAI
    //
    // Note the `gpt-5.5-pro` → `gpt-5.5`, `gpt-5.4-pro` → `gpt-5.4`,
    // `gpt-5.2-pro` → `gpt-5.2`, `gpt-4.1-nano` → `gpt-4.1-mini` →
    // `gpt-4.1`, and `o3-pro`/`o3-mini` → `o3` ordering: each shorter
    // prefix must follow its longer siblings or the longer ones become
    // unreachable.
    // ---------------------------------------------------------------------
    (
        "gpt-4o-mini-search-preview",
        ModelPricing::other(0.15, 0.60),
    ),
    ("gpt-4o-mini", ModelPricing::other(0.15, 0.60)),
    ("gpt-4o-search-preview", ModelPricing::other(2.5, 10.0)),
    ("gpt-4o", ModelPricing::other(2.5, 10.0)),
    ("gpt-4.5-preview", ModelPricing::other(75.0, 150.0)),
    ("gpt-4.1-nano", ModelPricing::other(0.10, 0.40)),
    ("gpt-4.1-mini", ModelPricing::other(0.40, 1.60)),
    ("gpt-4.1", ModelPricing::other(2.0, 8.0)),
    ("gpt-4-turbo", ModelPricing::other(10.0, 30.0)),
    ("gpt-4", ModelPricing::other(30.0, 60.0)),
    ("gpt-3.5-turbo", ModelPricing::other(0.50, 1.50)),
    ("chat-latest", ModelPricing::other(5.0, 30.0)),
    (
        "gpt-5.5-pro",
        ModelPricing::openai_long_context(30.0, 180.0, 1.0, 60.0, 270.0),
    ),
    (
        "gpt-5.5",
        ModelPricing::openai_long_context(5.0, 30.0, 0.1, 10.0, 45.0),
    ),
    (
        "gpt-5.4-pro",
        ModelPricing::openai_long_context(30.0, 180.0, 1.0, 60.0, 270.0),
    ),
    ("gpt-5.4-mini", ModelPricing::other(0.75, 4.50)),
    ("gpt-5.4-nano", ModelPricing::other(0.20, 1.25)),
    (
        "gpt-5.4",
        ModelPricing::openai_long_context(2.50, 15.0, 0.1, 5.0, 22.50),
    ),
    ("gpt-5.3-codex", ModelPricing::other(1.75, 14.0)),
    ("gpt-5.3-chat-latest", ModelPricing::other(1.75, 14.0)),
    ("gpt-5.2-pro", ModelPricing::other(21.0, 168.0)),
    ("gpt-5.2-codex", ModelPricing::other(1.75, 14.0)),
    ("gpt-5.2-chat-latest", ModelPricing::other(1.75, 14.0)),
    ("gpt-5.2", ModelPricing::other(1.75, 14.0)),
    ("gpt-5.1-codex-mini", ModelPricing::other(0.25, 2.0)),
    ("gpt-5.1-codex", ModelPricing::other(1.25, 10.0)),
    ("gpt-5.1-chat-latest", ModelPricing::other(1.25, 10.0)),
    ("gpt-5.1", ModelPricing::other(1.25, 10.0)),
    ("gpt-5-pro", ModelPricing::other(15.0, 120.0)),
    ("gpt-5-codex", ModelPricing::other(1.25, 10.0)),
    ("gpt-5-chat-latest", ModelPricing::other(1.25, 10.0)),
    ("gpt-5-nano", ModelPricing::other(0.05, 0.40)),
    ("gpt-5-mini", ModelPricing::other(0.25, 2.0)),
    ("gpt-5", ModelPricing::other(1.25, 10.0)),
    ("codex-mini-latest", ModelPricing::other(1.50, 6.0)),
    ("o1-pro", ModelPricing::other(150.0, 600.0)),
    ("o1-mini", ModelPricing::other(1.10, 4.40)),
    ("o1-preview", ModelPricing::other(15.0, 60.0)),
    ("o1", ModelPricing::other(15.0, 60.0)),
    ("o3-pro", ModelPricing::other(20.0, 80.0)),
    ("o3-mini", ModelPricing::other(1.10, 4.40)),
    ("o3", ModelPricing::other(2.0, 8.0)),
    ("o4-mini", ModelPricing::other(1.10, 4.40)),
    ("o4-pro", ModelPricing::other(10.0, 40.0)),
    ("o4", ModelPricing::other(10.0, 40.0)),
    // ---------------------------------------------------------------------
    // Google Gemini
    //
    // More-specific Gemini prefixes must precede shorter siblings to
    // avoid ordered-prefix shadowing. Google exposes no cache-write
    // usage counter; cache-write multipliers here are compatibility
    // fallbacks if a caller manually supplies that bucket.
    // ---------------------------------------------------------------------
    (
        "gemini-3.5-flash",
        ModelPricing::other_with_cache(1.50, 9.0, 0.1, 1.0),
    ),
    (
        "gemini-3.1-pro-preview-customtools",
        ModelPricing::other_with_cache_and_long_context(
            2.0,
            12.0,
            0.1,
            1.0,
            GOOGLE_LONG_CONTEXT_THRESHOLD_TOKENS,
            4.0,
            18.0,
        ),
    ),
    (
        "gemini-3.1-pro-preview",
        ModelPricing::other_with_cache_and_long_context(
            2.0,
            12.0,
            0.1,
            1.0,
            GOOGLE_LONG_CONTEXT_THRESHOLD_TOKENS,
            4.0,
            18.0,
        ),
    ),
    (
        "gemini-3.1-flash-lite",
        ModelPricing::other_with_cache(0.25, 1.50, 0.1, 1.0),
    ),
    (
        "gemini-3-flash-preview",
        ModelPricing::other_with_cache(0.50, 3.0, 0.1, 1.0),
    ),
    (
        "gemini-2.5-flash-lite",
        ModelPricing::other_with_cache(0.10, 0.40, 0.1, 1.0),
    ),
    (
        "gemini-2.5-flash",
        ModelPricing::other_with_cache(0.30, 2.50, 0.1, 1.0),
    ),
    (
        "gemini-2.5-pro",
        ModelPricing::other_with_cache_and_long_context(
            1.25,
            10.0,
            0.1,
            1.0,
            GOOGLE_LONG_CONTEXT_THRESHOLD_TOKENS,
            2.50,
            15.0,
        ),
    ),
    // Legacy Gemini IDs retained for historical sessions and explicit
    // caller-provided model IDs. They are not advertised in the static
    // Google model catalog.
    ("gemini-2.0-flash", ModelPricing::other(0.075, 0.30)),
    ("gemini-1.5-flash", ModelPricing::other(0.075, 0.30)),
    ("gemini-1.5-pro", ModelPricing::other(1.25, 5.0)),
    // ---------------------------------------------------------------------
    // DeepSeek
    // ---------------------------------------------------------------------
    (
        "deepseek-v4-flash",
        ModelPricing::other_with_cache(0.14, 0.28, 0.02, 1.0),
    ),
    (
        "deepseek-v4-pro",
        ModelPricing::other_with_cache(0.435, 0.87, 1.0 / 120.0, 1.0),
    ),
    // Compatibility aliases route to DeepSeek V4 Flash until their
    // announced 2026-07-24 retirement.
    (
        "deepseek-chat",
        ModelPricing::other_with_cache(0.14, 0.28, 0.02, 1.0),
    ),
    (
        "deepseek-reasoner",
        ModelPricing::other_with_cache(0.14, 0.28, 0.02, 1.0),
    ),
    ("deepseek-r1", ModelPricing::other(0.55, 2.19)),
    // ---------------------------------------------------------------------
    // Z.AI / GLM
    // ---------------------------------------------------------------------
    (
        "glm-5v-turbo",
        ModelPricing::other_with_cache(1.20, 4.0, 0.20, 1.0),
    ),
    (
        "glm-5.2",
        ModelPricing::other_with_cache(1.40, 4.40, 0.26 / 1.40, 1.0),
    ),
    (
        "glm-5.1",
        ModelPricing::other_with_cache(1.40, 4.40, 0.26 / 1.40, 1.0),
    ),
    (
        "glm-5-turbo",
        ModelPricing::other_with_cache(1.20, 4.0, 0.20, 1.0),
    ),
    (
        "glm-5",
        ModelPricing::other_with_cache(1.0, 3.20, 0.20, 1.0),
    ),
    (
        "glm-4.7-flashx",
        ModelPricing::other_with_cache(0.07, 0.40, 0.01 / 0.07, 1.0),
    ),
    ("glm-4.7-flash", ModelPricing::other(0.0, 0.0)),
    (
        "glm-4.7",
        ModelPricing::other_with_cache(0.60, 2.20, 0.11 / 0.60, 1.0),
    ),
    (
        "glm-4.6v-flashx",
        ModelPricing::other_with_cache(0.04, 0.40, 0.10, 1.0),
    ),
    ("glm-4.6v-flash", ModelPricing::other(0.0, 0.0)),
    (
        "glm-4.6v",
        ModelPricing::other_with_cache(0.30, 0.90, 0.05 / 0.30, 1.0),
    ),
    (
        "glm-4.6",
        ModelPricing::other_with_cache(0.60, 2.20, 0.11 / 0.60, 1.0),
    ),
    (
        "glm-4.5-airx",
        ModelPricing::other_with_cache(1.10, 4.50, 0.22 / 1.10, 1.0),
    ),
    (
        "glm-4.5-air",
        ModelPricing::other_with_cache(0.20, 1.10, 0.03 / 0.20, 1.0),
    ),
    ("glm-4.5-flash", ModelPricing::other(0.0, 0.0)),
    (
        "glm-4.5-x",
        ModelPricing::other_with_cache(2.20, 8.90, 0.45 / 2.20, 1.0),
    ),
    (
        "glm-4.5v",
        ModelPricing::other_with_cache(0.60, 1.80, 0.11 / 0.60, 1.0),
    ),
    (
        "glm-4.5",
        ModelPricing::other_with_cache(0.60, 2.20, 0.11 / 0.60, 1.0),
    ),
    ("glm-4-32b-0414-128k", ModelPricing::other(0.10, 0.10)),
    // ---------------------------------------------------------------------
    // Qwen / QwQ
    // ---------------------------------------------------------------------
    ("qwen3.7-max", ModelPricing::other(2.50, 7.50)),
    ("qwen3.7-plus", ModelPricing::other(0.40, 1.60)),
    ("qwen3.6-max-preview", ModelPricing::other(1.30, 7.80)),
    ("qwen3.6-plus", ModelPricing::other(0.50, 3.0)),
    ("qwen3.6-flash", ModelPricing::other(0.20, 1.20)),
    ("qwen3.6-35b-a3b", ModelPricing::other(0.25, 1.50)),
    ("qwen3.5-omni-plus", ModelPricing::other(1.40, 8.0)),
    ("qwen3.5-omni-flash", ModelPricing::other(0.44, 2.66)),
    ("qwen3.5-397b-a17b", ModelPricing::other(0.60, 3.60)),
    ("qwen3.5-122b-a10b", ModelPricing::other(0.40, 3.20)),
    ("qwen3.5-35b-a3b", ModelPricing::other(0.25, 2.0)),
    ("qwen3.5-27b", ModelPricing::other(0.30, 2.40)),
    ("qwen3.5-plus", ModelPricing::other(0.40, 2.40)),
    ("qwen3.5-flash", ModelPricing::other(0.10, 0.40)),
    (
        "qwen3-next-80b-a3b-thinking",
        ModelPricing::other(0.20, 2.0),
    ),
    (
        "qwen3-next-80b-a3b-instruct",
        ModelPricing::other(0.20, 0.80),
    ),
    (
        "qwen3-235b-a22b-thinking-2507",
        ModelPricing::other(0.40, 4.0),
    ),
    (
        "qwen3-235b-a22b-instruct-2507",
        ModelPricing::other(0.40, 1.60),
    ),
    ("qwen3-235b-a22b", ModelPricing::other(0.40, 4.0)),
    (
        "qwen3-30b-a3b-thinking-2507",
        ModelPricing::other(0.15, 1.50),
    ),
    (
        "qwen3-30b-a3b-instruct-2507",
        ModelPricing::other(0.15, 0.60),
    ),
    ("qwen3-30b-a3b", ModelPricing::other(0.15, 1.50)),
    ("qwen3-32b", ModelPricing::other(0.40, 4.0)),
    ("qwen3-14b", ModelPricing::other(0.20, 2.0)),
    ("qwen3-8b", ModelPricing::other(0.10, 1.0)),
    ("qwen3-vl-plus", ModelPricing::other(0.20, 2.0)),
    ("qwen3-vl-flash", ModelPricing::other(0.03, 0.30)),
    (
        "qwen3-coder-480b-a35b-instruct",
        ModelPricing::other(1.20, 4.80),
    ),
    (
        "qwen3-coder-30b-a3b-instruct",
        ModelPricing::other(0.30, 1.20),
    ),
    ("qwen3-coder-next", ModelPricing::other(0.20, 0.80)),
    ("qwen3-coder-plus", ModelPricing::other(0.574, 2.294)),
    ("qwen3-coder-flash", ModelPricing::other(0.30, 1.50)),
    ("qwen3-omni-flash", ModelPricing::other(0.36, 1.38)),
    ("qwen3-max", ModelPricing::other(1.20, 6.0)),
    ("qwen2.5-omni-7b", ModelPricing::other(0.12, 0.40)),
    ("qwen-vl-ocr", ModelPricing::other(0.06, 0.10)),
    ("qwen-vl-plus", ModelPricing::other(0.16, 0.40)),
    ("qwen-vl-max", ModelPricing::other(0.32, 0.80)),
    ("qwen-omni-turbo", ModelPricing::other(0.08, 0.32)),
    ("qwen-mt-plus", ModelPricing::other(0.36, 1.08)),
    ("qwen-mt-turbo", ModelPricing::other(0.14, 0.39)),
    ("qwen-mt-flash", ModelPricing::other(0.14, 0.39)),
    ("qwen-mt-lite", ModelPricing::other(0.12, 0.32)),
    ("qwen-plus-character-ja", ModelPricing::other(0.734, 2.055)),
    ("qwen-plus-character", ModelPricing::other(0.16, 0.40)),
    ("qwen-flash-character", ModelPricing::other(0.05, 0.30)),
    ("qwen-flash", ModelPricing::other(0.05, 0.40)),
    ("qwen-plus", ModelPricing::other(0.40, 1.20)),
    ("qwen-max", ModelPricing::other(0.50, 2.0)),
    ("qwen-turbo", ModelPricing::other(0.30, 0.60)),
    ("qwen-long", ModelPricing::other(0.50, 2.0)),
    ("qvq-max", ModelPricing::other(1.60, 6.40)),
    ("qvq-plus", ModelPricing::other(0.40, 1.0)),
    ("qwq-plus", ModelPricing::other(0.80, 2.40)),
    ("qwq-32b", ModelPricing::other(0.50, 2.0)),
    // ---------------------------------------------------------------------
    // Kimi / Moonshot
    // ---------------------------------------------------------------------
    (
        "kimi-k2.7-code-highspeed",
        ModelPricing::other_with_cache(1.90, 8.0, 0.20, 1.0),
    ),
    (
        "kimi-k2.7-code",
        ModelPricing::other_with_cache(0.95, 4.0, 0.20, 1.0),
    ),
    (
        "kimi-k2.6",
        ModelPricing::other_with_cache(0.95, 4.0, 0.16 / 0.95, 1.0),
    ),
    (
        "kimi-k2.5",
        ModelPricing::other_with_cache(0.60, 3.0, 1.0 / 6.0, 1.0),
    ),
    ("moonshot-v1-128k", ModelPricing::other(2.0, 5.0)),
    ("moonshot-v1-32k", ModelPricing::other(1.0, 3.0)),
    ("moonshot-v1-8k", ModelPricing::other(0.20, 2.0)),
    // ---------------------------------------------------------------------
    // MiniMax
    //
    // MiniMax-M3 publishes a higher >512k-input token tier. This static
    // prefix table records the standard <=512k pay-as-you-go tier; adding
    // per-request tiered pricing requires a broader cost-engine change.
    // ---------------------------------------------------------------------
    (
        "minimax-m3",
        ModelPricing::other_with_cache(0.30, 1.20, 0.20, 1.0),
    ),
    (
        "minimax-m2.7-highspeed",
        ModelPricing::other_with_cache(0.60, 2.40, 0.10, 0.625),
    ),
    (
        "minimax-m2.7",
        ModelPricing::other_with_cache(0.30, 1.20, 0.20, 1.25),
    ),
    (
        "minimax-m2.5-highspeed",
        ModelPricing::other_with_cache(0.60, 2.40, 0.05, 0.625),
    ),
    (
        "minimax-m2.5",
        ModelPricing::other_with_cache(0.30, 1.20, 0.10, 1.25),
    ),
    (
        "minimax-m2.1-highspeed",
        ModelPricing::other_with_cache(0.60, 2.40, 0.05, 0.625),
    ),
    (
        "minimax-m2.1",
        ModelPricing::other_with_cache(0.30, 1.20, 0.10, 1.25),
    ),
    (
        "minimax-m2",
        ModelPricing::other_with_cache(0.30, 1.20, 0.10, 1.25),
    ),
];

thread_local! {
    /// Thread-local "this thread has computed a cost for an unknown
    /// model" flag (#646).  Set by `calculate_cost_*` whenever the
    /// pricing lookup misses; observable via [`has_unknown_model_cost`]
    /// and resettable via [`clear_unknown_model_cost`].
    ///
    /// Thread-local rather than `static AtomicBool` because cost
    /// calculation runs on per-session worker tasks and a global flag
    /// would bleed signal between unrelated sessions running on the
    /// same process.  Callers that need a session-scoped read should
    /// invoke the accessor from the thread that just called
    /// `calculate_cost`.
    static UNKNOWN_MODEL_COST_SEEN: Cell<bool> = const { Cell::new(false) };
}

/// Returns `true` if any `calculate_cost*` call on **this thread** has
/// failed pricing lookup since the last [`clear_unknown_model_cost`].
///
/// Mirrors CC's `hasUnknownModelCost` session flag (#646), which feeds
/// the "costs may be inaccurate" warning.  Use this for session-level
/// reporting; the per-call analytics event is emitted independently
/// (target `openclaudia::analytics`, event `unknown_model_cost`).
#[must_use]
pub fn has_unknown_model_cost() -> bool {
    UNKNOWN_MODEL_COST_SEEN.with(Cell::get)
}

/// Reset the [`has_unknown_model_cost`] flag on the current thread.
///
/// Intended to be called at session start or after surfacing the
/// inaccuracy warning to the user so subsequent unknown-model events
/// can be detected again.
pub fn clear_unknown_model_cost() {
    UNKNOWN_MODEL_COST_SEEN.with(|c| c.set(false));
}

/// Mark the thread-local "unknown model cost seen" flag (#646).
///
/// Centralised so the set semantics stay in one place.
fn mark_unknown_model_cost() {
    UNKNOWN_MODEL_COST_SEEN.with(|c| c.set(true));
}

/// Look up pricing for a model by ordered prefix match (case-insensitive).
///
/// Returns the first [`PRICING_TABLE`] entry whose prefix the lower-cased
/// `model` starts with, or [`None`] if no entry matches.  Emits a single
/// `tracing::warn!` on miss so unknown models surface in operator logs.
///
/// **Side-effect-free with respect to the unknown-model session flag**
/// (#646) — the flag is set by `calculate_cost_*`, not by this
/// primitive, so pricing-table introspection (e.g. for status-bar
/// display) does not pollute the session-level inaccuracy signal.
#[must_use]
pub fn get_pricing(model: &str) -> Option<ModelPricing> {
    let key = model.to_lowercase();
    let hit = PRICING_TABLE
        .iter()
        .find(|(prefix, _)| key.starts_with(prefix))
        .map(|(_, pricing)| *pricing);
    if hit.is_none() {
        tracing::warn!(model = %model, "unknown pricing for model");
    }
    hit
}

/// Calculate the cost for given token usage and model.
///
/// Defaults to the 5 m ephemeral cache-write multiplier — equivalent to
/// the Anthropic API behaviour when `cache_control.ttl` is omitted.
/// Callers that have an explicit TTL should use
/// [`calculate_cost_with_ttl`]; callers operating in `/fast` mode
/// should use [`calculate_cost_fast_mode`] (#642).
///
/// On success this emits a structured `cost_tracked` analytics event
/// (#649); on unknown-model failure it emits an `unknown_model_cost`
/// event and sets the thread-local [`has_unknown_model_cost`] flag
/// (#646).
///
/// # Errors
///
/// Returns [`PricingError::UnknownModel`] when `model` does not match any
/// entry in [`PRICING_TABLE`].  Previously this case returned
/// `Some(0.0)` in downstream `.unwrap_or(0.0)` paths; the [`Result`]
/// forces callers to make the choice explicit.
pub fn calculate_cost(model: &str, usage: &TokenUsage) -> Result<f64, PricingError> {
    calculate_cost_with_ttl(model, usage, CacheWriteTtl::FiveMinutes)
}

/// Calculate cost with explicit cache-write TTL.
///
/// Standard (non-fast) mode, zero extras.  Emits the same analytics
/// events as [`calculate_cost`].
///
/// # Errors
///
/// Returns [`PricingError::UnknownModel`] when `model` does not match any
/// entry in [`PRICING_TABLE`].
pub fn calculate_cost_with_ttl(
    model: &str,
    usage: &TokenUsage,
    ttl: CacheWriteTtl,
) -> Result<f64, PricingError> {
    calculate_cost_impl(model, usage, UsageExtras::ZERO, ttl, /*fast=*/ false)
}

/// Calculate cost with explicit [`UsageExtras`] metadata.
///
/// Defaults to standard mode and 5 m cache-write TTL.
///
/// # Errors
///
/// Returns [`PricingError::UnknownModel`] when `model` does not match any
/// entry in [`PRICING_TABLE`].
pub fn calculate_cost_with_extras(
    model: &str,
    usage: &TokenUsage,
    extras: &UsageExtras,
) -> Result<f64, PricingError> {
    calculate_cost_impl(
        model,
        usage,
        *extras,
        CacheWriteTtl::FiveMinutes,
        /*fast=*/ false,
    )
}

/// Calculate cost using the model's fast-mode rate tier (#642).
///
/// Equivalent to [`calculate_cost`] for models without a configured
/// fast tier (so it is safe to call unconditionally when the request
/// is in `/fast` mode regardless of model family).  Defaults to the
/// 5 m cache-write TTL and zero extras.
///
/// # Errors
///
/// Returns [`PricingError::UnknownModel`] when `model` does not match any
/// entry in [`PRICING_TABLE`].
pub fn calculate_cost_fast_mode(model: &str, usage: &TokenUsage) -> Result<f64, PricingError> {
    calculate_cost_impl(
        model,
        usage,
        UsageExtras::ZERO,
        CacheWriteTtl::FiveMinutes,
        /*fast=*/ true,
    )
}

/// Calculate cost with full control over TTL, fast-mode, and extras.
///
/// Lower-level entry point used by callers that need control over all
/// three dimensions; the typical caller wants [`calculate_cost`],
/// [`calculate_cost_with_ttl`], [`calculate_cost_fast_mode`], or
/// [`calculate_cost_with_extras`].
///
/// # Errors
///
/// Returns [`PricingError::UnknownModel`] when `model` does not match any
/// entry in [`PRICING_TABLE`].
pub fn calculate_cost_full(
    model: &str,
    usage: &TokenUsage,
    extras: &UsageExtras,
    ttl: CacheWriteTtl,
    fast: bool,
) -> Result<f64, PricingError> {
    calculate_cost_impl(model, usage, *extras, ttl, fast)
}

/// Shared implementation backing all `calculate_cost*` entry points.
///
/// On unknown-model: emits the `unknown_model_cost` analytics event,
/// sets the thread-local session flag (#646), and returns
/// `PricingError::UnknownModel`.  On success: emits the `cost_tracked`
/// analytics event (#649) and returns the USD cost.
fn calculate_cost_impl(
    model: &str,
    usage: &TokenUsage,
    _extras: UsageExtras,
    ttl: CacheWriteTtl,
    fast: bool,
) -> Result<f64, PricingError> {
    let Some(pricing) = get_pricing(model) else {
        // Per #646: structured analytics event + thread-local session
        // flag so downstream UI can surface "costs may be inaccurate".
        // The event target/name mirror CC's `tengu_unknown_model_cost`.
        mark_unknown_model_cost();
        tracing::warn!(
            target: "openclaudia::analytics",
            event = "unknown_model_cost",
            model = %model,
            input_tokens = usage.input_tokens,
            output_tokens = usage.output_tokens,
            cache_read_tokens = usage.cache_read_tokens,
            cache_write_tokens = usage.cache_write_tokens,
            fast_mode = fast,
            "unknown model for cost lookup; costs may be inaccurate",
        );
        return Err(PricingError::UnknownModel(model.to_string()));
    };

    let input = f64_from_tokens(usage.input_tokens);
    let output = f64_from_tokens(usage.output_tokens);
    let cache_read = f64_from_tokens(usage.cache_read_tokens);
    let cache_write = f64_from_tokens(usage.cache_write_tokens);

    let input_rate = pricing.effective_input_per_million_for_usage(usage, fast);
    let output_rate = pricing.effective_output_per_million_for_usage(usage, fast);

    let input_cost = input * input_rate / 1_000_000.0;
    let output_cost = output * output_rate / 1_000_000.0;
    // Cache-token multipliers apply to the active input rate. For
    // Anthropic fast mode, cache reads/writes use the fast-mode input
    // price before applying the documented cache multiplier.
    let cache_read_cost = cache_read * input_rate * pricing.cache_read_multiplier / 1_000_000.0;
    let cache_write_cost =
        cache_write * input_rate * pricing.cache_write_multiplier(ttl) / 1_000_000.0;
    let cost = input_cost + output_cost + cache_read_cost + cache_write_cost;

    // Per #649: per-request analytics event, mirroring CC's OTEL
    // `getCostCounter().add()` / `getTokenCounter().add()` emission.
    tracing::info!(
        target: "openclaudia::analytics",
        event = "cost_tracked",
        model = %model,
        input_tokens = usage.input_tokens,
        output_tokens = usage.output_tokens,
        cache_read_tokens = usage.cache_read_tokens,
        cache_write_tokens = usage.cache_write_tokens,
        cache_write_ttl = ?ttl,
        fast_mode = fast,
        cost_usd = cost,
        "per-request cost tracked",
    );

    Ok(cost)
}

/// Lossless `u64 -> f64` conversion for token counts.
///
/// `f64` exactly represents every integer up to `2^53`.  Realistic token
/// counts per request are well under `u32::MAX` (~4.3 billion); for the
/// pathological case of a `u64` larger than that we saturate to
/// `u32::MAX` so the conversion via [`f64::from`] is exact and clippy's
/// pedantic `cast_precision_loss` lint does not fire.  Saturation here
/// is strictly preferable to silent precision loss: it produces an
/// obviously wrong (very large) cost number rather than a subtly wrong
/// one.
fn f64_from_tokens(n: u64) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Mandate test 1 — gpt-5.2 resolves BEFORE gpt-5 in the ordered walk.
    // Regression guard against the original 17-branch if/else hazard
    // where reordering silently broke pricing.
    // -----------------------------------------------------------------------
    #[test]
    fn ordering_gpt_5_2_resolves_before_gpt_5() {
        // gpt-5.2 has its own row at $1.75/M input / $14/M output. The
        // resolution path must hit the 5.2 row, not the generic 5 row.
        let idx_5_2 = PRICING_TABLE
            .iter()
            .position(|(p, _)| *p == "gpt-5.2")
            .expect("table must contain gpt-5.2 prefix");
        let idx_5 = PRICING_TABLE
            .iter()
            .position(|(p, _)| *p == "gpt-5")
            .expect("table must contain gpt-5 prefix");
        assert!(
            idx_5_2 < idx_5,
            "gpt-5.2 must precede gpt-5 in PRICING_TABLE (got {idx_5_2} vs {idx_5}); \
             otherwise starts_with(\"gpt-5\") shadows the 5.2 entry"
        );
        // And the lookup actually resolves.
        assert!(get_pricing("gpt-5.2").is_some());
        assert!(get_pricing("gpt-5.2-turbo").is_some());
    }

    #[test]
    fn ordering_current_gpt5_subfamilies_precede_generic_gpt5() {
        let idx_5 = PRICING_TABLE
            .iter()
            .position(|(p, _)| *p == "gpt-5")
            .expect("table must contain gpt-5 prefix");
        for prefix in [
            "gpt-5.5-pro",
            "gpt-5.5",
            "gpt-5.4-pro",
            "gpt-5.4-mini",
            "gpt-5.4-nano",
            "gpt-5.4",
            "gpt-5.3-codex",
            "gpt-5.3-chat-latest",
            "gpt-5.2-pro",
            "gpt-5.2-codex",
            "gpt-5.2-chat-latest",
            "gpt-5.2",
            "gpt-5.1-codex-mini",
            "gpt-5.1-codex",
            "gpt-5.1-chat-latest",
            "gpt-5.1",
            "gpt-5-pro",
            "gpt-5-codex",
            "gpt-5-chat-latest",
            "gpt-5-nano",
            "gpt-5-mini",
        ] {
            let idx = PRICING_TABLE
                .iter()
                .position(|(p, _)| *p == prefix)
                .unwrap_or_else(|| panic!("table must contain {prefix} prefix"));
            assert!(idx < idx_5, "{prefix} ({idx}) must precede gpt-5 ({idx_5})");
        }
    }

    // -----------------------------------------------------------------------
    // Mandate test 2 — Gemini specific model families resolve before
    // any shorter future `gemini-2`/`gemini-3` prefix.
    // -----------------------------------------------------------------------
    #[test]
    fn ordering_gemini_specific_families_resolve_before_generic_prefixes() {
        let idx_flash = PRICING_TABLE
            .iter()
            .position(|(p, _)| *p == "gemini-2.0-flash")
            .expect("table must contain gemini-2.0-flash");
        let idx_flash_lite = PRICING_TABLE
            .iter()
            .position(|(p, _)| *p == "gemini-2.5-flash-lite")
            .expect("table must contain gemini-2.5-flash-lite");
        let idx_flash_25 = PRICING_TABLE
            .iter()
            .position(|(p, _)| *p == "gemini-2.5-flash")
            .expect("table must contain gemini-2.5-flash");
        let idx_pro_customtools = PRICING_TABLE
            .iter()
            .position(|(p, _)| *p == "gemini-3.1-pro-preview-customtools")
            .expect("table must contain gemini-3.1-pro-preview-customtools");
        let idx_pro_preview = PRICING_TABLE
            .iter()
            .position(|(p, _)| *p == "gemini-3.1-pro-preview")
            .expect("table must contain gemini-3.1-pro-preview");
        assert!(
            idx_flash_lite < idx_flash_25,
            "gemini-2.5-flash-lite must precede gemini-2.5-flash"
        );
        assert!(
            idx_pro_customtools < idx_pro_preview,
            "gemini-3.1-pro-preview-customtools must precede gemini-3.1-pro-preview"
        );
        // Any future bare `gemini-2` prefix must appear strictly after.
        for (i, (prefix, _)) in PRICING_TABLE.iter().enumerate() {
            if *prefix == "gemini-2" {
                assert!(
                    i > idx_flash,
                    "a bare `gemini-2` prefix at {i} would shadow `gemini-2.0-flash` at {idx_flash}"
                );
            }
            if *prefix == "gemini-3" {
                assert!(
                    i > idx_pro_preview,
                    "a bare `gemini-3` prefix at {i} would shadow `gemini-3.1-pro-preview` at {idx_pro_preview}"
                );
            }
        }
        // And the specific flash entry resolves.
        let p = get_pricing("gemini-2.0-flash").expect("must resolve");
        assert!((p.input_per_million - 0.075).abs() < f64::EPSILON);
        let p = get_pricing("gemini-3.1-pro-preview-customtools").expect("must resolve");
        assert!((p.input_per_million - 2.0).abs() < f64::EPSILON);
    }

    // -----------------------------------------------------------------------
    // Mandate test 3 — ordering sanity: no entry is a strict prefix of an
    // earlier entry.  This is the structural invariant of an ordered
    // prefix table; violating it means the earlier entry would shadow
    // the later one for any model id long enough to match both.
    // -----------------------------------------------------------------------
    #[test]
    fn ordering_no_entry_is_prefix_of_earlier() {
        for (later_idx, (later_prefix, _)) in PRICING_TABLE.iter().enumerate() {
            for (earlier_prefix, _) in &PRICING_TABLE[..later_idx] {
                assert!(
                    !later_prefix.starts_with(earlier_prefix),
                    "PRICING_TABLE ordering violation: `{later_prefix}` (at {later_idx}) is \
                     shadowed by earlier entry `{earlier_prefix}` — move `{later_prefix}` \
                     before `{earlier_prefix}` or rename it"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // Mandate test 4 — unknown model returns PricingError::UnknownModel,
    // carrying the original input verbatim for operator diagnostics.
    // -----------------------------------------------------------------------
    #[test]
    fn unknown_model_returns_err() {
        let usage = TokenUsage {
            input_tokens: 1_000,
            output_tokens: 500,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
        };
        let err = calculate_cost("totally-unknown-model-xyz", &usage).unwrap_err();
        assert_eq!(
            err,
            PricingError::UnknownModel("totally-unknown-model-xyz".to_string())
        );
        // get_pricing surface is still Option-returning so the lookup
        // primitive stays cheap; the Result lives on the cost API.
        assert!(get_pricing("totally-unknown-model-xyz").is_none());
        assert!(get_pricing("").is_none());
    }

    // -----------------------------------------------------------------------
    // Mandate test 5 — 1 h cache write uses the 2.0× multiplier for
    // Anthropic models (the under-billing bug the issue called out).
    // -----------------------------------------------------------------------
    #[test]
    fn anthropic_1hr_cache_write_uses_two_x_multiplier() {
        // 1 M cache-write tokens at Sonnet input pricing ($3/M):
        //   5 m → 3 × 1.25 = $3.75
        //   1 h → 3 × 2.00 = $6.00
        let usage = TokenUsage {
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens: 0,
            cache_write_tokens: 1_000_000,
        };
        let cost_five_min =
            calculate_cost_with_ttl("claude-sonnet-4-5", &usage, CacheWriteTtl::FiveMinutes)
                .expect("sonnet must resolve");
        let cost_one_hour =
            calculate_cost_with_ttl("claude-sonnet-4-5", &usage, CacheWriteTtl::OneHour)
                .expect("sonnet must resolve");
        assert!(
            (cost_five_min - 3.75).abs() < 1e-9,
            "5m cache write must be 1.25× input (got {cost_five_min}, expected $3.75)"
        );
        assert!(
            (cost_one_hour - 6.0).abs() < 1e-9,
            "1h cache write must be 2.0× input (got {cost_one_hour}, expected $6.00) — \
             this is the under-billing bug from issue #388"
        );
        // And the 1 h cost is strictly greater than the 5 m cost, which
        // is the operational invariant downstream budget code relies on.
        assert!(
            cost_one_hour > cost_five_min,
            "1h cache write must cost more than 5m"
        );
    }

    // -----------------------------------------------------------------------
    // Mandate test 6 — property test: every model name that appears as a
    // string literal in src/providers/ resolves through the pricing
    // table.  The list is curated (not auto-scraped at test time) so the
    // assertion stays deterministic and the failure mode is obvious:
    // adding a new model literal to a provider that has no PRICING_TABLE
    // entry breaks this test, forcing the pricing entry to be added in
    // the same change.
    // -----------------------------------------------------------------------
    #[test]
    fn every_provider_model_name_resolves() {
        // Curated from grep across src/providers/*.rs at #388.  Add new
        // models here when they're introduced in a provider; the test
        // will fail loudly if PRICING_TABLE is out of sync.
        let provider_models: &[&str] = &[
            // Anthropic provider
            "claude-fable-5",
            "claude-mythos-5",
            "claude-mythos-preview",
            "claude-3-5-haiku-20241022",
            "claude-3-sonnet",
            "claude-code-20250219",
            "claude-opus-4",
            "claude-opus-4-5",
            "claude-opus-4-6",
            "claude-opus-4-7",
            "claude-opus-4-8",
            // OpenAI provider
            "gpt-4",
            "gpt-4o",
            "gpt-4o-mini",
            "gpt-5",
            "gpt-5-mini",
            "gpt-5-nano",
            "gpt-5-pro",
            "gpt-5.1-codex",
            "gpt-5.1-codex-max",
            "gpt-5.1-codex-mini",
            "gpt-5.2",
            "gpt-5.2-codex",
            "gpt-5.2-chat-latest",
            "gpt-5.2-pro",
            "gpt-5.3-codex",
            "gpt-5.3-chat-latest",
            "gpt-5.4",
            "gpt-5.4-mini",
            "gpt-5.4-nano",
            "gpt-5.4-pro",
            "gpt-5.5",
            "gpt-5.5-2026-04-23",
            "gpt-5.5-pro",
            "chat-latest",
            "codex-mini-latest",
            "gpt-3.5-turbo",
            "gpt-4.1-nano",
            "gpt-4.5-preview",
            "gpt-4-turbo",
            "gpt-4-turbo-preview",
            "gpt-4o-search-preview",
            "gpt-4o-mini-search-preview",
            "gpt-5.1-chat-latest",
            "gpt-5-codex",
            "gpt-5-chat-latest",
            "o1",
            "o1-mini",
            "o1-preview",
            "o1-pro",
            "o3",
            "o3-mini",
            "o3-pro",
            "o4",
            "o4-pro",
            // Google provider
            "gemini-3.5-flash",
            "gemini-3.1-pro-preview",
            "gemini-3.1-pro-preview-customtools",
            "gemini-3.1-flash-lite",
            "gemini-3-flash-preview",
            "gemini-2.5-pro",
            "gemini-2.5-flash",
            "gemini-2.5-flash-lite",
            // DeepSeek
            "deepseek-v4-pro",
            "deepseek-v4-flash",
            "deepseek-chat",
            "deepseek-r1",
            "deepseek-reasoner",
            // Qwen / QwQ
            "qwen-long",
            "qwq-32b",
        ];

        let mut missing = Vec::new();
        for name in provider_models {
            if get_pricing(name).is_none() {
                missing.push(*name);
            }
        }
        assert!(
            missing.is_empty(),
            "PRICING_TABLE is missing entries for provider model(s): {missing:?}"
        );
    }

    #[test]
    fn qwen_static_catalog_models_resolve_pricing() {
        let missing = crate::providers::QWEN_MODELS
            .iter()
            .copied()
            .filter(|model| get_pricing(model).is_none())
            .collect::<Vec<_>>();
        assert!(
            missing.is_empty(),
            "PRICING_TABLE is missing Qwen catalog model(s): {missing:?}"
        );
    }

    #[test]
    fn openai_static_catalog_models_resolve_pricing() {
        let missing = crate::providers::OPENAI_MODELS
            .iter()
            .copied()
            .filter(|model| get_pricing(model).is_none())
            .collect::<Vec<_>>();
        assert!(
            missing.is_empty(),
            "PRICING_TABLE is missing OpenAI catalog model(s): {missing:?}"
        );
    }

    #[test]
    fn google_catalog_marks_models_without_attributable_pricing_unknown() {
        let unpriced = crate::providers::GOOGLE_MODELS
            .iter()
            .copied()
            .filter(|model| get_pricing(model).is_none())
            .collect::<Vec<_>>();
        assert_eq!(unpriced, ["gemini-3.7-flash", "gemini-3.6-flash"]);

        let catalog = crate::providers::emergency_fallback_catalog("google");
        for model in unpriced {
            assert_eq!(
                catalog
                    .find(model)
                    .expect("fallback model")
                    .capabilities
                    .pricing,
                crate::providers::ModelPricingState::Unknown,
                "missing attributable prices must stay explicitly unknown"
            );
        }
    }

    #[test]
    fn priced_zai_static_catalog_models_resolve_pricing() {
        let missing = crate::providers::ZAI_MODELS
            .iter()
            .copied()
            .filter(|model| *model != "autoglm-phone-multilingual")
            .filter(|model| get_pricing(model).is_none())
            .collect::<Vec<_>>();
        assert!(
            missing.is_empty(),
            "PRICING_TABLE is missing priced Z.AI catalog model(s): {missing:?}"
        );
    }

    #[test]
    fn kimi_static_catalog_models_resolve_pricing() {
        let missing = crate::providers::KIMI_MODELS
            .iter()
            .copied()
            .filter(|model| get_pricing(model).is_none())
            .collect::<Vec<_>>();
        assert!(
            missing.is_empty(),
            "PRICING_TABLE is missing Kimi catalog model(s): {missing:?}"
        );
    }

    #[test]
    fn priced_minimax_static_catalog_models_resolve_pricing() {
        let missing = crate::providers::MINIMAX_MODELS
            .iter()
            .copied()
            .filter(|model| *model != "M2-her")
            .filter(|model| get_pricing(model).is_none())
            .collect::<Vec<_>>();
        assert!(
            missing.is_empty(),
            "PRICING_TABLE is missing priced MiniMax catalog model(s): {missing:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Behavioural regressions retained from #495 work — these keep the
    // pre-refactor cost numbers intact for default-TTL workloads.
    // -----------------------------------------------------------------------

    #[test]
    fn known_model_basic_lookup() {
        assert!(get_pricing("claude-3-opus-20240229").is_some());
        assert!(get_pricing("claude-3-sonnet-20240229").is_some());
        assert!(get_pricing("claude-3-haiku-20240307").is_some());
        assert!(get_pricing("gpt-4o").is_some());
        assert!(get_pricing("gpt-4o-mini").is_some());
        assert!(get_pricing("gemini-2.0-flash").is_some());
        assert!(get_pricing("deepseek-v4-pro").is_some());
        assert!(get_pricing("deepseek-v4-flash").is_some());
        assert!(get_pricing("deepseek-chat").is_some());
        assert!(get_pricing("deepseek-reasoner").is_some());
        assert!(get_pricing("qwen3.7-plus").is_some());
        assert!(get_pricing("qwen3.7-max-2026-05-17").is_some());
        assert!(get_pricing("qwen-plus-2025-12-01").is_some());
        assert!(get_pricing("kimi-k2.7-code").is_some());
        assert!(get_pricing("moonshot-v1-128k-vision-preview").is_some());
        assert!(get_pricing("MiniMax-M3").is_some());
        assert!(get_pricing("MiniMax-M2.7-highspeed").is_some());
    }

    /// Haiku pricing — 1 M input + 0.1 M output ≈ $0.375.
    #[test]
    fn basic_cost_haiku() {
        let usage = TokenUsage {
            input_tokens: 1_000_000,
            output_tokens: 100_000,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
        };
        let cost = calculate_cost("claude-3-haiku-20240307", &usage).expect("haiku must resolve");
        // 0.25 input + 0.125 output = 0.375
        assert!((cost - 0.375).abs() < 1e-9, "expected ~$0.375, got {cost}");
    }

    /// Exact rate declarations from `PRICING_TABLE` are returned verbatim.
    #[test]
    fn exact_rates_returned() {
        let p = get_pricing("claude-3-haiku-20240307").expect("haiku must be known");
        assert!((p.input_per_million - 0.25).abs() < f64::EPSILON);
        assert!((p.output_per_million - 1.25).abs() < f64::EPSILON);

        let p = get_pricing("gpt-4o").expect("gpt-4o must be known");
        assert!((p.input_per_million - 2.5).abs() < f64::EPSILON);
        assert!((p.output_per_million - 10.0).abs() < f64::EPSILON);

        let p = get_pricing("claude-opus-4-20250514").expect("opus-4 must be known");
        assert!((p.input_per_million - 15.0).abs() < f64::EPSILON);
        assert!((p.output_per_million - 75.0).abs() < f64::EPSILON);

        let p = get_pricing("claude-opus-4-8").expect("opus-4-8 must be known");
        assert!((p.input_per_million - 5.0).abs() < f64::EPSILON);
        assert!((p.output_per_million - 25.0).abs() < f64::EPSILON);

        let p = get_pricing("gemini-3.5-flash").expect("gemini-3.5-flash must be known");
        assert!((p.input_per_million - 1.50).abs() < f64::EPSILON);
        assert!((p.output_per_million - 9.0).abs() < f64::EPSILON);

        let p = get_pricing("gemini-2.5-flash-lite").expect("gemini-2.5-flash-lite must be known");
        assert!((p.input_per_million - 0.10).abs() < f64::EPSILON);
        assert!((p.output_per_million - 0.40).abs() < f64::EPSILON);

        let p = get_pricing("claude-fable-5").expect("fable must be known");
        assert!((p.input_per_million - 10.0).abs() < f64::EPSILON);
        assert!((p.output_per_million - 50.0).abs() < f64::EPSILON);

        let p = get_pricing("gpt-5.5-pro").expect("gpt-5.5-pro must be known");
        assert!((p.input_per_million - 30.0).abs() < f64::EPSILON);
        assert!((p.output_per_million - 180.0).abs() < f64::EPSILON);

        let p = get_pricing("gpt-5.4-mini").expect("gpt-5.4-mini must be known");
        assert!((p.input_per_million - 0.75).abs() < f64::EPSILON);
        assert!((p.output_per_million - 4.50).abs() < f64::EPSILON);

        let p = get_pricing("gpt-5.3-chat-latest").expect("gpt-5.3-chat-latest must be known");
        assert!((p.input_per_million - 1.75).abs() < f64::EPSILON);
        assert!((p.output_per_million - 14.0).abs() < f64::EPSILON);

        let p = get_pricing("codex-mini-latest").expect("codex-mini-latest must be known");
        assert!((p.input_per_million - 1.50).abs() < f64::EPSILON);
        assert!((p.output_per_million - 6.0).abs() < f64::EPSILON);

        let p = get_pricing("o3").expect("o3 must be known");
        assert!((p.input_per_million - 2.0).abs() < f64::EPSILON);
        assert!((p.output_per_million - 8.0).abs() < f64::EPSILON);

        let p = get_pricing("o3-pro").expect("o3-pro must be known");
        assert!((p.input_per_million - 20.0).abs() < f64::EPSILON);
        assert!((p.output_per_million - 80.0).abs() < f64::EPSILON);

        let p = get_pricing("o1-pro").expect("o1-pro must be known");
        assert!((p.input_per_million - 150.0).abs() < f64::EPSILON);
        assert!((p.output_per_million - 600.0).abs() < f64::EPSILON);

        let p = get_pricing("o1-mini").expect("o1-mini must be known");
        assert!((p.input_per_million - 1.10).abs() < f64::EPSILON);
        assert!((p.output_per_million - 4.40).abs() < f64::EPSILON);

        let p = get_pricing("deepseek-v4-pro").expect("deepseek-v4-pro must be known");
        assert!((p.input_per_million - 0.435).abs() < f64::EPSILON);
        assert!((p.output_per_million - 0.87).abs() < f64::EPSILON);

        let p = get_pricing("deepseek-v4-flash").expect("deepseek-v4-flash must be known");
        assert!((p.input_per_million - 0.14).abs() < f64::EPSILON);
        assert!((p.output_per_million - 0.28).abs() < f64::EPSILON);

        let p = get_pricing("deepseek-chat").expect("deepseek-chat must be known");
        assert!((p.input_per_million - 0.14).abs() < f64::EPSILON);
        assert!((p.output_per_million - 0.28).abs() < f64::EPSILON);

        let p = get_pricing("qwen3.7-max").expect("qwen3.7-max must be known");
        assert!((p.input_per_million - 2.50).abs() < f64::EPSILON);
        assert!((p.output_per_million - 7.50).abs() < f64::EPSILON);

        let p = get_pricing("qwen3.7-plus").expect("qwen3.7-plus must be known");
        assert!((p.input_per_million - 0.40).abs() < f64::EPSILON);
        assert!((p.output_per_million - 1.60).abs() < f64::EPSILON);

        let p = get_pricing("kimi-k2.7-code-highspeed")
            .expect("kimi-k2.7-code-highspeed must be known");
        assert!((p.input_per_million - 1.90).abs() < f64::EPSILON);
        assert!((p.output_per_million - 8.0).abs() < f64::EPSILON);

        let p = get_pricing("moonshot-v1-32k").expect("moonshot-v1-32k must be known");
        assert!((p.input_per_million - 1.0).abs() < f64::EPSILON);
        assert!((p.output_per_million - 3.0).abs() < f64::EPSILON);

        let p = get_pricing("MiniMax-M3").expect("MiniMax-M3 must be known");
        assert!((p.input_per_million - 0.30).abs() < f64::EPSILON);
        assert!((p.output_per_million - 1.20).abs() < f64::EPSILON);
    }

    /// Case-insensitive lookup on the input.
    #[test]
    fn lookup_is_case_insensitive() {
        assert!(get_pricing("GPT-4o").is_some());
        assert!(get_pricing("Claude-3-Haiku-20240307").is_some());
    }

    /// Cache-read tokens apply the 0.1× ratio (Anthropic).
    #[test]
    fn cache_read_tokens_apply_point_one_ratio() {
        let usage = TokenUsage {
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens: 1_000_000,
            cache_write_tokens: 0,
        };
        let cost = calculate_cost("claude-sonnet-4-5", &usage).expect("sonnet must resolve");
        let expected = 3.0 * 0.1; // $0.30
        assert!(
            (cost - expected).abs() < 1e-9,
            "cache-read must be 0.1× input; got {cost}, expected {expected}"
        );
    }

    /// Default-TTL cache write (5 m) → 1.25× input.
    #[test]
    fn default_cache_write_tokens_apply_one_point_two_five_ratio() {
        let usage = TokenUsage {
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens: 0,
            cache_write_tokens: 1_000_000,
        };
        let cost = calculate_cost("claude-sonnet-4-5", &usage).expect("sonnet must resolve");
        let expected = 3.0 * 1.25; // $3.75
        assert!(
            (cost - expected).abs() < 1e-9,
            "default cache-write (5m) must be 1.25× input; got {cost}, expected {expected}"
        );
    }

    /// Combined four-bucket sum on default TTL.
    #[test]
    fn all_four_token_buckets_sum_correctly() {
        // Haiku: $0.25/M input, $1.25/M output.
        // cache_read  = 0.25 × 0.1  = $0.025/M
        // cache_write = 0.25 × 1.25 = $0.3125/M
        let usage = TokenUsage {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
            cache_read_tokens: 1_000_000,
            cache_write_tokens: 1_000_000,
        };
        let cost = calculate_cost("claude-3-haiku-20240307", &usage).expect("haiku must resolve");
        let expected = 0.25f64.mul_add(1.25, 0.25f64.mul_add(0.1, 0.25 + 1.25));
        assert!(
            (cost - expected).abs() < 1e-9,
            "four-bucket sum wrong; got {cost}, expected {expected}"
        );
    }

    /// Zero usage returns Ok(0.0), not Err.
    #[test]
    fn zero_tokens_returns_zero_cost() {
        let usage = TokenUsage {
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
        };
        let cost = calculate_cost("claude-3-haiku-20240307", &usage).expect("haiku must resolve");
        assert!(cost.abs() < f64::EPSILON);
    }

    /// Sanity: claude-opus-4 prefix covers the original dated id and bare
    /// alias at the retired Opus 4 rate, while newer dateless Opus IDs
    /// resolve through their own lower-cost rows.
    #[test]
    fn claude_opus_4_prefix_covers_dated_and_rollforward() {
        for id in ["claude-opus-4", "claude-opus-4-20250514"] {
            let p = get_pricing(id).unwrap_or_else(|| panic!("{id} must resolve"));
            assert!((p.input_per_million - 15.0).abs() < f64::EPSILON, "{id}");
            assert!((p.output_per_million - 75.0).abs() < f64::EPSILON, "{id}");
        }
        for id in [
            "claude-opus-4-5",
            "claude-opus-4-6",
            "claude-opus-4-7",
            "claude-opus-4-8",
        ] {
            let p = get_pricing(id).unwrap_or_else(|| panic!("{id} must resolve"));
            assert!((p.input_per_million - 5.0).abs() < f64::EPSILON, "{id}");
            assert!((p.output_per_million - 25.0).abs() < f64::EPSILON, "{id}");
        }
    }

    /// Sanity: claude-3-opus and claude-opus-4 stay distinct families
    /// (the original failure mode that motivated exact-match in #495).
    /// With the ordered prefix table they share no common prefix.
    #[test]
    fn opus_3_and_opus_4_are_distinct_families() {
        let opus3 = get_pricing("claude-3-opus-20240229").expect("opus3 must resolve");
        let opus4 = get_pricing("claude-opus-4-20250514").expect("opus4 must resolve");
        // Both happen to share the $15 / $75 rate sheet today, so we
        // assert they resolved through different table entries instead
        // of through the same shadowing prefix.  We do this by reading
        // back which prefix matched each id.
        let key3 = "claude-3-opus-20240229";
        let key4 = "claude-opus-4-20250514";
        let prefix3 = PRICING_TABLE
            .iter()
            .find(|(p, _)| key3.starts_with(p))
            .map(|(p, _)| *p);
        let prefix4 = PRICING_TABLE
            .iter()
            .find(|(p, _)| key4.starts_with(p))
            .map(|(p, _)| *p);
        assert_eq!(prefix3, Some("claude-3-opus"));
        assert_eq!(prefix4, Some("claude-opus-4-"));
        assert_ne!(
            prefix3, prefix4,
            "opus-3 and opus-4 must resolve through distinct PRICING_TABLE rows"
        );
        // And the rates themselves still match the family's price sheet.
        assert!((opus3.input_per_million - opus4.input_per_million).abs() < f64::EPSILON);
    }

    // -----------------------------------------------------------------------
    // Browser-backed web_search is free to the user. UsageExtras remains as a
    // compatibility carrier, but it must not affect token pricing.
    // -----------------------------------------------------------------------
    #[test]
    fn usage_extras_do_not_add_search_cost() {
        let usage = TokenUsage::default();
        let extras = UsageExtras::ZERO;
        let cost = calculate_cost_with_extras("claude-sonnet-4-5", &usage, &extras)
            .expect("sonnet must resolve");
        assert!(
            (cost - 0.0).abs() < 1e-9,
            "zero-token usage with extras must stay free (got {cost})"
        );

        let usage_with_tokens = TokenUsage {
            input_tokens: 1_000_000,
            output_tokens: 0,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
        };
        let cost_no_search =
            calculate_cost("claude-sonnet-4-5", &usage_with_tokens).expect("sonnet must resolve");
        let cost_with_search =
            calculate_cost_with_extras("claude-sonnet-4-5", &usage_with_tokens, &extras)
                .expect("sonnet must resolve");
        assert!(
            (cost_with_search - cost_no_search).abs() < 1e-9,
            "UsageExtras must not change token cost \
             (cost_no_search={cost_no_search}, cost_with_search={cost_with_search})"
        );
    }

    // -----------------------------------------------------------------------
    // #642 — fast-mode tier swaps in $30/$150 rates for Opus 4.6+ and
    // leaves other models at their standard rates.
    // -----------------------------------------------------------------------
    #[test]
    fn fast_mode_uses_thirty_one_fifty_for_opus_4_6_plus() {
        let usage = TokenUsage {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
        };
        // Standard tier: $5 in + $25 out = $30 for 1M+1M.
        let standard = calculate_cost("claude-opus-4-6", &usage).expect("opus-4-6 must resolve");
        assert!(
            (standard - 30.0).abs() < 1e-9,
            "opus-4-6 standard tier: 1M input + 1M output = $30 (got {standard})"
        );
        // Fast tier: $30 in + $150 out = $180 for the same usage.
        let fast =
            calculate_cost_fast_mode("claude-opus-4-6", &usage).expect("opus-4-6 must resolve");
        assert!(
            (fast - 180.0).abs() < 1e-9,
            "opus-4-6 fast tier: 1M input + 1M output = $180 (got {fast})"
        );
        // Opus 4.7 inherits the same fast-mode override.
        let fast47 =
            calculate_cost_fast_mode("claude-opus-4-7", &usage).expect("opus-4-7 must resolve");
        assert!(
            (fast47 - 180.0).abs() < 1e-9,
            "opus-4-7 fast tier: 1M input + 1M output = $180 (got {fast47})"
        );
        // Opus 4.8 has its own lower fast-mode tier: $10 + $50 = $60.
        let fast48 =
            calculate_cost_fast_mode("claude-opus-4-8", &usage).expect("opus-4-8 must resolve");
        assert!(
            (fast48 - 60.0).abs() < 1e-9,
            "opus-4-8 fast tier: 1M input + 1M output = $60 (got {fast48})"
        );
    }

    #[test]
    fn fast_mode_cache_tokens_use_fast_input_rate() {
        let usage = TokenUsage {
            input_tokens: 0,
            output_tokens: 0,
            cache_read_tokens: 1_000_000,
            cache_write_tokens: 1_000_000,
        };
        let extras = UsageExtras::ZERO;

        let opus_48 = calculate_cost_full(
            "claude-opus-4-8",
            &usage,
            &extras,
            CacheWriteTtl::FiveMinutes,
            true,
        )
        .expect("opus-4-8 must resolve");
        // Fast-mode input $10/M: cache read $1 + 5m cache write $12.50.
        assert!(
            (opus_48 - 13.50).abs() < 1e-9,
            "opus-4-8 fast cache cost must use fast input rate; got {opus_48}"
        );

        let opus_46 = calculate_cost_full(
            "claude-opus-4-6",
            &usage,
            &extras,
            CacheWriteTtl::FiveMinutes,
            true,
        )
        .expect("opus-4-6 must resolve");
        // Fast-mode input $30/M: cache read $3 + 5m cache write $37.50.
        assert!(
            (opus_46 - 40.50).abs() < 1e-9,
            "opus-4-6 fast cache cost must use fast input rate; got {opus_46}"
        );
    }

    /// #642 — `calculate_cost_fast_mode` on a model with no fast tier
    /// configured returns the same number as standard `calculate_cost`.
    /// This is the "safe to call unconditionally in /fast mode" contract.
    #[test]
    fn fast_mode_falls_back_for_models_without_override() {
        let usage = TokenUsage {
            input_tokens: 1_000_000,
            output_tokens: 1_000_000,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
        };
        // claude-opus-4-5 has no fast-mode override — must equal standard.
        let standard = calculate_cost("claude-opus-4-5", &usage).expect("opus-4-5 must resolve");
        let fast =
            calculate_cost_fast_mode("claude-opus-4-5", &usage).expect("opus-4-5 must resolve");
        assert!(
            (standard - fast).abs() < f64::EPSILON,
            "models without fast-mode override must produce identical cost in either entry point \
             (standard={standard}, fast={fast})"
        );
        // Same for an OpenAI model that has no fast tier at all.
        let s2 = calculate_cost("gpt-4o", &usage).expect("gpt-4o must resolve");
        let f2 = calculate_cost_fast_mode("gpt-4o", &usage).expect("gpt-4o must resolve");
        assert!(
            (s2 - f2).abs() < f64::EPSILON,
            "gpt-4o has no fast tier — fast-mode call must equal standard call \
             (standard={s2}, fast={f2})"
        );
    }

    /// #642 — the ordered prefix table puts opus-4-6 / opus-4-7 / opus-4-8
    /// BEFORE `claude-opus-4-`, otherwise the fast-mode override would
    /// be silently lost.  Regression guard against re-ordering.
    #[test]
    fn fast_mode_rows_precede_generic_opus_4_prefix() {
        let idx_48 = PRICING_TABLE
            .iter()
            .position(|(p, _)| *p == "claude-opus-4-8")
            .expect("table must contain claude-opus-4-8");
        let idx_46 = PRICING_TABLE
            .iter()
            .position(|(p, _)| *p == "claude-opus-4-6")
            .expect("table must contain claude-opus-4-6");
        let idx_47 = PRICING_TABLE
            .iter()
            .position(|(p, _)| *p == "claude-opus-4-7")
            .expect("table must contain claude-opus-4-7");
        let idx_generic = PRICING_TABLE
            .iter()
            .position(|(p, _)| *p == "claude-opus-4-")
            .expect("table must contain claude-opus-4-");
        assert!(
            idx_48 < idx_generic,
            "claude-opus-4-8 ({idx_48}) must precede claude-opus-4- ({idx_generic})"
        );
        assert!(
            idx_46 < idx_generic,
            "claude-opus-4-6 ({idx_46}) must precede claude-opus-4- ({idx_generic}) — \
             otherwise the ordered table loses the fast-mode override"
        );
        assert!(
            idx_47 < idx_generic,
            "claude-opus-4-7 ({idx_47}) must precede claude-opus-4- ({idx_generic})"
        );
        // And the override actually lands on lookup.
        let p46 = get_pricing("claude-opus-4-6").expect("must resolve");
        assert_eq!(p46.fast_mode_input_per_million, Some(30.0));
        assert_eq!(p46.fast_mode_output_per_million, Some(150.0));
        let p47 = get_pricing("claude-opus-4-7").expect("must resolve");
        assert_eq!(p47.fast_mode_input_per_million, Some(30.0));
        assert_eq!(p47.fast_mode_output_per_million, Some(150.0));
        let p48 = get_pricing("claude-opus-4-8").expect("must resolve");
        assert_eq!(p48.fast_mode_input_per_million, Some(10.0));
        assert_eq!(p48.fast_mode_output_per_million, Some(50.0));
    }

    // -----------------------------------------------------------------------
    // #646 — unknown_model_cost sets a thread-local session flag that
    // downstream UI can read to surface "costs may be inaccurate".
    // -----------------------------------------------------------------------
    #[test]
    fn unknown_model_sets_thread_local_session_flag() {
        // Reset state for this test (flag is thread-local so other
        // tests on the same thread can pollute it).
        clear_unknown_model_cost();
        assert!(
            !has_unknown_model_cost(),
            "flag must start cleared after clear_unknown_model_cost()"
        );

        // A successful lookup must NOT set the flag.
        let usage = TokenUsage {
            input_tokens: 1_000,
            output_tokens: 100,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
        };
        let _ = calculate_cost("claude-3-haiku-20240307", &usage).expect("haiku must resolve");
        assert!(
            !has_unknown_model_cost(),
            "successful pricing lookup must not set the unknown-model flag"
        );

        // A failing lookup must set the flag and surface an Err.
        let err = calculate_cost("totally-unknown-model-zzz", &usage).unwrap_err();
        assert_eq!(
            err,
            PricingError::UnknownModel("totally-unknown-model-zzz".to_string())
        );
        assert!(
            has_unknown_model_cost(),
            "unknown-model lookup must set the session flag (#646)"
        );

        // clear_unknown_model_cost resets it.
        clear_unknown_model_cost();
        assert!(
            !has_unknown_model_cost(),
            "clear_unknown_model_cost() must reset the flag"
        );

        // The lookup primitive get_pricing must NOT touch the flag —
        // pricing-table introspection (status bar, etc.) shouldn't
        // pollute the session-level inaccuracy signal.
        assert!(get_pricing("totally-unknown-model-zzz").is_none());
        assert!(
            !has_unknown_model_cost(),
            "get_pricing miss must not set the unknown-model flag — only calculate_cost* does"
        );
    }

    // -----------------------------------------------------------------------
    // #642 — calculate_cost_full is the lower-level entry point and
    // composes correctly with both the fast-mode flag and extras.
    // -----------------------------------------------------------------------
    #[test]
    fn calculate_cost_full_composes_fast_mode_and_extras() {
        let usage = TokenUsage {
            input_tokens: 1_000_000,
            output_tokens: 0,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
        };
        let extras = UsageExtras::ZERO;
        // Fast tier on opus-4-6: 1M input @ $30/M = $30. Extras are
        // compatibility metadata and do not add user-facing charges.
        let cost = calculate_cost_full(
            "claude-opus-4-6",
            &usage,
            &extras,
            CacheWriteTtl::FiveMinutes,
            /*fast=*/ true,
        )
        .expect("opus-4-6 must resolve");
        assert!(
            (cost - 30.0).abs() < 1e-9,
            "fast-mode + extras must total $30.00 (got {cost})"
        );
    }

    // -----------------------------------------------------------------------
    // UsageExtras compatibility behaviour.
    // -----------------------------------------------------------------------
    #[test]
    fn usage_extras_accumulate_is_noop_for_empty_metadata() {
        let mut acc = UsageExtras::default();
        acc.accumulate(&UsageExtras::ZERO);
        assert_eq!(acc, UsageExtras::ZERO);
    }

    #[test]
    fn usage_extras_ignores_legacy_web_search_requests_json() {
        let extras: UsageExtras = serde_json::from_str(r#"{"web_search_requests":42}"#)
            .expect("legacy extras deserialize");
        assert_eq!(extras, UsageExtras::ZERO);
    }
}
